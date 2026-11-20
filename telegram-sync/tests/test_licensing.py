"""Regression tests for license activation, device lock/reset and tenant isolation.
No Telegram network calls; use a temporary SQLite database and HTTPS TestClient.
"""
import os
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class LicenseFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.fernet import Fernet

        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["DATABASE_URL"] = "sqlite:///" + str(Path(cls.tmp.name) / "license-tests.sqlite3")
        os.environ["SESSION_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
        os.environ["TG_API_ID"] = "123456"
        os.environ["TG_API_HASH"] = "test-api-hash"
        os.environ["ADMIN_PASSWORD"] = "owner-test-password"
        os.environ["WEB_SESSION_SECRET"] = "test-session-cookie-secret"
        from fastapi.testclient import TestClient
        from app.main import app

        cls.TestClient = TestClient
        cls.app = app

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def client(self):
        # Secure registered-device cookies must be tested on an HTTPS origin.
        return self.TestClient(self.app, base_url="https://testserver")

    def test_license_lifecycle_and_cross_tenant_isolation(self):
        from app.licensing import utcnow
        from app.models import Account, Delivery, License, Route, SessionLocal

        with self.client() as owner:
            res = owner.post("/api/login", json={"password": "owner-test-password"})
            self.assertEqual(res.status_code, 200, res.text)
            owner_headers = {"x-csrf-token": res.json()["csrf"]}

            keys = {}
            ids = {}
            for label, days in [("A", 1), ("B", 7), ("C", 30), ("Custom", 45)]:
                res = owner.post(
                    "/api/admin/licenses",
                    headers=owner_headers,
                    json={"label": label, "days": days},
                )
                self.assertEqual(res.status_code, 200, res.text)
                keys[label] = res.json()["code"]
                ids[label] = res.json()["license"]["id"]
                self.assertEqual(res.json()["license"]["duration_days"], days)
            listed = owner.get("/api/admin/licenses").json()
            self.assertEqual(len(listed), 4)
            self.assertNotIn("code", listed[0])
            self.assertEqual(owner.get("/api/me").json()["is_owner"], True)

            with self.client() as client_a, self.client() as client_b:
                register_a = client_a.post(
                    "/api/license/activate",
                    json={"code": keys["A"], "password": "strong-pass-A"},
                )
                self.assertEqual(register_a.status_code, 200, register_a.text)
                self.assertTrue(register_a.cookies.get("sync_registered_device"))
                a_headers = {"x-csrf-token": register_a.json()["csrf"]}
                register_b = client_b.post(
                    "/api/license/activate",
                    json={"code": keys["B"], "password": "strong-pass-B"},
                )
                self.assertEqual(register_b.status_code, 200, register_b.text)
                b_headers = {"x-csrf-token": register_b.json()["csrf"]}

                with SessionLocal() as db:
                    account_a = Account(
                        license_id=ids["A"], label="A-Admin", tg_id=100001,
                        session_encrypted="not-a-real-session", enabled=True,
                    )
                    account_b = Account(
                        license_id=ids["B"], label="B-Admin", tg_id=100002,
                        session_encrypted="not-a-real-session", enabled=True,
                    )
                    owner_account = Account(
                        license_id=None, label="Owner-Only", tg_id=100003,
                        session_encrypted="not-a-real-session", enabled=True,
                    )
                    db.add_all([account_a, account_b, owner_account])
                    db.commit()
                    db.refresh(account_a)
                    db.refresh(account_b)
                    db.refresh(owner_account)
                    aid, bid, oid = account_a.id, account_b.id, owner_account.id

                    route_b = Route(
                        watcher_id=bid, source_chat=-2000, target_chat=-3000,
                        mode="same", active=True,
                    )
                    db.add(route_b)
                    db.commit()
                    db.refresh(route_b)
                    rid_b = route_b.id
                    owner_route = Route(
                        watcher_id=oid, source_chat=-9000, target_chat=-9001,
                        mode="same", active=True,
                    )
                    db.add(owner_route)
                    db.commit()
                    db.refresh(owner_route)
                    rid_owner = owner_route.id
                    db.add_all([
                        Delivery(route_id=rid_b, source_id=10, status="sent"),
                        Delivery(route_id=rid_owner, source_id=11, status="sent"),
                    ])
                    db.commit()

                # The owner is a separate workspace, not a superuser wildcard.
                self.assertEqual(
                    [a["label"] for a in owner.get("/api/accounts").json()],
                    ["Owner-Only"],
                )
                self.assertEqual(
                    [route["id"] for route in owner.get("/api/routes").json()],
                    [rid_owner],
                )
                self.assertEqual(
                    [log["route_id"] for log in owner.get("/api/logs").json()],
                    [rid_owner],
                )
                self.assertEqual(owner.get(f"/api/accounts/{aid}/chats").status_code, 404)
                self.assertEqual(
                    owner.patch(f"/api/routes/{rid_b}", json={"enabled": False}, headers=owner_headers).status_code,
                    404,
                )
                self.assertEqual(
                    owner.post(
                        "/api/routes/bulk",
                        json={"route_ids": [rid_b], "enabled": False},
                        headers=owner_headers,
                    ).status_code,
                    404,
                )
                self.assertEqual(
                    owner.delete(f"/api/routes/{rid_b}", headers=owner_headers).status_code,
                    404,
                )
                self.assertEqual(
                    owner.post(
                        "/api/routes",
                        json={
                            "watcher_id": aid,
                            "source_chat": -100,
                            "target_chat": -101,
                            "mode": "same",
                        },
                        headers=owner_headers,
                    ).status_code,
                    404,
                )
                usage=owner.get("/api/admin/license-usage")
                self.assertEqual(usage.status_code, 200, usage.text)
                usage_by_id={item["license_id"]:item for item in usage.json()}
                self.assertEqual(usage_by_id[ids["A"]]["account_count"], 1)
                self.assertEqual(usage_by_id[ids["B"]]["route_count"], 1)
                self.assertEqual(usage_by_id[ids["B"]]["active_route_count"], 1)
                self.assertEqual(usage_by_id[ids["C"]]["account_count"], 0)
                self.assertEqual(client_a.get("/api/admin/license-usage").status_code, 403)
                self.assertEqual(client_a.get(f"/api/accounts/{oid}/chats").status_code, 404)
                self.assertEqual(client_a.get("/api/routes").json(), [])

                self.assertEqual([a["label"] for a in client_a.get("/api/accounts").json()], ["A-Admin"])
                self.assertEqual([a["label"] for a in client_b.get("/api/accounts").json()], ["B-Admin"])
                self.assertEqual(client_a.get(f"/api/accounts/{bid}/chats").status_code, 404)
                self.assertEqual(client_a.get("/api/routes").json(), [])
                self.assertEqual(client_a.get("/api/logs").json(), [])
                self.assertEqual(client_a.patch(
                    f"/api/routes/{rid_b}", json={"enabled": False}, headers=a_headers
                ).status_code, 404)
                self.assertEqual(client_a.delete(
                    f"/api/routes/{rid_b}", headers=a_headers
                ).status_code, 404)
                self.assertEqual(client_a.post(
                    "/api/routes/bulk", json={"route_ids": [rid_b], "enabled": False}, headers=a_headers
                ).status_code, 404)
                self.assertEqual(client_a.get("/api/admin/licenses").status_code, 403)
                self.assertEqual(client_a.post(
                    "/api/routes",
                    json={
                        "watcher_id": bid,
                        "source_chat": -123,
                        "target_chat": -456,
                        "mode": "same",
                    },
                    headers=a_headers,
                ).status_code, 404)

                self.assertEqual(client_a.put(
                    "/api/settings/delivery", json={"mode": "relaxed"}, headers=a_headers
                ).status_code, 200)
                self.assertEqual(client_b.get("/api/settings/delivery").json()["mode"], "normal")

                with self.client() as new_device:
                    rejected = new_device.post(
                        "/api/license/login",
                        json={"code": keys["A"], "password": "strong-pass-A"},
                    )
                    self.assertEqual(rejected.status_code, 403, rejected.text)
                    req = new_device.post(
                        "/api/license/reset-request",
                        json={"code": keys["A"], "password": "strong-pass-A"},
                    )
                    self.assertEqual(req.status_code, 200, req.text)
                    pending = owner.get("/api/admin/device-resets").json()
                    self.assertEqual(len(pending), 1)
                    approved = owner.post(
                        f'/api/admin/device-resets/{pending[0]["id"]}',
                        headers=owner_headers, json={"approved": True},
                    )
                    self.assertEqual(approved.status_code, 200, approved.text)
                    self.assertEqual(client_a.get("/api/accounts").status_code, 403)
                    new_login = new_device.post(
                        "/api/license/login",
                        json={"code": keys["A"], "password": "strong-pass-A"},
                    )
                    self.assertEqual(new_login.status_code, 200, new_login.text)
                    self.assertEqual(new_device.get("/api/accounts").status_code, 200)
                    with SessionLocal() as db:
                        row = db.get(License, ids["A"])
                        row.expires_at = utcnow() - timedelta(seconds=1)
                        db.commit()
                    self.assertEqual(new_device.get("/api/accounts").status_code, 403)

                self.assertEqual(client_b.get("/api/accounts").status_code, 200)
                blocked = owner.patch(
                    f'/api/admin/licenses/{ids["B"]}',
                    headers=owner_headers, json={"blocked": True},
                )
                self.assertEqual(blocked.status_code, 200)
                self.assertEqual(client_b.get("/api/accounts").status_code, 403)


    def test_same_message_two_watchers_sends_once_and_mirror_does_not_loop(self):
        import asyncio
        from types import SimpleNamespace
        from sqlalchemy import select
        from app.main import engine
        from app.models import Account, Route, ForwardClaim, SessionLocal, SyncSetting

        class MockClient:
            def __init__(self):
                self.sent=[]
            async def get_input_entity(self, chat):
                return chat
            async def send_message(self, chat, text, **kw):
                self.sent.append((chat,text))
                return SimpleNamespace(id=40000+len(self.sent))

        with SessionLocal() as db:
            watcher_a=Account(
                license_id=None,label="Loop Test A",tg_id=7700001,
                session_encrypted="test-session-not-connected",enabled=True)
            watcher_b=Account(
                license_id=None,label="Loop Test B",tg_id=7700002,
                session_encrypted="test-session-not-connected",enabled=True)
            db.add_all([watcher_a,watcher_b])
            setting=db.get(SyncSetting,"delivery_pace")
            if setting: setting.value="off"
            else: db.add(SyncSetting(key="delivery_pace",value="off"))
            db.commit()
            db.refresh(watcher_a);db.refresh(watcher_b)
            watcher_a_id,watcher_b_id=watcher_a.id,watcher_b.id
            db.add_all([
                Route(watcher_id=watcher_a_id,source_chat=-88001,target_chat=-88002,
                      mode="fixed",fixed_id=watcher_a_id,active=True),
                Route(watcher_id=watcher_b_id,source_chat=-88001,target_chat=-88002,
                      mode="fixed",fixed_id=watcher_b_id,active=True),
                Route(watcher_id=watcher_b_id,source_chat=-88002,target_chat=-88001,
                      mode="fixed",fixed_id=watcher_b_id,active=True)
            ])
            db.commit()

        ca,cb=MockClient(),MockClient()
        old_clients=dict(engine.clients)
        engine.clients[watcher_a_id]=ca
        engine.clients[watcher_b_id]=cb
        try:
            message=SimpleNamespace(raw_text="동일 게시물 복제 방지 점검",media=None,entities=None)
            source_event=SimpleNamespace(chat_id=-88001,id=771,sender_id=7700001,
                                         raw_text=message.raw_text,message=message)
            async def check():
                await engine.on_message(watcher_a_id,source_event)
                await engine.on_message(watcher_b_id,source_event)
                mirrored=SimpleNamespace(chat_id=-88002,id=779,sender_id=7700002,
                                         raw_text=message.raw_text,message=message)
                await engine.on_message(watcher_b_id,mirrored)
            asyncio.run(check())
            self.assertEqual(len(ca.sent)+len(cb.sent),1)
            self.assertEqual((ca.sent+cb.sent)[0],(-88002,message.raw_text))
            with SessionLocal() as db:
                claims=list(db.scalars(select(ForwardClaim).where(
                    ForwardClaim.source_chat==-88001,
                    ForwardClaim.source_id==771,
                    ForwardClaim.target_chat==-88002)))
                self.assertEqual(len(claims),1)
        finally:
            engine.clients=old_clients


    def test_link_preview_message_is_sent_as_formatted_text(self):
        import asyncio
        from types import SimpleNamespace
        from telethon.tl.types import MessageEntityTextUrl
        from sqlalchemy import select
        from app.main import engine
        from app.models import Account, Route, SessionLocal, SyncSetting

        class MockClient:
            def __init__(self): self.sent=[]
            async def get_input_entity(self, chat): return chat
            async def send_message(self, chat, text, **kw):
                self.sent.append((chat,text,kw))
                return SimpleNamespace(id=91001,entities=kw.get("formatting_entities"))
            async def send_file(self,*args,**kw):
                raise AssertionError("링크 미리보기를 파일로 전송하면 안 됩니다")

        with SessionLocal() as db:
            watcher=Account(
                license_id=None,label="Link Preview Test",tg_id=8800101,
                session_encrypted="not-real",enabled=True)
            db.add(watcher)
            setting=db.get(SyncSetting,"delivery_pace")
            if setting: setting.value="off"
            else: db.add(SyncSetting(key="delivery_pace",value="off"))
            db.commit()
            db.refresh(watcher)
            wid=watcher.id
            db.add(Route(
                watcher_id=wid,source_chat=-99001,target_chat=-99002,
                mode="fixed",fixed_id=wid,active=True))
            db.commit()

        client=MockClient()
        original=dict(engine.clients)
        engine.clients[wid]=client
        try:
            # A URL preview is a media object but NOT a photo or file.
            # A text-link entity should stay clickable in the target.
            entities=[MessageEntityTextUrl(offset=0,length=4,url="https://example.org/article")]
            message=SimpleNamespace(
                raw_text="기사보기 주요 내용",media=SimpleNamespace(webpage=object()),
                entities=entities)
            event=SimpleNamespace(
                chat_id=-99001,id=11122,sender_id=8800101,
                raw_text=message.raw_text,message=message)
            asyncio.run(engine.on_message(wid,event))
            self.assertEqual(len(client.sent),1)
            self.assertEqual(client.sent[0][0],-99002)
            self.assertEqual(client.sent[0][1],message.raw_text)
            self.assertEqual(client.sent[0][2]["formatting_entities"],entities)
            self.assertFalse(client.sent[0][2]["link_preview"])
            self.assertIsNone(client.sent[0][2]["parse_mode"])
        finally:
            engine.clients=original


    def test_text_url_repair_verifies_actual_telegram_message(self):
        import asyncio
        from types import SimpleNamespace
        from telethon.tl.types import MessageEntityTextUrl
        from app.main import engine

        link=MessageEntityTextUrl(offset=0,length=6,url="https://example.org/go")
        source=SimpleNamespace(entities=[link])
        class Fake:
            def __init__(self,repair_works):
                self.repair_works=repair_works
                self.edits=0
            async def get_messages(self,entity,ids):
                return SimpleNamespace(entities=[link] if self.edits and self.repair_works else [])
            async def edit_message(self,entity,msgid,text,**kwargs):
                self.edits+=1
                assert kwargs["formatting_entities"]==[link]
                assert kwargs["parse_mode"] is None
        async def run_case(works):
            client=Fake(works)
            sent=SimpleNamespace(id=99,entities=[])
            try:
                await engine.verify_hidden_links(client,-100,sent,source,"메시지보기")
                result=True
            except ValueError:
                result=False
            return result,client.edits
        self.assertEqual(asyncio.run(run_case(True)),(True,1))
        self.assertEqual(asyncio.run(run_case(False)),(False,1))


if __name__ == "__main__":
    unittest.main()
