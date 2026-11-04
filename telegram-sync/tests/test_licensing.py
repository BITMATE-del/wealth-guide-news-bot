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
                    db.add_all([account_a, account_b])
                    db.commit()
                    db.refresh(account_a)
                    db.refresh(account_b)
                    aid, bid = account_a.id, account_b.id

                    route_b = Route(
                        watcher_id=bid, source_chat=-2000, target_chat=-3000,
                        mode="same", active=True,
                    )
                    db.add(route_b)
                    db.commit()
                    db.refresh(route_b)
                    rid_b = route_b.id
                    db.add(Delivery(route_id=rid_b, source_id=10, status="sent"))
                    db.commit()

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


if __name__ == "__main__":
    unittest.main()
