import os, asyncio, io, logging, secrets, sqlite3, tempfile
from pathlib import Path
from cryptography.fernet import Fernet
from telethon import TelegramClient, events
from telethon.sessions import StringSession, SQLiteSession
from telethon.errors import FloodWaitError, SessionPasswordNeededError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from .models import SessionLocal, Account, Route, Delivery

log = logging.getLogger("group_sync")

class SyncEngine:
    def __init__(self):
        self.api_id = int(os.environ["TG_API_ID"])
        self.api_hash = os.environ["TG_API_HASH"]
        self.cipher = Fernet(os.environ["SESSION_ENCRYPTION_KEY"])
        self.clients = {}
        self.pending = {}
        self.locks = {}
    def encrypt(self, s): return self.cipher.encrypt(s.encode()).decode()
    def decrypt(self, s): return self.cipher.decrypt(s.encode()).decode()
    def make_client(self, session=""):
        return TelegramClient(StringSession(session), self.api_id, self.api_hash, sequential_updates=True, flood_sleep_threshold=0)
    async def start(self):
        with SessionLocal() as db:
            accounts = list(db.scalars(select(Account).where(Account.enabled == True)))
        for account in accounts:
            try: await self.attach(account)
            except Exception: log.exception("Account %s reconnect failed", account.id)
    async def stop(self):
        for c in list(self.clients.values()): await c.disconnect()
        for item in list(self.pending.values()): await item["client"].disconnect()
    async def attach(self, account):
        client = self.make_client(self.decrypt(account.session_encrypted))
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            raise ValueError("계정 인증이 만료되었습니다")
        self._handlers(client, account.id)
        old = self.clients.pop(account.id, None)
        if old: await old.disconnect()
        self.clients[account.id] = client
    def _handlers(self, client, watcher_id):
        @client.on(events.NewMessage)
        async def handler(event):
            try: await self.on_message(watcher_id, event)
            except Exception: log.exception("Message processing failed")
    async def save_account(self, client, label):
        identity = await client.get_me()
        session = StringSession.save(client.session)
        with SessionLocal() as db:
            account = db.scalar(select(Account).where(Account.tg_id == identity.id))
            if account:
                account.label = label or account.label
                account.session_encrypted = self.encrypt(session)
                account.username = identity.username
                account.enabled = True
            else:
                account = Account(label=label or identity.first_name or str(identity.id),
                                  tg_id=identity.id, username=identity.username,
                                  session_encrypted=self.encrypt(session), enabled=True)
                db.add(account)
            db.commit()
            db.refresh(account)
            account_id = account.id
            await self.attach(account)
        return {"id": account_id, "label": account.label}
    async def import_session(self, value, label):
        c = self.make_client(value)
        try:
            await c.connect()
            if not await c.is_user_authorized(): raise ValueError("올바른 세션이 아닙니다")
            return await self.save_account(c, label)
        finally: await c.disconnect()
    async def import_session_file(self, filename, contents, label):
        # A Telethon .session is a SQLite database containing Telegram credentials.
        # Validate it before opening it with Telethon; never keep the raw file.
        if not filename.lower().endswith(".session"):
            raise ValueError("Telethon .session 파일만 업로드할 수 있습니다")
        if not contents or len(contents) > 2 * 1024 * 1024:
            raise ValueError("파일 크기는 2MB 이하여야 합니다")
        if not contents.startswith(b"SQLite format 3\x00"):
            raise ValueError("Telethon 세션 파일 형식이 아닙니다")
        with tempfile.TemporaryDirectory(prefix="tg-session-") as directory:
            path = Path(directory) / "uploaded.session"
            path.write_bytes(contents)
            try:
                with sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True) as db:
                    db.execute("PRAGMA query_only=ON")
                    row = db.execute("SELECT dc_id, server_address, port, auth_key FROM sessions LIMIT 1").fetchone()
                    if row is None or not isinstance(row[3], bytes) or len(row[3]) != 256:
                        raise ValueError("인증 정보가 없는 세션 파일입니다")
            except sqlite3.DatabaseError as exc:
                raise ValueError("읽을 수 없는 세션 파일입니다") from exc
            client = TelegramClient(SQLiteSession(str(path)), self.api_id, self.api_hash,
                                    sequential_updates=True, flood_sleep_threshold=0)
            try:
                await client.connect()
                if not await client.is_user_authorized():
                    raise ValueError("로그인이 만료되었거나 사용할 수 없는 세션입니다")
                return await self.save_account(client, label)
            finally:
                await client.disconnect()

    async def phone_start(self, phone):
        if len(self.pending) >= 8: raise ValueError("인증 요청이 너무 많습니다")
        c = self.make_client()
        await c.connect()
        try: sent = await c.send_code_request(phone)
        except Exception:
            await c.disconnect()
            raise
        token = secrets.token_urlsafe(32)
        self.pending[token] = {"client":c,"phone":phone,"hash":sent.phone_code_hash,
                               "created":asyncio.get_running_loop().time()}
        return {"token":token}
    async def phone_finish(self, token, code, password, label):
        item = self.pending.get(token)
        if not item: raise ValueError("인증 요청을 다시 시작하세요")
        if asyncio.get_running_loop().time()-item["created"] > 300:
            self.pending.pop(token,None)
            await item["client"].disconnect()
            raise ValueError("인증 시간이 만료되었습니다")
        c = item["client"]
        try:
            if not await c.is_user_authorized():
                try:
                    if code: await c.sign_in(phone=item["phone"],code=code,phone_code_hash=item["hash"])
                    elif not password: raise ValueError("인증코드를 입력하세요")
                except SessionPasswordNeededError:
                    if not password: return {"password_required":True,"token":token}
                if not await c.is_user_authorized():
                    if not password: return {"password_required":True,"token":token}
                    await c.sign_in(password=password)
            result = await self.save_account(c,label)
            self.pending.pop(token,None)
            await c.disconnect()
            return result
        except Exception:
            if not self.pending.get(token):
                await c.disconnect()
            raise
    async def chats(self, account_id):
        c = self.clients.get(account_id)
        if not c: raise ValueError("계정이 연결되지 않았습니다")
        result=[]
        async for d in c.iter_dialogs(limit=300):
            if d.is_group or d.is_channel:
                result.append({"id":d.id,"name":d.name})
        return result
    async def on_message(self, watcher_id, event):
        if not event.chat_id or not event.sender_id: return
        # A message already delivered by this service must not trigger another forwarding route.
        with SessionLocal() as db:
            echo = db.execute(select(Delivery.id).join(Route, Delivery.route_id == Route.id).where(
                Route.target_chat == event.chat_id, Delivery.target_id == event.id,
                Delivery.status == "sent").limit(1)).first()
            if echo: return
        with SessionLocal() as db:
            routes = list(db.scalars(select(Route).where(Route.active == True,
                Route.watcher_id == watcher_id, Route.source_chat == event.chat_id)))
        for route in routes:
            if route.sender_filter and route.sender_filter != event.sender_id: continue
            if route.target_chat == event.chat_id: continue
            if route.mode == "fixed": sender_id = route.fixed_id
            else:
                with SessionLocal() as db:
                    a = db.scalar(select(Account).where(Account.tg_id == event.sender_id,Account.enabled == True))
                    sender_id = a.id if a else None
            with SessionLocal() as db:
                item=Delivery(route_id=route.id,source_id=event.id,sender_id=sender_id)
                db.add(item)
                try:
                    db.commit()
                    db.refresh(item)
                    delivery_id=item.id
                except IntegrityError:
                    db.rollback()
                    continue
            status, target_id, error = "failed", None, None
            try:
                c = self.clients.get(sender_id)
                if not c: raise ValueError("전송 계정이 연결되어 있지 않습니다")
                entity = await c.get_input_entity(route.target_chat)
                if event.message.media:
                    raw=await event.message.download_media(file=bytes)
                    if not raw: raise ValueError("지원하지 않는 첨부 형식입니다")
                    if len(raw)>20*1024*1024: raise ValueError("첨부파일 용량 제한 초과 (20MB)")
                    buffer=io.BytesIO(raw)
                    buffer.name=getattr(event.message.file,"name",None) or "attachment"
                    sent=await c.send_file(entity,buffer,caption=event.raw_text or "")
                else:
                    if not event.raw_text: raise ValueError("전송할 내용이 없습니다")
                    sent=await c.send_message(entity,event.raw_text,
                          formatting_entities=event.message.entities,link_preview=False)
                target_id=sent.id
                status="sent"
            except FloodWaitError as e:
                error=f"텔레그램 전송 제한으로 {e.seconds}초 대기가 필요합니다"
            except Exception as e:
                error=str(e)[:400]
            with SessionLocal() as db:
                delivery=db.get(Delivery,delivery_id)
                delivery.status=status
                delivery.target_id=target_id
                delivery.error=error
                db.commit()
