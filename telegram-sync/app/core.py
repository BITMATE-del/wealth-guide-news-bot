import os, asyncio, io, logging, secrets, sqlite3, tempfile, mimetypes
from pathlib import Path
from cryptography.fernet import Fernet
from telethon import TelegramClient, events
from telethon.tl.types import MessageMediaPhoto, MessageMediaDocument
from telethon.sessions import StringSession, SQLiteSession
from telethon.errors import FloodWaitError, SessionPasswordNeededError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from .models import SessionLocal, Account, Route, Delivery, SyncSetting, License
from .licensing import license_active

log = logging.getLogger("group_sync")

class SyncEngine:
    def __init__(self):
        self.api_id = int(os.environ["TG_API_ID"])
        self.api_hash = os.environ["TG_API_HASH"]
        self.cipher = Fernet(os.environ["SESSION_ENCRYPTION_KEY"])
        self.clients = {}
        self.pending = {}
        self.locks = {}
        self.next_send_at = {}
        self.member_count_cache = {}
        self.phone_start_lock = asyncio.Lock()
    def encrypt(self, s): return self.cipher.encrypt(s.encode()).decode()
    def decrypt(self, s): return self.cipher.decrypt(s.encode()).decode()
    def make_client(self, session=""):
        return TelegramClient(StringSession(session), self.api_id, self.api_hash, sequential_updates=True, flood_sleep_threshold=0)
    async def start(self):
        with SessionLocal() as db:
            accounts = list(db.scalars(select(Account).where(Account.enabled == True)))
        for account in accounts:
            if account.license_id is not None:
                with SessionLocal() as db:
                    if not license_active(db.get(License, account.license_id)):
                        continue
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
    async def save_account(self, client, label, license_id=None):
        identity = await client.get_me()
        session = StringSession.save(client.session)
        with SessionLocal() as db:
            account = db.scalar(select(Account).where(Account.tg_id == identity.id))
            if account:
                if account.license_id != license_id:
                    raise ValueError("이 텔레그램 계정은 다른 라이선스에 이미 등록되어 있습니다")
                account.label = label or account.label
                account.session_encrypted = self.encrypt(session)
                account.username = identity.username
                account.enabled = True
            else:
                account = Account(label=label or identity.first_name or str(identity.id),
                                  tg_id=identity.id, username=identity.username,
                                  session_encrypted=self.encrypt(session), enabled=True,
                                  license_id=license_id)
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
    async def import_session_file(self, filename, contents, label, license_id=None):
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
                return await self.save_account(client, label, license_id)
            finally:
                await client.disconnect()

    async def cleanup_phone_requests(self):
        now=asyncio.get_running_loop().time()
        expired=[(token,item) for token,item in list(self.pending.items())
                 if now-item["created"]>300]
        for token,item in expired:
            self.pending.pop(token,None)
            try: await item["client"].disconnect()
            except Exception: log.warning("Expired Telegram login session cleanup failed")

    async def phone_start(self, phone, license_id=None):
        # Avoid repeated send_code_request calls for an active phone session.
        # Reuse the existing code hash until it expires instead of triggering
        # Telegram's phone-code and API rate limits.
        async with self.phone_start_lock:
            await self.cleanup_phone_requests()
            now=asyncio.get_running_loop().time()
            for token,item in self.pending.items():
                if item["phone"]==phone and item["license_id"]==license_id:
                    remaining=max(0,int(300-(now-item["created"])))
                    return {"token":token,"reused":True,"expires_in":remaining}
            if len(self.pending)>=8:
                raise ValueError("진행 중인 인증 요청이 많습니다. 약 5분 후 다시 시도하세요")
            c=self.make_client()
            try:
                await asyncio.wait_for(c.connect(),timeout=20)
                sent=await asyncio.wait_for(c.send_code_request(phone),timeout=35)
            except Exception:
                try: await c.disconnect()
                except Exception: pass
                raise
            token=secrets.token_urlsafe(32)
            self.pending[token]={"client":c,"phone":phone,"hash":sent.phone_code_hash,
                                 "license_id":license_id,"created":asyncio.get_running_loop().time()}
            return {"token":token,"reused":False,"expires_in":300}

    async def phone_finish(self, token, code, password, label, license_id=None):
        item = self.pending.get(token)
        if not item: raise ValueError("인증 요청을 다시 시작하세요")
        if item["license_id"] != license_id: raise ValueError("다른 라이선스에서 요청한 인증입니다")
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
            result = await self.save_account(c,label,license_id)
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
        pending=[]
        now=asyncio.get_running_loop().time()
        async for d in c.iter_dialogs(limit=300):
            if not (d.is_group or d.is_channel): continue
            # Some Telegram dialog entities already contain member counts.
            value=getattr(d.entity,"participants_count",None)
            if not isinstance(value,int) or value<0: value=None
            cached=self.member_count_cache.get((account_id,d.id))
            if value is None and cached and now-cached[0]<600:
                value=cached[1]
            item={"id":d.id,"name":d.name,"member_count":value}
            result.append(item)
            if value is not None:
                self.member_count_cache[(account_id,d.id)]=(now,value)
            elif not cached or now-cached[0]>=600:
                pending.append((item,d.entity))

        # Telegram does not put member counts in every dialog. Fetch missing
        # counts with a bounded number of small requests so listing 300 chats
        # cannot trigger hundreds of API calls or stall the management screen.
        semaphore=asyncio.Semaphore(3)
        async def enrich(item,entity):
            async with semaphore:
                try:
                    count=await asyncio.wait_for(c.get_participants(entity,limit=0),timeout=5)
                    total=getattr(count,"total",None)
                    if isinstance(total,int) and total>=0:
                        item["member_count"]=total
                        self.member_count_cache[(account_id,item["id"])]=(asyncio.get_running_loop().time(),total)
                except Exception:
                    # An inaccessible/private group must not break the list.
                    self.member_count_cache[(account_id,item["id"])]=(asyncio.get_running_loop().time(),None)
        if pending:
            # Never delay the settings screen indefinitely on slow Telegram APIs.
            try:
                await asyncio.wait_for(
                    asyncio.gather(*(enrich(item,entity) for item,entity in pending[:45])),
                    timeout=12,
                )
            except asyncio.TimeoutError:
                pass
        return result
    def delivery_wait_seconds(self, message, license_id=None):
        # A deterministic, adjustable reading/typing-time approximation.
        # It is not a claim about a real person's typing speed and does not
        # bypass or replace Telegram's rate limits.
        with SessionLocal() as db:
            setting=db.get(SyncSetting,"delivery_pace" if license_id is None else "delivery_pace:"+str(license_id))
            mode=setting.value if setting else "normal"
        text=(message.raw_text or "").strip()
        chars=len(text)
        if mode=="off": return 0.0
        # Seconds: base time + length / estimated characters per second.
        # Large posts are capped so delivery queues remain manageable.
        if mode=="relaxed": return float(min(45,max(10,5 + chars / 4)))
        if mode=="fast": return float(min(12,max(3,1.5 + chars / 12)))
        return float(min(25,max(6,3 + chars / 7)))

    async def pace_sender(self, sender_id, message, license_id=None):
        # Queue all sends from one Telegram account, including simultaneous
        # source messages, to avoid an immediate burst to multiple groups.
        lock=self.locks.setdefault(sender_id,asyncio.Lock())
        await lock.acquire()
        try:
            loop=asyncio.get_running_loop()
            now=loop.time()
            wait=max(0.0,self.next_send_at.get(sender_id,now)-now)
            if wait: await asyncio.sleep(wait)
            # Reserve the next interval once the next send actually starts.
            self.next_send_at[sender_id]=loop.time()+self.delivery_wait_seconds(message,license_id)
            return lock
        except BaseException:
            lock.release()
            raise

    async def on_message(self, watcher_id, event):
        if not event.chat_id or not event.sender_id: return
        # A message already delivered by this service must not trigger another forwarding route.
        with SessionLocal() as db:
            echo = db.execute(select(Delivery.id).join(Route, Delivery.route_id == Route.id).where(
                Route.target_chat == event.chat_id, Delivery.target_id == event.id,
                Delivery.status == "sent").limit(1)).first()
            if echo: return
        with SessionLocal() as db:
            watcher=db.get(Account,watcher_id)
            if watcher is None or not watcher.enabled: return
            if watcher.license_id is not None and not license_active(db.get(License, watcher.license_id)):
                return
            routes = list(db.scalars(select(Route).where(Route.active == True,
                Route.watcher_id == watcher_id, Route.source_chat == event.chat_id)))
            owner_license_id=watcher.license_id
        for route in routes:
            if route.sender_filter and route.sender_filter != event.sender_id: continue
            if route.target_chat == event.chat_id: continue
            if route.mode == "fixed": sender_id = route.fixed_id
            else:
                with SessionLocal() as db:
                    a = db.scalar(select(Account).where(Account.tg_id == event.sender_id,Account.enabled == True,
                        Account.license_id == owner_license_id if owner_license_id is not None else Account.license_id.is_(None)))
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
                pace_lock=await self.pace_sender(sender_id,event.message,owner_license_id)
                try:
                    # Revalidate immediately before sending: a license could expire,
                    # a device reset could be approved, or a rule could be disabled
                    # while this message waits in the pacing queue.
                    with SessionLocal() as db:
                        if owner_license_id is not None and not license_active(db.get(License,owner_license_id)):
                            raise ValueError("라이선스가 만료되거나 기기가 초기화되어 전송을 중단했습니다")
                        current_sender=db.get(Account,sender_id)
                        if current_sender is None or not current_sender.enabled or current_sender.license_id!=owner_license_id:
                            raise ValueError("발신 계정이 현재 라이선스에서 사용 불가합니다")
                        current_route=db.get(Route,route.id)
                        if current_route is None or not current_route.active:
                            raise ValueError("전달 설정이 중지되거나 삭제됐습니다")
                    entity = await c.get_input_entity(route.target_chat)
                    if event.message.media:
                        raw=await event.message.download_media(file=bytes)
                        if not raw: raise ValueError("지원하지 않는 첨부 형식입니다")
                        if len(raw)>20*1024*1024: raise ValueError("첨부파일 용량 제한 초과 (20MB)")
                        media = event.message.media
                        file_info = event.message.file
                        original_name = getattr(file_info, "name", None) if file_info else None
                        mime_type = getattr(file_info, "mime_type", None) if file_info else None
                        # Telegram needs a meaningful extension to display uploaded bytes
                        # as an in-chat photo/video rather than an unnamed document.
                        if isinstance(media, MessageMediaPhoto):
                            filename = "photo.jpg"
                            mime_type = "image/jpeg"
                            send_as_document = False
                        elif isinstance(media, MessageMediaDocument):
                            extension = mimetypes.guess_extension(mime_type or "") or ""
                            if mime_type == "image/jpeg": extension = ".jpg"
                            elif mime_type == "video/mp4": extension = ".mp4"
                            filename = original_name or ("media" + extension if extension else "attachment.bin")
                            send_as_document = not bool(mime_type and (mime_type.startswith("image/") or mime_type.startswith("video/")))
                        else:
                            raise ValueError("현재 자동 전달에서 지원하지 않는 미디어 형식입니다")
                        buffer = io.BytesIO(raw)
                        buffer.name = filename
                        sent = await c.send_file(
                            entity, buffer, caption=event.raw_text or "",
                            force_document=send_as_document,
                            supports_streaming=bool(mime_type and mime_type.startswith("video/")),
                            formatting_entities=event.message.entities or None
                        )
                    else:
                        if not event.raw_text: raise ValueError("전송할 내용이 없습니다")
                        sent=await c.send_message(entity,event.raw_text,
                              formatting_entities=event.message.entities,link_preview=False)
                    target_id=sent.id
                    status="sent"
                finally:
                    pace_lock.release()
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
