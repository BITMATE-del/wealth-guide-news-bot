import os, re, secrets, hmac
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import select, desc, delete, or_
from .models import SessionLocal, Account, Route, Delivery, ChatName, SyncSetting, License, LicenseReset
from .core import SyncEngine
from .licensing import COOKIE, utcnow, aware, digest, hash_password, valid_password, license_active, get_identity, require_owner, license_summary, create_license, request_reset, request_ip

engine=None
@asynccontextmanager
async def lifespan(app):
    global engine
    required=["TG_API_ID","TG_API_HASH","SESSION_ENCRYPTION_KEY","ADMIN_PASSWORD","WEB_SESSION_SECRET"]
    missing=[k for k in required if not os.environ.get(k)]
    if missing: raise RuntimeError("환경변수 누락: "+", ".join(missing))
    engine=SyncEngine()
    await engine.start()
    yield
    await engine.stop()

app=FastAPI(lifespan=lifespan,docs_url=None,redoc_url=None)
app.add_middleware(SessionMiddleware,secret_key=os.environ.get("WEB_SESSION_SECRET","development-only"),
                   same_site="strict",https_only=os.environ.get("PUBLIC_ORIGIN","").startswith("https://"))

@app.middleware("http")
async def headers(request,call_next):
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Cache-Control"]="no-store"
    return response

def authorized(request:Request):
    license_id=get_identity(request)
    if request.method not in ("GET","HEAD","OPTIONS") and not secrets.compare_digest(
        str(request.headers.get("x-csrf-token") or ""), str(request.session.get("csrf") or "missing")
    ):
        raise HTTPException(403,"보안 확인에 실패했습니다")
    return license_id

class Login(BaseModel): password:str
class LicenseActivate(BaseModel):
    code:str
    password:str
class LicenseLogin(BaseModel):
    code:str
    password:str
class IssueLicense(BaseModel):
    label:str=""
    days:int=Field(ge=1,le=3650)
class ReviewReset(BaseModel):
    approved:bool
class BlockLicense(BaseModel):
    blocked:bool
class Phone(BaseModel): phone:str
class ResendCode(BaseModel): token:str
class Verify(BaseModel):
    token:str
    code:str=""
    password:str=""
    label:str=""
class RouteInput(BaseModel):
    watcher_id:int
    source_chat:int
    target_chat:int
    mode:str
    fixed_id:int|None=None
    sender_filter:int|None=None
class Switch(BaseModel): enabled:bool
class PaceSetting(BaseModel): mode:str
class RouteEdit(BaseModel):
    mode:str
    fixed_id:int|None=None
class BulkSwitch(BaseModel):
    route_ids:list[int]=Field(min_length=1,max_length=500)
    enabled:bool

@app.get("/")
async def index(): return FileResponse("static/index.html")

@app.get("/app")
async def customer_page():
    return FileResponse("static/index.html")

@app.get("/admin")
async def owner_page():
    return FileResponse("static/index.html")

@app.get("/health")
async def health(): return {"ok":True,"service":"telegram-sync"}

@app.get("/api/me")
async def me(request:Request):
    try: license_id=get_identity(request)
    except HTTPException:
        return {"logged_in":False,"csrf":""}
    result={"logged_in":True,"is_owner":license_id is None,"csrf":request.session.get("csrf","")}
    if license_id is not None:
        with SessionLocal() as db:
            result["license"]=license_summary(db.get(License,license_id))
    return result

@app.post("/api/login")
async def login(data:Login,request:Request):
    if not secrets.compare_digest(data.password,os.environ["ADMIN_PASSWORD"]):
        raise HTTPException(401,"비밀번호가 올바르지 않습니다")
    request.session.clear()
    request.session["admin"]=True
    request.session["csrf"]=secrets.token_urlsafe(32)
    return {"ok":True,"csrf":request.session["csrf"]}

@app.post("/api/logout",dependencies=[Depends(authorized)])
async def logout(request:Request):
    request.session.clear()
    # Keep the registered-device cookie: logging out must not lock the customer out.
    return {"ok":True}

# License keys are never stored in plaintext; the key is shown once on issue.
# Device cookies are browser-specific credentials, not hardware serial numbers.
_login_failures={}

def check_attempts(code):
    key=digest(code)
    cutoff=utcnow()-timedelta(minutes=10)
    attempts=[x for x in _login_failures.get(key,[]) if x>cutoff]
    _login_failures[key]=attempts
    if len(attempts)>=6:
        raise HTTPException(429,"로그인 시도가 많습니다. 10분 후 다시 시도하세요")

def failed_attempt(code):
    _login_failures.setdefault(digest(code),[]).append(utcnow())

def license_by_code(db, code):
    return db.scalar(select(License).where(License.code_hash==digest(code.strip().upper())))

def finish_customer_login(request, row, device_token):
    request.session.clear()
    request.session["license_id"]=row.id
    request.session["csrf"]=secrets.token_urlsafe(32)
    response=JSONResponse({"ok":True,"csrf":request.session["csrf"],"license":license_summary(row)})
    if device_token:
        response.set_cookie(COOKIE,device_token,httponly=True,secure=True,samesite="strict",path="/",max_age=63072000)
    return response

@app.post("/api/license/activate")
async def activate_license(data:LicenseActivate,request:Request):
    code=data.code.strip().upper()
    check_attempts(code)
    if len(data.password)<8 or len(data.password)>128:
        raise HTTPException(400,"2차 비밀번호는 8~128자로 설정하세요")
    with SessionLocal() as db:
        row=db.scalar(select(License).where(License.code_hash==digest(code)).with_for_update())
        if not row or row.active_at:
            failed_attempt(code)
            raise HTTPException(400,"등록할 수 없는 라이선스입니다")
        if row.blocked: raise HTTPException(403,"정지된 라이선스입니다")
        token=secrets.token_urlsafe(48)
        row.password_hash=hash_password(data.password)
        row.active_at=utcnow()
        row.expires_at=utcnow()+timedelta(days=row.duration_days)
        row.device_hash=digest(token)
        row.device_ip=request_ip(request)
        db.commit()
        db.refresh(row)
        return finish_customer_login(request,row,token)

@app.post("/api/license/login")
async def login_license(data:LicenseLogin,request:Request):
    code=data.code.strip().upper()
    check_attempts(code)
    with SessionLocal() as db:
        row=license_by_code(db,code)
        if not row or not valid_password(data.password,row.password_hash):
            failed_attempt(code)
            raise HTTPException(401,"라이선스 또는 2차 비밀번호가 올바르지 않습니다")
        if not row.active_at: raise HTTPException(403,"라이선스를 먼저 등록하세요")
        if row.blocked: raise HTTPException(403,"정지된 라이선스입니다")
        if not row.expires_at or aware(row.expires_at)<=utcnow():
            raise HTTPException(403,"라이선스 이용 기간이 만료되었습니다")
        cookie=request.cookies.get(COOKIE,"")
        if row.device_hash:
            if not cookie or not hmac.compare_digest(digest(cookie),row.device_hash):
                raise HTTPException(403,"다른 기기에서 로그인할 수 없습니다. 기기 초기화를 요청하세요")
            token=None
        else:
            token=secrets.token_urlsafe(48)
            row.device_hash=digest(token)
            row.device_ip=request_ip(request)
            db.commit()
            db.refresh(row)
        return finish_customer_login(request,row,token)

@app.post("/api/license/reset-request")
async def request_license_reset(data:LicenseLogin,request:Request):
    code=data.code.strip().upper()
    check_attempts(code)
    with SessionLocal() as db:
        row=license_by_code(db,code)
        if not row or not valid_password(data.password,row.password_hash):
            failed_attempt(code)
            raise HTTPException(401,"라이선스 또는 2차 비밀번호를 확인하세요")
        if not license_active(row): raise HTTPException(403,"유효한 라이선스만 초기화를 요청할 수 있습니다")
        reset_id=request_reset(row,request_ip(request))
        return {"ok":True,"request_id":reset_id,"message":"기기 초기화 승인 대기 중입니다"}

@app.get("/api/admin/licenses",dependencies=[Depends(authorized)])
async def list_licenses(request:Request):
    require_owner(request)
    with SessionLocal() as db:
        licenses=list(db.scalars(select(License).order_by(License.id.desc())))
        return [license_summary(x) for x in licenses]

@app.post("/api/admin/licenses",dependencies=[Depends(authorized)])
async def issue_license(data:IssueLicense,request:Request):
    require_owner(request)
    code,summary=create_license(data.label,data.days)
    return {"code":code,"license":summary}

@app.patch("/api/admin/licenses/{license_id}",dependencies=[Depends(authorized)])
async def block_license(license_id:int,data:BlockLicense,request:Request):
    require_owner(request)
    with SessionLocal() as db:
        row=db.get(License,license_id)
        if not row: raise HTTPException(404,"라이선스가 없습니다")
        row.blocked=data.blocked
        db.commit()
    return {"ok":True}

@app.get("/api/admin/device-resets",dependencies=[Depends(authorized)])
async def reset_requests(request:Request):
    require_owner(request)
    with SessionLocal() as db:
        rows=list(db.scalars(select(LicenseReset).where(LicenseReset.status=="pending").order_by(LicenseReset.id.desc())))
        return [{"id":x.id,"license_id":x.license_id,"ip":x.requested_ip,"requested_at":aware(x.requested_at).isoformat()} for x in rows]

@app.post("/api/admin/device-resets/{reset_id}",dependencies=[Depends(authorized)])
async def review_device_reset(reset_id:int,data:ReviewReset,request:Request):
    require_owner(request)
    with SessionLocal() as db:
        req=db.get(LicenseReset,reset_id)
        if not req or req.status!="pending": raise HTTPException(404,"승인 대기 요청이 없습니다")
        row=db.get(License,req.license_id)
        if not row: raise HTTPException(404,"라이선스가 없습니다")
        req.status="approved" if data.approved else "denied"
        req.reviewed_at=utcnow()
        if data.approved:
            row.device_hash=None
            row.device_ip=None
        db.commit()
    return {"ok":True}

def scoped_account(db, account_id, license_id):
    row=db.get(Account,account_id)
    if not row or (license_id is not None and row.license_id!=license_id):
        raise HTTPException(404,"계정이 없습니다")
    return row

def scoped_route(db, route_id, license_id):
    row=db.get(Route,route_id)
    if not row: raise HTTPException(404,"전달 설정이 없습니다")
    if license_id is not None:
        watcher=db.get(Account,row.watcher_id)
        if not watcher or watcher.license_id!=license_id:
            raise HTTPException(404,"전달 설정이 없습니다")
    return row

@app.get("/api/accounts",dependencies=[Depends(authorized)])
async def accounts(request:Request):
    license_id=get_identity(request)
    with SessionLocal() as db:
        query=select(Account).order_by(Account.id)
        if license_id is not None: query=query.where(Account.license_id==license_id)
        rows=db.scalars(query).all()
        return [{"id":a.id,"label":a.label,"username":a.username,"telegram_id":a.tg_id,
                 "enabled":a.enabled,"connected":a.id in engine.clients} for a in rows]

@app.post("/api/accounts/session/file",dependencies=[Depends(authorized)])
async def add_session_file(
    request:Request,
    file: UploadFile = File(...),
    label: str = Form("")
):
    if len(label) > 100:
        raise HTTPException(400,"계정 이름은 100자 이내로 입력하세요")
    if not file.filename or not file.filename.lower().endswith(".session"):
        raise HTTPException(400,"Telethon .session 파일을 선택하세요")
    try:
        contents = await file.read(2 * 1024 * 1024 + 1)
        return await engine.import_session_file(file.filename,contents,label.strip(),get_identity(request))
    except ValueError as exc:
        raise HTTPException(400,str(exc))
    except Exception:
        raise HTTPException(400,"세션 파일을 연결할 수 없습니다. 파일 형식과 로그인 상태를 확인하세요")
    finally:
        await file.close()

def telegram_auth_error(exc):
    # Only show explicitly whitelisted, actionable messages; do not leak API
    # keys, phone numbers, arbitrary Telegram RPC text or session data.
    name=type(exc).__name__
    if name=="FloodWaitError":
        seconds=max(1,min(int(getattr(exc,"seconds",60)),86400))
        return 429,f"텔레그램 요청 제한이 발생했습니다. {seconds}초 후 다시 시도하세요. 반복 클릭하지 마세요"
    mapped={
        "PhoneNumberInvalidError":"전화번호 형식이 올바르지 않습니다. 국가번호를 확인하세요",
        "PhoneNumberBannedError":"텔레그램에서 제한된 전화번호입니다. 계정 상태를 확인하세요",
        "PhoneNumberFloodError":"해당 번호의 인증 요청이 너무 많습니다. 텔레그램 제한이 해제된 후 다시 시도하세요",
        "ApiIdPublishedFloodError":"텔레그램 API 요청 제한이 발생했습니다. 잠시 후 다시 시도하세요",
        "PhoneCodeInvalidError":"인증코드가 올바르지 않습니다. 텔레그램 앱의 최신 코드를 확인하세요",
        "PhoneCodeExpiredError":"인증코드가 만료됐습니다. 인증을 다시 시작하세요",
        "PhoneCodeEmptyError":"인증코드를 입력하세요",
        "PasswordHashInvalidError":"2단계 비밀번호가 올바르지 않습니다",
        "AuthRestartError":"텔레그램이 인증 절차를 초기화했습니다. 다시 인증을 요청하세요",
        "SessionPasswordNeededError":"텔레그램 2단계 비밀번호를 입력하세요",
    }
    if isinstance(exc,ValueError):
        return 400,str(exc)
    if isinstance(exc,TimeoutError):
        return 504,"텔레그램 서버 응답 시간이 초과됐습니다. 잠시 후 다시 시도하세요"
    return (429 if "Flood" in name else 400), mapped.get(
        name,"텔레그램 인증 요청을 완료하지 못했습니다. 잠시 후 다시 시도하세요"
    )

@app.post("/api/accounts/phone/start",dependencies=[Depends(authorized)])
async def phone_start(data:Phone,request:Request):
    if not re.fullmatch(r"\+[1-9]\d{7,14}",data.phone):
        raise HTTPException(400,"국가번호를 포함해 입력하세요. 예: +8210...")
    try:
        return await engine.phone_start(data.phone,get_identity(request))
    except Exception as exc:
        status,message=telegram_auth_error(exc)
        raise HTTPException(status,message)

@app.post("/api/accounts/phone/resend",dependencies=[Depends(authorized)])
async def phone_resend(data:ResendCode,request:Request):
    try:
        return await engine.phone_resend(data.token,get_identity(request))
    except Exception as exc:
        status,message=telegram_auth_error(exc)
        raise HTTPException(status,message)

@app.post("/api/accounts/phone/finish",dependencies=[Depends(authorized)])
async def phone_finish(data:Verify,request:Request):
    try:
        return await engine.phone_finish(data.token,data.code,data.password,data.label,get_identity(request))
    except Exception as exc:
        status,message=telegram_auth_error(exc)
        raise HTTPException(status,message)

@app.get("/api/accounts/{account_id}/chats",dependencies=[Depends(authorized)])
async def chats(account_id:int,request:Request):
    license_id=get_identity(request)
    with SessionLocal() as db:
        scoped_account(db,account_id,license_id)
    try:
        items=await engine.chats(account_id)
        with SessionLocal() as db:
            for item in items:
                obj=db.get(ChatName,item["id"])
                if obj:
                    obj.name=item["name"][:300]
                    obj.updated_at=datetime.now(timezone.utc)
                else:
                    db.add(ChatName(chat_id=item["id"],name=item["name"][:300]))
            db.commit()
        return items
    except ValueError as e: raise HTTPException(400,str(e))

@app.get("/api/chat-names",dependencies=[Depends(authorized)])
async def chat_names(request:Request):
    license_id=get_identity(request)
    with SessionLocal() as db:
        if license_id is None:
            rows=db.scalars(select(ChatName)).all()
        else:
            ids=set()
            for route in db.scalars(select(Route).join(Account,Route.watcher_id==Account.id).where(Account.license_id==license_id)):
                ids.add(route.source_chat)
                ids.add(route.target_chat)
            rows=list(db.scalars(select(ChatName).where(ChatName.chat_id.in_(ids)))) if ids else []
        return {str(row.chat_id):row.name for row in rows}

@app.patch("/api/accounts/{account_id}",dependencies=[Depends(authorized)])
async def switch_account(account_id:int,data:Switch,request:Request):
    license_id=get_identity(request)
    with SessionLocal() as db:
        obj=scoped_account(db,account_id,license_id)
        obj.enabled=data.enabled
        db.commit()
        if data.enabled: await engine.attach(obj)
        else:
            client=engine.clients.pop(account_id,None)
            if client: await client.disconnect()
    return {"ok":True}

@app.delete("/api/accounts/{account_id}",dependencies=[Depends(authorized)])
async def delete_account(account_id:int,request:Request):
    license_id=get_identity(request)
    # Disconnect first so this account cannot initiate new deliveries.
    # Related routes and delivery records are removed together, with no orphan FKs.
    with SessionLocal() as db:
        account=scoped_account(db,account_id,license_id)
        connected=engine.clients.pop(account_id,None)
        if connected: await connected.disconnect()
        affected_ids=list(db.scalars(select(Route.id).where(
            or_(Route.watcher_id==account_id,Route.fixed_id==account_id)
        )))
        if affected_ids:
            db.execute(delete(Delivery).where(Delivery.route_id.in_(affected_ids)))
            db.execute(delete(Route).where(Route.id.in_(affected_ids)))
        db.delete(account)
        db.commit()
    return {"ok":True,"removed_routes":len(affected_ids)}

@app.get("/api/settings/delivery",dependencies=[Depends(authorized)])
async def get_delivery_settings(request:Request):
    license_id=get_identity(request)
    key="delivery_pace" if license_id is None else "delivery_pace:"+str(license_id)
    with SessionLocal() as db:
        row=db.get(SyncSetting,key)
        return {"mode":row.value if row else "normal"}

@app.put("/api/settings/delivery",dependencies=[Depends(authorized)])
async def set_delivery_settings(data:PaceSetting,request:Request):
    license_id=get_identity(request)
    if data.mode not in ("off","fast","normal","relaxed"):
        raise HTTPException(400,"전달 간격을 선택하세요")
    key="delivery_pace" if license_id is None else "delivery_pace:"+str(license_id)
    with SessionLocal() as db:
        row=db.get(SyncSetting,key)
        if row: row.value=data.mode
        else: db.add(SyncSetting(key=key,value=data.mode))
        db.commit()
    return {"ok":True,"mode":data.mode}

@app.get("/api/routes",dependencies=[Depends(authorized)])
async def routes(request:Request):
    license_id=get_identity(request)
    with SessionLocal() as db:
        query=select(Route).order_by(desc(Route.id))
        if license_id is not None:
            query=query.join(Account,Route.watcher_id==Account.id).where(Account.license_id==license_id)
        rows=db.scalars(query).all()
        return [{"id":r.id,"watcher_id":r.watcher_id,"source_chat":r.source_chat,"target_chat":r.target_chat,
                 "sender_filter":r.sender_filter,"mode":r.mode,"fixed_id":r.fixed_id,"active":r.active} for r in rows]

@app.post("/api/routes",dependencies=[Depends(authorized)])
async def create_route(data:RouteInput,request:Request):
    license_id=get_identity(request)
    if data.mode not in ("same","fixed"): raise HTTPException(400,"전송 방식을 선택하세요")
    if data.source_chat==data.target_chat: raise HTTPException(400,"원본방과 대상방은 같을 수 없습니다")
    with SessionLocal() as db:
        watcher=scoped_account(db,data.watcher_id,license_id)
        if not watcher.enabled: raise HTTPException(400,"감지 계정을 선택하세요")
        if data.mode=="fixed":
            sender=scoped_account(db,data.fixed_id,license_id) if data.fixed_id else None
            if not sender or not sender.enabled: raise HTTPException(400,"전송 계정을 선택하세요")
        route=Route(**data.model_dump())
        db.add(route)
        try:
            db.commit()
            db.refresh(route)
        except Exception:
            db.rollback()
            raise HTTPException(409,"이미 연결된 대상 그룹이거나 규칙을 저장할 수 없습니다")
        return {"id":route.id}

@app.patch("/api/routes/{route_id}",dependencies=[Depends(authorized)])
async def switch_route(route_id:int,data:Switch,request:Request):
    license_id=get_identity(request)
    with SessionLocal() as db:
        obj=scoped_route(db,route_id,license_id)
        obj.active=data.enabled
        db.commit()
    return {"ok":True}

@app.put("/api/routes/{route_id}",dependencies=[Depends(authorized)])
async def edit_route(route_id:int,data:RouteEdit,request:Request):
    license_id=get_identity(request)
    if data.mode not in ("same","fixed"):
        raise HTTPException(400,"전송 방식을 선택하세요")
    with SessionLocal() as db:
        route=scoped_route(db,route_id,license_id)
        if data.mode=="fixed":
            sender=scoped_account(db,data.fixed_id,license_id) if data.fixed_id else None
            if not sender or not sender.enabled:
                raise HTTPException(400,"사용 가능한 발신 계정을 선택하세요")
            route.fixed_id=sender.id
        else:
            route.fixed_id=None
        route.mode=data.mode
        db.commit()
    return {"ok":True}

@app.post("/api/routes/bulk",dependencies=[Depends(authorized)])
async def bulk_routes(data:BulkSwitch,request:Request):
    license_id=get_identity(request)
    with SessionLocal() as db:
        matches=list(db.scalars(select(Route).where(Route.id.in_(data.route_ids))))
        if len(matches)!=len(set(data.route_ids)):
            raise HTTPException(404,"일부 전달 설정이 존재하지 않습니다")
        for route in matches:
            scoped_route(db,route.id,license_id)
            route.active=data.enabled
        db.commit()
    return {"ok":True,"count":len(matches)}

@app.delete("/api/routes/{route_id}",dependencies=[Depends(authorized)])
async def delete_route(route_id:int,request:Request):
    license_id=get_identity(request)
    with SessionLocal() as db:
        route=scoped_route(db,route_id,license_id)
        db.execute(delete(Delivery).where(Delivery.route_id==route_id))
        db.delete(route)
        db.commit()
    return {"ok":True}

@app.get("/api/logs",dependencies=[Depends(authorized)])
async def logs(request:Request):
    license_id=get_identity(request)
    with SessionLocal() as db:
        query=select(Delivery).order_by(desc(Delivery.id)).limit(100)
        if license_id is not None:
            query=query.join(Route,Delivery.route_id==Route.id).join(Account,Route.watcher_id==Account.id).where(Account.license_id==license_id)
        rows=db.scalars(query).all()
        return [{"id":d.id,"route_id":d.route_id,"status":d.status,"error":d.error,
                 "created_at":d.created_at.isoformat()} for d in rows]
