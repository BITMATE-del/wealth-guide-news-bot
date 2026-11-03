import os, re, secrets
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import select, desc
from .models import SessionLocal, Account, Route, Delivery
from .core import SyncEngine

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
    if request.session.get("admin") is not True: raise HTTPException(401,"관리자 로그인이 필요합니다")
    if request.method not in ("GET","HEAD","OPTIONS") and request.headers.get("x-csrf-token") != request.session.get("csrf"):
        raise HTTPException(403,"보안 확인에 실패했습니다")

class Login(BaseModel): password:str
class ImportSession(BaseModel):
    label:str=Field(min_length=1,max_length=100)
    session:str=Field(min_length=30,max_length=4096)
class Phone(BaseModel): phone:str
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

@app.get("/")
async def index(): return FileResponse("static/index.html")

@app.get("/health")
async def health(): return {"ok":True,"service":"telegram-sync"}

@app.get("/api/me")
async def me(request:Request):
    return {"logged_in":request.session.get("admin",False),"csrf":request.session.get("csrf","")}

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
    return {"ok":True}

@app.get("/api/accounts",dependencies=[Depends(authorized)])
async def accounts():
    with SessionLocal() as db:
        rows=db.scalars(select(Account).order_by(Account.id)).all()
        return [{"id":a.id,"label":a.label,"username":a.username,"telegram_id":a.tg_id,
                 "enabled":a.enabled,"connected":a.id in engine.clients} for a in rows]

@app.post("/api/accounts/session",dependencies=[Depends(authorized)])
async def add_session(data:ImportSession):
    try: return await engine.import_session(data.session,data.label)
    except Exception: raise HTTPException(400,"세션 연결에 실패했습니다. 계정과 세션 형식을 확인하세요")

@app.post("/api/accounts/phone/start",dependencies=[Depends(authorized)])
async def phone_start(data:Phone):
    if not re.fullmatch(r"\+[1-9]\d{7,14}",data.phone):
        raise HTTPException(400,"국가번호를 포함해 입력하세요. 예: +8210...")
    try: return await engine.phone_start(data.phone)
    except Exception: raise HTTPException(400,"인증코드 요청에 실패했습니다. 잠시 후 다시 시도하세요")

@app.post("/api/accounts/phone/finish",dependencies=[Depends(authorized)])
async def phone_finish(data:Verify):
    try: return await engine.phone_finish(data.token,data.code,data.password,data.label)
    except ValueError as e: raise HTTPException(400,str(e))
    except Exception: raise HTTPException(400,"인증에 실패했습니다. 코드를 다시 확인하세요")

@app.get("/api/accounts/{account_id}/chats",dependencies=[Depends(authorized)])
async def chats(account_id:int):
    try: return await engine.chats(account_id)
    except ValueError as e: raise HTTPException(400,str(e))

@app.patch("/api/accounts/{account_id}",dependencies=[Depends(authorized)])
async def switch_account(account_id:int,data:Switch):
    with SessionLocal() as db:
        obj=db.get(Account,account_id)
        if not obj: raise HTTPException(404,"계정이 없습니다")
        obj.enabled=data.enabled
        db.commit()
        if data.enabled: await engine.attach(obj)
        else:
            client=engine.clients.pop(account_id,None)
            if client: await client.disconnect()
    return {"ok":True}

@app.get("/api/routes",dependencies=[Depends(authorized)])
async def routes():
    with SessionLocal() as db:
        rows=db.scalars(select(Route).order_by(desc(Route.id))).all()
        return [{"id":r.id,"watcher_id":r.watcher_id,"source_chat":r.source_chat,"target_chat":r.target_chat,
                 "sender_filter":r.sender_filter,"mode":r.mode,"fixed_id":r.fixed_id,"active":r.active} for r in rows]

@app.post("/api/routes",dependencies=[Depends(authorized)])
async def create_route(data:RouteInput):
    if data.mode not in ("same","fixed"): raise HTTPException(400,"전송 방식을 선택하세요")
    if data.source_chat==data.target_chat: raise HTTPException(400,"원본방과 대상방은 같을 수 없습니다")
    with SessionLocal() as db:
        watcher=db.get(Account,data.watcher_id)
        if not watcher or not watcher.enabled: raise HTTPException(400,"감지 계정을 선택하세요")
        if data.mode=="fixed":
            sender=db.get(Account,data.fixed_id) if data.fixed_id else None
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
async def switch_route(route_id:int,data:Switch):
    with SessionLocal() as db:
        obj=db.get(Route,route_id)
        if not obj: raise HTTPException(404,"규칙이 없습니다")
        obj.active=data.enabled
        db.commit()
    return {"ok":True}

@app.get("/api/logs",dependencies=[Depends(authorized)])
async def logs():
    with SessionLocal() as db:
        rows=db.scalars(select(Delivery).order_by(desc(Delivery.id)).limit(100)).all()
        return [{"id":d.id,"route_id":d.route_id,"status":d.status,"error":d.error,
                 "created_at":d.created_at.isoformat()} for d in rows]
