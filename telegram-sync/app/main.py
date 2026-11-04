import os, re, secrets
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import select, desc, delete, or_
from .models import SessionLocal, Account, Route, Delivery, ChatName
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
class RouteEdit(BaseModel):
    mode:str
    fixed_id:int|None=None
class BulkSwitch(BaseModel):
    route_ids:list[int]=Field(min_length=1,max_length=500)
    enabled:bool

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

@app.post("/api/accounts/session/file",dependencies=[Depends(authorized)])
async def add_session_file(
    file: UploadFile = File(...),
    label: str = Form("")
):
    if len(label) > 100:
        raise HTTPException(400,"계정 이름은 100자 이내로 입력하세요")
    if not file.filename or not file.filename.lower().endswith(".session"):
        raise HTTPException(400,"Telethon .session 파일을 선택하세요")
    try:
        contents = await file.read(2 * 1024 * 1024 + 1)
        return await engine.import_session_file(file.filename,contents,label.strip())
    except ValueError as exc:
        raise HTTPException(400,str(exc))
    except Exception:
        raise HTTPException(400,"세션 파일을 연결할 수 없습니다. 파일 형식과 로그인 상태를 확인하세요")
    finally:
        await file.close()

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
async def chat_names():
    with SessionLocal() as db:
        return {str(row.chat_id):row.name for row in db.scalars(select(ChatName))}

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

@app.delete("/api/accounts/{account_id}",dependencies=[Depends(authorized)])
async def delete_account(account_id:int):
    # Disconnect first so this account cannot initiate new deliveries.
    # Related routes and delivery records are removed together, with no orphan FKs.
    with SessionLocal() as db:
        account=db.get(Account,account_id)
        if not account: raise HTTPException(404,"이미 삭제되었거나 존재하지 않는 계정입니다")
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

@app.put("/api/routes/{route_id}",dependencies=[Depends(authorized)])
async def edit_route(route_id:int,data:RouteEdit):
    if data.mode not in ("same","fixed"):
        raise HTTPException(400,"전송 방식을 선택하세요")
    with SessionLocal() as db:
        route=db.get(Route,route_id)
        if not route: raise HTTPException(404,"전달 설정이 없습니다")
        if data.mode=="fixed":
            sender=db.get(Account,data.fixed_id) if data.fixed_id else None
            if not sender or not sender.enabled:
                raise HTTPException(400,"사용 가능한 발신 계정을 선택하세요")
            route.fixed_id=sender.id
        else:
            route.fixed_id=None
        route.mode=data.mode
        db.commit()
    return {"ok":True}

@app.post("/api/routes/bulk",dependencies=[Depends(authorized)])
async def bulk_routes(data:BulkSwitch):
    with SessionLocal() as db:
        matches=list(db.scalars(select(Route).where(Route.id.in_(data.route_ids))))
        if len(matches)!=len(set(data.route_ids)):
            raise HTTPException(404,"일부 전달 설정이 존재하지 않습니다")
        for route in matches:
            route.active=data.enabled
        db.commit()
    return {"ok":True,"count":len(matches)}

@app.delete("/api/routes/{route_id}",dependencies=[Depends(authorized)])
async def delete_route(route_id:int):
    with SessionLocal() as db:
        route=db.get(Route,route_id)
        if not route: raise HTTPException(404,"이미 삭제되었거나 존재하지 않는 전달 설정입니다")
        db.execute(delete(Delivery).where(Delivery.route_id==route_id))
        db.delete(route)
        db.commit()
    return {"ok":True}

@app.get("/api/logs",dependencies=[Depends(authorized)])
async def logs():
    with SessionLocal() as db:
        rows=db.scalars(select(Delivery).order_by(desc(Delivery.id)).limit(100)).all()
        return [{"id":d.id,"route_id":d.route_id,"status":d.status,"error":d.error,
                 "created_at":d.created_at.isoformat()} for d in rows]
