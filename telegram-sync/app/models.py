import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, String, BigInteger, Boolean, Text, Integer, DateTime, ForeignKey, UniqueConstraint, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

url = os.getenv("DATABASE_URL", "sqlite:///./sync.sqlite3")
db_engine = create_engine(url, pool_pre_ping=True, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=db_engine, expire_on_commit=False)

class Base(DeclarativeBase): pass

class Account(Base):
    __tablename__ = "sync_accounts"
    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(String(100))
    tg_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    session_encrypted: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    license_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

class Route(Base):
    __tablename__ = "sync_routes"
    id: Mapped[int] = mapped_column(primary_key=True)
    watcher_id: Mapped[int] = mapped_column(ForeignKey("sync_accounts.id"))
    source_chat: Mapped[int] = mapped_column(BigInteger)
    target_chat: Mapped[int] = mapped_column(BigInteger)
    sender_filter: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    mode: Mapped[str] = mapped_column(String(10))
    fixed_id: Mapped[int | None] = mapped_column(ForeignKey("sync_accounts.id"), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    __table_args__ = (UniqueConstraint("watcher_id","source_chat","target_chat", name="uq_sync_route"),)

class License(Base):
    __tablename__ = "sync_licenses"
    id: Mapped[int] = mapped_column(primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    code_prefix: Mapped[str] = mapped_column(String(16))
    label: Mapped[str] = mapped_column(String(100), default="")
    duration_days: Mapped[int] = mapped_column(Integer)
    password_hash: Mapped[str | None] = mapped_column(String(200), nullable=True)
    active_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    device_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class LicenseReset(Base):
    __tablename__ = "sync_license_resets"
    id: Mapped[int] = mapped_column(primary_key=True)
    license_id: Mapped[int] = mapped_column(ForeignKey("sync_licenses.id"))
    requested_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class ChatName(Base):
    __tablename__ = "sync_chat_names"
    chat_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column(String(300))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class SyncSetting(Base):
    __tablename__ = "sync_settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(String(80))

class Delivery(Base):
    __tablename__ = "sync_deliveries"
    id: Mapped[int] = mapped_column(primary_key=True)
    route_id: Mapped[int] = mapped_column(ForeignKey("sync_routes.id"))
    source_id: Mapped[int] = mapped_column(Integer)
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sender_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="processing")
    error: Mapped[str | None] = mapped_column(String(400), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    __table_args__ = (UniqueConstraint("route_id","source_id",name="uq_sync_delivery"),)

Base.metadata.create_all(db_engine)
# Safe additive migration for existing installations (create_all does not alter tables).
if "license_id" not in {column["name"] for column in inspect(db_engine).get_columns("sync_accounts")}:
    with db_engine.begin() as connection:
        connection.execute(text("ALTER TABLE sync_accounts ADD COLUMN license_id INTEGER"))
