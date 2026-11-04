import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from sqlalchemy import select
from .models import SessionLocal, License, LicenseReset

COOKIE = "sync_registered_device"


def utcnow():
    return datetime.now(timezone.utc)


def aware(value):
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_password(password):
    salt = secrets.token_bytes(16)
    result = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 390000)
    return salt.hex() + ":" + result.hex()


def valid_password(password, stored):
    if not stored:
        return False
    try:
        salt_hex, hashed = stored.split(":", 1)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 390000)
        return hmac.compare_digest(candidate, bytes.fromhex(hashed))
    except (ValueError, TypeError):
        return False


def license_active(license):
    return bool(
        license and not license.blocked and license.active_at
        and license.expires_at and aware(license.expires_at) > utcnow()
        and license.password_hash and license.device_hash
    )


def request_ip(request):
    # Do not trust arbitrary X-Forwarded-For values as an authentication factor.
    return (request.client.host if request.client else "unknown")[:64]


def get_identity(request: Request):
    if request.session.get("admin") is True:
        return None  # Owner can operate legacy records and manage licensing.
    license_id = request.session.get("license_id")
    if not isinstance(license_id, int):
        raise HTTPException(401, "로그인이 필요합니다")
    device_token = request.cookies.get(COOKIE, "")
    if not device_token:
        raise HTTPException(401, "등록된 기기 인증이 필요합니다")
    with SessionLocal() as db:
        row = db.get(License, license_id)
        if not license_active(row):
            raise HTTPException(403, "라이선스가 만료되거나 정지되었습니다")
        if not hmac.compare_digest(row.device_hash, digest(device_token)):
            raise HTTPException(403, "등록된 기기가 아닙니다. 기기 초기화를 요청하세요")
    return license_id


def require_owner(request: Request):
    if request.session.get("admin") is not True:
        raise HTTPException(403, "발급 관리자만 사용할 수 있습니다")
    return True


def license_summary(row):
    expiry = aware(row.expires_at)
    return {
        "id": row.id,
        "prefix": row.code_prefix,
        "label": row.label,
        "duration_days": row.duration_days,
        "activated": bool(row.active_at),
        "active_at": aware(row.active_at).isoformat() if row.active_at else None,
        "expires_at": expiry.isoformat() if expiry else None,
        "expired": bool(expiry and expiry <= utcnow()),
        "blocked": row.blocked,
        "device_bound": bool(row.device_hash),
        "device_ip": row.device_ip,
    }


def create_license(label, days):
    if days < 1 or days > 3650:
        raise HTTPException(400, "기간은 1~3650일 사이여야 합니다")
    code = "TGS-" + "-".join(secrets.token_hex(4).upper() for _ in range(4))
    row = License(
        code_hash=digest(code),
        code_prefix=code[:13],
        label=label.strip()[:100],
        duration_days=days,
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()
        db.refresh(row)
        return code, license_summary(row)


def request_reset(row, ip):
    with SessionLocal() as db:
        existing = db.scalar(select(LicenseReset).where(
            LicenseReset.license_id == row.id,
            LicenseReset.status == "pending"
        ))
        if existing:
            return existing.id
        reset = LicenseReset(license_id=row.id, requested_ip=ip)
        db.add(reset)
        db.commit()
        db.refresh(reset)
        return reset.id
