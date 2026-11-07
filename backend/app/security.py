import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from fastapi import Response
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AuthSession, User

password_context = CryptContext(schemes=["argon2"], deprecated="auto")
JWT_ALGORITHM = "HS256"
JWT_ISSUER = "privexai"
JWT_AUDIENCE = "privexai-api"
ACCESS_COOKIE = "access_token"
REFRESH_COOKIE = "refresh_token"
CSRF_COOKIE = "csrf_token"


def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return password_context.verify(password, password_hash)


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def create_access_token(user: User, session_key: str | None = None) -> str:
    if len(settings.secret_key) < 32:
        raise RuntimeError("SECRET_KEY must be configured with at least 32 characters.")
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "jti": str(uuid4()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "type": "access",
        "exp": int((now + timedelta(minutes=settings.access_token_minutes)).timestamp()),
    }
    if session_key:
        payload["sid"] = session_key
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALGORITHM)


def create_refresh_token(user: User, session_key: str | None = None) -> str:
    if len(settings.secret_key) < 32:
        raise RuntimeError("SECRET_KEY must be configured with at least 32 characters.")
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "jti": str(uuid4()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "type": "refresh",
        "exp": int((now + timedelta(days=settings.refresh_token_days)).timestamp()),
    }
    if session_key:
        payload["sid"] = session_key
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALGORITHM)


def decode_token(token: str, expected_type: str | None = None) -> dict[str, Any]:
    if len(settings.secret_key) < 32:
        raise RuntimeError("SECRET_KEY must be configured with at least 32 characters.")
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "jti", "iss", "aud", "type"]},
        )
    except (JWTError, ValueError) as exc:
        raise ValueError("Invalid or expired token") from exc

    if expected_type is not None and payload.get("type") != expected_type:
        raise ValueError("Unexpected token type")

    now_epoch = int(datetime.now(timezone.utc).timestamp())
    if payload.get("exp", 0) <= now_epoch:
        raise ValueError("Token expired")
    if payload.get("iat", 0) > now_epoch:
        raise ValueError("Token issued in the future")

    return payload


def _get_active_session(db: Session, payload: dict[str, Any], token_type: str) -> AuthSession:
    session_key = payload.get("sid")
    if not isinstance(session_key, str):
        raise ValueError("Session identifier missing")
    session = db.query(AuthSession).filter(AuthSession.session_key == session_key).first()
    if session is None:
        raise ValueError("Session not found")
    if session.user_id != int(payload["sub"]):
        raise ValueError("Session belongs to a different user")

    expected_jti = session.access_jti if token_type == "access" else session.refresh_jti
    token_jti = payload.get("jti")
    if not isinstance(token_jti, str) or token_jti != expected_jti:
        raise ValueError("Session token has been invalidated")
    if session.revoked_at is not None:
        revoked_at = session.revoked_at
        if revoked_at.tzinfo is None:
            revoked_at = revoked_at.replace(tzinfo=timezone.utc)
        if revoked_at <= datetime.now(timezone.utc):
            raise ValueError("Session has been revoked")
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        raise ValueError("Session expired")
    return session


def get_token_user(token: str, db: Session) -> User:
    payload = decode_token(token, expected_type="access")
    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active or payload.get("role") != user.role:
        raise ValueError("User is inactive or token permissions have changed")
    _get_active_session(db, payload, "access")
    return user


def set_auth_cookies(response: Response, access_token: str, refresh_token: str, csrf_token: str) -> None:
    response.set_cookie(
        key=ACCESS_COOKIE,
        value=access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=settings.access_token_minutes * 60,
    )
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=settings.refresh_token_days * 24 * 60 * 60,
    )
    response.set_cookie(
        key=CSRF_COOKIE,
        value=csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=60 * 60 * 12,
    )


def clear_auth_cookies(response: Response) -> None:
    for key in (ACCESS_COOKIE, REFRESH_COOKIE, CSRF_COOKIE):
        response.delete_cookie(key=key, path="/")
