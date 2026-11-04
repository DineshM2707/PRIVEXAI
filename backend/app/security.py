from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import settings
from app.models import User


password_context = CryptContext(schemes=["argon2"], deprecated="auto")
JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return password_context.verify(password, password_hash)


def create_access_token(user: User) -> str:
    if len(settings.secret_key) < 32:
        raise RuntimeError("SECRET_KEY must be configured with at least 32 characters.")
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_minutes)
    return jwt.encode(
        {"sub": str(user.id), "role": user.role, "exp": expires},
        settings.secret_key,
        algorithm=JWT_ALGORITHM,
    )


def get_token_user(token: str, db: Session) -> User:
    if len(settings.secret_key) < 32:
        raise RuntimeError("SECRET_KEY must be configured with at least 32 characters.")
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[JWT_ALGORITHM])
        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject.isdigit():
            raise ValueError("Invalid token subject")
    except (JWTError, ValueError) as exc:
        raise ValueError("Invalid or expired access token") from exc
    user = db.get(User, int(subject))
    if user is None or not user.is_active or payload.get("role") != user.role:
        raise ValueError("User is inactive or token permissions have changed")
    return user
