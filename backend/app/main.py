from contextlib import asynccontextmanager
from datetime import datetime, timezone
from threading import Lock
from time import monotonic
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import JSONResponse
from sqlalchemy import desc, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal, get_db
from app.models import Incident, Policy, ScanEvent, User
from app.schemas import (
    AnalyticsResponse,
    IncidentResponse,
    IncidentStatusUpdate,
    LoginRequest,
    PolicyResponse,
    PolicyUpdate,
    RegistrationRequest,
    ScanRequest,
    ScanResponse,
    TokenResponse,
    UserCreateRequest,
    UserResponse,
)
from app.security import create_access_token, get_token_user, hash_password, verify_password
from app.services import build_analytics, ensure_default_policies, evaluate_scan, seed_demo_incidents


@asynccontextmanager
async def lifespan(_: FastAPI):
    if len(settings.secret_key) < 32:
        raise RuntimeError("Set SECRET_KEY to a random value of at least 32 characters.")
    if not settings.admin_password:
        raise RuntimeError("Set ADMIN_PASSWORD before starting the API.")
    with SessionLocal() as db:
        admin = db.query(User).filter(User.username == settings.admin_username).first()
        if admin is None:
            admin = User(
                username=settings.admin_username,
                password_hash=hash_password(settings.admin_password),
                role="admin",
                is_active=True,
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
        ensure_default_policies(db)
        seed_demo_incidents(db, admin)
    yield


app = FastAPI(
    title="PRIVEXAI API",
    version="0.1.0",
    description="Sample-submission DLP demo. No network traffic is monitored.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(
    _: Request,
    __: RequestValidationError,
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Invalid request data. Check required fields and allowed values."},
    )


login_attempts: dict[tuple[str, str], list[float]] = {}
login_attempts_lock = Lock()
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_ATTEMPTS = 5


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


bearer = HTTPBearer(auto_error=False)
DbSession = Annotated[Session, Depends(get_db)]


def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: DbSession,
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in required.")
    try:
        return get_token_user(credentials.credentials, db)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


CurrentUser = Annotated[User, Depends(current_user)]


def require_roles(*roles: str):
    def role_guard(user: CurrentUser) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role.")
        return user

    return role_guard


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "PRIVEXAI API"}


@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: DbSession) -> TokenResponse:
    identifier = payload.username.strip().lower()
    client_ip = request.client.host if request.client else "unknown"
    key = (client_ip, "*")
    now = monotonic()
    with login_attempts_lock:
        recent = [attempt for attempt in login_attempts.get(key, []) if now - attempt < LOGIN_WINDOW_SECONDS]
        login_attempts[key] = recent
        if len(recent) >= LOGIN_MAX_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many sign-in attempts. Try again later.",
            )
    user = (
        db.query(User)
        .filter(
            or_(
                func.lower(User.username) == identifier,
                func.lower(User.email) == identifier,
            )
        )
        .first()
    )
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        with login_attempts_lock:
            login_attempts[key] = login_attempts.get(key, []) + [now]
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")
    with login_attempts_lock:
        login_attempts.pop(key, None)
    return TokenResponse(
        access_token=create_access_token(user),
        username=user.username,
        role=user.role,
    )


@app.post("/api/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegistrationRequest, db: DbSession) -> TokenResponse:
    duplicate = (
        db.query(User)
        .filter(
            or_(
                func.lower(User.username) == payload.username,
                func.lower(User.email) == payload.email,
            )
        )
        .first()
    )
    if duplicate is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username or email is already registered.")
    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role="viewer",
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered.",
        ) from exc
    db.refresh(user)
    return TokenResponse(
        access_token=create_access_token(user),
        username=user.username,
        role=user.role,
    )


@app.get("/api/auth/me", response_model=UserResponse)
def me(user: CurrentUser) -> UserResponse:
    return UserResponse(username=user.username, role=user.role)


@app.get("/api/users", response_model=list[UserResponse])
def users(
    db: DbSession,
    _: Annotated[User, Depends(require_roles("admin"))],
) -> list[User]:
    return db.query(User).order_by(User.username).all()


@app.post(
    "/api/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    payload: UserCreateRequest,
    db: DbSession,
    _: Annotated[User, Depends(require_roles("admin"))],
) -> User:
    if db.query(User).filter(User.username == payload.username).first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username is already registered.",
        )
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/api/scans", response_model=ScanResponse)
def scan(
    payload: ScanRequest,
    db: DbSession,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> ScanResponse:
    result, _ = evaluate_scan(
        db=db,
        user=user,
        text=payload.text,
        source=payload.source,
        destination=payload.destination,
        destination_authorized=payload.destination_authorized,
        context=payload.context,
    )
    return ScanResponse(**result)


@app.get("/api/incidents", response_model=list[IncidentResponse])
def incidents(
    db: DbSession,
    _: CurrentUser,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[Incident]:
    return db.query(Incident).order_by(desc(Incident.created_at)).limit(limit).all()


@app.patch("/api/incidents/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    payload: IncidentStatusUpdate,
    db: DbSession,
    _: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")
    incident.status = payload.status
    db.commit()
    db.refresh(incident)
    return incident


@app.get("/api/policies", response_model=list[PolicyResponse])
def policies(db: DbSession, _: CurrentUser) -> list[Policy]:
    return db.query(Policy).order_by(Policy.category).all()


@app.put("/api/policies/{category}", response_model=PolicyResponse)
def update_policy(
    category: str,
    payload: PolicyUpdate,
    db: DbSession,
    _: Annotated[User, Depends(require_roles("admin"))],
) -> Policy:
    policy = db.query(Policy).filter(Policy.category == category).first()
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found.")
    policy.action = payload.action
    policy.weight = payload.weight
    policy.enabled = payload.enabled
    policy.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(policy)
    return policy


@app.get("/api/analytics", response_model=AnalyticsResponse)
def analytics(db: DbSession, _: CurrentUser) -> dict:
    events = db.query(ScanEvent).all()
    records = db.query(Incident).all()
    return build_analytics(events, records)
