from collections import defaultdict
from contextlib import asynccontextmanager
import csv
from datetime import datetime, timedelta, timezone
from io import StringIO
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import JSONResponse, StreamingResponse
from jose import jwt
from sqlalchemy import desc, func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal, get_db
from app.models import AuthSession, Incident, Policy, ScanEvent, SecurityEvent, User
from app.schemas import (
    AnalyticsResponse,
    DocumentScanResponse,
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
from app.security import (
    ACCESS_COOKIE,
    CSRF_COOKIE,
    REFRESH_COOKIE,
    clear_auth_cookies,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_csrf_token,
    get_token_user,
    hash_password,
    set_auth_cookies,
    verify_password,
)
from app.services import build_analytics, ensure_default_policies, evaluate_scan, seed_demo_incidents
from app.documents import MAX_DOCUMENT_BYTES, DocumentReadError, extract_document_text


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
    exc: RequestValidationError,
) -> JSONResponse:
    field_errors: dict[str, str] = {}
    messages = {
        "full_name": "Enter a valid name between 2 and 120 characters.",
        "email": "Enter a valid email address.",
        "username": "Use 3–80 characters: start with a letter or number, then use only letters, numbers, periods, underscores, or hyphens.",
        "password": "Use 12–256 characters with uppercase, lowercase, a number, and a symbol.",
        "role": "Public registration does not accept a role.",
    }
    for error in exc.errors():
        location = error.get("loc", ())
        field = location[-1] if location else None
        if isinstance(field, str) and field in messages:
            field_errors[field] = messages[field]
        elif isinstance(field, str) and field not in {"body", "query", "path", "header"}:
            field_errors[field] = "Check this field's value and length."
        elif error.get("type") == "extra_forbidden":
            field_errors["role"] = messages["role"]

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Check the highlighted fields and try again.",
            "field_errors": field_errors,
        },
    )


LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_ATTEMPTS = 5
login_attempts: dict[str, list[datetime]] = defaultdict(list)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def jwt_payload_jti(token: str) -> str:
    claims = jwt.get_unverified_claims(token)
    jti = claims.get("jti")
    if not isinstance(jti, str):
        raise ValueError("Token is missing a jti claim")
    return jti


def record_security_event(
    db: Session,
    event_type: str,
    *,
    user_id: int | None = None,
    identifier: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict | None = None,
    commit: bool = True,
) -> None:
    db.add(
        SecurityEvent(
            user_id=user_id,
            event_type=event_type,
            identifier=identifier,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
        )
    )
    if commit:
        db.commit()


def enforce_csrf(request: Request) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    if request.url.path in {"/api/auth/login", "/api/auth/register", "/api/auth/refresh"}:
        return
    if request.headers.get("Authorization"):
        return
    if request.cookies.get(ACCESS_COOKIE) is None:
        return
    csrf_cookie = request.cookies.get(CSRF_COOKIE)
    csrf_header = request.headers.get("X-CSRF-Token")
    if not csrf_cookie or not csrf_header or not csrf_cookie == csrf_header:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed.")


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.middleware("http")
async def enforce_csrf_middleware(request: Request, call_next):
    try:
        enforce_csrf(request)
    except HTTPException:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "CSRF validation failed."},
        )
    return await call_next(request)


bearer = HTTPBearer(auto_error=False)
DbSession = Annotated[Session, Depends(get_db)]


def current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: DbSession,
) -> User:
    token = credentials.credentials if credentials is not None else request.cookies.get(ACCESS_COOKIE)
    if token is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in required.")
    try:
        return get_token_user(token, db)
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
def login(payload: LoginRequest, request: Request, response: Response, db: DbSession) -> TokenResponse:
    identifier = payload.username.strip().lower()
    ip = client_ip(request)
    key = f"{ip}:{identifier}"
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=LOGIN_WINDOW_SECONDS)
    failed_attempts = [attempt for attempt in login_attempts.get(key, []) if attempt >= cutoff]
    login_attempts[key] = failed_attempts

    if len(failed_attempts) >= LOGIN_MAX_ATTEMPTS:
        login_attempts[key].append(now)
        record_security_event(
            db,
            "login_failed",
            identifier=identifier,
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
            details={"reason": "rate_limited", "username": identifier},
        )
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
        login_attempts[key].append(now)
        record_security_event(
            db,
            "login_failed",
            user_id=user.id if user else None,
            identifier=identifier,
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
            details={"reason": "invalid_credentials", "username": identifier},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.")

    login_attempts.pop(key, None)
    db.query(SecurityEvent).filter(
        SecurityEvent.event_type == "login_failed",
    ).filter(
        or_(SecurityEvent.ip_address == ip, SecurityEvent.identifier == identifier),
    ).delete()
    session_key = str(uuid4())
    access_token = create_access_token(user, session_key)
    refresh_token = create_refresh_token(user, session_key)
    csrf_token = generate_csrf_token()
    auth_session = AuthSession(
        user_id=user.id,
        session_key=session_key,
        refresh_token_hash=hash_password(refresh_token),
        access_jti=jwt_payload_jti(access_token),
        refresh_jti=jwt_payload_jti(refresh_token),
        user_agent=request.headers.get("user-agent"),
        ip_address=ip,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_days),
    )
    db.add(auth_session)
    db.flush()
    set_auth_cookies(response, access_token, refresh_token, csrf_token)
    record_security_event(
        db,
        "login_success",
        user_id=user.id,
        identifier=user.username,
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
        details={"username": user.username, "role": user.role},
        commit=False,
    )
    db.commit()
    return TokenResponse(access_token=access_token, username=user.username, role=user.role)


@app.post("/api/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegistrationRequest, request: Request, response: Response, db: DbSession) -> TokenResponse:
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
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered.",
        ) from exc

    session_key = str(uuid4())
    access_token = create_access_token(user, session_key)
    refresh_token = create_refresh_token(user, session_key)
    csrf_token = generate_csrf_token()
    auth_session = AuthSession(
        user_id=user.id,
        session_key=session_key,
        refresh_token_hash=hash_password(refresh_token),
        access_jti=jwt_payload_jti(access_token),
        refresh_jti=jwt_payload_jti(refresh_token),
        user_agent=request.headers.get("user-agent"),
        ip_address=client_ip(request),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_days),
    )
    db.add(auth_session)
    db.flush()
    set_auth_cookies(response, access_token, refresh_token, csrf_token)
    record_security_event(
        db,
        "register_success",
        user_id=user.id,
        identifier=user.username,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={"username": user.username, "role": user.role},
        commit=False,
    )
    db.commit()
    return TokenResponse(access_token=access_token, username=user.username, role=user.role)


@app.get("/api/auth/me", response_model=UserResponse)
def me(user: CurrentUser) -> UserResponse:
    return UserResponse(username=user.username, role=user.role)


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, db: DbSession, user: CurrentUser) -> Response:
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    if refresh_token:
        try:
            payload = decode_token(refresh_token, expected_type="refresh")
        except ValueError:
            payload = None
        if payload is not None:
            session = db.query(AuthSession).filter(AuthSession.session_key == payload.get("sid")).first()
            if session is not None and session.user_id == user.id:
                if payload.get("jti") != session.refresh_jti:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been invalidated.")
                session.revoked_at = datetime.now(timezone.utc)
                db.commit()
    clear_auth_cookies(response)
    record_security_event(
        db,
        "logout",
        user_id=user.id,
        identifier=user.username,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={"username": user.username, "role": user.role},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.post("/api/auth/refresh", response_model=TokenResponse)
def refresh(request: Request, response: Response, db: DbSession) -> TokenResponse:
    refresh_token = request.cookies.get(REFRESH_COOKIE)
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing.")

    try:
        payload = decode_token(refresh_token, expected_type="refresh")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token.") from exc

    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active or payload.get("role") != user.role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User is inactive or token permissions have changed.")

    session = db.query(AuthSession).filter(AuthSession.session_key == payload.get("sid")).first()
    if session is None or session.user_id != user.id or session.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is invalid or has been revoked.")
    if payload.get("jti") != session.refresh_jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token has been invalidated.")

    if not verify_password(refresh_token, session.refresh_token_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token invalid.")

    new_session_key = str(uuid4())
    new_access_token = create_access_token(user, new_session_key)
    new_refresh_token = create_refresh_token(user, new_session_key)
    new_csrf_token = generate_csrf_token()
    new_session = AuthSession(
        user_id=user.id,
        session_key=new_session_key,
        refresh_token_hash=hash_password(new_refresh_token),
        access_jti=jwt_payload_jti(new_access_token),
        refresh_jti=jwt_payload_jti(new_refresh_token),
        user_agent=request.headers.get("user-agent"),
        ip_address=client_ip(request),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_days),
    )
    db.add(new_session)
    db.flush()
    session.revoked_at = datetime.now(timezone.utc)
    session.replaced_by_session_id = new_session.id
    set_auth_cookies(response, new_access_token, new_refresh_token, new_csrf_token)
    record_security_event(
        db,
        "refresh_success",
        user_id=user.id,
        identifier=user.username,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={"username": user.username, "role": user.role},
        commit=False,
    )
    db.commit()
    return TokenResponse(access_token=new_access_token, username=user.username, role=user.role)


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
    request: Request,
    db: DbSession,
    actor: Annotated[User, Depends(require_roles("admin"))],
) -> User:
    username = payload.username.strip().lower()
    if db.query(User).filter(func.lower(User.username) == username).first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username is already registered.",
        )
    user = User(
        username=username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    record_security_event(
        db,
        "privileged_account_change",
        user_id=actor.id,
        identifier=actor.username,
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={
            "action": "create_user",
            "target_user": user.username,
            "target_role": user.role,
            "actor": actor.username,
        },
    )
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


@app.post("/api/scans/document", response_model=DocumentScanResponse)
async def scan_document(
    file: Annotated[UploadFile, File()],
    destination: Annotated[str, Form(min_length=1, max_length=160)],
    context: Annotated[Literal["internal", "partner", "public"], Form()],
    destination_authorized: Annotated[bool, Form()],
    db: DbSession,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> DocumentScanResponse:
    content = await file.read(MAX_DOCUMENT_BYTES + 1)
    await file.close()
    try:
        extracted = extract_document_text(file.filename or "", content)
    except DocumentReadError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    result, _ = evaluate_scan(
        db=db,
        user=user,
        text=extracted.text,
        source=f"Document: {extracted.filename}"[:120],
        destination=destination,
        destination_authorized=destination_authorized,
        context=context,
    )
    return DocumentScanResponse(
        **result,
        filename=extracted.filename,
        extraction_method=extracted.extraction_method,
        extracted_characters=len(extracted.text),
        truncated=extracted.truncated,
    )


@app.get("/api/incidents", response_model=list[IncidentResponse])
def incidents(
    db: DbSession,
    _: CurrentUser,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[Incident]:
    return db.query(Incident).order_by(desc(Incident.created_at)).limit(limit).all()


@app.get("/api/incidents/report.csv")
def incident_report(
    db: DbSession,
    _: CurrentUser,
) -> StreamingResponse:
    output = StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "Incident reference",
            "Detection categories",
            "Risk score",
            "Severity",
            "Decision",
            "Explanation",
            "Recommended action",
            "Current status",
            "Created at",
        ]
    )
    for incident in db.query(Incident).order_by(desc(Incident.created_at)).limit(200).all():
        explanation = "; ".join(
            str(factor.get("label", ""))
            for factor in incident.risk_factors
            if factor.get("label")
        )
        writer.writerow(
            [
                f"PRIVEX-{incident.id:06d}",
                ", ".join(incident.categories),
                incident.risk_score,
                incident.severity,
                incident.decision,
                explanation,
                incident.recommended_action,
                incident.status,
                incident.created_at.isoformat(),
            ]
        )
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="privexai-incidents.csv"'},
    )


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
