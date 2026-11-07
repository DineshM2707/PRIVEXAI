from datetime import datetime, timedelta, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    email: Mapped[str | None] = mapped_column(String(254), unique=True, nullable=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    incidents: Mapped[list["Incident"]] = relationship(back_populates="actor")
    sessions: Mapped[list["AuthSession"]] = relationship(back_populates="user")
    security_events: Mapped[list["SecurityEvent"]] = relationship(back_populates="user")


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    session_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(255))
    access_jti: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    refresh_jti: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: utc_now() + timedelta(days=7))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    replaced_by_session_id: Mapped[int | None] = mapped_column(ForeignKey("auth_sessions.id"), nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    identifier: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    user: Mapped[User | None] = relationship(back_populates="security_events")


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    category: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    action: Mapped[str] = mapped_column(String(20))
    weight: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(String(240))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    source: Mapped[str] = mapped_column(String(120))
    destination: Mapped[str] = mapped_column(String(160))
    categories: Mapped[list[str]] = mapped_column(JSON)
    risk_score: Mapped[int] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_events.id"), unique=True)
    source: Mapped[str] = mapped_column(String(120))
    destination: Mapped[str] = mapped_column(String(160))
    categories: Mapped[list[str]] = mapped_column(JSON)
    finding_counts: Mapped[dict[str, int]] = mapped_column(JSON)
    risk_factors: Mapped[list[dict[str, str | int]]] = mapped_column(JSON)
    risk_score: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(20))
    decision: Mapped[str] = mapped_column(String(20))
    recommended_action: Mapped[str] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(20), default="open")
    masked_preview: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    actor: Mapped[User | None] = relationship(back_populates="incidents")
