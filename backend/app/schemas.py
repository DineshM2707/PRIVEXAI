from datetime import datetime
from typing import Literal

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class RegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    username: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    password: str = Field(min_length=12, max_length=256)

    @field_validator("full_name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = " ".join(value.split())
        if not value or not all(char.isalpha() or char in " '-." for char in value):
            raise ValueError("Enter a valid name.")
        return value

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
            raise ValueError("Enter a valid email address.")
        return value

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        if not (
            re.search(r"[a-z]", value)
            and re.search(r"[A-Z]", value)
            and re.search(r"\d", value)
            and re.search(r"[^A-Za-z0-9]", value)
        ):
            raise ValueError("Password must include uppercase, lowercase, a number, and a symbol.")
        return value


class UserCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    password: str = Field(min_length=12, max_length=256)
    role: Literal["analyst", "viewer"]

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        if not (
            re.search(r"[a-z]", value)
            and re.search(r"[A-Z]", value)
            and re.search(r"\d", value)
            and re.search(r"[^A-Za-z0-9]", value)
        ):
            raise ValueError("Password must include uppercase, lowercase, a number, and a symbol.")
        return value


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str


class UserResponse(BaseModel):
    username: str
    role: str


class ScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)
    source: str = Field(min_length=1, max_length=120)
    destination: str = Field(min_length=1, max_length=160)
    destination_authorized: bool = False
    context: Literal["internal", "partner", "public"] = "internal"


class FindingResponse(BaseModel):
    category: str
    count: int
    masked_examples: list[str]
    confidence: float = Field(ge=0, le=1)
    explanation: str


class ScanResponse(BaseModel):
    incident_id: int | None
    decision: Literal["allow", "mask", "block", "review"]
    risk_score: int
    severity: Literal["low", "medium", "high", "critical"]
    findings: list[FindingResponse]
    risk_factors: list[dict[str, str | int]]
    protected_preview: str
    recommended_action: str
    message: str


class DocumentScanResponse(ScanResponse):
    filename: str
    extraction_method: str
    extracted_characters: int
    truncated: bool


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    destination: str
    categories: list[str]
    finding_counts: dict[str, int]
    risk_factors: list[dict[str, str | int]]
    risk_score: int
    severity: str
    decision: str
    recommended_action: str
    status: str
    masked_preview: str
    created_at: datetime


class IncidentStatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


class PolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    category: str
    action: str
    weight: int
    description: str
    enabled: bool


class PolicyUpdate(BaseModel):
    action: Literal["mask", "block"]
    weight: int = Field(ge=0, le=100)
    enabled: bool


class TrendPoint(BaseModel):
    date: str
    scans: int
    blocked: int
    masked: int


class AnalyticsResponse(BaseModel):
    total_scans: int
    incidents: int
    blocked: int
    masked: int
    reviewed: int
    high_risk: int
    average_risk: int
    trends: list[TrendPoint]
    category_counts: dict[str, int]
