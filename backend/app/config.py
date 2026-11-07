import os
from dataclasses import dataclass


def _cookie_secure_from_environment() -> bool:
    configured = os.getenv("COOKIE_SECURE")
    if configured is not None:
        return configured.lower() in {"1", "true", "yes"}

    origins = tuple(
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS", "http://localhost:5173,http://localhost:3000"
        ).split(",")
        if origin.strip()
    )
    return bool(origins) and all(origin.lower().startswith("https://") for origin in origins)


def normalize_database_url(url: str) -> str:
    for scheme in ("postgres://", "postgresql://"):
        if url.startswith(scheme):
            return f"postgresql+psycopg://{url[len(scheme):]}"
    return url


@dataclass(frozen=True)
class Settings:
    database_url: str = normalize_database_url(
        os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://datashield:datashield@localhost:5432/datashield",
        )
    )
    secret_key: str = os.getenv("SECRET_KEY", "")
    access_token_minutes: int = int(os.getenv("ACCESS_TOKEN_MINUTES", "30"))
    refresh_token_days: int = int(os.getenv("REFRESH_TOKEN_DAYS", "7"))
    cookie_secure: bool = _cookie_secure_from_environment()
    admin_username: str = os.getenv("ADMIN_USERNAME", "admin")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "")
    cors_origins: tuple[str, ...] = tuple(
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS", "http://localhost:5173,http://localhost:3000"
        ).split(",")
        if origin.strip()
    )


settings = Settings()
