# PRIVEXAI Security Review

## Scope

Focused review of JWT/session handling, role authorization, sensitive-data handling, migration safety, frontend authentication flows, and performance.

## Findings

| Severity | File | Finding | Status |
|---|---|---|---|
| Medium | `backend/app/config.py:38` | Authentication cookies could lack the `Secure` attribute when `COOKIE_SECURE` was unset, including in the HTTPS deployment. This could expose session cookies to interception over HTTP. | Fixed in commit `7c4013440c91a919471c3eca73e872f7453b0645`. |

## Remediation

When `COOKIE_SECURE` is not explicitly configured, the application now enables secure cookies if every configured CORS origin uses HTTPS. Explicit `COOKIE_SECURE=true` or `false` continues to override the default. Local HTTP development remains usable.

## Verification

- Backend regression suite: 31 tests passed, including HTTPS/local cookie configuration and session-token invalidation checks.
- Alembic migration chain generated successfully in offline SQL mode; no database was modified.
- No production deployment or live database migration was performed.
