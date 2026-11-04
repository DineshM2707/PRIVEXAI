# PRIVEXAI Development Status

Last updated: 2026-11-05

## Task status

| Task | Status | Notes |
|---|---|---|
| Sample-based scanner, risk scoring, masking, blocking, and review | COMPLETED | Existing detection, decisions, incidents, and analytics remain in place; regression suite passes. These are prototype decisions for submitted samples, not live traffic enforcement. |
| Authentication, authorization, and viewer-only registration API | COMPLETED | JWT, Argon2id, admin/analyst/viewer checks, email-or-username login, server-enforced viewer registration, password validation, and failed-login throttling are implemented and covered by tests. |
| SQLite profile migration | COMPLETED | Existing database advanced additively from `0001_initial` to `0002_user_profile`; existing scans/incidents were preserved. Current database totals: 4 users, 21 scans, 18 incidents. |
| PRIVEXAI frontend rebrand and registration flow | COMPLETED | Browser registration, confirmation, email sign-in, live dashboard metrics, incidents and policy reads passed against the updated API. Viewer scanner navigation is hidden and policy controls are read-only. |
| Supplied product logo | COMPLETED | The user-provided logo is installed at `frontend/public/privexai-logo.png` and used in the header, login, registration, and favicon. |
| PostgreSQL/Docker deployment | NOT STARTED | The verified path is local SQLite. PostgreSQL and Docker remain unverified. |

## Current runtime

- The pre-existing API at `http://localhost:8000` was left untouched; it still reports `DataShield AI API`. The updated API at `http://127.0.0.1:8001` reports `PRIVEXAI API`.
- The tested frontend is `http://127.0.0.1:5175`; its Vite `/api` proxy was confirmed to reach the updated API on port 8001. The proxy now supports `VITE_API_PROXY_TARGET` and defaults to port 8000.
- Port 5174 was already occupied by an older frontend process, so Vite selected 5175. No unrelated process was terminated.
- The database is `backend/datashield-local.db`, SQLite, Alembic revision `0002_user_profile`. Existing scans/incidents were retained; synthetic viewer accounts were added for registration verification.
- API documentation is available at `http://127.0.0.1:8001/docs` for the updated API. PostgreSQL is not configured or tested.

## Validation record

- Backend: `python -m unittest discover -s tests -v` from `backend` — **19 passed**.
- Python compilation: `python -m compileall -q app migrations tests` from `backend` — **passed**.
- Frontend: `npm.cmd test` from `frontend` — **2 passed**.
- Frontend production build: `npm.cmd run build` from `frontend` — **passed**; Vite reports a non-fatal 610.45 kB JavaScript chunk advisory.
- Database migration: `python -m alembic upgrade head` with `DATABASE_URL=sqlite:///./datashield-local.db` — **passed**, current revision `0002_user_profile`.
- Updated API: health and docs returned HTTP 200; registration returned a viewer token; email login succeeded; policy read returned 200; viewer scan attempt returned 403. CORS allow/deny and security headers are covered by backend tests.
- Browser: registration page, logo image, create-account navigation, successful registration confirmation, duplicate-account HTTP 409 message, email login HTTP 200, live dashboard values, incidents (18 rows), policy list (9 rules, no admin editors), hidden scanner navigation for viewer, and logout-to-login were verified on port 5175.
- Request validation returns a generic 422 response without echoing oversized submitted sample text; regression test passed.
- The complete browser workflow for admin-only scanning, decisions, policy writes, and incident status changes was not repeated in this pass. Existing backend integration tests cover role restrictions, scan decisions, incident persistence/status, policy updates, analytics, and preview privacy.
- Docker/PostgreSQL, email verification, and password recovery — **NOT VERIFIED/UNAVAILABLE**.
- The frontend build emits a bundle-size advisory. The Python test run emits a third-party Passlib/argon2 deprecation warning; tests pass.

## Remaining work and limitations

1. If desired, repeat the admin-only scan and policy-write browser workflow using an authorized admin account. The existing admin password was not changed or recovered.
2. Configure and test PostgreSQL/Docker only if needed for deployment.
3. Email verification and password recovery are unavailable. The failed-login limiter is in-memory and process-local, not production-grade. JWTs are stored in browser `localStorage`; organization isolation and dedicated audit logs are not implemented.
4. The scanner's allow/mask/block/review outcomes apply only to explicitly submitted samples; the prototype does not intercept or enforce real transfers.

## Local startup

Use the **Local development** steps in `README.md`. Set `VITE_API_PROXY_TARGET` to the backend URL when it runs on a non-default port. For the verified live setup, the updated backend is at `http://127.0.0.1:8001` and the frontend is at `http://127.0.0.1:5175`; the legacy service on port 8000 remains untouched.
