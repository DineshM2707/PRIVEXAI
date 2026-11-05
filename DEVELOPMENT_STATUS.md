# PRIVEXAI Development Status

Last updated: 2026-11-05

## Task status

| Task | Status | Notes |
|---|---|---|
| Sample-based scanner, contextual explanations, risk scoring, masking, blocking, and review | COMPLETED | Existing regex rules remain the fallback; findings now include heuristic match strength and safe explanations. Context gates unlabeled 8–13 digit numbers to reduce avoidable account-number false positives. Decisions apply only to submitted samples. |
| TXT/CSV/PDF document scanning | COMPLETED | Added 2 MB upload limit, UTF-8/CSV parsing, text-based PDF extraction (50-page limit), 20,000-character scan cap with explicit truncation notice, and clear unsupported/encrypted/image-only PDF errors. OCR and Word documents are not supported. |
| Explainable incidents and CSV security report | COMPLETED | Incident investigation details show stored risk factors and protected preview. Authenticated CSV export contains only incident metadata, reasons, and remediation fields; raw submitted text is excluded. No assignment or status-history model was added because it requires a database migration. |
| Interactive dashboard charts | COMPLETED | Existing API analytics drive a centered findings donut with counts/percentages and top-category indicator; activity chart now includes scan, block, and mask trends. |
| Authentication, authorization, and viewer-only registration API | COMPLETED | JWT, Argon2id password hashing, role checks, username/email login, viewer-only public registration, duplicate handling, and login throttling are implemented and covered by tests. |
| Registration frontend-to-backend flow | COMPLETED | Frontend uses `/api`; local Vite proxies it to the configured backend. Health and registration requests were verified through the proxy. One synthetic viewer registered and logged in; duplicate registration returned HTTP 409 without a second insert. Invalid username returned a safe field-specific HTTP 422 response. |
| SQLite profile migration and existing demo data | COMPLETED | Existing database remains at Alembic revision `0002_user_profile`; it contains 6 users, 9 policies, 21 scan events, and 18 incidents. Two synthetic test/demo accounts are present. No database reset was performed. |
| Frontend tests, type check, and production build | COMPLETED | 4 frontend tests passed; TypeScript check and production build passed. Vite reports a non-fatal large-chunk advisory. |
| Backend regression tests | COMPLETED | Latest full run: 26 tests passed, including registration/login, roles, detection/risk, TXT/CSV/PDF upload, unsupported-file handling, and safe CSV reporting. |
| Local development runtime | COMPLETED | The app was verified locally through the Vite proxy and backend health endpoint. Services are not guaranteed to remain running after the current session; start commands are in `README.md`. |
| Public Render website, API, and PostgreSQL deployment | COMPLETED | Render Blueprint `privexai-production` provisioned the static frontend, FastAPI service, and PostgreSQL database on the configured free plans. The frontend and registration route return HTTP 200; API health returns HTTP 200. PostgreSQL migrations completed. Cloud registration/login were not separately exercised. |
| Docker/PostgreSQL runtime verification | BLOCKED | Hosted PostgreSQL was provisioned and Alembic migrations ran successfully. Docker CLI is unavailable; local development remains on SQLite. |

## Current database and runtime facts

- Database: `backend/datashield-local.db` (SQLite), Alembic revision `0002_user_profile`.
- Read-only counts at last inspection: 6 users, 9 policies, 21 scan events, and 18 incidents. The two synthetic accounts are retained for demonstration/testing.
- The hosted Render PostgreSQL database is separate from the local SQLite database. Its Alembic migrations completed during API startup; existing local user and incident records were not copied or reset.
- The previous registration error was caused by opening a stale local frontend URL/port with no listener. Browser events showed `ERR_CONNECTION_REFUSED` at port 5175. The valid local Vite/API configuration is frontend port 5173 with `/api` proxied to backend port 8000.
- Public frontend: `https://privexai-frontend.onrender.com/` and `/register` returned HTTP 200.
- Public API health: `https://privexai-api.onrender.com/api/health` returned `{"status":"ok","service":"PRIVEXAI API"}` with HTTP 200.
- Commits `1727858` (contextual scanner/report features) and `dcf95a8` (Alembic PostgreSQL URL normalization) are pushed to `origin/main`.
- Exactly one Render Blueprint was deployed: `privexai-production`, containing `privexai-frontend`, `privexai-api`, and `privexai-db`. The API deployment initially failed because Alembic used SQLAlchemy's default psycopg2 driver despite psycopg v3 being installed; `backend/migrations/env.py` now applies the project's PostgreSQL URL normalizer. The latest deploy completed migrations and started Uvicorn.
- Local servers are stopped; ports 5173 and 8000 were verified free. Public Render services remain deployed.

## Validation record

- Backend: `python -m unittest discover -s tests -v` — **26 passed** on the latest full run. An earlier run exposed a CSV `student_id` separator issue; the regex was corrected and the full suite now passes.
- Frontend: `npm.cmd test` — **4 passed**; `npm.cmd run build` (including `tsc -b`) — **passed**, with non-fatal large-chunk advisory.
- `git diff --check` — **passed after all changes**.
- Live local health: `GET /api/health` succeeded directly and through the frontend proxy on the prior local server session. Current shared browser diagnostics show 401 responses for stored-session requests; sign out and sign in again if that persists after a backend restart because JWT signing keys are process environment configuration.
- Registration: one synthetic account was created in the existing SQLite database, login succeeded, duplicate registration returned HTTP 409, and an invalid username returned a field-specific HTTP 422. No additional account was created during the latest connection check.
- Public deployment: frontend `/` and `/register` returned HTTP 200; API `/api/health` returned HTTP 200 after PostgreSQL migration and API startup. Cloud account creation and cloud login have not been tested; no cloud test account was created.
- Focused deployment-fix tests: `python -m unittest discover -s tests -p 'test_config.py' -v` — **2 passed**. `git diff --check` passed.

## Remaining work and limitations

1. Cloud registration and login have not been end-to-end tested; only the deployed registration page and API health endpoint were verified.
2. Docker is unavailable; local development uses SQLite, while hosted migrations on PostgreSQL completed.
3. Email verification, password recovery, OCR, DOCX, incident assignment/history, tenant isolation, and dedicated audit logs are not implemented. Login throttling is in-memory; JWTs are stored in browser `localStorage`.
4. Scanner decisions are for submitted samples only and do not monitor or enforce real network transfers. Match-strength values are explanatory heuristics, not calibrated confidence or ML.

## Local startup

Use the **Local development** steps in `README.md`. The standard local URLs are:

- Frontend: `http://127.0.0.1:5173`
- Backend health: `http://127.0.0.1:8000/api/health`

If the backend uses another port, set `VITE_API_PROXY_TARGET` before starting Vite. Do not use stale browser tabs on ports 5174 or 5175 unless a frontend server is intentionally running there.
