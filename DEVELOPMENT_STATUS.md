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
| Public Render website, API, and PostgreSQL deployment | BLOCKED | Configured hostnames previously returned HTTP 404. No live deployment is verified. Local changes are not pushed; deployment requires explicit user authorization and Render Blueprint setup. |
| Docker/PostgreSQL runtime verification | NOT STARTED | Docker CLI is unavailable in this environment. Local verification uses the existing SQLite database; hosted PostgreSQL has not been validated. |

## Current database and runtime facts

- Database: `backend/datashield-local.db` (SQLite), Alembic revision `0002_user_profile`.
- Read-only counts at last inspection: 6 users, 9 policies, 21 scan events, and 18 incidents. The two synthetic accounts are retained for demonstration/testing.
- The previous registration error was caused by opening a stale local frontend URL/port with no listener. Browser events showed `ERR_CONNECTION_REFUSED` at port 5175. The valid local Vite/API configuration is frontend port 5173 with `/api` proxied to backend port 8000.
- Render URL checks: `https://privexai-frontend.onrender.com/` returned HTTP 404; `https://privexai-api.onrender.com/api/health` returned HTTP 404. Treat these hostnames as unverified, not as a working public website.
- No GitHub commit or push was performed for the current registration-flow changes.

## Validation record

- Backend: `python -m unittest discover -s tests -v` — **26 passed** on the latest full run. An earlier run exposed a CSV `student_id` separator issue; the regex was corrected and the full suite now passes.
- Frontend: `npm.cmd test` — **4 passed**; `npm.cmd run build` (including `tsc -b`) — **passed**, with non-fatal large-chunk advisory.
- `git diff --check` — **passed after all changes**.
- Live local health: `GET /api/health` succeeded directly and through the frontend proxy on the prior local server session. Current shared browser diagnostics show 401 responses for stored-session requests; sign out and sign in again if that persists after a backend restart because JWT signing keys are process environment configuration.
- Registration: one synthetic account was created in the existing SQLite database, login succeeded, duplicate registration returned HTTP 409, and an invalid username returned a field-specific HTTP 422. No additional account was created during the latest connection check.
- External endpoints and browser console: the browser's stale port showed connection-refused errors; configured Render URLs returned 404. No public registration is available until the hosted frontend, backend, and database are deployed and connected.

## Remaining work and limitations

1. Review and authorize committing/pushing the local changes if desired; no commit or push has been made.
2. Deploy/configure the Render Blueprint, then verify actual service URLs, `VITE_API_BASE_URL`, `CORS_ORIGINS`, health, registration, and login.
3. Docker/PostgreSQL deployment behavior is not verified. Local development uses SQLite.
4. Email verification, password recovery, OCR, DOCX, incident assignment/history, tenant isolation, and dedicated audit logs are not implemented. Login throttling is in-memory; JWTs are stored in browser `localStorage`.
5. Scanner decisions are for submitted samples only and do not monitor or enforce real network transfers. Match-strength values are explanatory heuristics, not calibrated confidence or ML.

## Local startup

Use the **Local development** steps in `README.md`. The standard local URLs are:

- Frontend: `http://127.0.0.1:5173`
- Backend health: `http://127.0.0.1:8000/api/health`

If the backend uses another port, set `VITE_API_PROXY_TARGET` before starting Vite. Do not use stale browser tabs on ports 5174 or 5175 unless a frontend server is intentionally running there.
