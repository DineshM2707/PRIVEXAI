# PRIVEXAI MVP Plan

## Goal

Deliver a local demonstration that analyzes text explicitly submitted through its UI/API, detects sensitive-data patterns including labeled student identifiers, explains risk, returns allow/mask/block/review decisions, records incidents, and summarizes activity. It does not monitor network traffic or connect to external systems.

## Essential tasks

1. **COMPLETED — Establish the application shell.** React/Vite frontend and FastAPI backend are implemented and were started locally. Browser access at `http://localhost:5173` and backend health at `http://localhost:8000/api/health` were verified.
2. **COMPLETED — Implement detection and policy decisions.** Pattern detection for labeled student data, contextual scoring, category policies, and masked previews passed backend tests and live allow/mask/block/review checks.
3. **COMPLETED — Add secure persistence and access control.** SQLAlchemy models, the initial Alembic migration, JWT authentication, Argon2id password hashing, and role-based API checks passed tests. The existing SQLite database is the verified local runtime; PostgreSQL is not verified.
4. **COMPLETED — Deliver incidents and analytics.** Incident persistence/status updates and dashboard statistics, including the review queue, were checked through the live API and browser.
5. **COMPLETED — Package and verify the local MVP.** 18 backend tests and 2 frontend tests pass; the frontend production build succeeds. Docker/PostgreSQL deployment remains outside the verified local path.
6. **COMPLETED — Rebrand and add public registration.** PRIVEXAI user-facing branding, the registration/login UI, viewer-only registration API, username/email sign-in, and the additive profile migration were verified. Browser signup, email login, dashboard data, viewer restrictions, incidents, and read-only policies passed against the updated API.
7. **COMPLETED — Integrate the supplied product logo.** The attached logo is installed at `frontend/public/privexai-logo.png`, used in the app/header/auth screens, and configured as the favicon.

## Scope and safeguards

- Seed only clearly synthetic demonstration records; never use real customer data.
- Process only text submitted by the user in the demo UI/API. No network interception or external service integrations.
- Keep secrets in environment configuration, provide safe development defaults only where appropriate, and never expose submitted raw content in incident listings.
- If PostgreSQL or Docker is unavailable, use SQLite for the local demo and report the deployment limitation rather than claiming it was tested.
- Known non-MVP gaps: organization isolation, dedicated audit logs, distributed rate limiting, and real transfer enforcement. The demo's in-memory failed-login limiter is not production-ready.
