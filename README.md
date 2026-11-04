# PRIVEXAI

PRIVEXAI is a sample-based enterprise Data Leakage Prevention (DLP) demonstration for financial, healthcare, and technology teams. The MVP analyzes text explicitly submitted through its UI/API, calculates a transparent risk score, applies category policies, and displays synthetic incident and analytics data.

**It does not monitor network traffic, connect to enterprise systems, or provide production-grade compliance guarantees.** Do not submit real customer data to this demonstration.

## MVP capabilities

- Detect email, Indian-phone-shaped, Aadhaar-like, PAN-like, labeled account-number, selected API-secret, and explicitly labeled synthetic student-record patterns in submitted text.
- Apply enabled per-category mask/block rules, destination authorization, sharing context, and simple language-context cues to an explainable 0–100 risk score.
- Return allow/mask/block/review decisions and a masked preview. Submitted raw sample text is not persisted; only scan metadata and a redacted preview are stored.
- Track incidents, update incident status, and view synthetic demo statistics and seven-day trends.
- Protect API endpoints with JWT authentication, Argon2id password hashing, and administrator/analyst/viewer role checks.
- Register public accounts with server-enforced viewer access; administrators continue to grant analyst access separately.
- Sign in with a username or registered email address. Public registration requires a 12-character mixed-case, numeric, and symbol password.
- Manage category actions and enablement with an administrator account.

Detection is local and rule-based; no external AI model or NLP service is called. The seeded records are labeled synthetic demonstrations, not customer telemetry.

## Hackathon demo: synthetic student-data protection

1. Sign in with the locally configured administrator account.
2. Review the dashboard totals and synthetic/sample activity.
3. Open **Sample scanner**. Its prefilled example contains only synthetic data: `Student name: Jamie Rivera; email jamie.rivera@example.test; phone 9876543210; Student ID: STU-2048; GPA: 3.8`.
4. Analyze with an unauthorized external destination to demonstrate detection, risk factors, redaction, and a simulated block outcome.
5. To demonstrate masking, submit a synthetic email with an authorized internal destination. To demonstrate allow, submit ordinary text with an authorized internal destination.
6. To demonstrate manual review, use public context, an unauthorized destination, and text such as `Please share this synthetic report publicly.` The contextual risk rule returns **Review** and records an incident for a human decision.
7. Open **Incidents** to inspect the masked preview and update its status.
8. Open **Policies** as an administrator to change a category action or weight; restore it after the demonstration if desired.
9. Return to the dashboard to show the updated sample and incident statistics.

These are prototype decisions for user-submitted samples. No real student data is used or retained, and no actual network transfer is intercepted or blocked.

## Start with Docker Compose

Requirements: Docker Engine/Desktop with the Compose plugin.

1. Copy `.env.example` to `.env`.
2. Replace `POSTGRES_PASSWORD`, `SECRET_KEY` (at least 32 random characters), and `ADMIN_PASSWORD` with unique values. For example, generate a signing key using `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
3. From the repository root, start the services:

   ```powershell
   docker compose up --build
   ```

4. Open `http://localhost:3000` and sign in with `ADMIN_USERNAME` and `ADMIN_PASSWORD` from `.env`.
5. Stop the services with `Ctrl+C`, then run `docker compose down`. `docker compose down -v` deletes the database volume and is intentionally not part of the normal workflow.

The API is proxied through the frontend at `/api`; the PostgreSQL service is not published to the host. Compose runs Alembic migrations before starting the API.

## Deploy on Render

For a hosted frontend, API, and PostgreSQL setup, see [RENDER_DEPLOYMENT.md](./RENDER_DEPLOYMENT.md). The Render Blueprint is `render.yaml`; review it and its free-tier database limitations before creating services. Local `.env` values and the SQLite demo database are not used or uploaded by this configuration.

## Local development

Docker is not required for local development. To run the application immediately without installing a database server, use SQLite for the local demo. PostgreSQL remains the deployment/database target and uses the same SQLAlchemy models and Alembic migration.

```powershell
Set-Location backend
python -m venv .venv
$venvPython = ".\.venv\Scripts\python.exe"
& $venvPython -m pip install -r requirements.txt
$env:DATABASE_URL = "sqlite:///./datashield-local.db"
$env:SECRET_KEY = "replace-with-at-least-32-random-characters"
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "replace-with-a-unique-password"
& ".\.venv\Scripts\alembic.exe" upgrade head
& ".\.venv\Scripts\uvicorn.exe" app.main:app --reload --port 8000
```

In another terminal:

```powershell
Set-Location frontend
npm.cmd install
npm.cmd run dev
```

Open the Vite URL (normally `http://localhost:5173`). Its `/api` requests are proxied to `http://localhost:8000`. To use another backend port, set `VITE_API_PROXY_TARGET` before starting Vite, for example `$env:VITE_API_PROXY_TARGET = "http://127.0.0.1:8001"`.

To use PostgreSQL instead, install PostgreSQL 16 or newer locally, create a database/user, and set `DATABASE_URL` to a `postgresql+psycopg://...` URL before running the migration and API commands. URL-encode special characters in the URL username/password. For example:

```powershell
$env:DATABASE_URL = "postgresql+psycopg://datashield:YOUR_URL_SAFE_PASSWORD@localhost:5432/datashield"
```

The local SQLite database is stored at `backend/datashield-local.db` and ignored by Git. It is intended for development only.
The PRIVEXAI logo at `frontend/public/privexai-logo.png` is used in the login, registration, workspace header, and favicon.

## API overview

- `GET /api/health` — liveness check
- `POST /api/auth/register` — create a viewer-only account and receive a JWT
- `POST /api/auth/login` — exchange username/email and password for a short-lived JWT
- `GET /api/auth/me` — current account
- `GET /api/users` and `POST /api/users` — list/create analyst or viewer accounts (admin-only)
- `POST /api/scans` — analyze an explicitly submitted text sample (admin/analyst)
- `GET /api/incidents` and `PATCH /api/incidents/{id}` — list and update incident status
- `GET /api/policies` and `PUT /api/policies/{category}` — inspect/edit rules (admin-only edits)
- `GET /api/analytics` — sample counts, decisions, category totals, and seven-day trend

## Security and deployment notes

- Change all `.env` values before starting; `.env` is ignored by Git. Never reuse demo credentials or secrets in a deployed environment.
- TLS termination, secret management, backups, audit retention, distributed rate limiting, account provisioning, and production monitoring must be configured by the deployment owner.
- The demo applies a small in-memory failed-login limit and basic security response headers. This limiter is process-local, resets on restart, and is not sufficient for production or multi-worker deployments.
- Public registration does not verify email addresses, and password recovery is not available in the demo.
- The default admin account is bootstrapped only when its username does not already exist. Changing `ADMIN_PASSWORD` after initial boot does not rotate an existing account's password.
- Pattern matching is illustrative and will have false positives/negatives. Tune and validate rules against synthetic fixtures before any controlled pilot.
- The Compose network is private by default and only the frontend port is published. Add approved TLS and network controls before exposing the service beyond a trusted environment.

## Tests

From `backend`:

```powershell
python -m unittest discover -s tests -v
```

Frontend production build:

```powershell
Set-Location frontend
npm.cmd install
npm.cmd run build
```

Frontend API client tests:

```powershell
Set-Location frontend
npm.cmd test
```
