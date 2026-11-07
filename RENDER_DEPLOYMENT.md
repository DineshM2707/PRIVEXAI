# Deploy PRIVEXAI on Render

This deployment uses a Render Blueprint to create:

- A React/Vite static site: `privexai-frontend`
- A FastAPI web service: `privexai-api`
- A PostgreSQL database: `privexai-db`

The Blueprint is in [`render.yaml`](./render.yaml). It contains no credentials. Render generates `SECRET_KEY`; you supply `ADMIN_PASSWORD` through Render's setup/dashboard.

## Before deploying

1. Review `render.yaml` and this document.
2. After approving the configuration, commit and push the changes to the existing `main` branch.
3. Sign in to [Render](https://dashboard.render.com/) and select **New > Blueprint**.
4. Connect the existing `DineshM2707/PRIVEXAI` GitHub repository and select `main`.
5. Review the services and plans Render proposes before confirming creation. Do not continue if a plan or charge is unexpected.
6. When prompted for `ADMIN_PASSWORD`, set a unique strong password and save it in your password manager. Never put it in `render.yaml`, source code, or Git.
7. Wait for the database and service deployment to finish. The API runs Alembic migrations at startup.

The configured service names imply these URLs:

- Website: <https://privexai-frontend.onrender.com>
- API health endpoint: <https://privexai-api.onrender.com/api/health>

If Render assigns different service hostnames, update `VITE_API_BASE_URL` on the static site to `https://<actual-api-host>/api` and `CORS_ORIGINS` on the API to `https://<actual-frontend-host>`, then redeploy both services.

## Free-plan limitations

The Blueprint selects Singapore for the API and database; Render static sites are served globally. The API and database must remain in the same region for private database connectivity.

- Free web services can spin down after inactivity; the first request after a spin-down can take about a minute.
- Render's free PostgreSQL database expires 30 days after creation. Its data is not a permanent demo store. Upgrade or export/migrate it before expiry if the deployment must persist beyond that period.
- Free services have resource and usage limits. Review Render's current billing and free-plan terms before deployment; this configuration is for a demo, not production.

## Data, credentials, and security notes

- The hosted PostgreSQL database starts separately from the local SQLite demo database. This configuration does not copy local users, scans, or incidents to Render.
- The backend creates its admin user and default policies on first startup and seeds synthetic demo records in an empty database.
- Save the admin password you provide during setup. Changing `ADMIN_PASSWORD` later does not rotate a password for an already-created admin user.
- Render's generated `SECRET_KEY` is held in the service environment, not this repository.
- Authentication cookies automatically use the `Secure` attribute when all configured `CORS_ORIGINS` use HTTPS. Set `COOKIE_SECURE` explicitly only if you need to override this behavior.
- Do not submit real student, customer, financial, or health information. The scanner is a rule-based sample demo and does not monitor or block real network transfers.
- This configuration does not add email verification, password recovery, tenant isolation, distributed login throttling, or production audit/retention controls.

## Local development remains unchanged

When `VITE_API_BASE_URL` is unset, the frontend continues to call `/api`, using the existing Vite development proxy. The local SQLite database remains at `backend/datashield-local.db`; it is not modified by preparing or deploying this Blueprint.
