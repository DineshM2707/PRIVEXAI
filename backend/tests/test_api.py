from dataclasses import replace
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main, security
from app.config import settings as default_settings
from app.database import Base, get_db
from app.models import Incident, Policy, ScanEvent, User


class ApiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        cls.session_factory = sessionmaker(
            bind=cls.engine,
            autoflush=False,
            expire_on_commit=False,
        )
        Base.metadata.create_all(bind=cls.engine)
        cls.original_session_local = main.SessionLocal
        main.SessionLocal = cls.session_factory

        cls.test_settings = replace(
            default_settings,
            secret_key="test-signing-key-with-at-least-32-characters",
            admin_username="admin",
            admin_password="test-admin-password",
        )
        cls.original_main_settings = main.settings
        cls.original_security_settings = security.settings
        main.settings = cls.test_settings
        security.settings = cls.test_settings

        def override_get_db():
            with cls.session_factory() as db:
                yield db

        cls.original_get_db_override = main.app.dependency_overrides.get(get_db)
        main.app.dependency_overrides[get_db] = override_get_db

    @classmethod
    def tearDownClass(cls):
        if cls.original_get_db_override is None:
            main.app.dependency_overrides.pop(get_db, None)
        else:
            main.app.dependency_overrides[get_db] = cls.original_get_db_override
        main.SessionLocal = cls.original_session_local
        main.settings = cls.original_main_settings
        security.settings = cls.original_security_settings
        Base.metadata.drop_all(bind=cls.engine)
        cls.engine.dispose()

    def setUp(self):
        main.login_attempts.clear()
        with self.session_factory() as db:
            db.query(Incident).delete()
            db.query(ScanEvent).delete()
            db.query(Policy).delete()
            db.query(User).delete()
            db.commit()
        self.client = TestClient(main.app)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def login(self, username="admin", password="test-admin-password"):
        response = self.client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["access_token"]

    def test_authentication_bootstrap_and_incident_read_access(self):
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(health.headers["X-Frame-Options"], "DENY")
        self.assertEqual(self.client.get("/api/incidents").status_code, 401)

        token = self.login()
        response = self.client.get(
            "/api/incidents",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(response.json()), 6)

        with self.session_factory() as db:
            admin = db.query(User).filter_by(username="admin").one()
            self.assertTrue(admin.password_hash.startswith("$argon2id$"))

        allowed_origin = self.client.options(
            "/api/auth/login",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertEqual(allowed_origin.headers["access-control-allow-origin"], "http://localhost:5173")
        denied_origin = self.client.options(
            "/api/auth/login",
            headers={
                "Origin": "https://untrusted.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertNotIn("access-control-allow-origin", denied_origin.headers)

    def test_public_registration_creates_viewer_and_supports_email_login(self):
        payload = {
            "full_name": "  Alex   Example ",
            "email": "ALEX@example.test",
            "username": "Alex.Example",
            "password": "Strong-password-42!",
            "role": "admin",
        }
        escalated = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(escalated.status_code, 422)

        payload.pop("role")
        response = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["role"], "viewer")

        email_login = self.client.post(
            "/api/auth/login",
            json={"username": "alex@example.test", "password": payload["password"]},
        )
        self.assertEqual(email_login.status_code, 200, email_login.text)
        self.assertEqual(email_login.json()["role"], "viewer")
        headers = {"Authorization": f"Bearer {email_login.json()['access_token']}"}
        self.assertEqual(self.client.get("/api/policies", headers=headers).status_code, 200)
        self.assertEqual(self.client.post("/api/scans", headers=headers, json={}).status_code, 403)

        with self.session_factory() as db:
            registered_user = db.query(User).filter_by(username="alex.example").one()
            self.assertTrue(registered_user.password_hash.startswith("$argon2id$"))

        duplicate_username = self.client.post(
            "/api/auth/register",
            json={
                **payload,
                "username": "ALEX.EXAMPLE",
                "email": "another@example.test",
            },
        )
        self.assertEqual(duplicate_username.status_code, 409)

        duplicate_email = self.client.post(
            "/api/auth/register",
            json={
                **payload,
                "username": "other.account",
                "email": "alex@example.test",
            },
        )
        self.assertEqual(duplicate_email.status_code, 409)

    def test_login_rate_limit_after_five_invalid_attempts(self):
        for _ in range(main.LOGIN_MAX_ATTEMPTS):
            response = self.client.post(
                "/api/auth/login",
                json={"username": "limited-user", "password": "wrong-password"},
            )
            self.assertEqual(response.status_code, 401)
        limited = self.client.post(
            "/api/auth/login",
            json={"username": "limited-user", "password": "wrong-password"},
        )
        self.assertEqual(limited.status_code, 429)

    def test_request_validation_does_not_echo_oversized_sample_text(self):
        token = self.login()
        sensitive_marker = "SYNTHETIC_SECRET_MUST_NOT_BE_ECHOED"
        response = self.client.post(
            "/api/scans",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "text": sensitive_marker + ("x" * 20_000),
                "source": "Validation test",
                "destination": "Internal test",
                "destination_authorized": True,
                "context": "internal",
            },
        )

        self.assertEqual(response.status_code, 422)
        self.assertNotIn(sensitive_marker, response.text)
        self.assertEqual(
            response.json()["detail"],
            "Invalid request data. Check required fields and allowed values.",
        )

    def test_admin_can_create_roles_and_enforce_access(self):
        admin_token = self.login()
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        create_response = self.client.post(
            "/api/users",
            headers=admin_headers,
            json={
                "username": "demo.viewer",
                "password": "a-unique-viewer-password",
                "role": "viewer",
            },
        )
        self.assertEqual(create_response.status_code, 201, create_response.text)
        self.assertEqual(create_response.json()["role"], "viewer")
        self.assertEqual(
            self.client.post(
                "/api/users",
                headers=admin_headers,
                json={
                    "username": "demo.viewer",
                    "password": "a-unique-viewer-password",
                    "role": "viewer",
                },
            ).status_code,
            409,
        )

        viewer_token = self.login("demo.viewer", "a-unique-viewer-password")
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
        self.assertEqual(self.client.get("/api/policies", headers=viewer_headers).status_code, 200)
        self.assertEqual(self.client.post("/api/scans", headers=viewer_headers, json={}).status_code, 403)
        self.assertEqual(
            self.client.post(
                "/api/users",
                headers=viewer_headers,
                json={
                    "username": "not.allowed",
                    "password": "another-unique-password",
                    "role": "analyst",
                },
            ).status_code,
            403,
        )

        analyst_response = self.client.post(
            "/api/users",
            headers=admin_headers,
            json={
                "username": "demo.analyst",
                "password": "a-unique-analyst-password",
                "role": "analyst",
            },
        )
        self.assertEqual(analyst_response.status_code, 201, analyst_response.text)
        analyst_token = self.login("demo.analyst", "a-unique-analyst-password")
        analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
        analyst_scan = self.client.post(
            "/api/scans",
            headers=analyst_headers,
            json={
                "text": "No sensitive values in this synthetic note.",
                "source": "Analyst demo",
                "destination": "Internal archive",
                "destination_authorized": True,
                "context": "internal",
            },
        )
        self.assertEqual(analyst_scan.status_code, 200, analyst_scan.text)
        self.assertEqual(analyst_scan.json()["decision"], "allow")
        self.assertEqual(
            self.client.put(
                "/api/policies/email",
                headers=analyst_headers,
                json={"action": "block", "weight": 40, "enabled": True},
            ).status_code,
            403,
        )

    def test_scan_masks_and_persists_metadata_for_incident_and_analytics(self):
        token = self.login()
        headers = {"Authorization": f"Bearer {token}"}
        raw_sample = "Synthetic PAN ABCDE1234F goes to an unapproved partner."
        scan_response = self.client.post(
            "/api/scans",
            headers=headers,
            json={
                "text": raw_sample,
                "source": "Synthetic test",
                "destination": "Unapproved partner",
                "destination_authorized": False,
                "context": "partner",
            },
        )
        self.assertEqual(scan_response.status_code, 200, scan_response.text)
        scan = scan_response.json()
        self.assertEqual(scan["decision"], "block")
        self.assertEqual(scan["risk_score"], 70)
        self.assertNotIn("ABCDE1234F", scan["protected_preview"])
        self.assertEqual(scan["findings"][0]["masked_examples"], ["[ID REDACTED]"])

        incidents = self.client.get("/api/incidents", headers=headers).json()
        incident = next(item for item in incidents if item["id"] == scan["incident_id"])
        self.assertNotIn("ABCDE1234F", incident["masked_preview"])
        self.assertNotIn(raw_sample, incident["masked_preview"])
        self.assertEqual(incident["recommended_action"], scan["recommended_action"])

        policy_response = self.client.put(
            "/api/policies/email",
            headers=headers,
            json={"action": "block", "weight": 40, "enabled": True},
        )
        self.assertEqual(policy_response.status_code, 200, policy_response.text)
        email_scan = self.client.post(
            "/api/scans",
            headers=headers,
            json={
                "text": "Synthetic contact analyst@example.test.",
                "source": "Synthetic test",
                "destination": "Unapproved partner",
                "destination_authorized": False,
                "context": "partner",
            },
        )
        self.assertEqual(email_scan.status_code, 200, email_scan.text)
        self.assertEqual(email_scan.json()["decision"], "block")

        analytics = self.client.get("/api/analytics", headers=headers).json()
        self.assertEqual(analytics["total_scans"], 9)
        self.assertEqual(analytics["incidents"], 8)
        self.assertEqual(analytics["blocked"], 5)

    def test_review_decision_creates_incident_and_analytics_count(self):
        token = self.login()
        headers = {"Authorization": f"Bearer {token}"}
        response = self.client.post(
            "/api/scans",
            headers=headers,
            json={
                "text": "Please share this synthetic report publicly.",
                "source": "Synthetic review test",
                "destination": "Public demo",
                "destination_authorized": False,
                "context": "public",
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["decision"], "review")
        self.assertIsNotNone(result["incident_id"])
        self.assertIn("reviewer", result["recommended_action"])
        incident = next(
            item
            for item in self.client.get("/api/incidents", headers=headers).json()
            if item["id"] == result["incident_id"]
        )
        self.assertNotIn(
            "Please share this synthetic report publicly.",
            incident["masked_preview"],
        )
        self.assertEqual(
            self.client.get("/api/analytics", headers=headers).json()["reviewed"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
