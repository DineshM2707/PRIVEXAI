import unittest
from unittest.mock import patch

from app.config import _cookie_secure_from_environment, normalize_database_url


class DatabaseUrlTests(unittest.TestCase):
    def test_normalizes_render_postgres_url_for_psycopg_three(self):
        self.assertEqual(
            normalize_database_url("postgres://user:password@host/database"),
            "postgresql+psycopg://user:password@host/database",
        )
        self.assertEqual(
            normalize_database_url("postgresql://user:password@host/database"),
            "postgresql+psycopg://user:password@host/database",
        )

    def test_preserves_other_database_urls(self):
        sqlite_url = "sqlite:///./datashield-local.db"
        psycopg_url = "postgresql+psycopg://user:password@host/database"
        self.assertEqual(normalize_database_url(sqlite_url), sqlite_url)
        self.assertEqual(normalize_database_url(psycopg_url), psycopg_url)


class CookieSecurityConfigTests(unittest.TestCase):
    def test_https_origins_enable_secure_cookies_by_default(self):
        with patch.dict(
            "os.environ",
            {"CORS_ORIGINS": "https://privexai-frontend.onrender.com"},
            clear=True,
        ):
            self.assertTrue(_cookie_secure_from_environment())

    def test_http_origins_keep_local_development_cookies_usable(self):
        with patch.dict(
            "os.environ",
            {"CORS_ORIGINS": "http://localhost:5173,http://localhost:3000"},
            clear=True,
        ):
            self.assertFalse(_cookie_secure_from_environment())

    def test_explicit_cookie_security_setting_takes_precedence(self):
        with patch.dict(
            "os.environ",
            {
                "COOKIE_SECURE": "false",
                "CORS_ORIGINS": "https://privexai-frontend.onrender.com",
            },
            clear=True,
        ):
            self.assertFalse(_cookie_secure_from_environment())


if __name__ == "__main__":
    unittest.main()
