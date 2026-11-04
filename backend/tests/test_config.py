import unittest

from app.config import normalize_database_url


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


if __name__ == "__main__":
    unittest.main()
