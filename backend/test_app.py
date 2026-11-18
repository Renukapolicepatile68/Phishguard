import csv
import io
import sqlite3
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

with patch.dict("os.environ", {"DATABASE_URL": ""}):
    import app as application
    import database
    import migrate_sqlite_to_postgres as migration


class PhishGuardApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.original_database_path = database.DB_PATH
        database.DB_PATH = Path(self.temporary_directory.name) / "test.sqlite"
        database.init_db()
        application.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = application.app.test_client()
        self.csrf = ""

    def tearDown(self):
        database.DB_PATH = self.original_database_path
        self.temporary_directory.cleanup()

    def json_request(self, client, path, data=None, method="POST", csrf=None):
        headers = {"X-CSRF-Token": csrf} if csrf else {}
        return client.open(
            path,
            method=method,
            json=data,
            headers=headers,
        )

    def signup(self, client=None, email="person@example.com"):
        client = client or self.client
        response = self.json_request(
            client,
            "/api/signup",
            {"name": "Test Person", "email": email, "password": "secure-pass-123"},
        )
        self.assertEqual(response.status_code, 201, response.get_json())
        login = self.json_request(
            client,
            "/api/login",
            {"email": email, "password": "secure-pass-123"},
        )
        self.assertEqual(login.status_code, 200, login.get_json())
        return login.get_json()["user"]["csrf_token"]

    def test_frontend_and_pwa_files_are_served_without_exposing_backend_sources(self):
        response = self.client.get("/")
        try:
            self.assertIn(b"PhishGuard", response.data)
        finally:
            response.close()
        for path in (
            "/index.html",
            "/signup.html",
            "/forgot-password.html",
            "/reset-password.html",
            "/dashboard.html",
            "/manifest.webmanifest",
            "/sw.js",
            "/js/config.js",
            "/css/style.css",
            "/assets/app-icon-192.png",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                try:
                    self.assertEqual(response.status_code, 200)
                finally:
                    response.close()
        self.assertEqual(self.client.get("/backend/app.py").status_code, 404)

    def test_authentication_validation_and_password_hashing(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        invalid = self.json_request(
            self.client, "/api/signup",
            {"name": "A", "email": "not-an-email", "password": "short"},
        )
        self.assertEqual(invalid.status_code, 400)
        self.csrf = self.signup()
        self.assertEqual(self.client.get("/api/me").get_json()["user"]["email"], "person@example.com")
        duplicate = self.json_request(
            self.client, "/api/signup",
            {"name": "Test Person", "email": "person@example.com", "password": "secure-pass-123"},
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(self.json_request(self.client, "/api/logout", csrf="wrong").status_code, 403)
        self.assertEqual(self.json_request(self.client, "/api/logout", csrf=self.csrf).status_code, 200)
        bad_login = self.json_request(
            self.client, "/api/login",
            {"email": "person@example.com", "password": "incorrect"},
        )
        self.assertEqual(bad_login.status_code, 401)

    def test_signup_requires_manual_login_and_logout_clears_session(self):
        response = self.json_request(
            self.client,
            "/api/signup",
            {"name": "Test Person", "email": "manual@example.com", "password": "secure-pass-123"},
        )
        self.assertEqual(response.status_code, 201, response.get_json())
        self.assertEqual(
            response.get_json()["message"],
            "Account created successfully. Please log in.",
        )
        self.assertNotIn("Set-Cookie", response.headers)
        self.assertEqual(self.client.get("/api/me").status_code, 401)

        invalid_login = self.json_request(
            self.client,
            "/api/login",
            {"email": "manual@example.com", "password": "incorrect"},
        )
        self.assertEqual(invalid_login.status_code, 401)
        self.assertEqual(self.client.get("/api/me").status_code, 401)

        login = self.json_request(
            self.client,
            "/api/login",
            {"email": "manual@example.com", "password": "secure-pass-123"},
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(self.client.get("/api/me").status_code, 200)
        csrf = login.get_json()["user"]["csrf_token"]
        logout = self.json_request(self.client, "/api/logout", csrf=csrf)
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(self.client.get("/api/me").status_code, 401)

    def test_scan_history_analytics_and_owner_scoped_crud(self):
        self.csrf = self.signup()
        no_csrf = self.json_request(self.client, "/api/scan", {"url": "example.com"})
        self.assertEqual(no_csrf.status_code, 403)
        scan = self.json_request(
            self.client, "/api/scan", {"url": "http://192.168.1.1/verify-login-account-password"},
            csrf=self.csrf,
        )
        self.assertEqual(scan.status_code, 201, scan.get_json())
        record = scan.get_json()
        self.assertEqual(record["result"], "malicious")
        self.assertTrue(record["signals"])
        listed = self.client.get("/api/history?result=malicious&q=verify")
        self.assertEqual(listed.get_json()["total"], 1)
        detail = self.client.get(f"/api/history/{record['id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.get_json()["scan"]["url"], record["url"])
        analytics = self.client.get("/api/analytics?days=30").get_json()
        self.assertEqual(analytics["summary"]["total"], 1)
        self.assertEqual(len(analytics["activity"]), 30)

        other_client = application.app.test_client()
        self.signup(other_client, "other@example.com")
        self.assertEqual(other_client.get(f"/api/history/{record['id']}").status_code, 404)
        self.assertEqual(other_client.get("/api/history").get_json()["total"], 0)
        self.assertEqual(
            self.json_request(self.client, f"/api/history/{record['id']}", method="DELETE", csrf=self.csrf).status_code,
            200,
        )
        self.assertEqual(self.client.get("/api/history").get_json()["total"], 0)
        self.json_request(
            self.client, "/api/scan", {"url": "https://example.com"}, csrf=self.csrf,
        )
        self.assertEqual(self.json_request(
            self.client, "/api/history", method="DELETE", csrf=self.csrf,
        ).status_code, 200)
        self.assertEqual(self.client.get("/api/history").get_json()["total"], 0)

    def test_legacy_scan_labels_migrate_without_changing_new_results(self):
        self.csrf = self.signup()
        with database.get_db() as db:
            user_id = db.execute("SELECT id FROM users WHERE email = ?", ("person@example.com",)).fetchone()["id"]
            db.executemany(
                "INSERT INTO scans (user_id, url, result, risk_score) VALUES (?, ?, ?, ?)",
                [
                    (user_id, "https://safe-old.example", "likely_legitimate", 10),
                    (user_id, "https://phishing-old.example", "suspicious", 45),
                    (user_id, "https://malicious-old.example", "phishing", 90),
                ],
            )

        database.init_db()
        self.json_request(
            self.client, "/api/scan", {"url": "http://verify-login-account.example.test"},
            csrf=self.csrf,
        )
        database.init_db()
        with database.get_db() as db:
            results = {
                row["url"]: row["result"]
                for row in db.execute("SELECT url, result FROM scans")
            }
        self.assertEqual(results, {
            "https://safe-old.example": "safe",
            "https://phishing-old.example": "phishing",
            "https://malicious-old.example": "malicious",
            "http://verify-login-account.example.test": "phishing",
        })

    def test_scanner_rejects_non_web_schemes_and_malformed_hosts(self):
        self.csrf = self.signup()
        for value in ("ftp://example.com/file", "javascript:alert(1)", "https://not a host/"):
            response = self.json_request(
                self.client, "/api/scan", {"url": value}, csrf=self.csrf,
            )
            self.assertEqual(response.status_code, 400, value)
        self.assertEqual(self.client.get("/api/history").get_json()["total"], 0)

    def test_settings_control_history_and_alerts(self):
        self.csrf = self.signup()
        preferences = {"store_history": False, "critical_alerts": False}
        saved = self.json_request(
            self.client, "/api/settings", preferences, method="PUT", csrf=self.csrf,
        )
        self.assertEqual(saved.get_json()["settings"], preferences)
        scan = self.json_request(
            self.client, "/api/scan", {"url": "http://verify-login.example.test"},
            csrf=self.csrf,
        )
        self.assertEqual(scan.status_code, 201)
        self.assertIsNone(scan.get_json()["id"])
        self.assertEqual(self.client.get("/api/history").get_json()["total"], 0)
        self.assertEqual(self.client.get("/api/analytics").get_json()["recent_threats"], [])
        enabled_history = {"store_history": True, "critical_alerts": False}
        self.json_request(
            self.client, "/api/settings", enabled_history, method="PUT", csrf=self.csrf,
        )
        self.json_request(
            self.client, "/api/scan",
            {"url": "http://192.168.1.1/verify-login-account-password"},
            csrf=self.csrf,
        )
        self.assertEqual(self.client.get("/api/analytics").get_json()["recent_threats"], [])
        self.json_request(
            self.client, "/api/settings", {"store_history": True, "critical_alerts": True},
            method="PUT", csrf=self.csrf,
        )
        self.assertEqual(len(self.client.get("/api/analytics").get_json()["recent_threats"]), 1)
        self.assertEqual(
            self.client.get("/api/settings").get_json()["settings"],
            {"store_history": True, "critical_alerts": True},
        )
        self.assertEqual(
            self.json_request(self.client, "/api/settings", {"store_history": 1}, method="PUT", csrf=self.csrf).status_code,
            400,
        )

    def test_bulk_csv_is_validated_and_results_are_saved(self):
        self.csrf = self.signup()
        upload = {"file": (io.BytesIO(
            b"url\nhttps://example.com\nhttp://verify-login-account.example.test\n"
            b"http://192.168.1.1/verify-login-account-password\n"
        ), "urls.csv")}
        response = self.client.post(
            "/api/bulk-scan", data=upload, headers={"X-CSRF-Token": self.csrf},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201, response.get_json())
        results = response.get_json()
        self.assertEqual(results["total"], 3)
        self.assertEqual(results["counts"], {"safe": 1, "phishing": 1, "malicious": 1})
        self.assertEqual(
            [scan["classification"] for scan in results["scans"]],
            ["Safe", "Phishing", "Malicious"],
        )
        self.assertTrue(all("url" in scan and "risk_score" in scan for scan in results["scans"]))
        self.assertEqual(self.client.get("/api/history").get_json()["total"], 3)
        analytics = self.client.get("/api/analytics").get_json()["summary"]
        self.assertEqual(
            {key: analytics[key] for key in ("safe", "phishing", "malicious")},
            results["counts"],
        )
        for threat_type in ("safe", "phishing", "malicious"):
            self.assertEqual(
                self.client.get(f"/api/history?result={threat_type}").get_json()["total"],
                1,
            )
        invalid = {"file": (io.BytesIO(b"not a url\nhttps://example.com\n"), "bad.csv")}
        response = self.client.post(
            "/api/bulk-scan", data=invalid, headers={"X-CSRF-Token": self.csrf},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.get("/api/history").get_json()["total"], 3)

    def test_reports_and_csv_contain_real_account_data(self):
        self.csrf = self.signup()
        self.json_request(
            self.client, "/api/scan", {"url": "https://example.com"}, csrf=self.csrf,
        )
        for report_type in ("url", "threat", "model"):
            report = self.client.get(f"/api/reports/{report_type}.pdf")
            self.assertEqual(report.status_code, 200)
            self.assertEqual(report.mimetype, "application/pdf")
            self.assertTrue(report.data.startswith(b"%PDF"))
        csv_export = self.client.get("/api/history/export.csv")
        self.assertEqual(csv_export.status_code, 200)
        rows = list(csv.reader(io.StringIO(csv_export.data.decode("utf-8-sig"))))
        self.assertEqual(rows[0][:3], ["URL", "Threat type", "Risk score"])
        self.assertEqual(rows[1][0], "https://example.com")
        self.assertEqual(self.client.get("/api/reports/unknown.pdf").status_code, 404)

    def test_email_password_reset_is_single_use_and_revokes_old_sessions(self):
        self.csrf = self.signup()
        captured = {}

        def capture_email(email, token):
            captured.update(email=email, token=token)

        with patch.object(application, "send_reset_email", side_effect=capture_email), \
                patch.dict("os.environ", {"PHISHGUARD_SMTP_HOST": "smtp.example.com", "PHISHGUARD_SMTP_FROM": "noreply@example.com"}):
            response = self.json_request(
                self.client, "/api/forgot-password", {"email": "person@example.com"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", captured)
        reset = self.json_request(
            self.client, "/api/reset-password",
            {"token": captured["token"], "password": "new-secure-pass-456"},
        )
        self.assertEqual(reset.status_code, 200)
        self.assertEqual(self.client.get("/api/me").status_code, 401)
        self.assertEqual(self.json_request(
            self.client, "/api/reset-password",
            {"token": captured["token"], "password": "another-pass-123"},
        ).status_code, 400)
        login = self.json_request(
            self.client, "/api/login",
            {"email": "person@example.com", "password": "new-secure-pass-456"},
        )
        self.assertEqual(login.status_code, 200)

    def test_password_reset_requires_mail_delivery_configuration(self):
        self.signup()
        with patch.dict("os.environ", {"PHISHGUARD_SMTP_HOST": "", "PHISHGUARD_SMTP_FROM": ""}):
            response = self.json_request(
                self.client, "/api/forgot-password", {"email": "person@example.com"},
            )
        self.assertEqual(response.status_code, 503)
        self.assertIn("SMTP", response.get_json()["error"])

    def test_profile_update_and_account_deletion(self):
        self.csrf = self.signup()
        update = self.json_request(
            self.client, "/api/profile",
            {"name": "Updated Person", "email": "updated@example.com", "current_password": "secure-pass-123"},
            method="PUT", csrf=self.csrf,
        )
        self.assertEqual(update.status_code, 200)
        self.assertEqual(self.client.get("/api/me").get_json()["user"]["name"], "Updated Person")
        deleted = self.json_request(
            self.client, "/api/me", {"password": "secure-pass-123"},
            method="DELETE", csrf=self.csrf,
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.client.get("/api/me").status_code, 401)

    def test_sqlite_migration_preserves_scan_data_and_normalizes_legacy_labels(self):
        source = sqlite3.connect(":memory:")
        source.row_factory = sqlite3.Row
        source.execute("""
            CREATE TABLE scans (
                id INTEGER, user_id INTEGER, url TEXT, result TEXT, risk_score INTEGER,
                created_at TEXT, signals_json TEXT
            )
        """)
        source.execute(
            "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
            (7, 3, "https://legacy.example", "suspicious", 45,
             "2024-01-02 03:04:05", '["legacy signal"]'),
        )
        row = source.execute("SELECT * FROM scans").fetchone()
        values = migration.row_values("scans", row)
        source.close()

        self.assertEqual(values["id"], 7)
        self.assertEqual(values["result"], "phishing")
        self.assertEqual(values["created_at"], datetime(2024, 1, 2, 3, 4, 5))
        self.assertEqual(values["signals_json"], '["legacy signal"]')

    def test_sqlite_migration_requires_database_url_before_creating_backup(self):
        source_path = Path(self.temporary_directory.name) / "source.sqlite"
        source = sqlite3.connect(source_path)
        try:
            source.execute("CREATE TABLE users (id INTEGER)")
        finally:
            source.close()
        with patch.object(migration, "DATABASE_URL", ""):
            with self.assertRaisesRegex(RuntimeError, "DATABASE_URL"):
                migration.migrate(source_path)
        self.assertEqual(list(source_path.parent.glob("*.pre-postgres-*.sqlite")), [])


if __name__ == "__main__":
    unittest.main()
