"""Enrollment, identity, password compatibility and guessing-limit checks."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.datastructures import MultiDict
from werkzeug.security import check_password_hash, generate_password_hash

from app import create_app
from database import get_db
from models import get_level_progress, mark_completed
from routes.student_registration import initialize_student_profiles


class StudentRegistrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="student-registration-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = {
            "TESTING": True, "SECRET_KEY": "student-registration-test-secret",
            "STUDENT_REGISTRATION_ENABLED": True,
            "REGISTRATION_RATE_LIMIT": 200,
            "DATABASE_DIR": str(self.root), "DATABASE_PATH": str(self.root / "main.db"),
            "SOC_FEATURE_DATABASE_PATH": str(self.root / "features.db"),
            "LOG_DIR": str(self.root), "LOG_FILE": str(self.root / "test.log"),
        }
        self.app = create_app(self.config)
        self.addCleanup(self.close_logging)
        self.client = self.app.test_client()
        self.password = "A private student password 123!"

    def close_logging(self):
        for handler in list(self.app.logger.handlers):
            if getattr(handler, "baseFilename", "").startswith(str(self.root)):
                self.app.logger.removeHandler(handler)
                handler.close()

    def fields(self, client=None, **changes):
        client = client or self.client
        client.get("/register")
        with client.session_transaction() as state:
            token = state["operations_csrf"]
        return {
            "csrf_token": token, "full_name": "Alice Student", "username": "alice.student",
            "password": self.password, "confirm_password": self.password,
            "usn": "", **changes,
        }

    def register(self, client=None, **changes):
        client = client or self.client
        return client.post("/register", data=self.fields(client, **changes))

    def rows(self, table):
        with self.app.app_context():
            return [dict(row) for row in get_db().execute("SELECT * FROM " + table + " ORDER BY 1")]

    def login(self, username="alice.student", client=None, password=None, **kwargs):
        return (client or self.client).post(
            "/login", data={"username": username, "password": password or self.password}, **kwargs,
        )

    def test_registration_requires_instructor_toggle(self):
        for enabled in (False, None, "false", "1"):
            self.app.config["STUDENT_REGISTRATION_ENABLED"] = enabled
            for path in ("/register", "/student/register"):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 503)
                self.assertNotIn(b'<form', response.data)
                self.assertEqual(self.client.post(path, data=self.fields()).status_code, 503)
        self.assertEqual(self.rows("student_profiles"), [])
        self.assertEqual(len(self.rows("users")), 1)

    def test_registration_creates_hashed_student_and_profile_atomically(self):
        with self.client.session_transaction() as state:
            state["stale_identity"] = "must be cleared"
        response = self.register(full_name="  Alice   Student  ", role="admin", name_locked="1")
        self.assertTrue(response.location.endswith("/login"))
        student = next(row for row in self.rows("users") if row["username"] == "alice.student")
        self.assertEqual(student["role"], "student")
        self.assertNotEqual(student["password"], self.password)
        self.assertTrue(check_password_hash(student["password"], self.password))
        profile = self.rows("student_profiles")[0]
        self.assertEqual(profile["full_name"], "Alice Student")
        self.assertIsNone(profile["usn"])
        self.assertEqual(profile["name_locked"], 0)
        with self.client.session_transaction() as state:
            self.assertNotIn("stale_identity", state)
            self.assertNotIn("logged_in", state)
        self.assertEqual(self.login().status_code, 302)
        with self.client.session_transaction() as state:
            self.assertEqual((state["username"], state["role"]), ("alice.student", "student"))

    def test_optional_usn_is_normalized_and_shown_only_in_own_profile(self):
        self.assertEqual(self.register(usn="  1ab/2026-001  ").status_code, 302)
        self.assertEqual(self.rows("student_profiles")[0]["usn"], "1AB/2026-001")
        self.register(username="bob.student", full_name="Bob Student", usn="BOB-001")
        self.login()
        response = self.client.get("/profile?username=bob.student")
        self.assertIn(b"1AB/2026-001", response.data)
        self.assertNotIn(b"BOB-001", response.data)

    def test_usn_may_be_omitted_or_blank_and_alias_accepts_registration(self):
        fields = self.fields(username="omitted.student")
        fields.pop("usn")
        self.assertEqual(self.client.post("/student/register", data=fields).status_code, 302)
        self.assertEqual(self.register(username="blank.student", usn="  ").status_code, 302)
        self.assertTrue(all(row["usn"] is None for row in self.rows("student_profiles")))
        self.login("omitted.student")
        self.assertIn(b"Not provided", self.client.get("/profile").data)

    def test_invalid_usn_does_not_hash_password_or_create_accounts(self):
        for usn in ("AB", "A" * 33, "AB CD", "ABC_123", "/ABC", "\u2603ABC", "<script>"):
            with self.subTest(usn=usn), patch("routes.student_registration.generate_password_hash") as hashing:
                response = self.register(usn=usn)
                self.assertEqual(response.status_code, 400)
                self.assertNotIn(self.password.encode(), response.data)
                if usn == "<script>":
                    self.assertIn(b'value="&lt;script&gt;"', response.data)
                hashing.assert_not_called()
        self.assertEqual(self.rows("student_profiles"), [])
        self.assertEqual([row["username"] for row in self.rows("users")], ["analyst"])

    def test_usn_boundary_lengths_are_accepted(self):
        for index, length in enumerate((3, 32)):
            self.assertEqual(self.register(username=f"usn{index}", usn="A" * length).status_code, 302)

    def test_existing_profile_schema_migrates_without_changing_identity(self):
        with sqlite3.connect(":memory:") as db:
            db.row_factory = sqlite3.Row
            db.execute("CREATE TABLE users (username TEXT PRIMARY KEY)")
            db.execute("INSERT INTO users VALUES ('legacy.student')")
            db.execute("""CREATE TABLE student_profiles (
                username TEXT PRIMARY KEY REFERENCES users(username),
                full_name TEXT NOT NULL CHECK(length(full_name) BETWEEN 2 AND 100),
                created_at TEXT NOT NULL,
                name_locked INTEGER NOT NULL DEFAULT 0 CHECK(name_locked IN (0, 1)))""")
            db.execute("INSERT INTO student_profiles VALUES ('legacy.student', 'Legacy Student', '2026-01-01', 1)")
            for _ in range(2):
                initialize_student_profiles(db)
                self.assertEqual(dict(db.execute("SELECT * FROM student_profiles").fetchone()), {
                    "username": "legacy.student", "full_name": "Legacy Student",
                    "created_at": "2026-01-01", "name_locked": 1, "usn": None,
                })
                with self.assertRaisesRegex(sqlite3.IntegrityError, "identity is locked"):
                    db.execute("UPDATE student_profiles SET full_name='Changed Name'")
            self.assertEqual(len(db.execute("PRAGMA table_info(student_profiles)").fetchall()), 5)

    def test_duplicate_usernames_are_case_normalized_without_overwriting_identity(self):
        self.assertEqual(self.register().status_code, 302)
        original_users = self.rows("users")
        original_profiles = self.rows("student_profiles")
        response = self.register(username="ALICE.STUDENT", full_name="Another Person")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.rows("users"), original_users)
        self.assertEqual(self.rows("student_profiles"), original_profiles)

    def test_existing_legacy_user_cannot_be_claimed_through_registration(self):
        original = self.rows("users")
        self.assertEqual(self.register(username="analyst").status_code, 400)
        self.assertEqual(self.rows("users"), original)
        self.assertEqual(self.rows("student_profiles"), [])
        self.assertEqual(self.login("analyst", password="Analyst@123").status_code, 302)
        self.assertIn(b"Profile Not Available", self.client.get("/profile").data)

    def test_username_name_and_password_validation(self):
        for username in ("abc", "1alice", "alice name", "\u00e9tudiant", "a" * 33, "admin", "root", "alice<script>"):
            with self.subTest(username=username):
                self.assertEqual(self.register(username=username).status_code, 400)
        for name in ("", "A", "x" * 101, "Name\nOther", "Name\x00Other", "<script>", "1234"):
            with self.subTest(name=name):
                self.assertEqual(self.register(full_name=name).status_code, 400)
        for password, confirmation in (("x" * 14, "x" * 14), ("x" * 129, "x" * 129),
                                       (self.password, "different password")):
            self.assertEqual(self.register(password=password, confirm_password=confirmation).status_code, 400)
        self.assertEqual(self.rows("student_profiles"), [])
        self.assertEqual(self.register(full_name="Zo\u00eb O\u2019Connor-\u674e").status_code, 302)
        self.assertEqual(self.rows("student_profiles")[0]["full_name"], "Zo\u00eb O\u2019Connor-\u674e")

    def test_password_boundary_lengths_are_accepted(self):
        for index, length in enumerate((15, 128)):
            password = "P" * length
            self.assertEqual(self.register(username=f"boundary{index}", password=password,
                                           confirm_password=password).status_code, 302)

    def test_passphrases_and_password_whitespace_are_preserved(self):
        for index, password in enumerate(("quiet falcons cross the valley", "  quiet falcons cross the valley  ")):
            username = f"passphrase{index}"
            self.assertEqual(self.register(username=username, password=password, confirm_password=password).status_code, 302)
            user = next(row for row in self.rows("users") if row["username"] == username)
            self.assertTrue(check_password_hash(user["password"], password))
            if password != password.strip():
                self.assertFalse(check_password_hash(user["password"], password.strip()))
            client = self.app.test_client()
            self.assertEqual(self.login(username, client, password=password).status_code, 302)

    def test_common_passwords_and_whitespace_only_passwords_are_rejected(self):
        for password in ("passwordpassword", "PASSWORDPASSWORD1", "123456789012345", "correct horse battery staple", " " * 15):
            with self.subTest(password=password), patch("routes.student_registration.generate_password_hash") as hashing:
                response = self.register(password=password, confirm_password=password)
                self.assertEqual(response.status_code, 400)
                self.assertIn(b"less common password", response.data)
                if password.strip():
                    self.assertNotIn(password.encode(), response.data)
                hashing.assert_not_called()
        self.assertEqual(self.rows("student_profiles"), [])

    def test_csrf_and_duplicate_fields_cannot_create_accounts(self):
        for token in ("", "wrong", "\u2603", "x" * 129):
            self.assertEqual(self.register(csrf_token=token).status_code, 403)
        for field in ("username", "usn", "password", "full_name", "confirm_password"):
            data = MultiDict(self.fields())
            data.add(field, "another-value")
            self.assertEqual(self.client.post("/register", data=data).status_code, 400)
        self.assertEqual(self.rows("student_profiles"), [])

    def test_profiles_are_read_only_and_scoped_to_logged_in_student(self):
        self.assertEqual(self.client.get("/profile").status_code, 302)
        self.register()
        self.register(username="bob.student", full_name="Bob Student")
        self.login()
        response = self.client.get("/profile?username=bob.student")
        self.assertIn(b"Alice Student", response.data)
        self.assertNotIn(b"Bob Student", response.data)
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertEqual(self.client.post("/profile", data={"full_name": "Forged Name"}).status_code, 405)
        self.assertTrue(self.client.get("/register").location.endswith("/profile"))
        self.assertTrue(self.client.post("/register", data={}).location.endswith("/profile"))

    def test_profile_failure_rolls_back_user_insert(self):
        with self.app.app_context():
            db = get_db()
            db.execute("""CREATE TRIGGER fail_profile BEFORE INSERT ON student_profiles
                          BEGIN SELECT RAISE(ABORT, 'forced profile failure'); END""")
            db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.register()
        self.assertEqual(self.rows("student_profiles"), [])
        self.assertEqual([row["username"] for row in self.rows("users")], ["analyst"])

    def test_duplicate_created_during_hashing_is_handled_without_partial_profile(self):
        def racing_registration(password):
            db = get_db()
            db.execute("INSERT INTO users(username,password,role) VALUES ('alice.student','first-writer','student')")
            db.commit()
            return generate_password_hash(password)
        with patch("routes.student_registration.generate_password_hash", side_effect=racing_registration):
            self.assertEqual(self.register().status_code, 409)
        self.assertEqual(self.rows("student_profiles"), [])
        self.assertEqual(next(row for row in self.rows("users") if row["username"] == "alice.student")["password"], "first-writer")

    def test_registration_limit_survives_cookie_reset_restart_and_forwarded_headers(self):
        self.app.config["REGISTRATION_RATE_LIMIT"] = 2
        with patch("auth_limits.time.time", return_value=1000):
            self.assertEqual(self.register(usn="!!").status_code, 400)
            self.assertEqual(self.client.post("/student/register", data=self.fields(usn="!!")).status_code, 400)
            client = self.app.test_client()
            blocked = client.post("/register", data=self.fields(client), headers={"X-Forwarded-For": "192.0.2.77"})
            self.assertEqual(blocked.status_code, 429)
            self.assertEqual(blocked.headers["Retry-After"], "900")
            config = dict(self.config, REGISTRATION_RATE_LIMIT=2)
            recreated = create_app(config).test_client()
            self.assertEqual(self.register(recreated).status_code, 429)
        with patch("auth_limits.time.time", return_value=1901):
            self.assertEqual(self.register().status_code, 302)

    def test_login_limits_apply_per_username_across_addresses_and_per_ip(self):
        self.register()
        self.app.config.update(LOGIN_USERNAME_RATE_LIMIT=2, LOGIN_IP_RATE_LIMIT=20)
        with patch("auth_limits.time.time", return_value=1000):
            for address in ("192.0.2.1", "192.0.2.2"):
                self.assertEqual(self.login(password="wrong", environ_overrides={"REMOTE_ADDR": address}).status_code, 200)
            self.assertEqual(self.login(environ_overrides={"REMOTE_ADDR": "192.0.2.3"}).status_code, 429)
        with patch("auth_limits.time.time", return_value=1901):
            self.assertEqual(self.login().status_code, 302)
        client = self.app.test_client()
        self.app.config["LOGIN_IP_RATE_LIMIT"] = 2
        for username in ("unknown1", "unknown2"):
            self.assertEqual(self.login(username, client, password="wrong").status_code, 200)
        self.assertEqual(self.login("unknown3", client, headers={"X-Forwarded-For": "192.0.2.88"}).status_code, 429)

    def test_attempt_records_do_not_store_identifiers_or_credentials(self):
        self.register(usn="bad secret")
        self.login("private.username", password="private-password")
        records = repr(self.rows("auth_rate_limits"))
        for secret in ("127.0.0.1", "private.username", "bad secret", "private-password"):
            self.assertNotIn(secret, records)

    def test_registration_leaves_legacy_passwords_and_ctf_progress_unchanged(self):
        with self.app.app_context():
            mark_completed("analyst", "BF-2026-001")
        original_users = self.rows("users")
        original_progress = self.rows("progress")
        self.register()
        self.register(username="bob.student", full_name="Bob Student")
        self.assertEqual(self.rows("progress"), original_progress)
        self.assertEqual(next(row for row in self.rows("users") if row["username"] == "analyst"), original_users[0])
        with self.app.app_context():
            mark_completed("alice.student", "BF-2026-002")
            self.assertEqual(get_level_progress("alice.student", "beginner")["completed"], 1)
            self.assertEqual(get_level_progress("bob.student", "beginner")["completed"], 0)
        before = self.rows("student_profiles")
        create_app(self.config)
        self.assertEqual(self.rows("student_profiles"), before)

    def test_startup_preserves_a_rotated_analyst_password(self):
        # Only this test's disposable database is changed. The release utility
        # is deliberately not invoked during development or test discovery.
        self.register()
        rotated_password = "Disposable release-rotation test credential"
        with self.app.app_context():
            mark_completed("analyst", "BF-2026-001")
            mark_completed("alice.student", "BF-2026-002")
            db = get_db()
            db.execute("UPDATE users SET password=? WHERE username='analyst'",
                       (generate_password_hash(rotated_password),))
            db.commit()
        before = {table: self.rows(table) for table in ("users", "student_profiles", "progress")}
        recreated = create_app(self.config)
        for table, records in before.items():
            self.assertEqual(self.rows(table), records)
        client = recreated.test_client()
        self.assertEqual(self.login("analyst", client, password="Analyst@123").status_code, 200)
        self.assertEqual(self.login("analyst", client, password=rotated_password).status_code, 302)
        self.assertEqual(self.login().status_code, 302)


if __name__ == "__main__":
    unittest.main()
