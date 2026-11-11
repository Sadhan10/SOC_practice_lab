"""Certificate eligibility, preview, ownership and permanent issuance checks."""

import hashlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfWriter

from app import create_app
from certificate_generator import CertificateGenerationError
from database import get_db
from routes.final_soc_challenge import CASE_ID, QUESTIONS
from routes.soc_certificates import DRAFT_KEY, initialize_certificates


PAGE = "/soc/final/certificate"


def sample_pdf(pages=1, landscape=True):
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=792 if landscape else 612, height=612 if landscape else 792)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


class CertificateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="soc-certificates-test-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.config = {
            "TESTING": True, "SECRET_KEY": "certificate-test-key",
            "DATABASE_DIR": str(self.root), "DATABASE_PATH": str(self.root / "test.db"),
            "SOC_FEATURE_DATABASE_PATH": str(self.root / "features.db"),
            "LOG_DIR": str(self.root), "LOG_FILE": str(self.root / "test.log"),
        }
        self.app = create_app(self.config)
        self.addCleanup(self.close_logging)
        self.create_profile()
        self.client = self.app.test_client()
        self.login(self.client)
        self.pdf = sample_pdf()
        self.converter = patch("routes.soc_certificates.generate_certificate_pdf", return_value=self.pdf)
        self.generate = self.converter.start()
        self.addCleanup(self.converter.stop)

    def create_profile(self, username="analyst", full_name="Ada Lovelace"):
        with self.app.app_context():
            db = get_db()
            db.execute("INSERT OR IGNORE INTO users(username,password,role) VALUES (?, 'fixture', 'student')", (username,))
            db.execute("INSERT INTO student_profiles(username,full_name,created_at) VALUES (?, ?, '2026-11-07')",
                       (username, full_name))
            db.commit()

    def close_logging(self):
        for handler in list(self.app.logger.handlers):
            if getattr(handler, "baseFilename", "").startswith(str(self.root)):
                self.app.logger.removeHandler(handler)
                handler.close()

    def login(self, client, username="analyst"):
        with client.session_transaction() as state:
            state.clear()
            state.update(logged_in=True, username=username)

    def token(self, client=None):
        client = client or self.client
        client.get(PAGE)
        with client.session_transaction() as state:
            return state["operations_csrf"]

    def attempt(self, score=74, *, username="analyst", passed=1, percentage=None):
        with self.app.app_context():
            db = get_db()
            cursor = db.execute("""
                INSERT INTO final_soc_attempts
                    (username, case_id, answers_json, feedback_json, score, percentage, passed, submitted_at)
                VALUES (?, ?, '{}', '[]', ?, ?, ?, '2026-11-07T00:00:00+00:00')
            """, (username, CASE_ID, score, score if percentage is None else percentage, passed))
            db.commit()
            return cursor.lastrowid

    def rows(self):
        with self.app.app_context():
            return [dict(row) for row in get_db().execute("SELECT * FROM soc_certificates ORDER BY id")]

    def preview(self, name="Ada Lovelace", client=None, **extra):
        client = client or self.client
        return client.post(PAGE + "/preview", data={
            "csrf_token": self.token(client), "student_name": name, **extra,
        })

    def issue(self, client=None, **extra):
        client = client or self.client
        with client.session_transaction() as state:
            data = {"csrf_token": state["operations_csrf"],
                    "preview_token": state.get(DRAFT_KEY, {}).get("token", "")}
        return client.post(PAGE + "/issue", data={**data, **extra})

    def test_all_routes_require_login_and_username(self):
        for state in ({}, {"logged_in": True}, {"username": "analyst", "logged_in": False}):
            client = self.app.test_client()
            with client.session_transaction() as session:
                session.update(state)
            for route in (PAGE, PAGE + "/download"):
                self.assertEqual(client.get(route).status_code, 302)
            for route in (PAGE + "/preview", PAGE + "/issue"):
                self.assertEqual(client.post(route).status_code, 302)
        self.assertEqual(self.rows(), [])

    def test_locked_student_cannot_supply_their_own_marks(self):
        self.attempt(69)
        self.attempt(100, username="other")
        self.assertIn(b"Certificate Locked", self.client.get(PAGE).data)
        self.assertEqual(self.preview(score="100", passed="1").status_code, 403)
        self.assertEqual(self.client.get(PAGE + "/download").status_code, 404)
        self.assertEqual(self.rows(), [])
        self.generate.assert_not_called()

    def test_exact_70_is_eligible_but_saved_pass_and_percentage_are_required(self):
        self.attempt(100, passed=0)
        self.attempt(100, percentage=69)
        self.assertIn(b"Certificate Locked", self.client.get(PAGE).data)
        self.attempt(70)
        self.assertEqual(self.preview().status_code, 200)
        self.assertEqual(self.issue().status_code, 302)
        self.assertEqual(self.rows()[0]["score"], 70)

    def test_preview_then_issue_uses_only_verified_details(self):
        attempt_id = self.attempt(74)
        preview = self.preview("Another Person", score="100", certificate_id="FORGED")
        self.assertIn(b"Preview Certificate Details", preview.data)
        self.assertIn(b"Ada Lovelace", preview.data)
        self.assertEqual(self.rows(), [])
        self.generate.assert_not_called()
        response = self.issue(student_name="Changed Name", score="100", attempt_id="999")
        self.assertEqual(response.status_code, 302)
        saved = self.rows()[0]
        self.assertEqual((saved["student_name"], saved["score"], saved["source_attempt_id"]),
                         ("Ada Lovelace", 74, attempt_id))
        self.assertEqual(saved["pdf_sha256"], hashlib.sha256(self.pdf).hexdigest())
        self.assertEqual(self.generate.call_args.kwargs["score"], "74/100")
        self.assertEqual(self.generate.call_args.kwargs["certificate_id"], saved["certificate_id"])
        self.assertIn(b"Certificate Issued", self.client.get(PAGE).data)

    def test_csrf_and_preview_confirmation_are_required(self):
        self.attempt()
        self.token()
        self.assertEqual(self.issue().status_code, 400)
        for token in ("", "wrong", "x" * 129, "\u2603"):
            self.assertEqual(self.client.post(PAGE + "/preview", data={
                "student_name": "Ada", "csrf_token": token,
            }).status_code, 403)
        self.preview()
        self.assertEqual(self.issue(csrf_token="wrong").status_code, 403)
        self.assertEqual(self.issue(preview_token="wrong").status_code, 400)
        self.assertEqual(self.rows(), [])

    def test_stored_name_validation_and_unicode_support(self):
        self.attempt()
        for name in ("Ada\nLovelace", "Ada\x00Name", "<script>", "1234"):
            with self.subTest(name=name):
                with self.app.app_context():
                    db = get_db()
                    db.execute("UPDATE student_profiles SET full_name=? WHERE username='analyst'", (name,))
                    db.commit()
                self.assertEqual(self.preview("Valid Forged Name").status_code, 400)
        with self.app.app_context():
            db = get_db()
            db.execute("UPDATE student_profiles SET full_name=? WHERE username='analyst'", ("Zo\u00eb O\u2019Connor-\u674e",))
            db.commit()
        self.assertEqual(self.preview("Another Person").status_code, 200)
        self.assertEqual(self.issue().status_code, 302)
        self.assertEqual(self.rows()[0]["student_name"], "Zo\u00eb O\u2019Connor-\u674e")

    def test_highest_passing_attempt_is_selected_and_preview_is_stable_on_retake(self):
        best_id = self.attempt(90)
        self.attempt(74)
        self.attempt(0, passed=0)
        self.preview()
        self.attempt(100)
        self.issue()
        self.assertEqual((self.rows()[0]["score"], self.rows()[0]["source_attempt_id"]), (90, best_id))

    def test_certificate_is_immutable_across_retries_retakes_and_restarts(self):
        self.attempt()
        self.preview()
        self.issue()
        original = self.rows()
        self.attempt(100)
        self.preview("New Name")
        self.issue()
        self.assertEqual(self.rows(), original)
        self.assertEqual(self.generate.call_count, 1)
        recreated = create_app(self.config)
        client = recreated.test_client()
        self.login(client)
        download = client.get(PAGE + "/download")
        self.assertEqual(download.data, self.pdf)
        self.assertEqual(download.mimetype, "application/pdf")
        self.assertIn(original[0]["certificate_id"], download.headers["Content-Disposition"])
        self.assertIn("no-store", download.headers["Cache-Control"])

    def test_ownership_is_scoped_to_current_account(self):
        self.attempt()
        self.preview()
        self.issue()
        other = self.app.test_client()
        self.login(other, "other")
        self.assertIn(b"Certificate Locked", other.get(PAGE).data)
        self.assertEqual(other.get(PAGE + "/download?username=analyst").status_code, 404)
        self.attempt(100, username="other")
        self.create_profile("other", "Other Student")
        self.preview("Other Student", client=other)
        self.assertEqual(self.issue(other).status_code, 302)
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0]["certificate_id"], rows[1]["certificate_id"])

    def test_conversion_failure_does_not_issue_and_can_be_retried(self):
        self.attempt()
        self.preview()
        self.generate.side_effect = CertificateGenerationError("missing converter")
        self.assertEqual(self.issue().status_code, 503)
        self.assertEqual(self.rows(), [])
        self.generate.side_effect = None
        self.assertEqual(self.issue().status_code, 302)

    def test_invalid_multpage_and_portrait_pdfs_are_never_saved(self):
        self.attempt()
        self.preview()
        for pdf in (b"invalid", sample_pdf(pages=2), sample_pdf(landscape=False)):
            self.generate.return_value = pdf
            self.assertEqual(self.issue().status_code, 503)
            self.assertEqual(self.rows(), [])

    def test_previewed_attempt_is_rechecked_before_and_after_conversion(self):
        attempt_id = self.attempt(74)
        self.preview()
        with self.app.app_context():
            db = get_db()
            db.execute("UPDATE final_soc_attempts SET score=90, percentage=90 WHERE id=?", (attempt_id,))
            db.commit()
        self.assertEqual(self.issue().status_code, 403)
        self.generate.assert_not_called()
        self.preview()
        def revoke_during_conversion(**kwargs):
            db = get_db()
            db.execute("UPDATE final_soc_attempts SET passed=0 WHERE id=?", (attempt_id,))
            db.commit()
            return self.pdf
        self.generate.side_effect = revoke_during_conversion
        self.assertEqual(self.issue().status_code, 403)
        self.assertEqual(self.rows(), [])

    def test_duplicate_insertion_keeps_first_issued_pdf(self):
        attempt_id = self.attempt()
        self.preview()
        winner_pdf = sample_pdf()
        def simultaneous_issuance(**kwargs):
            db = get_db()
            db.execute("""
                INSERT INTO soc_certificates
                    (certificate_id, username, course_key, course_name, student_name, score,
                     source_attempt_id, issued_at, pdf_blob, pdf_sha256)
                VALUES ('OBF-WINNER', 'analyst', 'final_soc', 'SOC', 'First Request', 74, ?, 'Today', ?, ?)
            """, (attempt_id, winner_pdf, hashlib.sha256(winner_pdf).hexdigest()))
            db.commit()
            return self.pdf
        self.generate.side_effect = simultaneous_issuance
        self.assertEqual(self.issue().status_code, 302)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0]["certificate_id"], "OBF-WINNER")
        self.assertEqual(self.client.get(PAGE + "/download").data, winner_pdf)

    def test_real_assessment_links_to_certificate_and_initialization_is_idempotent(self):
        data = {question["id"]: question["answer"] for question in QUESTIONS}
        data["csrf_token"] = self.token()
        response = self.client.post("/soc/final/submit", data=data)
        result = self.client.get(response.location)
        self.assertIn(b"View / Generate Certificate", result.data)
        self.preview()
        self.issue()
        original = self.rows()
        with self.app.app_context():
            initialize_certificates(get_db())
        self.assertEqual(self.rows(), original)

    def test_legacy_account_requires_profile_but_issued_pdf_remains_available(self):
        self.attempt()
        with self.app.app_context():
            db = get_db()
            db.execute("DELETE FROM student_profiles WHERE username='analyst'")
            db.commit()
        self.assertIn(b"student profile is not configured", self.client.get(PAGE).data)
        self.assertEqual(self.preview().status_code, 403)
        self.create_profile()
        self.preview()
        self.issue()
        saved = self.rows()
        with self.app.app_context():
            db = get_db()
            db.execute("DELETE FROM student_profiles WHERE username='analyst'")
            db.commit()
        self.assertEqual(self.client.get(PAGE + "/download").data, self.pdf)
        self.assertIn(b"Certificate Issued", self.client.get(PAGE).data)
        self.assertEqual(self.rows(), saved)

    def test_profile_identity_is_locked_atomically_after_issuance(self):
        self.attempt()
        self.preview()
        self.issue(student_name="Forged Name")
        with self.app.app_context():
            db = get_db()
            self.assertEqual(db.execute("SELECT name_locked FROM student_profiles").fetchone()[0], 1)
            for statement in (
                "UPDATE student_profiles SET full_name='New Name'",
                "UPDATE student_profiles SET username='other'",
                "UPDATE student_profiles SET name_locked=0",
            ):
                with self.assertRaises(sqlite3.IntegrityError), db:
                    db.execute(statement)
        self.assertEqual(self.rows()[0]["student_name"], "Ada Lovelace")

    def test_profile_changes_are_rechecked_before_and_after_conversion(self):
        self.attempt()
        self.preview()
        with self.app.app_context():
            db = get_db()
            db.execute("UPDATE student_profiles SET full_name='Updated Name' WHERE username='analyst'")
            db.commit()
        self.assertEqual(self.issue().status_code, 403)
        self.generate.assert_not_called()
        self.preview()
        def change_during_conversion(**kwargs):
            db = get_db()
            db.execute("UPDATE student_profiles SET full_name='Changed During Conversion' WHERE username='analyst'")
            db.commit()
            return self.pdf
        self.generate.side_effect = change_during_conversion
        self.assertEqual(self.issue().status_code, 403)
        self.assertEqual(self.rows(), [])


if __name__ == "__main__":
    unittest.main()
