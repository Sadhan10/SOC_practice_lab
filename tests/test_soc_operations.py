import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import soc_features
from app import create_app
from database import get_db
from investigation_loader import load_investigation
from level_config import get_all_cases
from routes.soc_operations import ASSESSMENT_FIELDS, initialize_operations, score_assessment
from routes.assessment_scoring import MIN_REPORT_LENGTH, calculate_assessment_status
from models import mark_completed, mark_findings_validated
from solution_store import hash_answer


ROOT = Path(__file__).resolve().parents[1]


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="soc-operations-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        feature_patch = patch.object(soc_features, "feature_database_path", return_value=str(self.root / "features.db"))
        feature_patch.start()
        self.addCleanup(feature_patch.stop)
        self.config = {
            "TESTING": True, "SECRET_KEY": "operations-test",
            "DATABASE_DIR": str(self.root / "database"),
            "DATABASE_PATH": str(self.root / "database" / "test.db"),
            "LOG_DIR": str(self.root / "logs"), "LOG_FILE": str(self.root / "logs" / "test.log"),
            "SOLUTION_STORE_PATH": str(self.root / "solutions.json"),
        }
        self.app = create_app(self.config)
        self.addCleanup(self.close_logging)
        self.client = self.app.test_client()
        self.login()
        self.expected = {}
        store = {}
        with self.app.app_context():
            for case_id in get_all_cases():
                questions = load_investigation(case_id)["questions"]
                self.expected[case_id] = {question["field"]: f"accepted {case_id} {question['field']}" for question in questions}
                store[case_id] = {field: [hash_answer(answer), hash_answer(answer + " alternative")]
                                  for field, answer in self.expected[case_id].items()}
        (self.root / "solutions.json").write_text(json.dumps(store), encoding="utf-8")

    def close_logging(self):
        for handler in list(self.app.logger.handlers):
            if getattr(handler, "baseFilename", "").startswith(str(self.root)):
                self.app.logger.removeHandler(handler)
                handler.close()

    def login(self, username="analyst", client=None):
        with (client or self.client).session_transaction() as user_session:
            user_session.clear()
            user_session.update(logged_in=True, username=username, selected_level="medium")

    def token(self, client=None):
        client = client or self.client
        self.assertEqual(client.get("/soc/triage").status_code, 200)
        with client.session_transaction() as user_session:
            return user_session["operations_csrf"]

    def triage_data(self, client=None):
        return {"csrf_token": self.token(client), "severity": "High", "verdict": "True Positive",
                "status": "Investigating", "response": "Block malicious IP", "findings": "Evidence justifies response."}

    def report_data(self, case_id="BF-M-001", client=None):
        data = {field: f"Evidence-based {field}" for field in ASSESSMENT_FIELDS}
        data.update({"answer_" + field: answer for field, answer in self.expected[case_id].items()})
        data.update(csrf_token=self.token(client), action="submit")
        return data

    def saved_report(self, case_id="BF-M-001", username="analyst"):
        with self.app.app_context():
            row = get_db().execute("SELECT * FROM operations_assessments WHERE username=? AND case_id=?", (username, case_id)).fetchone()
            return dict(row) if row else None

    def test_all_operations_routes_require_authenticated_analyst(self):
        for path, method in (("/soc/triage", "get"), ("/soc/triage/BF-M-001", "post"),
                             ("/soc/assessment", "get"), ("/soc/assessment/BF-M-001", "get"),
                             ("/soc/assessment/BF-M-001", "post")):
            for invalid in (None, False, "true", 1):
                with self.client.session_transaction() as user_session:
                    user_session["logged_in"] = invalid
                response = getattr(self.client, method)(path)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response.location.endswith("/login"))
        with self.client.session_transaction() as user_session:
            user_session.clear()
            user_session["logged_in"] = True
        self.assertEqual(self.client.get("/soc/triage").status_code, 302)

    def test_all_cases_render_and_have_case_scoped_investigation_links(self):
        triage = self.client.get("/soc/triage").get_data(as_text=True)
        dashboard = self.client.get("/soc/assessment").get_data(as_text=True)
        for case_id in get_all_cases():
            self.assertIn(case_id, triage)
            self.assertIn(case_id, dashboard)
            form = self.client.get("/soc/assessment/" + case_id)
            self.assertEqual(form.status_code, 200)
            self.assertIn(("/siem?case=" + case_id).encode(), form.data)
            for field in self.expected[case_id]:
                self.assertIn(("answer_" + field).encode(), form.data)

    def test_triage_round_trip_update_and_analyst_isolation(self):
        data = self.triage_data()
        self.assertEqual(self.client.post("/soc/triage/BF-M-001", data=data).status_code, 302)
        data.update(status="Resolved", findings="Analyst-only finding", severity="Critical")
        self.client.post("/soc/triage/BF-M-001", data=data)
        other = self.app.test_client()
        self.login("another-analyst", other)
        self.assertNotIn(b"Analyst-only finding", other.get("/soc/triage").data)
        other_data = self.triage_data(other)
        other_data["findings"] = "Other analyst finding"
        other.post("/soc/triage/BF-M-001", data=other_data)
        own = self.client.get("/soc/triage").data
        self.assertIn(b"Analyst-only finding", own)
        self.assertNotIn(b"Other analyst finding", own)
        with self.app.app_context():
            rows = get_db().execute("SELECT * FROM operations_triage WHERE case_id='BF-M-001'").fetchall()
            self.assertEqual(len(rows), 2)
            self.assertEqual(next(row for row in rows if row["username"] == "analyst")["status"], "Resolved")

    def test_post_requires_csrf_and_cross_analyst_tokens_fail(self):
        data = self.triage_data()
        other = self.app.test_client()
        self.login("other", other)
        wrong_token = self.token(other)
        for token in ("", "wrong", "\u2603", "x" * 129, wrong_token):
            data["csrf_token"] = token
            self.assertEqual(self.client.post("/soc/triage/BF-M-001", data=data).status_code, 403)
            self.assertEqual(self.client.post("/soc/assessment/BF-M-001", data=data).status_code, 403)
        self.assertIsNone(self.saved_report())

    def test_invalid_case_ids_never_create_records(self):
        token = self.token()
        for case_id in ("BF-M-999", "BF-X-001", "not-a-case"):
            self.assertEqual(self.client.post("/soc/triage/" + case_id, data={"csrf_token": token}).status_code, 404)
            self.assertEqual(self.client.get("/soc/assessment/" + case_id).status_code, 404)

    def test_triage_validation_rejects_invalid_enums_and_text(self):
        for field, value in (("severity", "Urgent"), ("verdict", "maybe"), ("status", "Done"),
                             ("response", "Delete everything"), ("findings", " "), ("findings", "x" * 3001)):
            data = self.triage_data()
            data[field] = value
            self.assertEqual(self.client.post("/soc/triage/BF-M-001", data=data).status_code, 400)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM operations_triage").fetchone()[0], 0)

    def test_draft_completion_and_submission_rules(self):
        data = {"csrf_token": self.token(), "action": "draft", "incident_summary": "Partial reconstruction"}
        self.assertEqual(self.client.post("/soc/assessment/BF-M-001", data=data).status_code, 302)
        saved = self.saved_report()
        self.assertEqual(saved["status"], "Draft")
        self.assertEqual(saved["completion_score"], 12)
        self.assertEqual(saved["accuracy_score"], 0)
        data["action"] = "submit"
        self.assertEqual(self.client.post("/soc/assessment/BF-M-001", data=data).status_code, 400)
        self.assertEqual(self.saved_report()["status"], "Draft")

    def test_all_fifteen_rubrics_grade_correct_wrong_and_partial_answers(self):
        with self.app.app_context():
            for case_id in get_all_cases():
                with self.subTest(case=case_id):
                    questions = load_investigation(case_id)["questions"]
                    answers = self.expected[case_id]
                    correct, feedback, version = score_assessment(case_id, questions, answers)
                    self.assertEqual(correct, 100)
                    self.assertTrue(all(item["result"] == "Correct" for item in feedback))
                    wrong, _, _ = score_assessment(case_id, questions, {field: "unrelated" for field in answers})
                    self.assertEqual(wrong, 0)
                    partial, _, _ = score_assessment(case_id, questions, {questions[0]["field"]: answers[questions[0]["field"]]})
                    self.assertEqual(partial, round(100 / len(questions)))
                    variants = {field: answer.upper() + " ALTERNATIVE" for field, answer in answers.items()}
                    self.assertEqual(score_assessment(case_id, questions, variants)[0], 100)
                    self.assertRegex(version, r"^[a-f0-9]{64}$")

    def test_real_protected_store_covers_every_case_question(self):
        protected_store = os.environ.get("BLACK_FALCON_SOLUTION_STORE", str(ROOT / "private" / "solutions.json"))
        with self.app.app_context(), patch.dict(self.app.config, {"SOLUTION_STORE_PATH": protected_store}):
            for case_id in get_all_cases():
                questions = load_investigation(case_id)["questions"]
                score, feedback, _ = score_assessment(case_id, questions, {})
                self.assertEqual(score, 0, case_id)
                self.assertEqual(len(feedback), len(questions))
                self.assertTrue(all(item["result"] != "Unavailable" for item in feedback))

    def test_full_report_persists_scores_feedback_and_edits(self):
        data = self.report_data()
        response = self.client.post("/soc/assessment/BF-M-001", data=data, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"100%", response.data)
        saved = self.saved_report()
        self.assertEqual(saved["completion_score"], 100)
        self.assertEqual(saved["accuracy_score"], 100)
        self.assertEqual(saved["status"], "Submitted")
        first_field = next(iter(self.expected["BF-M-001"]))
        data["answer_" + first_field] = "incorrect"
        self.client.post("/soc/assessment/BF-M-001", data=data)
        self.assertLess(self.saved_report()["accuracy_score"], 100)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM operations_assessments").fetchone()[0], 1)

    def test_filling_report_with_arbitrary_text_does_not_earn_accuracy(self):
        data = self.report_data()
        for field in self.expected["BF-M-001"]:
            data["answer_" + field] = "arbitrary narrative"
        self.client.post("/soc/assessment/BF-M-001", data=data)
        saved = self.saved_report()
        self.assertEqual(saved["completion_score"], 100)
        self.assertEqual(saved["accuracy_score"], 0)

    def test_missing_or_malformed_rubric_saves_without_claiming_accuracy(self):
        for payload in ({}, [], {"BF-M-001": "invalid"}, {"BF-M-001": {"attacker_ip": ["bad hash"]}}):
            (self.root / "solutions.json").write_text(json.dumps(payload), encoding="utf-8")
            response = self.client.post("/soc/assessment/BF-M-001", data=self.report_data(), follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            self.assertIsNone(self.saved_report()["accuracy_score"])
            self.assertIn(b"accuracy has not been graded", response.data)

    def test_assessment_privacy_and_no_expected_answer_or_hash_disclosure(self):
        data = self.report_data()
        data["incident_summary"] = "Private narrative for analyst"
        self.client.post("/soc/assessment/BF-M-001", data=data)
        other = self.app.test_client()
        self.login("another-analyst", other)
        response = other.get("/soc/assessment/BF-M-001")
        self.assertNotIn(b"Private narrative for analyst", response.data)
        for answer in self.expected["BF-M-001"].values():
            self.assertNotIn(answer.encode(), response.data)
            self.assertNotIn(hash_answer(answer).encode(), response.data)
        self.assertNotIn(b"100%", other.get("/soc/assessment").data)

    def test_html_escaping_and_sql_parameters_preserve_literal_user_text(self):
        payload = '<script>alert("xss")</script>\'; DROP TABLE users; --'
        triage = self.triage_data()
        triage["findings"] = payload
        self.client.post("/soc/triage/BF-M-001", data=triage)
        data = self.report_data()
        data["incident_summary"] = payload
        data["answer_" + next(iter(self.expected["BF-M-001"]))] = payload
        self.client.post("/soc/assessment/BF-M-001", data=data)
        for path in ("/soc/triage", "/soc/assessment/BF-M-001"):
            html = self.client.get(path).data
            self.assertNotIn(b'<script>alert', html)
            self.assertIn(b'&lt;script&gt;', html)
        with self.app.app_context():
            self.assertGreater(get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
        self.assertEqual(json.loads(self.saved_report()["report_json"])["incident_summary"], payload)

    def test_overlong_and_incomplete_reports_preserve_last_saved_record(self):
        self.client.post("/soc/assessment/BF-M-001", data=self.report_data())
        saved = self.saved_report()
        for field, value in (("impact", "x" * 3001), ("entry_point", ""),
                             ("answer_" + next(iter(self.expected["BF-M-001"])), "x" * 3001), ("action", "erase")):
            data = self.report_data()
            data[field] = value
            self.assertEqual(self.client.post("/soc/assessment/BF-M-001", data=data).status_code, 400)
            self.assertEqual(self.saved_report(), saved)

    def test_startup_is_idempotent_and_records_survive_app_recreation(self):
        self.client.post("/soc/triage/BF-M-001", data=self.triage_data())
        self.client.post("/soc/assessment/BF-M-001", data=self.report_data())
        saved = self.saved_report()
        with self.app.app_context():
            initialize_operations(get_db())
        recreated = create_app(self.config)
        client = recreated.test_client()
        self.login(client=client)
        self.assertIn(b"Evidence justifies response", client.get("/soc/triage").data)
        self.assertIn(b"Evidence-based incident_summary", client.get("/soc/assessment/BF-M-001").data)
        self.assertEqual(self.saved_report(), saved)

    def test_operations_do_not_modify_original_challenge_progress(self):
        with self.app.app_context():
            before = {table: [tuple(row) for row in get_db().execute("SELECT * FROM " + table)]
                      for table in ("progress", "submissions", "validated_findings")}
        self.client.post("/soc/triage/BF-M-001", data=self.triage_data())
        self.client.post("/soc/assessment/BF-M-001", data=self.report_data())
        with self.app.app_context():
            after = {table: [tuple(row) for row in get_db().execute("SELECT * FROM " + table)] for table in before}
        self.assertEqual(before, after)

    def test_client_cannot_set_another_analyst_or_forge_scores(self):
        data = self.report_data()
        data.update(username="other", completion_score="100", accuracy_score="100")
        for field in self.expected["BF-M-001"]:
            data["answer_" + field] = "wrong"
        self.client.post("/soc/assessment/BF-M-001", data=data)
        self.assertEqual(self.saved_report()["accuracy_score"], 0)
        self.assertIsNone(self.saved_report(username="other"))

    def test_dashboard_uses_live_verified_findings_and_flag_progress(self):
        self.client.post("/soc/assessment/BF-M-001", data=self.report_data())
        with self.app.app_context():
            status = calculate_assessment_status("analyst", get_db())
            self.assertEqual(status["passed"], 0)
            mark_findings_validated("analyst", "BF-M-001")
            self.assertEqual(calculate_assessment_status("analyst", get_db())["passed"], 0)
            mark_completed("analyst", "BF-M-001")
            self.assertEqual(calculate_assessment_status("analyst", get_db())["passed"], 1)
        html = self.client.get("/soc/assessment").get_data(as_text=True)
        self.assertIn("Incident Assessment Center", html)
        self.assertIn("Assessments Passed", html)
        self.assertRegex(html, r"siem-low[^>]*>\s*Passed")
        other = self.app.test_client()
        self.login("other", other)
        self.assertNotRegex(other.get("/soc/assessment").get_data(as_text=True), r"siem-low[^>]*>\s*Passed")

    def test_complete_draft_is_pending_until_submitted(self):
        data = self.report_data()
        data["action"] = "draft"
        self.client.post("/soc/assessment/BF-M-001", data=data)
        with self.app.app_context():
            mark_findings_validated("analyst", "BF-M-001")
            mark_completed("analyst", "BF-M-001")
            self.assertEqual(calculate_assessment_status("analyst", get_db())["passed"], 0)
        data["action"] = "submit"
        self.client.post("/soc/assessment/BF-M-001", data=data)
        with self.app.app_context():
            self.assertEqual(calculate_assessment_status("analyst", get_db())["passed"], 1)

    def test_report_submission_rejects_short_or_whitespace_sections(self):
        for field in ASSESSMENT_FIELDS:
            for text in (" \t\n ", "x" * (MIN_REPORT_LENGTH - 1), "   " + "x" * (MIN_REPORT_LENGTH - 1) + "   "):
                with self.subTest(field=field, length=len(text.strip())):
                    data = self.report_data()
                    data[field] = text
                    response = self.client.post("/soc/assessment/BF-M-001", data=data)
                    self.assertEqual(response.status_code, 400)
                    self.assertIn(b"Each answer must contain at least 20 characters", response.data)
                    self.assertIsNone(self.saved_report())

    def test_twenty_character_sections_submit_and_score_consistently(self):
        data = self.report_data()
        data.update({field: "  " + "x" * MIN_REPORT_LENGTH + "  " for field in ASSESSMENT_FIELDS})
        self.assertEqual(self.client.post("/soc/assessment/BF-M-001", data=data).status_code, 302)
        saved = self.saved_report()
        self.assertEqual(saved["completion_score"], 100)
        self.assertTrue(all(len(value) == MIN_REPORT_LENGTH for value in json.loads(saved["report_json"]).values()))
        with self.app.app_context():
            status = calculate_assessment_status("analyst", get_db())
        item = next(item for item in status["cases"] if item["case_id"] == "BF-M-001")
        self.assertEqual(item["report_completion"], saved["completion_score"])
        self.assertFalse(item["assessment_passed"])

    def test_short_drafts_save_without_earning_completion_credit(self):
        data = {"csrf_token": self.token(), "action": "draft", "incident_summary": "short"}
        self.assertEqual(self.client.post("/soc/assessment/BF-M-001", data=data).status_code, 302)
        self.assertEqual(self.saved_report()["completion_score"], 0)
        data["entry_point"] = "x" * MIN_REPORT_LENGTH
        self.client.post("/soc/assessment/BF-M-001", data=data)
        self.assertEqual(self.saved_report()["completion_score"], 12)

    def test_short_report_edit_preserves_previously_saved_submission(self):
        self.client.post("/soc/assessment/BF-M-001", data=self.report_data())
        original = self.saved_report()
        data = self.report_data()
        data["incident_summary"] = "placeholder"
        self.assertEqual(self.client.post("/soc/assessment/BF-M-001", data=data).status_code, 400)
        self.assertEqual(self.saved_report(), original)

    def test_startup_creates_operations_tables_and_preserves_existing_users(self):
        with self.app.app_context():
            db = get_db()
            tables = {row["name"] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertTrue({"operations_triage", "operations_assessments", "users", "progress", "submissions", "validated_findings"}.issubset(tables))
            users_before = [tuple(row) for row in db.execute("SELECT * FROM users ORDER BY username")]
            initialize_operations(db)
            self.assertEqual([tuple(row) for row in db.execute("SELECT * FROM users ORDER BY username")], users_before)


if __name__ == "__main__":
    unittest.main()
