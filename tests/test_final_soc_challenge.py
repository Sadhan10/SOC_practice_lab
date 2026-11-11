import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import template_rendered
from werkzeug.datastructures import MultiDict

import soc_features
from app import create_app
from database import get_db
from routes.final_soc_challenge import CASE_ID, QUESTIONS, init_final_soc


ROOT = Path(__file__).resolve().parents[1]


class FinalSocTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="final-soc-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        feature_patch = patch.object(soc_features, "feature_database_path", return_value=str(self.root / "features.db"))
        feature_patch.start()
        self.addCleanup(feature_patch.stop)
        self.config = {
            "TESTING": True, "SECRET_KEY": "final-soc-test", "FINAL_SOC_SHOW_ANSWERS": False,
            "DATABASE_DIR": str(self.root / "database"),
            "DATABASE_PATH": str(self.root / "database" / "test.db"),
            "LOG_DIR": str(self.root / "logs"), "LOG_FILE": str(self.root / "logs" / "test.log"),
        }
        self.app = create_app(self.config)
        self.addCleanup(self.close_logging)
        self.client = self.app.test_client()
        self.login(self.client)

    def close_logging(self):
        for handler in list(self.app.logger.handlers):
            if getattr(handler, "baseFilename", "").startswith(str(self.root)):
                self.app.logger.removeHandler(handler)
                handler.close()

    def login(self, client, username="analyst"):
        with client.session_transaction() as sess:
            sess.clear()
            sess.update(logged_in=True, username=username)

    def data(self, correct=None, client=None):
        correct = len(QUESTIONS) if correct is None else correct
        client = client or self.client
        self.assertEqual(client.get("/soc/final").status_code, 200)
        with client.session_transaction() as sess:
            token = sess["operations_csrf"]
        data = {"csrf_token": token}
        for index, question in enumerate(QUESTIONS):
            data[question["id"]] = question["answer"] if index < correct else next(
                value for value, label in question["options"] if value != question["answer"])
        return data

    def attempts(self):
        with self.app.app_context():
            return [dict(row) for row in get_db().execute("SELECT * FROM final_soc_attempts ORDER BY id")]

    def test_all_routes_require_an_authenticated_analyst(self):
        for session_data in ({}, {"logged_in": True}, {"logged_in": False, "username": "analyst"}):
            client = self.app.test_client()
            with client.session_transaction() as sess:
                sess.update(session_data)
            for path in ("/soc/final", "/soc/final/result/1", "/soc/final/export"):
                self.assertEqual(client.get(path).status_code, 302)
            self.assertEqual(client.post("/soc/final/submit").status_code, 302)
        self.assertEqual(self.attempts(), [])

    def test_csrf_and_answers_are_validated_before_any_write(self):
        data = self.data()
        for token in ("", "bad", "x" * 129, "\u2603"):
            self.assertEqual(self.client.post("/soc/final/submit", data=dict(data, csrf_token=token)).status_code, 403)
        for question in QUESTIONS:
            for value in (None, "invalid", "", "x" * 4000):
                invalid = dict(data)
                if value is None:
                    invalid.pop(question["id"])
                else:
                    invalid[question["id"]] = value
                response = self.client.post("/soc/final/submit", data=invalid)
                self.assertEqual(response.status_code, 400)
                self.assertIn(b'role="alert"', response.data)
        duplicate = MultiDict(data)
        duplicate.add("q1", "a")
        self.assertEqual(self.client.post("/soc/final/submit", data=duplicate).status_code, 400)
        self.assertEqual(self.attempts(), [])

    def test_every_score_pass_threshold_retake_history_and_feedback(self):
        for correct in range(len(QUESTIONS) + 1):
            expected_score = sum(question["weight"] for question in QUESTIONS[:correct])
            data = self.data(correct)
            data.update(score="100", percentage="100", passed="1", username="other", case_id="BF-2026-001")
            response = self.client.post("/soc/final/submit", data=data)
            self.assertEqual(response.status_code, 302)
            attempt = self.attempts()[-1]
            self.assertEqual(attempt["score"], expected_score)
            self.assertEqual(attempt["percentage"], expected_score)
            self.assertEqual(attempt["passed"], int(expected_score >= 70))
            self.assertEqual(attempt["username"], "analyst")
            self.assertEqual(attempt["case_id"], CASE_ID)
            feedback = json.loads(attempt["feedback_json"])
            self.assertEqual(sum(item["correct"] for item in feedback), correct)
            self.assertEqual(sum(item["marks_available"] for item in feedback), 100)
            self.assertEqual(sum(item["marks_awarded"] for item in feedback), expected_score)
            for question, item in zip(QUESTIONS, feedback):
                self.assertEqual(item["marks_available"], question["weight"])
                self.assertEqual(item["marks_awarded"], question["weight"] if item["correct"] else 0)
            result = self.client.get(response.location)
            self.assertEqual(result.status_code, 200)
            self.assertIn(f'{expected_score}/100'.encode(), result.data)
            for item in feedback:
                self.assertTrue(item["evidence"])
                for filename in item["files"]:
                    self.assertTrue((ROOT / "evidence" / filename).is_file())
        self.assertEqual(len(self.attempts()), len(QUESTIONS) + 1)
        history = self.client.get("/soc/final").data
        self.assertIn(b"Attempt History", history)
        for attempt in self.attempts():
            self.assertIn(f'/soc/final/result/{attempt["id"]}'.encode(), history)

    def test_results_and_exports_are_isolated_between_analysts(self):
        first = self.client.post("/soc/final/submit", data=self.data())
        other = self.app.test_client()
        self.login(other, "other")
        self.assertEqual(other.get(first.location).status_code, 404)
        self.assertEqual(other.get("/soc/final/result/999999").status_code, 404)
        self.assertNotIn(b"Previous Attempt", other.get("/soc/final").data)
        empty = list(csv.reader(io.StringIO(other.get("/soc/final/export").get_data(as_text=True))))
        self.assertEqual(len(empty), 1)
        second = other.post("/soc/final/submit", data=self.data(0, other))
        self.assertEqual(self.client.get(second.location).status_code, 404)
        exported = self.client.get("/soc/final/export")
        rows = list(csv.DictReader(io.StringIO(exported.get_data(as_text=True))))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "analyst")
        self.assertEqual(rows[0]["score"], "100")
        self.assertIn("attachment", exported.headers["Content-Disposition"])
        self.assertEqual(exported.mimetype, "text/csv")

    def test_question_page_excludes_private_rubric_and_hide_feedback_setting(self):
        captured = {}

        def capture(sender, template, context, **extra):
            captured.update(context)

        template_rendered.connect(capture, self.app, weak=False)
        try:
            page = self.client.get("/soc/final")
        finally:
            template_rendered.disconnect(capture, self.app)
        for question in captured["questions"]:
            self.assertEqual(set(question), {"id", "title", "prompt", "options", "weight"})
        self.assertNotIn(b"Expected Answer", page.data)
        self.assertIn(b"Incident Timeline Reconstruction", page.data)
        self.assertIn(b"Incident Response Strategy", page.data)
        self.assertNotIn(b"Each question is worth 20", page.data)
        self.assertEqual(page.data.count(b"Marks available:"), 7)
        self.assertNotIn(QUESTIONS[5]["evidence"].encode(), page.data)
        result = self.client.post("/soc/final/submit", data=self.data())
        default_result = self.client.get(result.location)
        self.assertNotIn(b"Expected Answer", default_result.data)
        self.assertNotIn(b"Supporting Evidence", default_result.data)
        self.assertIn("no-store", default_result.headers["Cache-Control"])
        self.app.config["FINAL_SOC_SHOW_ANSWERS"] = True
        self.assertIn(b"Expected Answer", self.client.get(result.location).data)
        self.app.config["FINAL_SOC_SHOW_ANSWERS"] = False
        hidden = self.client.get(result.location).data
        self.assertNotIn(b"Expected Answer", hidden)
        self.assertNotIn(b"Supporting Evidence", hidden)
        self.assertNotIn(QUESTIONS[0]["evidence"].encode(), hidden)
        self.assertIn(b"Correct", hidden)
        self.assertEqual(hidden.count(b"Marks Awarded:"), 7)

    def test_persistence_and_original_challenge_state_are_independent(self):
        def snapshot():
            with self.app.app_context():
                return {table: [tuple(row) for row in get_db().execute("SELECT * FROM " + table)]
                        for table in ("users", "progress", "submissions", "validated_findings",
                                      "operations_assessments", "operations_triage", "soc_alert_triage")}

        before = snapshot()
        result = self.client.post("/soc/final/submit", data=self.data())
        saved = self.attempts()
        self.assertEqual(snapshot(), before)
        with self.app.app_context():
            init_final_soc(get_db())
        recreated = create_app(self.config)
        client = recreated.test_client()
        self.login(client)
        self.assertEqual(client.get(result.location).status_code, 200)
        self.assertIn(b"100/100", client.get("/soc/final").data)
        self.assertEqual(saved, self.attempts())
        self.assertEqual(snapshot(), before)

    def test_csv_safely_handles_quoted_unicode_and_formula_names(self):
        username = '=HYPERLINK("bad"),\u2603\nanalyst'
        self.login(self.client, username)
        self.client.post("/soc/final/submit", data=self.data())
        self.client.post("/soc/final/submit", data=self.data(0))
        rows = list(csv.DictReader(io.StringIO(self.client.get("/soc/final/export").get_data(as_text=True))))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["username"], "'" + username)
        self.assertEqual([row["result"] for row in rows], ["Passed", "Not Passed"])

    def test_final_assessment_is_linked_as_fifth_lab(self):
        page = self.client.get("/soc/labs")
        self.assertIn(b"PRACTICAL LAB 5 / GRADED", page.data)
        self.assertIn(b'href="/soc/final"', page.data)
        self.assertRegex(self.client.get("/soc/final").get_data(as_text=True), r'class="active"\s+href="/soc/final"')


    def test_weighted_pass_boundary_is_used_by_submission_and_csv(self):
        failing = self.data(4)
        passing = dict(failing, q6=QUESTIONS[5]["answer"])
        for data, score, passed in ((failing, 64, 0), (passing, 74, 1)):
            response = self.client.post("/soc/final/submit", data=data)
            self.assertEqual(response.status_code, 302)
            attempt = self.attempts()[-1]
            self.assertEqual((attempt["score"], attempt["percentage"], attempt["passed"]),
                             (score, score, passed))
            self.assertIn(f"{score}/100".encode(), self.client.get(response.location).data)
        rows = list(csv.DictReader(io.StringIO(self.client.get("/soc/final/export").get_data(as_text=True))))
        self.assertEqual([row["score"] for row in rows], ["64", "74"])
        self.assertEqual([row["result"] for row in rows], ["Not Passed", "Passed"])

    def test_historical_five_question_attempt_keeps_original_marks_and_score(self):
        answers = {}
        feedback = []
        for index, question in enumerate(QUESTIONS[:5]):
            correct = index < 4
            choices = dict(question["options"])
            selected = question["answer"] if correct else next(value for value in choices if value != question["answer"])
            answers[question["id"]] = selected
            feedback.append({"id": question["id"], "title": question["title"], "selected": choices[selected],
                             "correct": correct, "expected": choices[question["answer"]],
                             "evidence": question["evidence"], "files": question["files"]})
        with self.app.app_context():
            db = get_db()
            cursor = db.execute("""
                INSERT INTO final_soc_attempts
                    (username, case_id, answers_json, feedback_json, score, percentage, passed, submitted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, ("analyst", CASE_ID, json.dumps(answers), json.dumps(feedback), 80, 80, 1, "2026-08-21T12:00:00Z"))
            db.commit()
            result_id = cursor.lastrowid
        before = self.attempts()
        page = self.client.get(f"/soc/final/result/{result_id}").data
        self.assertIn(b"80/100", page)
        self.assertIn(b"original five-question assessment", page)
        self.assertEqual(page.count(b"Marks Awarded:"), 5)
        self.assertNotIn(b"Incident Timeline Reconstruction", page)
        self.app.config["FINAL_SOC_SHOW_ANSWERS"] = False
        hidden = self.client.get(f"/soc/final/result/{result_id}").data
        self.assertNotIn(b"Expected Answer", hidden)
        self.assertEqual(hidden.count(b"Marks Awarded:"), 5)
        self.assertEqual(self.attempts(), before)
        rows = list(csv.DictReader(io.StringIO(self.client.get("/soc/final/export").get_data(as_text=True))))
        self.assertEqual((rows[0]["score"], rows[0]["percentage"]), ("80", "80"))



    def test_assessment_mode_strips_private_fields_from_all_template_context(self):
        self.app.config["FINAL_SOC_SHOW_EXPECTED_ANSWERS"] = True
        submitted = self.client.post("/soc/final/submit", data=dict(self.data(0), show_answers="1"))
        captured = {}
        def capture(sender, template, context, **extra):
            captured.update(context)
        template_rendered.connect(capture, self.app, weak=False)
        try:
            page = self.client.get(submitted.location + "?show_answers=1")
        finally:
            template_rendered.disconnect(capture, self.app)
        self.assertNotIn(b"Expected Answer", page.data)
        self.assertNotIn(b"Supporting Evidence", page.data)
        self.assertFalse(captured["show_answers"])
        self.assertNotIn("feedback_json", captured["result"])
        self.assertNotIn("answers_json", captured["result"])
        for item in captured["feedback"]:
            self.assertFalse({"expected", "evidence", "files"} & set(item))
        self.assertNotIn(QUESTIONS[6]["evidence"].encode(), page.data)
        self.assertNotIn(dict(QUESTIONS[6]["options"])[QUESTIONS[6]["answer"]].encode(), page.data)

    def test_truthy_strings_cannot_enable_answer_disclosure(self):
        result = self.client.post("/soc/final/submit", data=self.data(0))
        for mode in ("1", "0", "true", 1):
            self.app.config["FINAL_SOC_SHOW_ANSWERS"] = mode
            self.assertNotIn(b"Expected Answer", self.client.get(result.location).data)

    def test_server_threshold_controls_scoring_and_display(self):
        self.app.config["FINAL_SOC_PASS_PERCENTAGE"] = 80
        answers = self.data(4)
        answers["q6"] = QUESTIONS[5]["answer"]
        result = self.client.post("/soc/final/submit", data=answers)
        self.assertEqual(result.status_code, 302)
        attempt = self.attempts()[-1]
        self.assertEqual((attempt["score"], attempt["passed"]), (74, 0))
        self.assertIn(b"80%", self.client.get("/soc/final").data)


if __name__ == "__main__":
    unittest.main()
