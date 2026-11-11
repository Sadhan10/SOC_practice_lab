"""Assessment verification coverage for the deferred final regression run."""

import itertools
import json
import sqlite3
import unittest
from unittest.mock import patch

from level_config import get_all_cases
from routes.assessment_scoring import (
    MIN_REPORT_LENGTH, REPORT_FIELDS, calculate_assessment_status, calculate_report_completion,
)


class AssessmentScoringTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.execute("""
            CREATE TABLE operations_assessments (
                username TEXT, case_id TEXT, report_json TEXT, status TEXT,
                completion_score INTEGER, accuracy_score INTEGER,
                PRIMARY KEY (username, case_id)
            )
        """)
        self.progress = {}
        progress_patch = patch("routes.assessment_scoring.get_progress", return_value=self.progress)
        self.progress_reader = progress_patch.start()
        self.addCleanup(progress_patch.stop)
        self.case_id = get_all_cases()[0]
        self.report = {field: "Evidence-based narrative" for field in REPORT_FIELDS}

    def save(self, report=None, status="Submitted", username="analyst", case_id=None):
        self.db.execute(
            "INSERT OR REPLACE INTO operations_assessments VALUES (?, ?, ?, ?, 100, 100)",
            (username, case_id or self.case_id, json.dumps(self.report if report is None else report), status),
        )

    def item(self, username="analyst"):
        return next(item for item in calculate_assessment_status(username, self.db)["cases"]
                    if item["case_id"] == self.case_id)

    def test_completion_counts_only_sufficient_narrative_fields(self):
        for report in (None, [], "complete", {}, {field: None for field in REPORT_FIELDS},
                       {field: " \t\n" for field in REPORT_FIELDS},
                       {field: {"text": "not a narrative"} for field in REPORT_FIELDS}):
            self.assertEqual(calculate_report_completion(report), 0)
        self.assertEqual(calculate_report_completion(self.report), 100)
        self.assertEqual(calculate_report_completion({REPORT_FIELDS[0]: "x" * MIN_REPORT_LENGTH, "unrelated": "Filled"}), 12)

    def test_report_length_boundaries_ignore_surrounding_whitespace(self):
        for length in (0, 1, MIN_REPORT_LENGTH - 1, MIN_REPORT_LENGTH, MIN_REPORT_LENGTH + 1):
            report = {field: " \n" + "x" * length + "\t " for field in REPORT_FIELDS}
            self.assertEqual(calculate_report_completion(report), 100 if length >= MIN_REPORT_LENGTH else 0)

    def test_legacy_short_report_cannot_use_cached_completion_to_pass(self):
        self.save({field: "placeholder" for field in REPORT_FIELDS})
        self.progress[self.case_id] = {"findings_validated": 1, "completed": 1}
        self.assertEqual(self.item()["report_completion"], 0)
        self.assertFalse(self.item()["assessment_passed"])

    def test_every_pass_condition_is_required(self):
        for complete, submitted, findings, flag in itertools.product((False, True), repeat=4):
            with self.subTest(complete=complete, submitted=submitted, findings=findings, flag=flag):
                self.save(self.report if complete else {}, "Submitted" if submitted else "Draft")
                self.progress[self.case_id] = {"findings_validated": int(findings), "completed": int(flag)}
                item = self.item()
                self.assertEqual(item["assessment_passed"], complete and submitted and findings and flag)
                self.assertEqual(item["findings_verified"], findings)
                self.assertEqual(item["flag_verified"], flag)

    def test_missing_report_cannot_pass_a_verified_investigation(self):
        self.progress[self.case_id] = {"findings_validated": 1, "completed": 1}
        item = self.item()
        self.assertEqual(item["report_completion"], 0)
        self.assertFalse(item["report_submitted"])
        self.assertFalse(item["assessment_passed"])

    def test_report_scores_cannot_substitute_for_verified_progress(self):
        self.save()
        item = self.item()
        self.assertEqual(item["report_completion"], 100)
        self.assertFalse(item["findings_verified"])
        self.assertFalse(item["flag_verified"])
        self.assertFalse(item["assessment_passed"])

    def test_corrupted_or_non_object_reports_do_not_pass(self):
        self.save()
        self.progress[self.case_id] = {"findings_validated": 1, "completed": 1}
        for raw in ("{broken", "null", "[]", '"text"'):
            self.db.execute("UPDATE operations_assessments SET report_json = ?", (raw,))
            self.assertEqual(self.item()["report_completion"], 0)
            self.assertFalse(self.item()["assessment_passed"])

    def test_reports_and_progress_are_scoped_to_the_requested_analyst(self):
        self.save(username="other")
        self.assertEqual(self.item()["report_completion"], 0)
        self.assertEqual(self.item("other")["report_completion"], 100)
        self.progress_reader.assert_called_with("other")
        self.assertEqual(self.item("' OR 1=1 --")["report_completion"], 0)

    def test_summary_counts_only_configured_cases(self):
        for case_id in get_all_cases():
            self.save(case_id=case_id)
            self.progress[case_id] = {"findings_validated": 1, "completed": 1}
        self.save(case_id="BF-M-999")
        self.progress["BF-M-999"] = {"findings_validated": 1, "completed": 1}
        summary = calculate_assessment_status("analyst", self.db)
        self.assertEqual((summary["total"], summary["passed"], summary["remaining"], summary["percentage"]), (15, 15, 0, 100))
        self.progress[get_all_cases()[-1]]["completed"] = 0
        summary = calculate_assessment_status("analyst", self.db)
        self.assertEqual((summary["passed"], summary["remaining"], summary["percentage"]), (14, 1, 93))

    def test_status_reading_never_changes_saved_work(self):
        self.save()
        before = self.db.iterdump()
        before = list(before)
        calculate_assessment_status("analyst", self.db)
        self.assertEqual(list(self.db.iterdump()), before)

    def test_empty_case_configuration_has_zero_percentage(self):
        with patch("routes.assessment_scoring.get_all_cases", return_value=[]):
            summary = calculate_assessment_status("analyst", self.db)
        self.assertEqual(summary, {"cases": [], "total": 0, "passed": 0, "remaining": 0, "percentage": 0})


if __name__ == "__main__":
    unittest.main()
