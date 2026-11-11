"""Audit, safe initialization, and release-configuration regression tests."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from audit_soc_integration import audit_app, main, timeline_findings, REQUIRED_BLUEPRINTS
from database import get_db


ROOT = Path(__file__).resolve().parents[1]


class IntegrationAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="integration-audit-test-")
        self.root = Path(self.temp.name)
        self.config = {"SECRET_KEY": "audit-test", "TESTING": True, "FINAL_SOC_SHOW_ANSWERS": False,
                       "DATABASE_DIR": str(self.root), "DATABASE_PATH": str(self.root / "main.db"),
                       "SOC_FEATURE_DATABASE_PATH": str(self.root / "features.db"),
                       "LOG_DIR": str(self.root / "logs"), "LOG_FILE": str(self.root / "logs/test.log")}
        self.app = create_app(self.config)

    def tearDown(self):
        for handler in list(self.app.logger.handlers):
            if getattr(handler, "baseFilename", "").startswith(str(self.root)):
                self.app.logger.removeHandler(handler)
                handler.close()
        self.temp.cleanup()

    def test_full_audit_passes_structurally_but_flags_evidence_release_issue(self):
        result = audit_app(self.app)
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["ok"])
        self.assertFalse(result["release_ready"])
        self.assertIn("Zeek", " ".join(result["warnings"]))
        self.assertEqual(set(self.app.blueprints), REQUIRED_BLUEPRINTS)
        json.dumps(result)

    def test_missing_table_endpoint_and_file_are_reported(self):
        with self.app.app_context():
            db = get_db()
            db.execute("DROP TABLE final_soc_attempts")
            db.commit()
        with patch("audit_soc_integration.REQUIRED_ENDPOINTS", {"missing.endpoint"}):
            report = audit_app(self.app, self.root)
        self.assertFalse(report["ok"])
        self.assertTrue(any("final_soc_attempts" in error for error in report["errors"]))
        self.assertTrue(any("missing.endpoint" in error for error in report["errors"]))
        self.assertTrue(any("Required file" in error for error in report["errors"]))

    def test_practice_mode_is_explicitly_flagged_for_release(self):
        self.app.config["FINAL_SOC_SHOW_ANSWERS"] = True
        self.assertTrue(any("Practice mode" in message for message in audit_app(self.app)["warnings"]))

    def test_config_environment_defaults_to_assessment_and_opt_in_is_exact(self):
        for value, expected in ((None, False), ("0", False), ("true", False), ("1", True)):
            environment = os.environ.copy()
            environment.pop("BLACK_FALCON_SHOW_ASSESSMENT_ANSWERS", None)
            if value is not None:
                environment["BLACK_FALCON_SHOW_ASSESSMENT_ANSWERS"] = value
            result = subprocess.run([sys.executable, "-B", "-c",
                "from config import Config; print(int(Config.FINAL_SOC_SHOW_ANSWERS), Config.FINAL_SOC_PASS_PERCENTAGE)"],
                cwd=ROOT, env=environment, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), f"{int(expected)} 70")

    def test_existing_records_and_passwords_survive_reinitialization(self):
        with self.app.app_context():
            db = get_db()
            before = [tuple(row) for row in db.execute("SELECT * FROM users")]
            db.execute("INSERT INTO final_soc_attempts (username, case_id, answers_json, feedback_json, score, percentage, passed, submitted_at) VALUES ('analyst','BF-H-005','{}','[]',74,74,1,'test')")
            db.commit()
        other = create_app(self.config)
        with other.app_context():
            db = get_db()
            self.assertEqual([tuple(row) for row in db.execute("SELECT * FROM users")], before)
            self.assertEqual(db.execute("SELECT score FROM final_soc_attempts").fetchone()["score"], 74)

    def test_timeline_drift_is_measured_not_silently_normalized(self):
        rows = timeline_findings()
        self.assertEqual([item["year_difference"] for item in rows], [1, 1, 1])
        self.assertEqual(rows[0]["clock_difference_seconds_after_year_alignment"], 0)
        self.assertEqual(rows[2]["clock_difference_seconds_after_year_alignment"], 600)

    def test_default_audit_cli_uses_temporary_databases_and_strict_exit_codes(self):
        from contextlib import redirect_stdout
        import io
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--json"])
        report = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(report["ok"])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--strict-release"]), 2)


if __name__ == "__main__":
    unittest.main()
