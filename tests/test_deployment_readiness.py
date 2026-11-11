"""Portable release checks; these do not replace testing the Ubuntu VM itself."""

import os
import sqlite3
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import Flask
from database import init_db

from app import create_app


ROOT = Path(__file__).resolve().parents[1]


class DeploymentReadinessTests(unittest.TestCase):
    def test_project_validator_covers_all_fifteen_challenges(self):
        environment = os.environ.copy()
        environment.setdefault("BLACK_FALCON_SOLUTION_STORE", str(ROOT / "private" / "solutions.json"))
        result = subprocess.run(
            [sys.executable, str(ROOT / "validate_project.py")],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Configured cases : 15", result.stdout)
        self.assertIn("Errors           : 0", result.stdout)
        self.assertIn("Warnings         : 0", result.stdout)

    def test_case_sensitive_paths_exist_for_linux_deployment(self):
        # Windows resolves mismatched casing; Linux would return 404 or fail imports.
        required = (
            "routes/soc_operations.py", "routes/assessment_scoring.py", "routes/siem.py", "templates/soc_triage.html",
            "templates/soc_assessment.html", "templates/soc_assessment_form.html",
            "templates/siem.html", "static/css/siem.css", "deploy/black-falcon.service",
        )
        for relative in required:
            directory = ROOT
            for component in relative.split("/"):
                self.assertIn(component, {item.name for item in directory.iterdir()}, relative)
                directory /= component

    def test_production_requires_secret_and_service_uses_app_factory(self):
        with self.assertRaisesRegex(RuntimeError, "SECRET_KEY"):
            create_app({"SECRET_KEY": ""})
        service = (ROOT / "deploy" / "black-falcon.service").read_text(encoding="utf-8")
        self.assertIn('"app:create_app()"', service)
        self.assertIn("EnvironmentFile=/etc/black-falcon.env", service)
        self.assertIn("User=blackfalcon", service)


    def test_database_initialization_closes_connections_on_success_and_failure(self):
        connect = sqlite3.connect
        for fail in (False, True):
            with self.subTest(initialization_failure=fail), tempfile.TemporaryDirectory(prefix="database-startup-") as folder:
                root = Path(folder)
                app = Flask(__name__)
                app.config.update(DATABASE_DIR=str(root), DATABASE_PATH=str(root / "startup.db"),
                                  INVESTIGATION_DIR=str(root / "investigations"),
                                  EVIDENCE_DIR=str(root / "evidence"), LOG_DIR=str(root / "logs"))
                opened = []
                def tracked_connect(*args, **kwargs):
                    connection = connect(*args, **kwargs)
                    opened.append(connection)
                    return connection
                try:
                    with patch("database.sqlite3.connect", side_effect=tracked_connect):
                        if fail:
                            with patch("database.create_tables", side_effect=RuntimeError("forced failure")):
                                with self.assertRaisesRegex(RuntimeError, "forced failure"):
                                    init_db(app)
                        else:
                            init_db(app)
                    self.assertEqual(len(opened), 1)
                    with self.assertRaises(sqlite3.ProgrammingError):
                        opened[0].execute("SELECT 1")
                finally:
                    for connection in opened:
                        connection.close()


if __name__ == "__main__":
    unittest.main()
