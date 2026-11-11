"""Integration checks for the guided lab entry points and existing workspaces."""

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import soc_features
from app import create_app
from database import get_db


class SOCLabsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="soc-labs-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        feature_patch = patch.object(
            soc_features, "feature_database_path", return_value=str(root / "features.db")
        )
        feature_patch.start()
        self.addCleanup(feature_patch.stop)
        self.app = create_app({
            "TESTING": True, "SECRET_KEY": "labs-test",
            "DATABASE_DIR": str(root / "database"),
            "DATABASE_PATH": str(root / "database" / "test.db"),
            "LOG_DIR": str(root / "logs"), "LOG_FILE": str(root / "logs" / "test.log"),
        })
        self.addCleanup(self.close_logging)
        self.client = self.app.test_client()

    def close_logging(self):
        for handler in list(self.app.logger.handlers):
            if getattr(handler, "baseFilename", "").endswith("test.log"):
                self.app.logger.removeHandler(handler)
                handler.close()

    def login(self):
        with self.client.session_transaction() as user_session:
            user_session.update(logged_in=True, username="analyst", selected_level="beginner")

    def test_labs_require_an_authenticated_analyst(self):
        for value in (None, False, "true", 1, True):
            with self.client.session_transaction() as user_session:
                user_session.clear()
                user_session["logged_in"] = value
                if value is not True:
                    user_session["username"] = "analyst"
            for path in ("/soc/labs", "/soc/labs/1"):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response.location.endswith("/login"))

    def test_four_labs_and_workspace_links_render(self):
        self.login()
        response = self.client.get("/soc/labs")
        self.assertEqual(response.status_code, 200)
        index = response.get_data(as_text=True)
        self.assertEqual(index.count("Open Practical Lab"), 4)
        self.assertLess(index.index(">SOC Practical Labs</a>"), index.index(">Evidence Locker</a>"))
        for lab_id in range(1, 5):
            response = self.client.get(f"/soc/labs/{lab_id}")
            self.assertEqual(response.status_code, 200)
            page = response.get_data(as_text=True)
            case_id = f"BF-M-{lab_id:03}"
            self.assertIn(f'/investigations/{case_id}', page)
            self.assertIn(f'/siem?case={case_id}', page)
            self.assertIn("This practical is ungraded", page)
            self.assertRegex(page, r'class="active"\s+href="/soc/labs"')
            workspace = page.split('<div class="soc-lab-links">', 1)[1].split('</div>', 1)[0]
            for link in re.findall(r'href="([^"]+)"', workspace):
                self.assertEqual(self.client.get(link).status_code, 200, link)
        for path in ("/soc/labs/0", "/soc/labs/5", "/soc/labs/invalid"):
            self.assertEqual(self.client.get(path).status_code, 404)

    def test_viewing_labs_does_not_write_progress_or_operations(self):
        self.login()

        def snapshot():
            with self.app.app_context():
                db = get_db()
                tables = [row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )]
                return {table: [tuple(row) for row in db.execute(f'SELECT * FROM "{table}"')]
                        for table in tables}

        before = snapshot()
        self.client.get("/soc/labs")
        for lab_id in range(1, 5):
            self.client.get(f"/soc/labs/{lab_id}")
        self.assertEqual(snapshot(), before)


if __name__ == "__main__":
    unittest.main()
