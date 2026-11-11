import json
import os
import re
import shutil
import tempfile
import unittest

import soc_features as soc_features_module
from app import create_app
from investigation_loader import (
    load_investigation,
)
from level_config import (
    get_all_cases,
    get_case_level,
    get_level,
    get_level_cases,
)
from models import (
    get_level_progress,
    get_overall_progress,
    mark_completed,
    mark_findings_validated,
)
from routes.flags import build_case_flag, hash_flag
from models import save_validated_findings, verify_user_password, get_user
from database import get_db


PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        os.pardir,
    )
)


class LevelIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(
            prefix="black-falcon-tests-"
        )
        self.original_feature_database_path = (
            soc_features_module.feature_database_path
        )
        feature_database = os.path.join(
            self.temp_dir,
            "soc_features.db",
        )
        soc_features_module.feature_database_path = (
            lambda: feature_database
        )

        database_dir = os.path.join(
            self.temp_dir,
            "database",
        )
        log_dir = os.path.join(
            self.temp_dir,
            "logs",
        )

        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "level-integration-test",
                "DATABASE_DIR": database_dir,
                "DATABASE_PATH": os.path.join(
                    database_dir,
                    "black_falcon.db",
                ),
                "LOG_DIR": log_dir,
                "LOG_FILE": os.path.join(
                    log_dir,
                    "ctf.log",
                ),
                "INVESTIGATION_DIR": os.path.join(
                    PROJECT_ROOT,
                    "investigations",
                ),
                "EVIDENCE_DIR": os.path.join(
                    PROJECT_ROOT,
                    "evidence",
                ),
                "EVIDENCE_FOLDER": os.path.join(
                    PROJECT_ROOT,
                    "evidence",
                ),
                "SOLUTION_STORE_PATH": os.environ.get(
                    "BLACK_FALCON_SOLUTION_STORE",
                    os.path.join(PROJECT_ROOT, "private", "solutions.json"),
                ),
            }
        )
        self.client = self.app.test_client()
        self.login_for_level("medium")

    def tearDown(self):
        soc_features_module.feature_database_path = (
            self.original_feature_database_path
        )

        for handler in list(
            self.app.logger.handlers
        ):
            base_filename = getattr(
                handler,
                "baseFilename",
                "",
            )

            if base_filename.startswith(
                self.temp_dir
            ):
                self.app.logger.removeHandler(
                    handler
                )
                handler.close()

        shutil.rmtree(self.temp_dir)

    def login_for_level(self, level_name):
        with self.client.session_transaction() as user_session:
            user_session["logged_in"] = True
            user_session["username"] = "analyst"
            user_session["role"] = "student"
            user_session["selected_level"] = level_name

    def prepare_validated_flag(self, case_id):
        # Isolate submission behavior using already validated recipe fields.
        findings = {
            "BF-M-001": {"attacker_ip": "192.168.56.104", "target_host": "192.168.56.10"},
            "BF-M-005": {"exfil_domain": "exfil.blackfalcon-c2.local", "exfil_ip": "192.168.56.201"},
            "BF-H-001": {"attacker_ip": "192.168.56.104", "primary_target": "192.168.56.10", "secondary_target": "192.168.56.20"},
            "BF-H-005": {"compromised_account": "admin", "c2_domain": "api.blackfalcon-c2.local", "exfil_destination": "192.168.56.201"},
        }[case_id]
        save_validated_findings("analyst", case_id, findings)
        mark_findings_validated("analyst", case_id)
        return build_case_flag(case_id, findings)

    def complete_cases(self, case_ids):
        with self.app.app_context():
            for case_id in case_ids:
                mark_completed(
                    "analyst",
                    case_id,
                )

    def test_passwords_require_hashes_and_default_user_creation_is_idempotent(self):
        from models import create_default_users
        with self.app.app_context():
            user = get_user("analyst")
            original_hash = user["password"]
            self.assertTrue(verify_user_password(user, "Analyst@123"))
            self.assertFalse(verify_user_password(user, "wrong-password"))
            self.assertFalse(verify_user_password({"password": "Analyst@123"}, "Analyst@123"))
            self.assertFalse(verify_user_password({"password": "scrypt:invalid"}, "anything"))
            create_default_users()
            self.assertEqual(get_user("analyst")["password"], original_hash)

    def test_progress_rejects_duplicate_user_case_rows(self):
        import sqlite3
        with self.app.app_context():
            db = get_db()
            mark_findings_validated("analyst", "BF-M-001")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute(
                    "INSERT INTO progress (username, investigation_id) VALUES (?, ?)",
                    ("analyst", "BF-M-001"),
                )
            db.rollback()

    def test_submission_requires_validation_and_stores_only_hash(self):
        response = self.client.post("/submit-flag", data={
            "investigation_id": "BF-M-001", "flag": "FLAG{UNVALIDATED}",
        })
        self.assertIn(b"Validate the investigation", response.data)
        with self.app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM submissions").fetchone()[0], 0)
            expected_flag = self.prepare_validated_flag("BF-M-001")
        response = self.client.post("/submit-flag", data={
            "investigation_id": "BF-M-001", "flag": expected_flag.lower(),
        })
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            row = get_db().execute("SELECT * FROM submissions").fetchone()
            self.assertEqual(row["submitted_flag"], hash_flag(expected_flag))
            self.assertEqual(row["is_correct"], 1)
            self.assertNotEqual(row["submitted_flag"], expected_flag)

    def test_level_configuration_is_the_single_case_source(self):
        self.assertEqual(
            get_level_cases("medium"),
            [
                "BF-M-001",
                "BF-M-002",
                "BF-M-003",
                "BF-M-004",
                "BF-M-005",
            ],
        )
        self.assertEqual(
            get_case_level("BF-2026-001"),
            "beginner",
        )
        self.assertEqual(
            get_case_level("BF-M-001"),
            "medium",
        )
        self.assertEqual(
            get_level("hard")["difficulty"],
            "Hard",
        )
        self.assertEqual(
            len(get_level("medium")["tools"]),
            5,
        )
        self.assertEqual(len(get_all_cases()), 15)

    def test_medium_progress_does_not_change_beginner_progress(self):
        self.complete_cases(["BF-M-001"])

        with self.app.app_context():
            medium = get_level_progress(
                "analyst",
                "medium",
            )
            beginner = get_level_progress(
                "analyst",
                "beginner",
            )
            overall = get_overall_progress(
                "analyst"
            )

        self.assertEqual(medium["completed"], 1)
        self.assertEqual(medium["total"], 5)
        self.assertEqual(medium["percentage"], 20)
        self.assertEqual(beginner["completed"], 0)
        self.assertEqual(beginner["percentage"], 0)
        self.assertEqual(overall["completed"], 1)
        self.assertEqual(overall["total"], 15)

    def test_beginner_and_generic_medium_dashboards_open(self):
        beginner_response = self.client.get(
            "/level/beginner",
            follow_redirects=True,
        )
        self.assertEqual(beginner_response.status_code, 200)
        self.assertIn(
            b"Security Operations Center",
            beginner_response.data,
        )

        medium_response = self.client.get(
            "/level/medium",
            follow_redirects=True,
        )
        self.assertEqual(medium_response.status_code, 200)

        for case_id in get_level_cases("medium"):
            self.assertIn(
                case_id.encode("utf-8"),
                medium_response.data,
            )

    def test_every_medium_case_and_its_evidence_open(self):
        for case_id in get_level_cases("medium"):
            investigation_response = self.client.get(
                f"/investigations/{case_id}"
            )
            self.assertEqual(
                investigation_response.status_code,
                200,
                case_id,
            )

            with self.app.app_context():
                investigation = load_investigation(
                    case_id
                )

            for resource in investigation["resources"]:
                evidence_response = self.client.get(
                    "/soc/evidence",
                    query_string={
                        "case_id": case_id,
                        "path": resource["path"],
                    },
                )
                self.assertEqual(
                    evidence_response.status_code,
                    200,
                    f"{case_id}: {resource['path']}",
                )

    def test_hard_level_dashboard_uses_shared_layout(self):
        response = self.client.get(
            "/level/hard",
            follow_redirects=True,
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Threat Hunter", page)
        self.assertIn("Silent Reconnaissance", page)
        self.assertIn(
            "Identity Abuse and Lateral Movement",
            page,
        )
        self.assertIn("Web-to-Host Compromise", page)
        self.assertIn("Covert C2 and Data Staging", page)
        self.assertIn("Full Incident Reconstruction", page)
        self.assertIn("BF-H-005", page)
        self.assertIn("THREAT HUNT QUEUE", page)
        self.assertIn("START THREAT HUNT", page)
        self.assertEqual(
            page.count("IN DEVELOPMENT"),
            0,
        )
        self.assertEqual(
            page.count("Classified Investigation"),
            0,
        )
        self.assertRegex(
            page,
            re.compile(r"0\s*/\s*5"),
        )

    def test_generic_level_dashboard_replaces_wrapper_routes(self):
        medium = self.client.get(
            "/level-dashboard/medium"
        )
        hard = self.client.get(
            "/level-dashboard/hard"
        )

        self.assertEqual(medium.status_code, 200)
        self.assertEqual(hard.status_code, 200)
        self.assertEqual(
            self.client.get("/medium").status_code,
            404,
        )
        self.assertEqual(
            self.client.get("/hard").status_code,
            404,
        )

    def test_active_hard_cases_and_all_evidence_resources_open(self):
        self.login_for_level("hard")

        for case_id in (
            "BF-H-001",
            "BF-H-002",
            "BF-H-003",
            "BF-H-004",
            "BF-H-005",
        ):
            with self.app.app_context():
                investigation = load_investigation(
                    case_id
                )

            self.assertIsNotNone(investigation)
            self.assertEqual(
                investigation["level"],
                "hard",
            )

            investigation_response = self.client.get(
                f"/investigations/{case_id}"
            )
            self.assertEqual(
                investigation_response.status_code,
                200,
            )

            for resource in investigation["resources"]:
                evidence_response = self.client.get(
                    "/soc/evidence",
                    query_string={
                        "case_id": case_id,
                        "path": resource["path"],
                    },
                )
                self.assertEqual(
                    evidence_response.status_code,
                    200,
                    resource["path"],
                )

    def test_hard_solution_store_contains_hashes_only(self):
        with open(
            os.path.join(
                PROJECT_ROOT,
                "private",
                "solutions.json",
            ),
            "r",
            encoding="utf-8",
        ) as solution_file:
            solution_store = json.load(
                solution_file
            )

        hard_solution = solution_store[
            "BF-H-001"
        ]

        self.assertEqual(
            set(hard_solution),
            {
                "attacker_ip",
                "primary_target",
                "authorized_scanner",
                "recon_method",
                "secondary_target",
                "first_seen",
            },
        )
        self.assertEqual(
            len(hard_solution["recon_method"]),
            5,
        )

        for accepted_hashes in hard_solution.values():
            for accepted_hash in accepted_hashes:
                self.assertRegex(
                    accepted_hash,
                    re.compile(r"^[a-f0-9]{64}$"),
                )

        lateral_solution = solution_store[
            "BF-H-002"
        ]

        self.assertEqual(
            set(lateral_solution),
            {
                "compromised_account",
                "initial_host",
                "pivot_host",
                "destination_host",
                "lateral_service",
                "legitimate_admin_ip",
            },
        )
        self.assertEqual(
            len(lateral_solution["lateral_service"]),
            2,
        )

        for accepted_hashes in lateral_solution.values():
            for accepted_hash in accepted_hashes:
                self.assertRegex(
                    accepted_hash,
                    re.compile(r"^[a-f0-9]{64}$"),
                )

        web_host_solution = solution_store[
            "BF-H-003"
        ]

        self.assertEqual(
            set(web_host_solution),
            {
                "attacker_ip",
                "exploit_endpoint",
                "exploit_type",
                "executed_command",
                "payload",
                "execution_user",
            },
        )
        self.assertEqual(
            len(web_host_solution["exploit_type"]),
            3,
        )
        self.assertEqual(
            len(web_host_solution["payload"]),
            2,
        )

        for accepted_hashes in web_host_solution.values():
            for accepted_hash in accepted_hashes:
                self.assertRegex(
                    accepted_hash,
                    re.compile(r"^[a-f0-9]{64}$"),
                )

        covert_c2_solution = solution_store[
            "BF-H-004"
        ]

        self.assertEqual(
            set(covert_c2_solution),
            {
                "compromised_host",
                "c2_domain",
                "c2_ip",
                "beacon_interval",
                "staging_directory",
                "staged_archive",
                "collected_data",
            },
        )
        self.assertEqual(
            len(covert_c2_solution["beacon_interval"]),
            4,
        )
        self.assertEqual(
            len(covert_c2_solution["staging_directory"]),
            2,
        )
        self.assertEqual(
            len(covert_c2_solution["collected_data"]),
            4,
        )

        for accepted_hashes in covert_c2_solution.values():
            for accepted_hash in accepted_hashes:
                self.assertRegex(
                    accepted_hash,
                    re.compile(r"^[a-f0-9]{64}$"),
                )

        reconstruction_solution = solution_store[
            "BF-H-005"
        ]

        self.assertEqual(
            set(reconstruction_solution),
            {
                "attacker_ip",
                "compromised_account",
                "pivot_path",
                "host_execution",
                "c2_domain",
                "staged_archive",
                "exfil_destination",
                "exfil_method",
                "incident_start",
            },
        )
        self.assertEqual(
            len(reconstruction_solution["pivot_path"]),
            5,
        )
        self.assertEqual(
            len(reconstruction_solution["host_execution"]),
            3,
        )
        self.assertEqual(
            len(reconstruction_solution["exfil_method"]),
            4,
        )

        for accepted_hashes in reconstruction_solution.values():
            for accepted_hash in accepted_hashes:
                self.assertRegex(
                    accepted_hash,
                    re.compile(r"^[a-f0-9]{64}$"),
                )

    def test_hard_003_accepts_documented_answer_variants(self):
        self.login_for_level("hard")

        response = self.client.post(
            "/investigations/BF-H-003",
            data={
                "attacker_ip": "192.168.56.104",
                "exploit_endpoint": "api/export",
                "exploit_type": "OS command injection",
                "executed_command": "whoami",
                "payload": "/tmp/bfstage.sh",
                "execution_user": "www-data",
            },
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Findings Validated", page)

    def test_hard_004_accepts_documented_answer_variants(self):
        self.login_for_level("hard")

        response = self.client.post(
            "/investigations/BF-H-004",
            data={
                "compromised_host": "192.168.56.21",
                "c2_domain": "api.blackfalcon-c2.local",
                "c2_ip": "192.168.56.200",
                "beacon_interval": "every 90 seconds",
                "staging_directory": "/var/tmp/.bfcache",
                "staged_archive": (
                    "/var/tmp/.bfcache/ops_backup.tar.gz"
                ),
                "collected_data": (
                    "customers.db, transactions.csv"
                ),
            },
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Findings Validated", page)

    def test_hard_005_accepts_documented_answer_variants(self):
        self.login_for_level("hard")

        response = self.client.post(
            "/investigations/BF-H-005",
            data={
                "attacker_ip": "192.168.56.104",
                "compromised_account": "admin",
                "pivot_path": (
                    "192.168.56.10 -> 192.168.56.20 "
                    "-> 192.168.56.21"
                ),
                "host_execution": "shell command injection",
                "c2_domain": "api.blackfalcon-c2.local",
                "staged_archive": (
                    "/var/tmp/.bfcache/ops_backup.tar.gz"
                ),
                "exfil_destination": "192.168.56.201",
                "exfil_method": "HTTPS POST",
                "incident_start": "10:04:11",
            },
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Findings Validated", page)

    def test_hard_progress_is_independent_and_uses_five_case_total(self):
        self.complete_cases(["BF-H-001"])

        with self.app.app_context():
            hard = get_level_progress(
                "analyst",
                "hard",
            )
            medium = get_level_progress(
                "analyst",
                "medium",
            )

        self.assertEqual(hard["completed"], 1)
        self.assertEqual(hard["total"], 5)
        self.assertEqual(hard["percentage"], 20)
        self.assertEqual(medium["completed"], 0)

        self.login_for_level("hard")
        page = self.client.get(
            "/level-dashboard/hard"
        ).get_data(as_text=True)
        self.assertRegex(
            page,
            re.compile(r"1\s*/\s*5"),
        )
        self.assertIn("20% complete", page)

    def test_one_medium_case_renders_one_of_five_and_twenty_percent(self):
        self.complete_cases(["BF-M-001"])
        response = self.client.get(
            "/level-dashboard/medium"
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertRegex(
            page,
            re.compile(r"1\s*/\s*5"),
        )
        self.assertIn("20% complete", page)

    def test_wrong_flag_does_not_leak_expected_flag(self):
        with self.app.app_context():
            mark_findings_validated(
                "analyst",
                "BF-M-001",
            )
            expected_flag = self.prepare_validated_flag(
                "BF-M-001"
            )

        response = self.client.post(
            "/submit-flag",
            data={
                "investigation_id": "BF-M-001",
                "flag": "definitely-wrong",
            },
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Incorrect flag", page)
        self.assertNotIn(expected_flag, page)

    def test_wrong_findings_do_not_leak_expected_flag(self):
        for case_id in (
            "BF-M-001",
            "BF-H-001",
        ):
            with self.app.app_context():
                investigation = load_investigation(
                    case_id
                )
                expected_flag = "FLAG{DEFINITELY-WRONG}"

            wrong_answers = {
                question["field"]: "definitely-wrong"
                for question in investigation["questions"]
            }
            response = self.client.post(
                f"/investigations/{case_id}",
                data=wrong_answers,
            )
            page = response.get_data(as_text=True)

            self.assertEqual(response.status_code, 200)
            self.assertIn(
                "Some findings are incorrect",
                page,
            )
            self.assertNotIn(expected_flag, page)
            self.assertNotIn("Findings Validated", page)

    def test_final_medium_flag_redirects_to_medium_completion(self):
        self.complete_cases(
            get_level_cases("medium")[:-1]
        )

        with self.app.app_context():
            mark_findings_validated(
                "analyst",
                "BF-M-005",
            )
            expected_flag = self.prepare_validated_flag(
                "BF-M-005"
            )

        response = self.client.post(
            "/submit-flag",
            data={
                "investigation_id": "BF-M-005",
                "flag": expected_flag,
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response.location.endswith(
                "/level-completed/medium"
            )
        )

        completion = self.client.get(
            response.location
        )
        self.assertIn(
            b"Medium Completed",
            completion.data,
        )

    def test_final_hard_flag_redirects_to_hard_completion(self):
        self.login_for_level("hard")
        self.complete_cases(
            get_level_cases("hard")[:-1]
        )

        with self.app.app_context():
            mark_findings_validated(
                "analyst",
                "BF-H-005",
            )
            expected_flag = self.prepare_validated_flag(
                "BF-H-005"
            )

        response = self.client.post(
            "/submit-flag",
            data={
                "investigation_id": "BF-H-005",
                "flag": expected_flag,
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response.location.endswith(
                "/level-completed/hard"
            )
        )

        completion = self.client.get(
            response.location
        )
        self.assertIn(
            b"Hard Completed",
            completion.data,
        )

        certificate = self.client.get(
            "/soc/certificate/hard"
        )
        certificate_page = certificate.get_data(
            as_text=True
        )
        self.assertEqual(certificate.status_code, 200)
        self.assertIn("HARD", certificate_page)
        self.assertIn("Threat Hunter", certificate_page)
        self.assertIn("5 / 5", certificate_page)
        self.assertIn("TRACK COMPLETE", certificate_page)

    def test_medium_certificate_is_track_specific(self):
        self.complete_cases(
            get_level_cases("medium")
        )

        response = self.client.get(
            "/soc/certificate/medium"
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("MEDIUM", page)
        self.assertIn("SOC Analyst", page)
        self.assertIn("5 / 5", page)
        self.assertIn("TRACK COMPLETE", page)

        beginner_certificate = self.client.get(
            "/soc/certificate/beginner"
        )
        self.assertEqual(
            beginner_certificate.status_code,
            403,
        )

    def test_final_certificate_requires_all_cases_and_report(
        self,
    ):
        all_cases = get_all_cases()
        self.complete_cases(
            all_cases[:-1]
        )

        locked = self.client.get(
            "/soc/certificate"
        )
        self.assertEqual(
            locked.status_code,
            403,
        )

        self.complete_cases(
            [all_cases[-1]]
        )

        # Completing all fifteen cases alone should
        # not yet unlock the overall certificate.
        report_required = self.client.get(
            "/soc/certificate"
        )
        self.assertEqual(
            report_required.status_code,
            403,
        )

        # The final report is now available.
        report = self.client.get(
            "/soc/report"
        )
        self.assertEqual(report.status_code, 200)
        submitted = self.client.post(
            "/soc/report",
            follow_redirects=True,
        )
        self.assertEqual(submitted.status_code, 200)
        self.assertIn(b"Final report submitted", submitted.data)

        response = self.client.get("/soc/certificate")
        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "ADVANCED SOC INVESTIGATION PROGRAM",
            page,
        )
        self.assertIn("15 / 15", page)
        self.assertIn("PROGRAM COMPLETE", page)

    def test_final_report_requires_all_fifteen_cases(self):
        all_cases = get_all_cases()
        self.complete_cases(all_cases[:-1])

        locked = self.client.get(
            "/soc/report"
        )
        self.assertEqual(locked.status_code, 403)

        self.complete_cases([all_cases[-1]])

        response = self.client.get(
            "/soc/report"
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("FULL 15-CASE PROGRAM", page)
        self.assertIn("15", page)


if __name__ == "__main__":
    unittest.main()
