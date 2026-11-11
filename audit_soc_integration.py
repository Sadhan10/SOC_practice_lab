"""Structural SOC audit. Defaults to disposable databases, never learner data."""
import argparse
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REQUIRED_FILES = (
    "routes/siem.py", "routes/wazuh_parser.py", "routes/soc_operations.py",
    "routes/assessment_scoring.py", "routes/soc_labs.py", "routes/alert_triage.py",
    "routes/final_soc_challenge.py", "templates/siem.html", "templates/soc_triage.html",
    "templates/soc_assessment.html", "templates/soc_assessment_form.html",
    "templates/soc_labs.html", "templates/soc_lab_detail.html",
    "templates/soc_alert_queue.html", "templates/soc_alert_detail.html",
    "templates/final_soc_challenge.html", "templates/final_soc_result.html", "static/css/siem.css",
    "templates/_bf_h_005_chronology_advisory.html",
    "certificate_generator.py", "routes/soc_certificates.py", "templates/soc_certificate.html",
    "certificate_templates/certificate_of_completion.docx",
    "auth_limits.py", "routes/student_registration.py",
    "templates/student_register.html", "templates/student_profile.html",
)
REQUIRED_BLUEPRINTS = {
    "auth", "dashboard", "investigations", "flags", "evidence", "bank", "soc_features",
    "siem", "operations", "labs", "alert_triage", "final_soc", "soc_certificates", "registration",
}
REQUIRED_ENDPOINTS = {
    "siem.search_events", "operations.triage_dashboard", "operations.save_triage",
    "operations.assessment_dashboard", "operations.assessment", "labs.index", "labs.view_lab",
    "alert_triage.alert_queue", "alert_triage.alert_detail", "final_soc.challenge",
    "final_soc.submit", "final_soc.result", "final_soc.export_results",
    "investigations.investigation_detail", "evidence.evidence",
    "evidence.download_evidence", "evidence.timeline",
    "soc_certificates.certificate_page", "soc_certificates.preview_certificate",
    "soc_certificates.issue_certificate", "soc_certificates.download_certificate",
    "registration.register", "registration.profile",
}
REQUIRED_TABLES = {
    "users": {"username", "password", "role"},
    "progress": {"username", "investigation_id", "findings_validated", "completed"},
    "submissions": {"username", "investigation_id"},
    "validated_findings": {"username", "investigation_id"},
    "operations_triage": {"username", "case_id", "findings"},
    "operations_assessments": {"username", "case_id", "report_json", "status"},
    "soc_alert_triage": {"username", "case_id", "alert_id", "findings"},
    "final_soc_attempts": {"username", "case_id", "answers_json", "feedback_json", "score", "percentage", "passed"},
    "soc_certificates": {"certificate_id", "username", "student_name", "score",
                         "source_attempt_id", "issued_at", "pdf_blob", "pdf_sha256"},
    "student_profiles": {"username", "full_name", "created_at", "name_locked"},
    "auth_rate_limits": {"scope", "bucket_hash", "attempts", "expires_at"},
}


def timeline_findings(root=ROOT):
    """Compare candidate cross-source anchors without modifying original evidence."""
    anchors = []
    alerts_path = root / "evidence/suricata/BF-H-005_eve.json"
    http_path = root / "evidence/zeek/BF-H-005_http.log"
    alerts = [json.loads(line) for line in alerts_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    references = {item["alert"]["signature"]: datetime.fromisoformat(item["timestamp"]) for item in alerts}
    records = {}
    fields = None
    for line in http_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line and not line.startswith("#") and fields:
            item = dict(zip(fields, line.split("\t")))
            records[item["uid"]] = item
    for uid, signature in (
        ("H02", "ET WEB_SERVER Possible Command Injection"),
        ("H05", "ET MALWARE Suspicious Periodic HTTPS Beacon"),
        ("H06", "ET POLICY Unusually Large Outbound HTTPS POST"),
    ):
        observed = datetime.fromtimestamp(float(Decimal(records[uid]["ts"])), timezone.utc)
        expected = references[signature]
        calendar_aligned = observed.replace(year=expected.year)
        anchors.append({"zeek_uid": uid, "zeek_time_utc": observed.isoformat(),
                        "suricata_time": expected.isoformat(), "year_difference": expected.year - observed.year,
                        "clock_difference_seconds_after_year_alignment": round((calendar_aligned - expected).total_seconds(), 3)})
    return anchors


def audit_app(app, root=ROOT):
    from database import get_db
    from routes.final_soc_challenge import QUESTIONS, public_questions, pass_percentage
    report = {"errors": [], "warnings": [], "checks": [], "timeline": []}
    def check(condition, message):
        report["checks"].append(message)
        if not condition:
            report["errors"].append(message)
    for relative in REQUIRED_FILES:
        path = root
        valid = True
        for component in relative.split("/"):
            if not path.is_dir() or component not in {item.name for item in path.iterdir()}:
                valid = False
                break
            path /= component
        check(valid and path.is_file(), "Required file with exact casing: " + relative)
    check(REQUIRED_BLUEPRINTS <= set(app.blueprints), "Original and SOC blueprints registered")
    endpoints = {rule.endpoint: rule for rule in app.url_map.iter_rules()}
    for endpoint in sorted(REQUIRED_ENDPOINTS):
        check(endpoint in endpoints, "Registered endpoint: " + endpoint)
    for endpoint in ("final_soc.submit", "operations.save_triage", "operations.assessment", "alert_triage.alert_detail",
                     "soc_certificates.preview_certificate", "soc_certificates.issue_certificate", "registration.register"):
        check(endpoint in endpoints and "POST" in endpoints[endpoint].methods, "POST method: " + endpoint)
    for name in (relative for relative in REQUIRED_FILES if relative.startswith("templates/")):
        try:
            app.jinja_env.get_template(name.removeprefix("templates/"))
        except Exception as error:
            report["errors"].append("Template compilation: " + name + " (" + type(error).__name__ + ")")
    with app.app_context():
        db = get_db()
        tables = {row["name"] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table, columns in REQUIRED_TABLES.items():
            actual = {row["name"] for row in db.execute("PRAGMA table_info(" + table + ")")}
            check(table in tables and columns <= actual, "Database table and columns: " + table)
        check(len(QUESTIONS) == 7 and [q["weight"] for q in QUESTIONS] == [16] * 5 + [10, 10],
              "Seven questions weighted 16/16/16/16/16/10/10")
        check(sum(q["weight"] for q in QUESTIONS) == 100, "Assessment marks total 100")
        try:
            check(pass_percentage() == 70, "Configured pass percentage is 70")
        except ValueError:
            check(False, "Configured pass percentage is 70")
        check(all(not ({"answer", "expected", "evidence", "files"} & set(q)) for q in public_questions()),
              "Public questions omit private rubric")
        mode = app.config.get("FINAL_SOC_SHOW_ANSWERS", False)
        check(type(mode) is bool, "Assessment disclosure configuration is boolean")
        if mode is True:
            report["warnings"].append("Practice mode is enabled; expected answers are disclosed after submission.")
    try:
        report["timeline"] = timeline_findings(root)
        if any(item["year_difference"] or abs(item["clock_difference_seconds_after_year_alignment"]) > 1 for item in report["timeline"]):
            report["warnings"].append(
                "BF-H-005 Zeek timestamps disagree with Suricata by calendar year and clock time. "
                "Cross-source anchor matches require review; do not rewrite evidence using an assumed uniform offset. "
                "Use Wazuh/Suricata for grading until the training dataset is reconciled.")
    except (OSError, ValueError, KeyError, TypeError) as error:
        report["errors"].append("Evidence chronology comparison failed: " + type(error).__name__)
    report["ok"] = not report["errors"]
    report["release_ready"] = not report["errors"] and not report["warnings"]
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, help="Optional DEVELOPMENT COPY of the main SQLite database; startup initializes missing tables.")
    parser.add_argument("--json", action="store_true", help="Print a machine-readable report.")
    parser.add_argument("--strict-release", action="store_true", help="Exit 2 when release warnings remain; errors always exit 1.")
    args = parser.parse_args(argv)
    from app import create_app
    with tempfile.TemporaryDirectory(prefix="black-falcon-audit-") as folder:
        runtime = Path(folder)
        database = args.database.resolve() if args.database else runtime / "audit.db"
        configuration = {
            "SECRET_KEY": os.environ.get("BLACK_FALCON_SECRET_KEY") or secrets.token_urlsafe(32),
            "DATABASE_DIR": str(database.parent), "DATABASE_PATH": str(database),
            "LOG_DIR": str(runtime / "logs"), "LOG_FILE": str(runtime / "logs/audit.log"),
            "SOC_FEATURE_DATABASE_PATH": str(runtime / "features.db"),
        }
        app = None
        try:
            app = create_app(configuration)
            report = audit_app(app)
        except Exception as error:
            report = {"ok": False, "release_ready": False, "errors": ["Audit initialization failed: " + type(error).__name__],
                      "warnings": [], "checks": [], "timeline": []}
        finally:
            if app:
                for handler in list(app.logger.handlers):
                    if getattr(handler, "baseFilename", "").startswith(str(runtime)):
                        app.logger.removeHandler(handler)
                        handler.close()
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("Operation Black Falcon - SOC structural integration audit")
            print("Database scope:", "explicit development copy" if args.database else "disposable audit databases")
            print("Checks:", len(report["checks"]), "Errors:", len(report["errors"]), "Warnings:", len(report["warnings"]))
            for message in report["errors"]:
                print("ERROR:", message)
            for message in report["warnings"]:
                print("WARNING:", message)
            print("Structural audit:", "PASS" if report["ok"] else "FAIL")
            print("Release readiness:", "PASS" if report["release_ready"] else "REVIEW REQUIRED")
            print("Structural checks do not replace regression, browser, persistence, or Ubuntu/OVA validation.")
        return 1 if report["errors"] else 2 if args.strict_release and report["warnings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
