"""Read-only assessment status from report content and verified case progress."""

import json

from level_config import get_all_cases
from models import get_progress


REPORT_FIELDS = (
    "incident_summary", "entry_point", "affected_assets", "indicators",
    "attack_sequence", "impact", "containment", "recovery",
)
MIN_REPORT_LENGTH = 20


def calculate_report_completion(report):
    """Count sections meeting the minimum length, without grading correctness."""
    if not isinstance(report, dict):
        return 0
    completed = sum(
        isinstance(report.get(field), str) and len(report[field].strip()) >= MIN_REPORT_LENGTH
        for field in REPORT_FIELDS
    )
    return round(completed * 100 / len(REPORT_FIELDS))


def calculate_assessment_status(username, db):
    """Combine this analyst's saved reports with canonical findings/flag progress.

    Report accuracy scores and client-provided scores cannot verify a challenge.
    Drafts remain pending even if all narrative sections have been filled in.
    This function does not change challenge progress or report records.
    """
    progress = get_progress(username)
    reports = {
        row["case_id"]: row for row in db.execute(
            "SELECT case_id, report_json, status FROM operations_assessments WHERE username = ?",
            (username,),
        )
    }
    cases = []
    for case_id in get_all_cases():
        saved = reports.get(case_id)
        report = {}
        if saved is not None:
            try:
                report = json.loads(saved["report_json"])
            except (TypeError, ValueError, RecursionError):
                pass
        completion = calculate_report_completion(report)
        submitted = saved is not None and saved["status"] == "Submitted"
        verified = progress.get(case_id, {})
        findings_verified = verified.get("findings_validated") == 1
        flag_verified = verified.get("completed") == 1
        cases.append({
            "case_id": case_id,
            "report_completion": completion,
            "report_submitted": submitted,
            "findings_verified": findings_verified,
            "flag_verified": flag_verified,
            "assessment_passed": submitted and completion == 100 and findings_verified and flag_verified,
        })
    total = len(cases)
    passed = sum(item["assessment_passed"] for item in cases)
    return {
        "cases": cases, "total": total, "passed": passed, "remaining": total - passed,
        "percentage": round(passed * 100 / total) if total else 0,
    }
