"""Per-analyst alert triage, incident reports, and evidence-based assessment."""

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Blueprint, abort, flash, redirect, render_template, request, session, url_for,
)

from database import get_db
from investigation_loader import load_investigation
from level_config import get_all_cases
from routes.assessment_scoring import (
    MIN_REPORT_LENGTH, REPORT_FIELDS,
    calculate_assessment_status, calculate_report_completion,
)
from solution_store import hash_answer, load_solution_store


operations_bp = Blueprint("operations", __name__)
SEVERITIES = ("Critical", "High", "Medium", "Low")
VERDICTS = ("True Positive", "False Positive", "Inconclusive")
STATUSES = ("New", "Investigating", "Escalated", "Resolved")
RESPONSES = (
    "Monitor", "Block malicious IP", "Isolate affected host",
    "Disable compromised account", "Escalate to incident response", "No action required",
)
ASSESSMENT_FIELDS = REPORT_FIELDS
MAX_TEXT = 3000


def initialize_operations(db):
    """Add independent tables without modifying challenge progress or submissions."""
    db.execute("""
        CREATE TABLE IF NOT EXISTS operations_triage (
            username TEXT NOT NULL,
            case_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            verdict TEXT NOT NULL,
            status TEXT NOT NULL,
            response TEXT NOT NULL,
            findings TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (username, case_id)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS operations_assessments (
            username TEXT NOT NULL,
            case_id TEXT NOT NULL,
            report_json TEXT NOT NULL,
            answers_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('Draft', 'Submitted')),
            completion_score INTEGER NOT NULL CHECK (completion_score BETWEEN 0 AND 100),
            accuracy_score INTEGER CHECK (accuracy_score BETWEEN 0 AND 100),
            feedback_json TEXT NOT NULL,
            rubric_version TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (username, case_id)
        )
    """)
    db.commit()


def analyst_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("logged_in") is not True or not session.get("username"):
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def require_case(case_id):
    if case_id not in get_all_cases():
        abort(404)
    investigation = load_investigation(case_id)
    if not investigation:
        abort(404)
    return investigation


def csrf_token():
    if "operations_csrf" not in session:
        session["operations_csrf"] = secrets.token_urlsafe(32)
    return session["operations_csrf"]


def validate_csrf():
    token = request.form.get("csrf_token", "")
    expected = session.get("operations_csrf", "")
    if not expected or len(token) > 128 or not hmac.compare_digest(token.encode(), expected.encode()):
        abort(403)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_text(name, errors):
    value = request.form.get(name, "").strip()
    if len(value) > MAX_TEXT:
        errors.append(f"{name.replace('_', ' ').title()} must be at most {MAX_TEXT} characters.")
    return value


def score_assessment(case_id, questions, answers):
    """Grade explicit factual answers against the existing protected case rubric.

    Narrative quality is not graded. A missing rubric makes accuracy unavailable,
    rather than reducing the denominator or awarding credit for missing answers.
    """
    store = load_solution_store()
    case_rubric = store.get(case_id, {}) if isinstance(store, dict) else {}
    if not isinstance(case_rubric, dict):
        case_rubric = {}
    feedback = []
    version_data = []
    for question in questions:
        field = question["field"]
        accepted = case_rubric.get(field, [])
        configured = (
            isinstance(accepted, list) and bool(accepted)
            and all(isinstance(value, str) and len(value) == 64
                    and all(char in "0123456789abcdef" for char in value) for value in accepted)
        )
        correct = configured and bool(answers.get(field, "").strip()) and any(
            hmac.compare_digest(hash_answer(answers[field]), expected) for expected in accepted
        )
        feedback.append({
            "field": field, "label": question["label"],
            "result": "Correct" if correct else "Review evidence" if configured else "Unavailable",
        })
        version_data.append((field, accepted if configured else []))
    version = hashlib.sha256(json.dumps(version_data, sort_keys=True).encode()).hexdigest()
    available = bool(feedback) and all(item["result"] != "Unavailable" for item in feedback)
    accuracy = round(100 * sum(item["result"] == "Correct" for item in feedback) / len(feedback)) if available else None
    return accuracy, feedback, version


def render_triage(overrides=None, errors=None, code=200):
    saved = {
        row["case_id"]: dict(row) for row in get_db().execute(
            "SELECT * FROM operations_triage WHERE username = ?", (session["username"],)
        )
    }
    if overrides:
        saved.update(overrides)
    return render_template(
        "soc_triage.html", cases=get_all_cases(), saved=saved, token=csrf_token(),
        severities=SEVERITIES, verdicts=VERDICTS, statuses=STATUSES, responses=RESPONSES,
        errors=errors or [],
    ), code


@operations_bp.route("/soc/triage")
@analyst_required
def triage_dashboard():
    return render_triage()


@operations_bp.route("/soc/triage/<case_id>", methods=["POST"])
@analyst_required
def save_triage(case_id):
    require_case(case_id)
    validate_csrf()
    errors = []
    item = {}
    for field, choices in (("severity", SEVERITIES), ("verdict", VERDICTS), ("status", STATUSES), ("response", RESPONSES)):
        item[field] = request.form.get(field, "")
        if item[field] not in choices:
            errors.append(f"Choose a valid {field}.")
    item["findings"] = read_text("findings", errors)
    if not item["findings"]:
        errors.append("Investigation findings are required.")
    if errors:
        return render_triage({case_id: item}, errors, 400)
    with get_db() as db:
        db.execute("""
            INSERT INTO operations_triage
                (username, case_id, severity, verdict, status, response, findings, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username, case_id) DO UPDATE SET
                severity=excluded.severity, verdict=excluded.verdict, status=excluded.status,
                response=excluded.response, findings=excluded.findings, updated_at=excluded.updated_at
        """, (session["username"], case_id, item["severity"], item["verdict"], item["status"],
              item["response"], item["findings"], utc_now()))
    flash(f"Alert triage saved for {case_id}.", "success")
    return redirect(url_for("operations.triage_dashboard", _anchor=case_id))


@operations_bp.route("/soc/assessment", methods=["GET"])
@analyst_required
def assessment_dashboard():
    assessment_status = calculate_assessment_status(session["username"], get_db())
    return render_template("soc_assessment.html", min_report_length=MIN_REPORT_LENGTH, **assessment_status)


@operations_bp.route("/soc/assessment/<case_id>", methods=["GET", "POST"])
@analyst_required
def assessment(case_id):
    investigation = require_case(case_id)
    questions = investigation.get("questions", [])
    existing = get_db().execute(
        "SELECT * FROM operations_assessments WHERE username = ? AND case_id = ?",
        (session["username"], case_id),
    ).fetchone()
    report = json.loads(existing["report_json"]) if existing else {}
    answers = json.loads(existing["answers_json"]) if existing else {}
    feedback = json.loads(existing["feedback_json"]) if existing else []
    errors = []
    if request.method == "POST":
        validate_csrf()
        action = request.form.get("action", "submit")
        if action not in ("draft", "submit"):
            errors.append("Choose Save Draft or Submit Investigation Report.")
        report = {field: read_text(field, errors) for field in ASSESSMENT_FIELDS}
        answers = {question["field"]: read_text("answer_" + question["field"], errors) for question in questions}
        completion = calculate_report_completion(report)
        if action == "submit":
            if completion != 100:
                errors.append(
                    "Complete all eight investigation sections. "
                    f"Each answer must contain at least {MIN_REPORT_LENGTH} characters."
                )
            if not all(answers.values()):
                errors.append("Complete all evidence findings before submitting, or save a draft.")
        if not errors:
            accuracy, feedback, version = score_assessment(case_id, questions, answers)
            status = "Submitted" if action == "submit" else "Draft"
            with get_db() as db:
                db.execute("""
                    INSERT INTO operations_assessments
                        (username, case_id, report_json, answers_json, status, completion_score,
                         accuracy_score, feedback_json, rubric_version, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(username, case_id) DO UPDATE SET
                        report_json=excluded.report_json, answers_json=excluded.answers_json,
                        status=excluded.status, completion_score=excluded.completion_score,
                        accuracy_score=excluded.accuracy_score, feedback_json=excluded.feedback_json,
                        rubric_version=excluded.rubric_version, updated_at=excluded.updated_at
                """, (session["username"], case_id, json.dumps(report), json.dumps(answers), status,
                      completion, accuracy, json.dumps(feedback), version, utc_now()))
            flash(f"Incident report {'submitted' if action == 'submit' else 'draft saved'} for {case_id}.", "success")
            return redirect(url_for("operations.assessment", case_id=case_id))
    return render_template(
        "soc_assessment_form.html", case_id=case_id, investigation=investigation,
        fields=ASSESSMENT_FIELDS, report=report, answers=answers, questions=questions,
        token=csrf_token(), errors=errors, saved=dict(existing) if existing else None, feedback=feedback,
        min_report_length=MIN_REPORT_LENGTH,
    ), 400 if errors else 200
