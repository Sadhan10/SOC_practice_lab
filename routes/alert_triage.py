"""Individual security alert triage for Operation Black Falcon."""

import hashlib
import json
import re

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for

from database import get_db
from level_config import get_all_cases
from routes.siem import iter_events
from routes.soc_operations import analyst_required, csrf_token, utc_now, validate_csrf


alert_triage_bp = Blueprint("alert_triage", __name__)
ALERT_SOURCES = ("wazuh", "suricata")
VERDICTS = ("True Positive", "False Positive", "Inconclusive")
PRIORITIES = ("Critical", "High", "Medium", "Low")
STATUSES = ("New", "Investigating", "Escalated", "Resolved")
ACTIONS = (
    "Continue monitoring", "Block suspicious IP", "Isolate affected endpoint",
    "Disable compromised account", "Escalate to incident response", "No further action",
)
MAX_VISIBLE = 100


def initialize_alert_triage(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS soc_alert_triage (
            username TEXT NOT NULL,
            case_id TEXT NOT NULL,
            alert_id TEXT NOT NULL,
            verdict TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL,
            response_action TEXT NOT NULL,
            findings TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (username, case_id, alert_id)
        )
    """)
    db.commit()


def alert_events(case_id, source="", scan_status=None):
    """Identify the complete evidence entry, including its original location."""
    for category in (source,) if source else ALERT_SOURCES:
        for event in iter_events(category, case_id, scan_status):
            if event["source"] not in ALERT_SOURCES:
                continue
            if event["source"] == "suricata" and event.get("event_type") != "alert":
                continue
            identity = [case_id, event["relative_path"], event["line"], event["search_text"]]
            event["alert_id"] = hashlib.sha256(
                json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            # The SIEM preview is shortened; the investigation needs the full entry.
            event["raw"] = event.pop("search_text")
            yield event


@alert_triage_bp.route("/soc/alerts")
@analyst_required
def alert_queue():
    cases = get_all_cases()
    case_id = request.args.get("case", cases[0]).strip().upper()
    if case_id not in cases:
        abort(404)
    source = request.args.get("source", "").strip().lower()
    if source and source not in ALERT_SOURCES:
        abort(400)
    events = []
    scan_status = {}
    for event in alert_events(case_id, source, scan_status):
        if len(events) == MAX_VISIBLE:
            scan_status["limited"] = True
            break
        events.append(event)
    saved = {
        row["alert_id"]: dict(row) for row in get_db().execute(
            "SELECT * FROM soc_alert_triage WHERE username = ? AND case_id = ?",
            (session["username"], case_id),
        )
    }
    return render_template(
        "soc_alert_queue.html", cases=cases, case_id=case_id, source=source,
        events=events, saved=saved, limit=MAX_VISIBLE, limited=scan_status.get("limited", False),
    )


@alert_triage_bp.route("/soc/alerts/<case_id>/<alert_id>", methods=["GET", "POST"])
@analyst_required
def alert_detail(case_id, alert_id):
    if case_id not in get_all_cases() or not re.fullmatch(r"[0-9a-f]{64}", alert_id):
        abort(404)
    if request.method == "POST":
        validate_csrf()
    event = next((item for item in alert_events(case_id) if item["alert_id"] == alert_id), None)
    if event is None:
        abort(404)
    existing = get_db().execute(
        "SELECT * FROM soc_alert_triage WHERE username = ? AND case_id = ? AND alert_id = ?",
        (session["username"], case_id, alert_id),
    ).fetchone()
    saved = dict(existing) if existing else {}
    errors = []
    if request.method == "POST":
        for field, choices in (("verdict", VERDICTS), ("priority", PRIORITIES),
                               ("status", STATUSES), ("response_action", ACTIONS)):
            saved[field] = request.form.get(field, "")
            if saved[field] not in choices:
                errors.append(f"Choose a valid {field.replace('_', ' ')}.")
        saved["findings"] = request.form.get("findings", "").strip()
        if not 20 <= len(saved["findings"]) <= 3000:
            errors.append("Investigation findings must contain between 20 and 3000 characters.")
        if not errors:
            with get_db() as db:
                db.execute("""
                    INSERT INTO soc_alert_triage
                        (username, case_id, alert_id, verdict, priority, status,
                         response_action, findings, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(username, case_id, alert_id) DO UPDATE SET
                        verdict=excluded.verdict, priority=excluded.priority,
                        status=excluded.status, response_action=excluded.response_action,
                        findings=excluded.findings, updated_at=excluded.updated_at
                """, (session["username"], case_id, alert_id, saved["verdict"], saved["priority"],
                      saved["status"], saved["response_action"], saved["findings"], utc_now()))
            flash("Alert triage saved.", "success")
            return redirect(url_for("alert_triage.alert_detail", case_id=case_id, alert_id=alert_id))
    return render_template(
        "soc_alert_detail.html", case_id=case_id, event=event, saved=saved, errors=errors,
        token=csrf_token(), verdicts=VERDICTS, priorities=PRIORITIES, statuses=STATUSES, actions=ACTIONS,
    ), 400 if errors else 200
