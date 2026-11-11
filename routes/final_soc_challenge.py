"""Independent, graded BF-H-005 training assessment."""

import csv
import io
import json

from flask import Blueprint, abort, current_app, has_app_context, make_response, redirect, render_template, request, session, url_for

from database import get_db
from routes.soc_operations import analyst_required, csrf_token, utc_now, validate_csrf


final_soc_bp = Blueprint("final_soc", __name__)
CASE_ID = "BF-H-005"
PASS_PERCENTAGE = 70
PASSING_SCORE = PASS_PERCENTAGE  # Keep compatibility with existing imports.
QUESTIONS = (
    {
        "id": "q1", "weight": 16, "title": "Initial Reconnaissance",
        "prompt": "Which IP address originated the suspicious port scanning activity?",
        "options": (("a", "192.168.56.10"), ("b", "192.168.56.104"),
                    ("c", "192.168.56.21"), ("d", "192.168.56.200")),
        "answer": "b",
        "evidence": "Suricata records a TCP port sweep from 192.168.56.104; Zeek connection entries R01–R05 show that source probing multiple ports.",
        "files": ("suricata/BF-H-005_eve.json", "zeek/BF-H-005_conn.log"),
    },
    {
        "id": "q2", "weight": 16, "title": "Compromised Identity",
        "prompt": "Which account was used for successful password authentication from the scanning source and subsequent remote logins?",
        "options": (("a", "backup"), ("b", "www-data"), ("c", "admin"), ("d", "root")),
        "answer": "c",
        "evidence": "Authentication records show accepted password logins for admin from 192.168.56.104, then from the application and API hosts. Wazuh records the same account.",
        "files": ("system/BF-H-005_auth.log", "wazuh/BF-H-005_wazuh_alerts.log"),
    },
    {
        "id": "q3", "weight": 16, "title": "Lateral Movement",
        "prompt": "Which internal host sequence matches the observed pivot path after the attacker's first successful login?",
        "options": (("a", "192.168.56.10 → 192.168.56.20 → 192.168.56.21"),
                    ("b", "192.168.56.21 → 192.168.56.20 → 192.168.56.10"),
                    ("c", "192.168.56.10 → 192.168.56.30 → 192.168.56.200"),
                    ("d", "192.168.56.104 → 192.168.56.201 → 192.168.56.30")),
        "answer": "a",
        "evidence": "Zeek entries A02–A04 connect .10 to .20 and .20 to .21. Process records show ssh admin@192.168.56.20 followed by SMB and SSH connections to .21.",
        "files": ("zeek/BF-H-005_conn.log", "system/BF-H-005_process.log"),
    },
    {
        "id": "q4", "weight": 16, "title": "Data Exfiltration",
        "prompt": "Which observation supports exfiltration of the staged banking archive?",
        "options": (("a", "A normal update check to 192.168.56.30"),
                    ("b", "A DNS lookup for bank.blackfalcon.local"),
                    ("c", "Small recurring status messages to 192.168.56.200 only"),
                    ("d", "An HTTPS POST of ops_backup.tar.gz from 192.168.56.21 to drop.blackfalcon-c2.local (192.168.56.201)")),
        "answer": "d",
        "evidence": "Process telemetry shows curl posting ops_backup.tar.gz to /upload. Zeek HTTP entry H06 records a 3,984,112-byte POST, DNS resolves the host to .201, and Suricata flags the large transfer.",
        "files": ("system/BF-H-005_process.log", "zeek/BF-H-005_http.log",
                  "zeek/BF-H-005_dns.log", "suricata/BF-H-005_eve.json"),
    },
    {
        "id": "q5", "weight": 16, "title": "Incident Containment",
        "prompt": "Which immediate response best addresses the observed host compromise, stolen identity and outbound transfers while preserving evidence?",
        "options": (("a", "Delete the logs and staged archive before investigating"),
                    ("b", "Isolate affected hosts, suspend the compromised admin account, block the identified C2/exfiltration destinations and escalate while preserving evidence"),
                    ("c", "Block only the legitimate update server and leave admin sessions active"),
                    ("d", "Continue normal operations because an HTTP 200 response proves the traffic is safe")),
        "answer": "b",
        "evidence": "The correlated admin logins, shell execution, archive staging and outbound transfers justify host and account containment plus blocking the C2 (.200) and exfiltration (.201) destinations. This question grades a response recommendation based on those observations.",
        "files": ("wazuh/BF-H-005_wazuh_alerts.log", "system/BF-H-005_process.log",
                  "suricata/BF-H-005_eve.json"),
    },
    {
        "id": "q6", "title": "Incident Timeline Reconstruction",
        "prompt": (
            "Based on the Wazuh and Suricata evidence, which sequence best "
            "represents the observed incident?"
        ),
        "options": (
            ("a", "Data exfiltration -> Reconnaissance -> Authentication -> Command execution"),
            ("b", "Reconnaissance -> Authentication -> Command execution -> Data staging -> C2 communication -> Outbound transfer"),
            ("c", "Command execution -> Data staging -> Reconnaissance -> Authentication"),
            ("d", "C2 communication -> Outbound transfer -> Reconnaissance -> Command execution"),
        ),
        "answer": "b", "weight": 10,
        "evidence": (
            "BF-H-005 Suricata and Wazuh chronology: TCP port scanning at 10:04:13; "
            "successful authentication at 10:15:21; shell execution, a command-injection "
            "alert and script creation at 10:32:04-10:32:13; staging and archive creation "
            "at 10:40:22-10:40:44; periodic HTTPS communication at 10:43:25; and a large "
            "outbound transfer at 10:45:52. These sources date the activity to August 21, "
            "2026. Zeek epoch timestamps disagree and are not used for this graded chronology."
        ),
        "files": ("suricata/BF-H-005_eve.json", "wazuh/BF-H-005_wazuh_alerts.log"),
    },
    {
        "id": "q7", "title": "Incident Response Strategy",
        "prompt": (
            "After immediate containment of this incident, which follow-up strategy "
            "best supports investigation and safe recovery?"
        ),
        "options": (
            ("a", "Reconnect all affected hosts immediately because outbound traffic has stopped"),
            ("b", "Delete the logs and archive, then rebuild without recording the incident"),
            ("c", "Preserve and correlate evidence, document timestamp disagreements, investigate the entry point and scope, address compromised credentials and persistence, then validate recovery and monitor for recurrence"),
            ("d", "Treat every Zeek timestamp as authoritative and ignore the Wazuh and Suricata chronology"),
        ),
        "answer": "c", "weight": 10,
        "evidence": (
            "The correlated authentication, shell execution, script creation, archive staging "
            "and outbound activity support investigating the entry point and affected systems "
            "before recovery. Retain the original evidence and record the timestamp conflict; "
            "use Wazuh and Suricata for the graded chronology. This answer is a recommended "
            "response strategy, not a claim that eradication or recovery has already occurred."
        ),
        "files": ("wazuh/BF-H-005_wazuh_alerts.log", "suricata/BF-H-005_eve.json",
                  "system/BF-H-005_auth.log", "system/BF-H-005_process.log"),
    },
)


def public_questions():
    """Return learner-facing fields without answer keys or explanations."""
    return [{key: question[key] for key in ("id", "title", "prompt", "options", "weight")}
            for question in QUESTIONS]


def pass_percentage():
    """Use the server's configured threshold, including outside a request."""
    value = current_app.config.get("FINAL_SOC_PASS_PERCENTAGE", PASS_PERCENTAGE) if has_app_context() else PASS_PERCENTAGE
    if type(value) is not int or not 1 <= value <= 100:
        raise ValueError("Final SOC passing percentage must be an integer from 1 to 100")
    return value


@final_soc_bp.after_request
def private_assessment_response(response):
    response.headers["Cache-Control"] = "private, no-store"
    response.vary.add("Cookie")
    return response


def score_answers(answers):
    """Calculate a weighted score out of 100 marks."""
    total_marks = sum(question["weight"] for question in QUESTIONS)
    if total_marks != 100:
        raise ValueError("Final SOC assessment weights must total 100")
    earned_marks = sum(question["weight"] for question in QUESTIONS
                       if answers.get(question["id"]) == question["answer"])
    percentage = round(earned_marks / total_marks * 100)
    return {"score": earned_marks, "percentage": percentage,
            "passed": percentage >= pass_percentage()}


def init_final_soc(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS final_soc_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            case_id TEXT NOT NULL,
            answers_json TEXT NOT NULL,
            feedback_json TEXT NOT NULL,
            score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
            percentage INTEGER NOT NULL CHECK (percentage BETWEEN 0 AND 100),
            passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
            submitted_at TEXT NOT NULL
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS final_soc_analyst_history ON final_soc_attempts(username, id)")
    db.commit()


def render_challenge(answers=None, errors=None):
    attempts = get_db().execute(
        "SELECT id, score, passed, submitted_at FROM final_soc_attempts WHERE username = ? ORDER BY id DESC",
        (session["username"],),
    ).fetchall()
    # Only send public question fields to the assessment template.
    return render_template(
        "final_soc_challenge.html", case_id=CASE_ID, questions=public_questions(),
        latest=attempts[0] if attempts else None, attempts=attempts,
        csrf_token=csrf_token(), answers=answers or {}, errors=errors or [],
        pass_percentage=pass_percentage(),
        show_answers=current_app.config.get("FINAL_SOC_SHOW_ANSWERS", False) is True,
    ), 400 if errors else 200


@final_soc_bp.route("/soc/final")
@analyst_required
def challenge():
    return render_challenge()


@final_soc_bp.route("/soc/final/submit", methods=["POST"])
@analyst_required
def submit():
    validate_csrf()
    answers = {}
    errors = []
    for question in QUESTIONS:
        values = request.form.getlist(question["id"])
        choices = dict(question["options"])
        if len(values) != 1 or values[0] not in choices:
            errors.append(f"Choose one valid answer for {question['title']}.")
        else:
            answers[question["id"]] = values[0]
    if errors:
        return render_challenge(answers, errors)
    feedback = []
    for question in QUESTIONS:
        choices = dict(question["options"])
        selected = answers[question["id"]]
        feedback.append({
            "id": question["id"], "title": question["title"], "selected": choices[selected],
            "correct": selected == question["answer"], "expected": choices[question["answer"]],
            "evidence": question["evidence"], "files": question["files"],
            "marks_available": question["weight"],
            "marks_awarded": question["weight"] if selected == question["answer"] else 0,
        })
    scored = score_answers(answers)
    with get_db() as db:
        cursor = db.execute("""
            INSERT INTO final_soc_attempts
                (username, case_id, answers_json, feedback_json, score, percentage, passed, submitted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session["username"], CASE_ID, json.dumps(answers), json.dumps(feedback),
              scored["score"], scored["percentage"], int(scored["passed"]), utc_now()))
        result_id = cursor.lastrowid
    return redirect(url_for("final_soc.result", result_id=result_id))


@final_soc_bp.route("/soc/final/result/<int:result_id>")
@analyst_required
def result(result_id):
    attempt = get_db().execute(
        "SELECT * FROM final_soc_attempts WHERE id = ? AND username = ?",
        (result_id, session["username"]),
    ).fetchone()
    if attempt is None:
        abort(404)
    feedback = json.loads(attempt["feedback_json"])
    # Legacy attempts retain their original five-question, 20-mark rubric.
    legacy_assessment = len(feedback) == 5 and all("marks_available" not in item for item in feedback)
    if legacy_assessment:
        feedback = [dict(item, marks_available=20, marks_awarded=20 if item["correct"] else 0)
                    for item in feedback]
    show_answers = current_app.config.get("FINAL_SOC_SHOW_ANSWERS", False) is True
    public_fields = ("id", "title", "selected", "correct", "marks_available", "marks_awarded")
    allowed_fields = public_fields + (("expected", "evidence", "files") if show_answers else ())
    feedback = [{key: value for key, value in item.items() if key in allowed_fields} for item in feedback]
    # Raw JSON contains private rubric data: never pass the database row to Jinja.
    result_metadata = {key: attempt[key] for key in
                       ("id", "case_id", "username", "score", "percentage", "passed", "submitted_at")}
    return render_template("final_soc_result.html", result=result_metadata, feedback=feedback,
                           show_answers=show_answers, legacy_assessment=legacy_assessment)


def csv_cell(value):
    """Keep spreadsheet applications from executing an analyst name as a formula."""
    text = str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")) else text


@final_soc_bp.route("/soc/final/export")
@analyst_required
def export_results():
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("attempt_id", "username", "case_id", "submitted_at_utc", "score", "max_score", "percentage", "result"))
    for attempt in get_db().execute(
        "SELECT * FROM final_soc_attempts WHERE username = ? ORDER BY id", (session["username"],),
    ):
        writer.writerow((attempt["id"], csv_cell(attempt["username"]), attempt["case_id"],
                         attempt["submitted_at"], attempt["score"], 100, attempt["percentage"],
                         "Passed" if attempt["passed"] else "Not Passed"))
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = 'attachment; filename="final_soc_results.csv"'
    response.headers["Cache-Control"] = "no-store"
    return response
