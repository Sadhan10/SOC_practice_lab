"""Operation Black Falcon guided, ungraded SOC training labs."""

from flask import Blueprint, abort, render_template

from routes.soc_operations import analyst_required


labs_bp = Blueprint("labs", __name__)

LABS = {
    1: {
        "title": "Log Analysis and Suspicious Activity Detection",
        "objective": "Examine security logs and identify suspicious activity using event evidence.",
        "case_id": "BF-M-001",
        "activities": [
            "Open the Evidence Locker and locate the relevant logs.",
            "Identify suspicious source and destination IP addresses.",
            "Examine security events and identify unusual traffic.",
            "Record the indicators that support your findings.",
            "Summarise the suspicious activity.",
        ],
        "tools": ["Suricata", "Zeek"],
        "graded": False,
    },
    2: {
        "title": "SIEM Search and Event Investigation",
        "objective": "Search, filter and investigate security events using the SIEM interface.",
        "case_id": "BF-M-002",
        "activities": [
            "Open SIEM Search with the associated case filter.",
            "Search for suspicious IP addresses and authentication activity.",
            "Filter by log source, severity and date to narrow the results.",
            "Compare related events across available log sources.",
            "Record the evidence supporting a suspected credential compromise.",
        ],
        "tools": ["SIEM Event Search", "Wazuh logs", "Zeek"],
        "graded": False,
    },
    3: {
        "title": "Alert Triage and Response Decisions",
        "objective": "Evaluate security alerts, prioritise suspicious activity and explain an appropriate response.",
        "case_id": "BF-M-003",
        "activities": [
            "Review the case alerts and the related web application logs.",
            "Compare suspicious requests with legitimate user activity.",
            "Determine whether the evidence supports a true or false positive.",
            "Open Individual Alert Triage, select an event and record its classification, priority and status.",
            "Select a response and explain the evidence supporting your decision.",
        ],
        "tools": ["Suricata", "Zeek", "Web application logs", "Alert Triage"],
        "graded": False,
    },
    4: {
        "title": "Incident Reconstruction and Timeline Analysis",
        "objective": "Correlate endpoint and network evidence to reconstruct an incident and recommend response actions.",
        "case_id": "BF-M-004",
        "activities": [
            "Review the associated investigation and its endpoint and network logs.",
            "Identify the affected host and suspicious process or persistence activity.",
            "Correlate DNS queries and outbound connections with endpoint events.",
            "Use the Attack Timeline as context and order the case events by timestamp.",
            "Summarise the incident sequence and recommend containment actions.",
        ],
        "tools": ["Wazuh logs", "Zeek", "Process logs", "Attack Timeline"],
        "graded": False,
    },
}


@labs_bp.route("/soc/labs")
@analyst_required
def index():
    return render_template("soc_labs.html", labs=LABS)


@labs_bp.route("/soc/labs/<int:lab_id>")
@analyst_required
def view_lab(lab_id):
    lab = LABS.get(lab_id)
    if lab is None:
        abort(404)
    return render_template("soc_lab_detail.html", lab_id=lab_id, lab=lab)
