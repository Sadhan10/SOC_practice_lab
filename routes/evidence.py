import os

from flask import (
    Blueprint,
    abort,
    current_app,
    redirect,
    render_template,
    send_from_directory,
    session,
    url_for,
)

from models import get_progress


evidence_bp = Blueprint(
    "evidence",
    __name__,
)


def require_login():
    return session.get("logged_in") is True


def get_evidence_files():
    evidence_root = current_app.config[
        "EVIDENCE_DIR"
    ]

    categories = {
        "wazuh": [],
        "suricata": [],
        "zeek": [],
        "cowrie": [],
        "openvas": [],
        "opencti": [],
        "reports": [],
    }

    for category in categories:
        category_path = os.path.join(
            evidence_root,
            category,
        )

        os.makedirs(
            category_path,
            exist_ok=True,
        )

        for file_name in sorted(
            os.listdir(category_path)
        ):
            file_path = os.path.join(
                category_path,
                file_name,
            )

            if not os.path.isfile(file_path):
                continue

            categories[category].append(
                {
                    "name": file_name,
                    "path": f"{category}/{file_name}",
                    "size": os.path.getsize(file_path),
                }
            )

    return categories


@evidence_bp.route("/evidence")
def evidence():
    if not require_login():
        return redirect(
            url_for("auth.login")
        )

    return render_template(
        "evidence.html",
        evidence_categories=get_evidence_files(),
    )


@evidence_bp.route(
    "/evidence/download/<path:filename>"
)
def download_evidence(filename):
    if not require_login():
        return redirect(
            url_for("auth.login")
        )

    evidence_root = os.path.abspath(
        current_app.config["EVIDENCE_DIR"]
    )

    requested_path = os.path.abspath(
        os.path.join(
            evidence_root,
            filename,
        )
    )

    try:
        common_path = os.path.commonpath(
            [
                evidence_root,
                requested_path,
            ]
        )
    except ValueError:
        abort(403)

    if common_path != evidence_root:
        abort(403)

    if not os.path.isfile(requested_path):
        abort(404)

    directory = os.path.dirname(
        requested_path
    )

    file_name = os.path.basename(
        requested_path
    )

    return send_from_directory(
        directory,
        file_name,
        as_attachment=True,
    )


@evidence_bp.route("/threat-intel")
def threat_intel():
    if not require_login():
        return redirect(
            url_for("auth.login")
        )

    username = session["username"]
    progress = get_progress(username)
    completed = {
        case_id
        for case_id, item in progress.items()
        if item["completed"]
    }

    iocs = [
        {
            "indicator": "192.168.56.104",
            "type": "IP Address",
            "confidence": "High",
            "case": "BF-2026-001",
            "notes": (
                "Source of reconnaissance and "
                "suspicious scanning activity"
            ),
        },
        {
            "indicator": "admin",
            "type": "Compromised Account",
            "confidence": "High",
            "case": "BF-2026-002",
            "notes": (
                "Administrator account accessed "
                "after repeated failures"
            ),
        },
        {
            "indicator": "shell.php",
            "type": "File Artifact",
            "confidence": "High",
            "case": "BF-2026-003",
            "notes": (
                "Uploaded PHP artifact associated "
                "with web-shell command requests"
            ),
        },
        {
            "indicator": "api.blackfalcon-c2.local",
            "type": "Domain",
            "confidence": "High",
            "case": "BF-2026-004",
            "notes": (
                "Command-and-control staging domain "
                "correlated with local DNS telemetry"
            ),
        },
        {
            "indicator": "exfil.blackfalcon-c2.local",
            "type": "Domain",
            "confidence": "Critical",
            "case": "BF-2026-004",
            "notes": (
                "Data exfiltration endpoint correlated "
                "with increasing outbound transfers"
            ),
        },
        {
            "indicator": (
                "572db6dc17de9dba31225688ee312443c"
                "866c919ef21d7e8f2e8ab8c615e7d81"
            ),
            "type": "Malware SHA-256",
            "confidence": "Critical",
            "case": "BF-2026-004",
            "notes": (
                "FalconLoader process hash observed "
                "in Wazuh and OpenCTI evidence"
            ),
        },
    ]

    iocs = [
        item
        for item in iocs
        if item["case"] in completed
    ]

    return render_template(
        "threat_intel.html",
        iocs=iocs,
    )


@evidence_bp.route("/timeline")
def timeline():
    if not require_login():
        return redirect(
            url_for("auth.login")
        )

    timeline_events = [
        {
            "sequence": 1,
            "time": "08:45 AM",
            "case": "BF-2026-001",
            "title": "External Reconnaissance",
            "description": (
                "Suricata and Zeek detect scanning activity "
                "against the public Black Falcon Bank server. "
                "The attacker enumerates exposed services and "
                "identifies possible entry points."
            ),
            "technique": "TA0043",
            "status": "Investigation 1",
        },
        {
            "sequence": 2,
            "time": "09:35 AM",
            "case": "BF-2026-002",
            "title": "Credential Compromise",
            "description": (
                "Repeated SSH authentication failures are "
                "followed by a successful login using the "
                "administrator account, confirming that the "
                "attacker obtained valid credentials."
            ),
            "technique": "T1110",
            "status": "Investigation 2",
        },
        {
            "sequence": 3,
            "time": "10:02 AM",
            "case": "BF-2026-003",
            "title": "Banking Application Compromise",
            "description": (
                "The attacker exploits the banking application's "
                "transaction search, accesses the hidden "
                "administration area and uploads a malicious "
                "web-shell file."
            ),
            "technique": "T1190 / T1505.003",
            "status": "Investigation 3",
        },
        {
            "sequence": 4,
            "time": "10:09 AM",
            "case": "BF-2026-004",
            "title": "Internal Compromise and Exfiltration",
            "description": (
                "Host and network evidence reveals persistence, "
                "malware execution, command-and-control traffic "
                "and the transfer of data outside the bank "
                "environment."
            ),
            "technique": "T1053.003 / T1071.001 / T1041",
            "status": "Investigation 4",
        },
        {
            "sequence": 5,
            "time": "12:15 PM",
            "case": "BF-2026-005",
            "title": "Executive Incident Reconstruction",
            "description": (
                "The lead SOC analyst correlates findings from "
                "all previous investigations, reconstructs the "
                "complete attack chain and prepares the final "
                "executive incident report."
            ),
            "technique": "Incident Response",
            "status": "Investigation 5",
        },
    ]

    return render_template(
        "timeline.html",
        timeline_events=timeline_events,
    )


@evidence_bp.route("/help")
def help_page():
    if not require_login():
        return redirect(
            url_for("auth.login")
        )

    return render_template("help.html")
