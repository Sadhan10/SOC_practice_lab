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


def format_evidence_size(size_in_bytes):
    size = float(size_in_bytes)
    for unit in ("bytes", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            if unit == "bytes":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size_in_bytes} bytes"


def get_evidence_file_metadata(file_name):
    extension = os.path.splitext(file_name)[1].lower()
    type_labels = {
        ".log": "Log file", ".txt": "Text document",
        ".json": "JSON document", ".xml": "XML document",
        ".csv": "CSV document", ".tsv": "TSV document",
        ".html": "HTML source", ".htm": "HTML source",
        ".pdf": "PDF document", ".png": "PNG image",
        ".jpg": "JPEG image", ".jpeg": "JPEG image",
        ".gif": "GIF image", ".webp": "WebP image",
        ".pcap": "Packet capture", ".pcapng": "Packet capture",
    }
    return {
        "type_label": type_labels.get(extension, "Evidence file"),
        "badge": extension[1:].upper() or "FILE",
    }


def get_evidence_files():
    evidence_root = current_app.config[
        "EVIDENCE_DIR"
    ]

    categories = {
        "wazuh": [],
        "suricata": [],
        "zeek": [],
        "system": [],
        "web": [],
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

        if not os.path.isdir(category_path):
            continue

        for file_name in sorted(
            os.listdir(category_path)
        ):
            file_path = os.path.join(
                category_path,
                file_name,
            )

            if not os.path.isfile(file_path):
                continue

            size = os.path.getsize(file_path)
            categories[category].append(
                {
                    "name": file_name,
                    "path": f"{category}/{file_name}",
                    "size": size,
                    "size_label": format_evidence_size(size),
                    **get_evidence_file_metadata(file_name),
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

    username = session["username"]

    progress = get_progress(
        username
    )

    completed = {
        case_id
        for case_id, item in progress.items()
        if item["completed"]
    }

    timeline_events = [
        {
            "sequence": 1,
            "time": "08:45",
            "case": "BF-2026-001",
            "title": "External Reconnaissance",
            "description": (
                "Suricata and Zeek identify coordinated "
                "reconnaissance against the public banking "
                "server."
            ),
            "technique": "TA0043",
        },

        {
            "sequence": 2,
            "time": "09:35",
            "case": "BF-2026-002",
            "title": "Credential Compromise",
            "description": (
                "Authentication evidence confirms that "
                "reconnaissance progressed into account "
                "compromise."
            ),
            "technique": "T1110",
        },

        {
            "sequence": 3,
            "time": "10:02",
            "case": "BF-2026-003",
            "title": "Banking Application Compromise",
            "description": (
                "Web telemetry identifies exploitation of "
                "the banking application and subsequent "
                "server-side compromise."
            ),
            "technique": "T1190 / T1505.003",
        },

        {
            "sequence": 4,
            "time": "10:09",
            "case": "BF-2026-004",
            "title": "Persistence and Command & Control",
            "description": (
                "Endpoint and network evidence confirms "
                "persistence and command-and-control "
                "activity on the compromised host."
            ),
            "technique": (
                "T1053.003 / T1071.001"
            ),
        },

        {
            "sequence": 5,
            "time": "10:15",
            "case": "BF-2026-005",
            "title": "Data Exfiltration",
            "description": (
                "The final reconstruction confirms that "
                "data left the affected environment through "
                "attacker-controlled infrastructure."
            ),
            "technique": "T1041",
        },
    ]

    for event in timeline_events:
        event["unlocked"] = (
            event["case"] in completed
        )

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
