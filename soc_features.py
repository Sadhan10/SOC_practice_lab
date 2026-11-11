from __future__ import annotations

import json
import mimetypes
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator
from xml.dom import minidom

from flask import (
    Blueprint,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import safe_join

from investigation_loader import load_investigation
from level_config import (
    LEVELS,
    get_all_cases,
    get_case_level,
    get_level,
    get_level_cases,
)
from models import (
    get_level_progress,
    get_overall_progress,
    get_progress,
    reset_user_progress,
)


soc_features = Blueprint(
    "soc_features",
    __name__,
)


BEGINNER_CASE_IDS = get_level_cases(
    "beginner"
)

MEDIUM_CASE_IDS = get_level_cases(
    "medium"
)

HARD_CASE_IDS = get_level_cases(
    "hard"
)

CASE_IDS = get_all_cases()


def build_case_titles() -> dict[str, str]:
    titles: dict[str, str] = {}
    investigation_dir = (
        Path(__file__).resolve().parent
        / "investigations"
    )

    for case_id in CASE_IDS:
        investigation_path = (
            investigation_dir
            / f"{case_id}.json"
        )

        try:
            with investigation_path.open(
                "r",
                encoding="utf-8",
            ) as investigation_file:
                investigation = json.load(
                    investigation_file
                )

            titles[case_id] = investigation.get(
                "title",
                case_id,
            )
        except (OSError, json.JSONDecodeError):
            titles[case_id] = case_id

    return titles


CASE_TITLES = build_case_titles()


CASE_POINTS = {
    case_id: 1
    for case_id in CASE_IDS
}


INCIDENT_TIMELINE = [
    {
        "sequence": 1,
        "time": "08:45",
        "title": "External Reconnaissance",
        "case_id": "BF-2026-001",
        "technique": "TA0043",
        "description": (
            "Suricata and Zeek detect coordinated scanning "
            "against the public banking server."
        ),
    },
    {
        "sequence": 2,
        "time": "09:35",
        "title": "Credential Compromise",
        "case_id": "BF-2026-002",
        "technique": "T1110",
        "description": (
            "Repeated SSH authentication failures are followed "
            "by a successful administrator login."
        ),
    },
    {
        "sequence": 3,
        "time": "10:02",
        "title": "Banking Application Compromise",
        "case_id": "BF-2026-003",
        "technique": "T1190 / T1505.003",
        "description": (
            "The attacker exploits the banking application and "
            "uploads a malicious web shell."
        ),
    },
    {
        "sequence": 4,
        "time": "10:09",
        "title": "Persistence and Command & Control",
        "case_id": "BF-2026-004",
        "technique": "T1053.003 / T1071.001",
        "description": (
            "Persistence and command-and-control activity "
            "are identified on the compromised host."
        ),
    },
    {
        "sequence": 5,
        "time": "10:15",
        "title": "Data Exfiltration",
        "case_id": "BF-2026-005",
        "technique": "T1041",
        "description": (
            "The final reconstruction confirms data "
            "exfiltration from the affected environment."
        ),
    },
]


ALERTS = [
    {
        "time": "08:45",
        "source": "Suricata",
        "title": "External reconnaissance detected",
        "severity": "medium",
        "case_id": "BF-2026-001",
    },
    {
        "time": "09:35",
        "source": "Cowrie",
        "title": "Multiple SSH authentication failures",
        "severity": "high",
        "case_id": "BF-2026-002",
    },
    {
        "time": "09:40",
        "source": "Wazuh",
        "title": "Successful login after repeated failures",
        "severity": "high",
        "case_id": "BF-2026-002",
    },
    {
        "time": "10:02",
        "source": "Suricata",
        "title": "Possible SQL injection activity",
        "severity": "high",
        "case_id": "BF-2026-003",
    },
    {
        "time": "10:05",
        "source": "Wazuh",
        "title": "Suspicious PHP file uploaded",
        "severity": "critical",
        "case_id": "BF-2026-003",
    },
    {
        "time": "10:09",
        "source": "Wazuh",
        "title": "Suspicious cron persistence",
        "severity": "critical",
        "case_id": "BF-2026-004",
    },
    {
        "time": "10:12",
        "source": "Zeek",
        "title": "Command-and-control domain contacted",
        "severity": "critical",
        "case_id": "BF-2026-004",
    },
    {
        "time": "10:15",
        "source": "Zeek",
        "title": "Abnormal outbound data transfer",
        "severity": "critical",
        "case_id": "BF-2026-004",
    },
]


MITRE_TECHNIQUES = [
    {
        "id": "TA0043",
        "name": "Reconnaissance",
        "description": (
            "The attacker gathered information about exposed "
            "systems, ports and services."
        ),
        "case_id": "BF-2026-001",
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "description": (
            "Repeated authentication attempts were made against "
            "a remotely accessible service."
        ),
        "case_id": "BF-2026-002",
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "description": (
            "A compromised account was used to access the bank "
            "environment."
        ),
        "case_id": "BF-2026-002",
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": (
            "The exposed banking application was targeted through "
            "a web application weakness."
        ),
        "case_id": "BF-2026-003",
    },
    {
        "id": "T1505.003",
        "name": "Web Shell",
        "description": (
            "A malicious server-side script was placed in the "
            "web application directory."
        ),
        "case_id": "BF-2026-003",
    },
    {
        "id": "T1053.003",
        "name": "Cron",
        "description": (
            "A cron entry was configured to repeatedly execute "
            "malicious code."
        ),
        "case_id": "BF-2026-004",
    },
    {
        "id": "T1071.001",
        "name": "Web Protocols",
        "description": (
            "HTTPS traffic was used for command-and-control "
            "communication."
        ),
        "case_id": "BF-2026-004",
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "description": (
            "Data was transferred through the established "
            "command-and-control channel."
        ),
        "case_id": "BF-2026-004",
    },
]


MEDIUM_MITRE_TECHNIQUES = [
    {
        "case_id": "BF-M-001",
        "tactic": "Reconnaissance",
        "technique_id": "T1595",
        "technique": "Active Scanning",
    },
    {
        "case_id": "BF-M-002",
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
    },
    {
        "case_id": "BF-M-003",
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
    },
    {
        "case_id": "BF-M-003",
        "tactic": "Persistence",
        "technique_id": "T1505.003",
        "technique": "Web Shell",
    },
    {
        "case_id": "BF-M-004",
        "tactic": "Persistence",
        "technique_id": "T1053.003",
        "technique": "Cron",
    },
    {
        "case_id": "BF-M-004",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique": "Web Protocols",
    },
    {
        "case_id": "BF-M-005",
        "tactic": "Collection",
        "technique_id": "T1560.001",
        "technique": "Archive Collected Data",
    },
    {
        "case_id": "BF-M-005",
        "tactic": "Exfiltration",
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
    },
]


HARD_MITRE_TECHNIQUES = [
    {
        "case_id": "BF-H-001",
        "tactic": "Reconnaissance",
        "technique_id": "T1595.001",
        "technique": "Scanning IP Blocks",
    },
    {
        "case_id": "BF-H-002",
        "tactic": "Credential Access",
        "technique_id": "T1078",
        "technique": "Valid Accounts",
    },
    {
        "case_id": "BF-H-002",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.004",
        "technique": "SSH",
    },
    {
        "case_id": "BF-H-002",
        "tactic": "Lateral Movement",
        "technique_id": "T1021.002",
        "technique": "SMB/Windows Admin Shares",
    },
    {
        "case_id": "BF-H-003",
        "tactic": "Execution",
        "technique_id": "T1059.004",
        "technique": "Unix Shell",
    },
    {
        "case_id": "BF-H-003",
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
    },
    {
        "case_id": "BF-H-004",
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique": "Web Protocols",
    },
    {
        "case_id": "BF-H-004",
        "tactic": "Collection",
        "technique_id": "T1074.001",
        "technique": "Local Data Staging",
    },
    {
        "case_id": "BF-H-005",
        "tactic": "Collection",
        "technique_id": "T1560.001",
        "technique": "Archive Collected Data",
    },
    {
        "case_id": "BF-H-005",
        "tactic": "Exfiltration",
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
    },
]


MITRE_TECHNIQUES = (
    MITRE_TECHNIQUES
    + MEDIUM_MITRE_TECHNIQUES
    + HARD_MITRE_TECHNIQUES
)


IOC_SEED_DATA = [
    {
        "type": "IPv4",
        "value": "192.168.56.104",
        "case_id": "BF-2026-001",
        "description": "Suspected attacker address",
    },
    {
        "type": "IPv4",
        "value": "192.168.56.10",
        "case_id": "BF-2026-003",
        "description": "Compromised bank web server",
    },
    {
        "type": "Domain",
        "value": "api.blackfalcon-c2.local",
        "case_id": "BF-2026-004",
        "description": "Command-and-control domain",
    },
    {
        "type": "Domain",
        "value": "exfil.blackfalcon-c2.local",
        "case_id": "BF-2026-004",
        "description": "Exfiltration domain",
    },
    {
        "type": "IPv4",
        "value": "10.10.14.20",
        "case_id": "BF-2026-004",
        "description": "Command-and-control server",
    },
    {
        "type": "IPv4",
        "value": "10.10.14.25",
        "case_id": "BF-2026-004",
        "description": "Exfiltration receiver",
    },
    {
        "type": "SHA-256",
        "value": (
            "572db6dc17de9dba31225688ee312443"
            "c866c919ef21d7e8f2e8ab8c615e7d81"
        ),
        "case_id": "BF-2026-004",
        "description": "FalconLoader malware hash",
    },
]


def feature_database_path() -> str:
    configured = current_app.config.get("SOC_FEATURE_DATABASE_PATH")
    if configured:
        destination = Path(configured)
        destination.parent.mkdir(parents=True, exist_ok=True)
        return str(destination)

    instance_path = Path(
        current_app.instance_path
    )

    instance_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    return str(
        instance_path / "soc_features.db"
    )


@contextmanager
def get_feature_db() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(
        feature_database_path()
    )

    connection.row_factory = sqlite3.Row

    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialise_soc_features() -> None:
    with get_feature_db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS analyst_profile (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                analyst_name TEXT NOT NULL DEFAULT 'SOC Analyst',
                mission_started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS investigation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL UNIQUE,
                note_text TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS analyst_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                case_id TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                UNIQUE(ioc_type, ioc_value, case_id)
            );

            CREATE TABLE IF NOT EXISTS evidence_views (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_path TEXT NOT NULL UNIQUE,
                case_id TEXT,
                first_viewed_at TEXT NOT NULL,
                last_viewed_at TEXT NOT NULL,
                view_count INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS incorrect_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL UNIQUE,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS report_submissions (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                submitted INTEGER NOT NULL DEFAULT 0,
                submitted_at TEXT
            );
            """
        )

        now = datetime.now().isoformat(
            timespec="seconds"
        )

        connection.execute(
            """
            INSERT OR IGNORE INTO analyst_profile (
                id,
                analyst_name,
                mission_started_at,
                updated_at
            )
            VALUES (1, 'SOC Analyst', ?, ?)
            """,
            (
                now,
                now,
            ),
        )

        connection.execute(
            """
            INSERT OR IGNORE INTO report_submissions (
                id,
                submitted,
                submitted_at
            )
            VALUES (1, 0, NULL)
            """
        )

        connection.commit()


def user_is_logged_in() -> bool:
    """
    Supports common session keys.

    Add your own login session key here if your project uses a
    different key.
    """

    return bool(
        session.get("logged_in")
        or session.get("analyst_logged_in")
        or session.get("user_id")
        or session.get("username")
        or session.get("analyst")
    )


def require_login() -> None:
    if not user_is_logged_in():
        abort(
            401,
            "Please log in to access the SOC workspace.",
        )


def normalise_case_id(
    case_id: str,
) -> str:
    cleaned = case_id.strip().upper()

    if (
        cleaned not in CASE_IDS
        or not load_investigation(cleaned)
    ):
        abort(404)

    return cleaned


def get_completed_case_ids() -> set[str]:
    """
    Reads completion from common session formats.

    Your existing flag route must call:
        set_case_completed_in_session(case_id)

    after a correct flag is accepted.
    """

    completed: set[str] = set()

    possible_values = [
        session.get("completed_cases"),
        session.get("completed_investigations"),
        session.get("solved_cases"),
    ]

    for value in possible_values:
        if isinstance(value, list):
            completed.update(
                str(item).upper()
                for item in value
            )

        elif isinstance(value, dict):
            for case_id, status in value.items():
                if status:
                    completed.add(
                        str(case_id).upper()
                    )

        elif isinstance(value, str):
            completed.update(
                item.strip().upper()
                for item in value.split(",")
                if item.strip()
            )

    for case_id in CASE_IDS:
        if session.get(
            f"completed_{case_id}"
        ):
            completed.add(case_id)

    username = session.get("username")

    if username:
        progress = get_progress(username)

        completed.update(
            case_id
            for case_id, item in progress.items()
            if item.get("completed")
        )

    return completed.intersection(
        set(CASE_IDS)
    )


def set_case_completed_in_session(
    case_id: str,
) -> None:
    """
    Call after your existing successful flag validation.

    It does not replace your existing progress database.
    """

    case_id = normalise_case_id(
        case_id
    )

    completed = set(
        session.get(
            "completed_cases",
            [],
        )
    )

    completed.add(case_id)

    session["completed_cases"] = sorted(
        completed
    )

    session.modified = True


def record_incorrect_attempt(
    case_id: str,
) -> None:
    case_id = normalise_case_id(
        case_id
    )

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    with get_feature_db() as connection:
        connection.execute(
            """
            INSERT INTO incorrect_attempts (
                case_id,
                attempt_count,
                updated_at
            )
            VALUES (?, 1, ?)
            ON CONFLICT(case_id)
            DO UPDATE SET
                attempt_count = attempt_count + 1,
                updated_at = excluded.updated_at
            """,
            (
                case_id,
                now,
            ),
        )

        connection.commit()


def get_incorrect_attempt_count(
    case_ids: list[str] | None = None,
) -> int:
    if case_ids is None:
        case_ids = CASE_IDS

    if not case_ids:
        return 0

    placeholders = ", ".join(
        "?"
        for _ in case_ids
    )

    with get_feature_db() as connection:
        row = connection.execute(
            f"""
            SELECT COALESCE(
                SUM(attempt_count),
                0
            ) AS total
            FROM incorrect_attempts
            WHERE case_id IN ({placeholders})
            """,
            tuple(case_ids),
        ).fetchone()

    return int(
        row["total"]
    )


def calculate_score(
    completed_cases: set[str],
) -> int:
    if not CASE_IDS:
        return 0

    valid_completed = [
        case_id
        for case_id in completed_cases
        if case_id in CASE_IDS
    ]

    return int(
        len(valid_completed)
        / len(CASE_IDS)
        * 100
    )


def get_analyst_profile() -> dict[str, Any]:
    with get_feature_db() as connection:
        row = connection.execute(
            """
            SELECT
                analyst_name,
                mission_started_at,
                updated_at
            FROM analyst_profile
            WHERE id = 1
            """
        ).fetchone()

    return dict(row)


def update_analyst_name(
    analyst_name: str,
) -> None:
    analyst_name = re.sub(
        r"\s+",
        " ",
        analyst_name,
    ).strip()

    if not analyst_name:
        analyst_name = "SOC Analyst"

    analyst_name = analyst_name[:80]

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    with get_feature_db() as connection:
        connection.execute(
            """
            UPDATE analyst_profile
            SET
                analyst_name = ?,
                updated_at = ?
            WHERE id = 1
            """,
            (
                analyst_name,
                now,
            ),
        )

        connection.commit()


def get_evidence_view_count() -> int:
    with get_feature_db() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM evidence_views
            """
        ).fetchone()

    return int(
        row["total"]
    )


def get_ioc_count() -> int:
    with get_feature_db() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM analyst_iocs
            """
        ).fetchone()

    return int(
        row["total"]
    )


def get_report_status() -> bool:
    with get_feature_db() as connection:
        row = connection.execute(
            """
            SELECT submitted
            FROM report_submissions
            WHERE id = 1
            """
        ).fetchone()

    return bool(
        row["submitted"]
    )


def format_display_timestamp(value):
    if not value:
        return None
    try:
        timestamp = datetime.fromisoformat(str(value))
        return timestamp.strftime("%d %B %Y, %I:%M %p")
    except ValueError:
        return str(value)


def get_completion_date_for_cases(username, case_ids):
    """Return the date on which the final supplied case was completed."""
    progress = get_progress(username)
    completion_times = []
    for case_id in case_ids:
        completed_at = progress.get(case_id, {}).get("completed_at")
        if completed_at:
            try:
                completion_times.append(datetime.fromisoformat(str(completed_at)))
            except ValueError:
                continue
    if not completion_times:
        return None
    return max(completion_times).strftime("%d %B %Y")


def build_dashboard_context() -> dict[str, Any]:
    initialise_soc_features()

    completed = get_completed_case_ids()
    beginner_completed = {
        case_id
        for case_id in completed
        if case_id in BEGINNER_CASE_IDS
    }

    cases = [
        {
            "id": case_id,
            "title": CASE_TITLES[case_id],
            "completed": case_id in beginner_completed,
            "points": 20,
        }
        for case_id in BEGINNER_CASE_IDS
    ]

    timeline = [
        {
            **item,
            "completed": (
                item["case_id"]
                in beginner_completed
            ),
        }
        for item in INCIDENT_TIMELINE
    ]

    alerts = [
        {
            **alert,
            "resolved": (
                alert["case_id"]
                in beginner_completed
            ),
        }
        for alert in ALERTS
    ]

    completed_count = len(
        beginner_completed
    )

    completion_percentage = int(
        completed_count
        / len(BEGINNER_CASE_IDS)
        * 100
    )

    unlocked_techniques = [
        item
        for item in MITRE_TECHNIQUES
        if (
            item["case_id"]
            in beginner_completed
        )
    ]

    overall_progress = get_overall_progress(
        session.get("username")
    )

    return {
        "cases": cases,
        "timeline": timeline,
        "alerts": alerts,
        "completed_cases": beginner_completed,
        "completed_count": completed_count,
        "total_cases": len(BEGINNER_CASE_IDS),
        "pending_count": (
            len(BEGINNER_CASE_IDS)
            - completed_count
        ),
        "completion_percentage": (
            completion_percentage
        ),
        "score": completion_percentage,
        "incorrect_attempts": (
            get_incorrect_attempt_count(
                BEGINNER_CASE_IDS
            )
        ),
        "evidence_view_count": (
            get_evidence_view_count()
        ),
        "ioc_count": get_ioc_count(),
        "mitre_count": len(
            unlocked_techniques
        ),
        "mission_complete": (
            completed_count
            == len(BEGINNER_CASE_IDS)
        ),
        "overall_complete": overall_progress[
            "is_complete"
        ],
        "report_submitted": get_report_status(),
        "analyst": get_analyst_profile(),
        "executive_summary": {
            "status": (
                "Contained"
                if completed_count
                == len(BEGINNER_CASE_IDS)
                else "Under Investigation"
            ),
            "attacker_ip": (
                "192.168.56.104"
                if "BF-2026-001" in beginner_completed
                else "Unknown"
            ),
            "initial_access": (
                "Credential compromise"
                if "BF-2026-002" in beginner_completed
                else "Under Investigation"
            ),
            "affected_host": (
                "192.168.56.10"
                if "BF-2026-003" in beginner_completed
                else "Unknown"
            ),
            "web_attack": (
                "SQL injection"
                if "BF-2026-003" in beginner_completed
                else "Under Investigation"
            ),
            "threat_actor": (
                "Black Falcon Group"
                if "BF-2026-004" in beginner_completed
                else "Unknown"
            ),
            "malware": (
                "FalconLoader"
                if "BF-2026-004" in beginner_completed
                else "Unknown"
            ),
            "persistence": (
                "Cron job"
                if "BF-2026-004" in beginner_completed
                else "Under Investigation"
            ),
            "c2": (
                "api.blackfalcon-c2.local"
                if "BF-2026-004" in beginner_completed
                else "Unknown"
            ),
            "exfiltration": (
                "Confirmed"
                if "BF-2026-004" in beginner_completed
                else "Under Investigation"
            ),
            "risk": (
                "Critical"
                if "BF-2026-004" in beginner_completed
                else "Assessing"
            ),
        },
    }


TEXT_PREVIEW_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".tsv",
    ".conf",
    ".cfg",
    ".ini",
    ".yaml",
    ".yml",
    ".md",
    ".sql",
    ".py",
    ".sh",
    ".ps1",
    ".bat",
    ".properties",
}

STRUCTURED_TEXT_EXTENSIONS = {
    ".json",
    ".xml",
    ".html",
    ".htm",
}

IMAGE_PREVIEW_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".svg",
}

PDF_PREVIEW_EXTENSIONS = {
    ".pdf",
}

DOWNLOAD_ONLY_EXTENSIONS = {
    ".pcap",
    ".pcapng",
    ".evtx",
    ".zip",
    ".7z",
    ".rar",
    ".gz",
    ".tar",
    ".tgz",
}

MAX_TEXT_PREVIEW_BYTES = 5 * 1024 * 1024


def resolve_evidence_directory() -> str:
    """
    Return the configured evidence directory.

    The project currently uses EVIDENCE_DIR in routes/evidence.py.
    Older versions of soc_features.py may use EVIDENCE_FOLDER.

    This function supports both names so the Evidence Locker and
    Evidence Viewer always point to the same directory.
    """

    configured_path = (
        current_app.config.get("EVIDENCE_DIR")
        or current_app.config.get("EVIDENCE_FOLDER")
    )

    if configured_path:
        return os.path.abspath(
            os.fspath(configured_path)
        )

    return os.path.abspath(
        os.path.join(
            current_app.root_path,
            "evidence",
        )
    )


def validate_evidence_path(
    requested_path: str,
) -> str:
    """
    Validate that the requested evidence file exists inside the
    configured evidence directory.

    Prevents directory traversal such as ../../etc/passwd.
    """

    requested_path = str(
        requested_path or ""
    ).strip()

    if not requested_path:
        abort(404)

    requested_path = requested_path.replace(
        "\\",
        "/",
    )

    evidence_root = os.path.realpath(
        resolve_evidence_directory()
    )

    absolute_path = safe_join(
        evidence_root,
        requested_path,
    )

    if not absolute_path:
        abort(404)

    absolute_path = os.path.realpath(
        absolute_path
    )

    try:
        common_path = os.path.commonpath(
            [
                evidence_root,
                absolute_path,
            ]
        )
    except ValueError:
        abort(403)

    if common_path != evidence_root:
        abort(403)

    if not os.path.isfile(
        absolute_path
    ):
        abort(404)

    return absolute_path


def read_text_evidence(
    absolute_path: str,
) -> str:
    """
    Read a text-based evidence file using common forensic log
    encodings.

    Binary files are not passed to this function.
    """

    file_size = os.path.getsize(
        absolute_path
    )

    if file_size > MAX_TEXT_PREVIEW_BYTES:
        raise ValueError(
            "This evidence file is too large for an in-browser "
            "text preview. Download the original evidence file "
            "to inspect it locally."
        )

    encodings = (
        "utf-8-sig",
        "utf-8",
        "utf-16",
        "utf-16-le",
        "utf-16-be",
        "latin-1",
    )

    for encoding in encodings:
        try:
            with open(
                absolute_path,
                "r",
                encoding=encoding,
            ) as evidence_file:
                return evidence_file.read()

        except UnicodeDecodeError:
            continue

    raise ValueError(
        "The evidence file could not be decoded as readable text."
    )


def format_structured_evidence(
    content: str,
    extension: str,
) -> str:
    """
    Format JSON and XML for easier investigation.

    HTML is intentionally displayed as source code rather than
    executed in the browser.
    """

    extension = extension.lower()

    if extension == ".json":
        try:
            parsed_json = json.loads(
                content
            )

            return json.dumps(
                parsed_json,
                indent=4,
                ensure_ascii=False,
            )

        except json.JSONDecodeError:
            return content

    if extension == ".xml":
        try:
            parsed_xml = minidom.parseString(
                content.encode("utf-8")
            )

            formatted_xml = parsed_xml.toprettyxml(
                indent="    "
            )

            return "\n".join(
                line
                for line in formatted_xml.splitlines()
                if line.strip()
            )

        except Exception:
            return content

    return content


def normalise_relative_evidence_path(
    absolute_path: str,
) -> str:
    """
    Return a portable relative evidence path using forward slashes.
    """

    relative_path = os.path.relpath(
        absolute_path,
        resolve_evidence_directory(),
    )

    return relative_path.replace(
        os.sep,
        "/",
    )


def get_evidence_preview_type(
    extension: str,
) -> str:
    extension = extension.lower()

    if (
        extension in TEXT_PREVIEW_EXTENSIONS
        or extension in STRUCTURED_TEXT_EXTENSIONS
    ):
        return "text"

    if extension in IMAGE_PREVIEW_EXTENSIONS:
        return "image"

    if extension in PDF_PREVIEW_EXTENSIONS:
        return "pdf"

    return "download"


def get_evidence_file_type_label(
    extension: str,
) -> str:
    labels = {
        ".txt": "Text document",
        ".log": "Log file",
        ".json": "JSON document",
        ".xml": "XML document",
        ".html": "HTML source",
        ".htm": "HTML source",
        ".csv": "CSV document",
        ".tsv": "TSV document",
        ".pdf": "PDF document",
        ".png": "PNG image",
        ".jpg": "JPEG image",
        ".jpeg": "JPEG image",
        ".gif": "GIF image",
        ".webp": "WebP image",
        ".bmp": "Bitmap image",
        ".svg": "SVG image",
        ".pcap": "Packet capture",
        ".pcapng": "Packet capture",
        ".evtx": "Windows event log",
        ".zip": "ZIP archive",
        ".7z": "7-Zip archive",
        ".rar": "RAR archive",
        ".gz": "GZip archive",
        ".tar": "TAR archive",
        ".tgz": "Compressed TAR archive",
    }

    return labels.get(
        extension.lower(),
        "Evidence file",
    )


def get_readable_file_size(
    size_in_bytes: int,
) -> str:
    size = float(
        size_in_bytes
    )

    units = (
        "bytes",
        "KB",
        "MB",
        "GB",
    )

    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "bytes":
                return f"{int(size)} {unit}"

            return f"{size:.2f} {unit}"

        size /= 1024

    return f"{size_in_bytes} bytes"


def record_evidence_view(
    evidence_path: str,
    case_id: str | None,
) -> None:
    now = datetime.now().isoformat(
        timespec="seconds"
    )

    with get_feature_db() as connection:
        connection.execute(
            """
            INSERT INTO evidence_views (
                evidence_path,
                case_id,
                first_viewed_at,
                last_viewed_at,
                view_count
            )
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(evidence_path)
            DO UPDATE SET
                last_viewed_at = excluded.last_viewed_at,
                view_count = view_count + 1,
                case_id = COALESCE(
                    excluded.case_id,
                    evidence_views.case_id
                )
            """,
            (
                evidence_path,
                case_id,
                now,
                now,
            ),
        )

        connection.commit()
def validate_ioc(
    ioc_type: str,
    ioc_value: str,
) -> tuple[bool, str]:
    ioc_type = ioc_type.strip()
    ioc_value = ioc_value.strip()

    if not ioc_value:
        return False, "IOC value is required."

    if ioc_type == "IPv4":
        parts = ioc_value.split(".")

        if len(parts) != 4:
            return False, "Invalid IPv4 address."

        try:
            valid_parts = all(
                0 <= int(part) <= 255
                for part in parts
            )

        except ValueError:
            valid_parts = False

        if not valid_parts:
            return False, "Invalid IPv4 address."

    elif ioc_type == "Domain":
        if not re.fullmatch(
            r"[a-zA-Z0-9.-]+\.[a-zA-Z0-9-]+",
            ioc_value,
        ):
            return False, "Invalid domain name."

        ioc_value = ioc_value.lower()

    elif ioc_type == "SHA-256":
        if not re.fullmatch(
            r"[a-fA-F0-9]{64}",
            ioc_value,
        ):
            return (
                False,
                "SHA-256 must contain 64 hexadecimal characters.",
            )

        ioc_value = ioc_value.lower()

    elif ioc_type == "MD5":
        if not re.fullmatch(
            r"[a-fA-F0-9]{32}",
            ioc_value,
        ):
            return (
                False,
                "MD5 must contain 32 hexadecimal characters.",
            )

        ioc_value = ioc_value.lower()

    elif ioc_type == "URL":
        if not re.fullmatch(
            r"https?://.+",
            ioc_value,
        ):
            return (
                False,
                "URL must begin with http:// or https://.",
            )

    elif ioc_type == "Email":
        if not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            ioc_value,
        ):
            return False, "Invalid email address."

    elif ioc_type == "Filename":
        if (
            "/" in ioc_value
            or "\\" in ioc_value
        ):
            return (
                False,
                "Enter only the filename, not a complete path.",
            )

    else:
        return False, "Unsupported IOC type."

    return True, ioc_value


@soc_features.before_request
def initialise_before_request() -> None:
    initialise_soc_features()


@soc_features.route(
    "/soc/dashboard"
)
def dashboard():
    require_login()

    return render_template(
        "dashboard.html",
        **build_dashboard_context(),
    )


@soc_features.route(
    "/level-completed/<level_name>"
)
def level_completed(level_name):
    if not session.get("logged_in"):
        return redirect(
            url_for("auth.login")
        )

    level_name = str(level_name).lower()
    level = get_level(level_name)

    if not level:
        return redirect(
            url_for(
                "dashboard.levels"
            )
        )

    progress = get_level_progress(
        session["username"],
        level_name,
    )

    if not progress["is_complete"]:
        return redirect(
            url_for(
                "dashboard.levels"
            )
        )

    return render_template(
        "level_completed.html",
        level=level,
        level_name=level_name,
        progress=progress,
    )


@soc_features.route(
    "/soc/profile",
    methods=["POST"],
)
def update_profile():
    require_login()

    update_analyst_name(
        request.form.get(
            "analyst_name",
            "",
        )
    )

    return redirect(
        url_for(
            "soc_features.dashboard"
        )
    )


@soc_features.route(
    "/soc/evidence"
)
def evidence_viewer():
    """
    Render the common SOC evidence viewer interface.

    Text files are displayed in the code-editor area.
    Images and PDFs are embedded inside the same interface.
    Binary forensic files receive a download-only screen.
    """

    require_login()

    requested_path = request.args.get(
        "path",
        "",
    )

    case_id = request.args.get(
        "case_id",
        "",
    ).strip().upper()

    if not load_investigation(case_id):
        case_id = ""

    absolute_path = validate_evidence_path(
        requested_path
    )

    relative_path = normalise_relative_evidence_path(
        absolute_path
    )

    extension = Path(
        absolute_path
    ).suffix.lower()

    preview_type = get_evidence_preview_type(
        extension
    )

    file_size_bytes = os.path.getsize(
        absolute_path
    )

    evidence_name = os.path.basename(
        absolute_path
    )

    mime_type = (
        mimetypes.guess_type(
            evidence_name
        )[0]
        or "application/octet-stream"
    )

    record_evidence_view(
        relative_path,
        case_id or None,
    )

    evidence_lines: list[str] = []
    preview_error = ""

    if preview_type == "text":
        try:
            content = read_text_evidence(
                absolute_path
            )

            if extension in STRUCTURED_TEXT_EXTENSIONS:
                content = format_structured_evidence(
                    content,
                    extension,
                )

            evidence_lines = content.splitlines()

            if not evidence_lines:
                evidence_lines = [""]

        except ValueError as error:
            preview_error = str(
                error
            )

    return render_template(
        "evidence_viewer.html",
        evidence_path=relative_path,
        evidence_name=evidence_name,
        evidence_lines=evidence_lines,
        evidence_extension=extension,
        evidence_type_label=get_evidence_file_type_label(
            extension
        ),
        evidence_size=get_readable_file_size(
            file_size_bytes
        ),
        evidence_size_bytes=file_size_bytes,
        evidence_mime_type=mime_type,
        preview_type=preview_type,
        preview_error=preview_error,
        case_id=case_id,
    )


@soc_features.route(
    "/soc/evidence/raw"
)
def evidence_raw():
    """
    Serve image and PDF evidence inline.

    This endpoint is used only by the preview area in
    evidence_viewer.html.
    """

    require_login()

    requested_path = request.args.get(
        "path",
        "",
    )

    absolute_path = validate_evidence_path(
        requested_path
    )

    extension = Path(
        absolute_path
    ).suffix.lower()

    permitted_inline_extensions = (
        IMAGE_PREVIEW_EXTENSIONS
        | PDF_PREVIEW_EXTENSIONS
    )

    if extension not in permitted_inline_extensions:
        abort(415)

    response = send_file(
        absolute_path,
        as_attachment=False,
        conditional=True,
        etag=True,
        max_age=0,
    )

    response.headers[
        "Content-Disposition"
    ] = (
        f'inline; filename="{os.path.basename(absolute_path)}"'
    )

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    return response


@soc_features.route(
    "/soc/evidence/download"
)
def download_evidence():
    """
    Download the original evidence file without altering it.
    """

    require_login()

    requested_path = request.args.get(
        "path",
        "",
    )

    absolute_path = validate_evidence_path(
        requested_path
    )

    return send_file(
        absolute_path,
        as_attachment=True,
        download_name=os.path.basename(
            absolute_path
        ),
        conditional=True,
        etag=True,
        max_age=0,
    )
@soc_features.route(
    "/soc/notes/<case_id>",
    methods=["GET", "POST"],
)
def investigation_notes(
    case_id: str,
):
    require_login()

    case_id = normalise_case_id(
        case_id
    )

    if request.method == "POST":
        note_text = request.form.get(
            "note_text",
            "",
        )[:20000]

        now = datetime.now().isoformat(
            timespec="seconds"
        )

        with get_feature_db() as connection:
            connection.execute(
                """
                INSERT INTO investigation_notes (
                    case_id,
                    note_text,
                    updated_at
                )
                VALUES (?, ?, ?)
                ON CONFLICT(case_id)
                DO UPDATE SET
                    note_text = excluded.note_text,
                    updated_at = excluded.updated_at
                """,
                (
                    case_id,
                    note_text,
                    now,
                ),
            )

            connection.commit()

        if request.headers.get(
            "X-Requested-With"
        ) == "XMLHttpRequest":
            return jsonify(
                {
                    "success": True,
                    "updated_at": now,
                }
            )

        return redirect(
            url_for(
                "soc_features.investigation_notes",
                case_id=case_id,
            )
        )

    with get_feature_db() as connection:
        row = connection.execute(
            """
            SELECT
                note_text,
                updated_at
            FROM investigation_notes
            WHERE case_id = ?
            """,
            (
                case_id,
            ),
        ).fetchone()

    return render_template(
        "notes.html",
        case_id=case_id,
        case_title=CASE_TITLES[case_id],
        note_text=(
            row["note_text"]
            if row
            else ""
        ),
        updated_at=(
            row["updated_at"]
            if row
            else None
        ),
    )


@soc_features.route(
    "/soc/iocs",
    methods=["GET", "POST"],
)
def ioc_notebook():
    require_login()

    error = None

    selected_case_id = request.args.get(
        "case_id",
        "",
    ).strip().upper()

    if selected_case_id not in CASE_IDS:
        selected_case_id = ""

    if request.method == "POST":
        ioc_type = request.form.get(
            "ioc_type",
            "",
        )

        ioc_value = request.form.get(
            "ioc_value",
            "",
        )

        case_id = request.form.get(
            "case_id",
            "",
        ).strip().upper()

        description = request.form.get(
            "description",
            "",
        ).strip()[:500]

        if case_id not in CASE_IDS:
            error = "Select a valid investigation."

        else:
            valid, result = validate_ioc(
                ioc_type,
                ioc_value,
            )

            if not valid:
                error = result

            else:
                try:
                    with get_feature_db() as connection:
                        connection.execute(
                            """
                            INSERT INTO analyst_iocs (
                                ioc_type,
                                ioc_value,
                                case_id,
                                description,
                                created_at
                            )
                            VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                ioc_type,
                                result,
                                case_id,
                                description,
                                datetime.now().isoformat(
                                    timespec="seconds"
                                ),
                            ),
                        )

                        connection.commit()

                except sqlite3.IntegrityError:
                    error = (
                        "This IOC is already stored "
                        "for the selected investigation."
                    )

                if not error:
                    return redirect(
                        url_for(
                            "soc_features.ioc_notebook"
                        )
                    )

    with get_feature_db() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                ioc_type,
                ioc_value,
                case_id,
                description,
                created_at
            FROM analyst_iocs
            ORDER BY id DESC
            """
        ).fetchall()

    case_options = []

    for level_name, level in LEVELS.items():
        for case_id in level["cases"]:
            case_options.append(
                {
                    "id": case_id,
                    "title": CASE_TITLES.get(
                        case_id,
                        case_id,
                    ),
                    "level": level_name,
                    "level_name": level["name"],
                }
            )

    return render_template(
        "ioc_notebook.html",
        iocs=[
            dict(row)
            for row in rows
        ],
        case_options=case_options,
        selected_case_id=selected_case_id,
        error=error,
    )


@soc_features.route(
    "/soc/iocs/delete/<int:ioc_id>",
    methods=["POST"],
)
def delete_ioc(
    ioc_id: int,
):
    require_login()

    with get_feature_db() as connection:
        connection.execute(
            """
            DELETE FROM analyst_iocs
            WHERE id = ?
            """,
            (
                ioc_id,
            ),
        )

        connection.commit()

    return redirect(
        url_for(
            "soc_features.ioc_notebook"
        )
    )


@soc_features.route(
    "/soc/iocs/seed",
    methods=["POST"],
)
def seed_iocs():
    require_login()

    completed = get_completed_case_ids()

    now = datetime.now().isoformat(
        timespec="seconds"
    )

    with get_feature_db() as connection:
        for item in IOC_SEED_DATA:
            if item["case_id"] not in completed:
                continue

            connection.execute(
                """
                INSERT OR IGNORE INTO analyst_iocs (
                    ioc_type,
                    ioc_value,
                    case_id,
                    description,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    item["type"],
                    item["value"],
                    item["case_id"],
                    item["description"],
                    now,
                ),
            )

        connection.commit()

    return redirect(
        url_for(
            "soc_features.ioc_notebook"
        )
    )


@soc_features.route(
    "/soc/mitre"
)
def mitre_mapping():
    require_login()

    completed = get_completed_case_ids()

    techniques = []

    for technique in MITRE_TECHNIQUES:
        case_id = technique["case_id"]
        level_name = get_case_level(
            case_id
        )
        level = get_level(level_name)
        technique_id = technique.get(
            "technique_id",
            technique.get("id", "Unknown"),
        )
        technique_name = technique.get(
            "technique",
            technique.get("name", "Unknown"),
        )
        tactic = technique.get(
            "tactic",
            "",
        )
        description = technique.get(
            "description"
        )

        if not description:
            description = (
                f"{tactic}: {technique_name}"
                if tactic
                else technique_name
            )

        techniques.append(
            {
                **technique,
                "id": technique_id,
                "name": technique_name,
                "description": description,
                "unlocked": case_id in completed,
                "level": level_name,
                "level_label": (
                    level["name"]
                    if level
                    else "Unknown"
                ),
            }
        )

    return render_template(
        "mitre.html",
        techniques=techniques,
        unlocked_count=sum(
            1
            for technique in techniques
            if technique["unlocked"]
        ),
        total_count=len(
            techniques
        ),
    )


@soc_features.route(
    "/soc/report",
    methods=["GET", "POST"],
)
def executive_report():
    require_login()

    completed = get_completed_case_ids()
    username = session["username"]
    beginner_progress = get_level_progress(
        username,
        "beginner",
    )
    medium_progress = get_level_progress(
        username,
        "medium",
    )
    hard_progress = get_level_progress(
        username,
        "hard",
    )
    overall_progress = get_overall_progress(
        username
    )

    if not set(CASE_IDS).issubset(completed):
        abort(
            403,
            (
                "Complete all fifteen investigations across "
                "Beginner, Medium and Hard before opening "
                "the final executive report."
            ),
        )

    if request.method == "POST":
        now = datetime.now().isoformat(
            timespec="seconds"
        )

        with get_feature_db() as connection:
            connection.execute(
                """
                UPDATE report_submissions
                SET
                    submitted = 1,
                    submitted_at = ?
                WHERE id = 1
                """,
                (
                    now,
                ),
            )

            connection.commit()

        return redirect(
            url_for(
                "soc_features.executive_report"
            )
        )

    with get_feature_db() as connection:
        ioc_rows = connection.execute(
            """
            SELECT
                ioc_type,
                ioc_value,
                case_id,
                description
            FROM analyst_iocs
            ORDER BY case_id, ioc_type
            """
        ).fetchall()

        note_rows = connection.execute(
            """
            SELECT
                case_id,
                note_text,
                updated_at
            FROM investigation_notes
            ORDER BY case_id
            """
        ).fetchall()

        report_row = connection.execute(
            """
            SELECT
                submitted,
                submitted_at
            FROM report_submissions
            WHERE id = 1
            """
        ).fetchone()

        report_submitted_at_display = format_display_timestamp(
            report_row["submitted_at"]
        )

    context = build_dashboard_context()
    context.update(
        {
            "report_submitted": bool(
                report_row["submitted"]
            ),
            "report_submitted_at": report_submitted_at_display,
            "can_submit": set(CASE_IDS).issubset(
                completed
            ),
        }
    )

    return render_template(
        "executive_report.html",
        iocs=[
            dict(row)
            for row in ioc_rows
        ],
        notes=[
            dict(row)
            for row in note_rows
        ],
        beginner_progress=beginner_progress,
        medium_progress=medium_progress,
        hard_progress=hard_progress,
        overall_progress=overall_progress,
        **context,
    )


@soc_features.route(
    "/soc/certificate",
    defaults={"level_name": None},
)
@soc_features.route(
    "/soc/certificate/<level_name>"
)
def certificate(level_name):
    require_login()

    username = session.get("username")

    if level_name is None:
        overall = get_overall_progress(
            username
        )

        if not overall["is_complete"]:
            abort(
                403,
                (
                    "Complete all fifteen investigations "
                    "to unlock the final certificate."
                ),
            )

        if not get_report_status():
            abort(
                403,
                (
                    "Submit the final executive report "
                    "to unlock the final certificate."
                ),
            )

        return render_template(
            "certificate.html",
            analyst=get_analyst_profile(),
            is_overall=True,
            completed_count=overall["completed"],
            total_cases=overall["total"],
            score=100,
            beginner_progress=overall["levels"][
                "beginner"
            ],
            medium_progress=overall["levels"][
                "medium"
            ],
            hard_progress=overall["levels"][
                "hard"
            ],
            completion_date=(
                get_completion_date_for_cases(
                    username,
                    get_all_cases(),
                )
            ),
        )

    level_name = str(level_name).lower()
    level = get_level(level_name)

    if not level:
        abort(404)

    progress = get_level_progress(
        username,
        level_name,
    )

    if not progress["is_complete"]:
        abort(
            403,
            (
                f"Complete all {level['name']} investigations "
                "to unlock this track certificate."
            ),
        )

    return render_template(
        "certificate.html",
        analyst=get_analyst_profile(),
        is_overall=False,
        level=level,
        level_name=level_name,
        completed_count=progress["completed"],
        total_cases=progress["total"],
        score=progress["percentage"],
        completion_date=(
            get_completion_date_for_cases(
                username,
                get_level_cases(
                    level_name
                ),
            )
        ),
    )


@soc_features.route(
    "/soc/reset-features",
    methods=["POST"],
)
def reset_features():
    require_login()

    with get_feature_db() as connection:
        connection.executescript(
            """
            DELETE FROM investigation_notes;
            DELETE FROM analyst_iocs;
            DELETE FROM evidence_views;
            DELETE FROM incorrect_attempts;

            UPDATE report_submissions
            SET
                submitted = 0,
                submitted_at = NULL
            WHERE id = 1;
            """
        )

        connection.commit()

    session.pop(
        "completed_cases",
        None,
    )

    username = session.get("username")

    if username:
        reset_user_progress(username)

    session.modified = True

    return redirect(
        url_for(
            "soc_features.dashboard"
        )
    )
