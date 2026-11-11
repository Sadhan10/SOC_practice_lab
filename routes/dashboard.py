from flask import (
    Blueprint,
    redirect,
    render_template,
    session,
    url_for,
)

from investigation_loader import load_investigation
from level_config import (
    get_level,
    get_level_cases,
)
from models import (
    get_level_progress,
    get_overall_progress,
    get_progress,
)
from soc_features import (
    get_report_status,
)


dashboard_bp = Blueprint(
    "dashboard",
    __name__,
)


def require_login():
    return session.get("logged_in") is True


@dashboard_bp.route("/levels")
def levels():
    if not require_login():
        return redirect(
            url_for("auth.login")
        )

    username = session.get("username")

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

    return render_template(
        "levels.html",
        beginner_progress=beginner_progress,
        medium_progress=medium_progress,
        hard_progress=hard_progress,
        overall_progress=overall_progress,
    )


@dashboard_bp.route("/operation-complete")
def operation_complete():
    if not require_login():
        return redirect(
            url_for("auth.login")
        )

    username = session.get("username")
    progress = get_overall_progress(
        username
    )

    if not progress["is_complete"]:
        return redirect(
            url_for("dashboard.levels")
        )

    return render_template(
        "operation_complete.html",
        progress=progress,
        report_submitted=(
            get_report_status()
        ),
    )


@dashboard_bp.route("/dashboard")
def dashboard():
    if not require_login():
        return redirect(
            url_for("auth.login")
        )

    level = session.get(
        "selected_level",
        "beginner",
    )

    if level in (
        "medium",
        "hard",
    ):
        return redirect(
            url_for(
                "dashboard.level_dashboard",
                level_name=level,
            )
        )

    return redirect(
        url_for(
            "soc_features.dashboard"
        )
    )


@dashboard_bp.route("/level/<level_name>")
def select_level(level_name):
    if not require_login():
        return redirect(
            url_for("auth.login")
        )

    level_name = level_name.lower()

    if level_name == "beginner":
        session["selected_level"] = "beginner"

        return redirect(
            url_for(
                "soc_features.dashboard"
            )
        )

    if level_name in (
        "medium",
        "hard",
    ):
        session["selected_level"] = level_name

        return redirect(
            url_for(
                "dashboard.level_dashboard",
                level_name=level_name,
            )
        )

    return redirect(
        url_for(
            "dashboard.levels"
        )
    )


@dashboard_bp.route(
    "/level-dashboard/<level_name>"
)
def level_dashboard(level_name):
    if not require_login():
        return redirect(
            url_for("auth.login")
        )

    level_name = level_name.lower()
    level = get_level(level_name)

    if not level:
        return redirect(
            url_for("dashboard.levels")
        )

    if level_name == "beginner":
        session["selected_level"] = "beginner"

        return redirect(
            url_for(
                "soc_features.dashboard"
            )
        )

    session["selected_level"] = level_name

    username = session.get("username")
    progress = get_progress(username)
    level_progress = get_level_progress(
        username,
        level_name,
    )
    case_ids = get_level_cases(
        level_name
    )
    investigations = []

    for case_id in case_ids:
        investigation = load_investigation(
            case_id
        )

        if investigation is None:
            investigations.append(
                {
                    "id": case_id,
                    "available": False,
                }
            )
            continue

        case_progress = progress.get(
            case_id,
            {},
        )

        completed = bool(
            case_progress.get(
                "completed",
                False,
            )
        )

        findings_validated = bool(
            case_progress.get(
                "findings_validated",
                False,
            )
        )

        investigations.append(
            {
                "id": case_id,
                "available": True,
                "title": investigation.get(
                    "title",
                    case_id,
                ),
                "difficulty": investigation.get(
                    "difficulty",
                    level["difficulty"],
                ),
                "priority": investigation.get(
                    "priority",
                    "Medium",
                ),
                "objective": investigation.get(
                    "objective",
                    "",
                ),
                "tools": investigation.get(
                    "tools",
                    [],
                ),
                "completed": completed,
                "findings_validated": findings_validated,
            }
        )

    return render_template(
        "level_dashboard.html",
        level=level,
        level_name=level_name,
        investigations=investigations,
        completed_count=level_progress[
            "completed"
        ],
        total_cases=level_progress[
            "total"
        ],
        completion_percentage=level_progress[
            "percentage"
        ],
    )
