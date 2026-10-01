from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from investigation_loader import load_investigation, validate_findings
from level_config import get_case_level
from models import (
    ensure_progress,
    mark_findings_validated,
    save_validated_findings,
)
from routes.flags import get_flag_rule

investigations_bp = Blueprint("investigations", __name__)


def require_login():
    return session.get("logged_in") is True


@investigations_bp.route("/investigations/<investigation_id>", methods=["GET", "POST"])
def investigation_detail(investigation_id):
    if not require_login():
        return redirect(url_for("auth.login"))

    investigation = load_investigation(investigation_id)
    case_level = get_case_level(investigation_id)

    if not investigation or not case_level:
        return redirect(url_for("dashboard.dashboard"))

    session["selected_level"] = case_level

    username = session["username"]
    progress = ensure_progress(username, investigation_id)
    validation_results = {}
    submitted_answers = {}

    if request.method == "POST":
        submitted_answers = {
            question["field"]: request.form.get(question["field"], "").strip()
            for question in investigation.get("questions", [])
        }

        all_correct, validation_results = validate_findings(
            investigation,
            submitted_answers,
        )

        if all_correct:
            # Store the validated plaintext answers. These values are only
            # stored after the entire answer set has been proven correct.
            save_validated_findings(
                username,
                investigation_id,
                submitted_answers,
            )
            mark_findings_validated(username, investigation_id)
            progress = ensure_progress(username, investigation_id)

            if investigation_id == "BF-2026-005":
                flash(
                    "Executive report validated. "
                    "Use your investigation findings "
                    "to construct the final flag.",
                    "success",
                )
            else:
                flash(
                    "Findings validated. Use the "
                    "flag construction rule to "
                    "recover the final flag.",
                    "success",
                )
        else:
            flash("Some findings are incorrect. Review the evidence and try again.", "error")

    flag_rule = get_flag_rule(
        investigation_id
    )

    return render_template(
        "investigation.html",
        investigation=investigation,
        progress=progress,
        validation_results=validation_results,
        submitted_answers=submitted_answers,
        flag_rule=flag_rule,
    )
