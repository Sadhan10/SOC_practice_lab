import hashlib
import hmac

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from investigation_loader import (
    load_all_investigations,
    load_investigation,
)
from level_config import (
    get_case_level,
    get_level_cases,
)
from models import (
    get_investigation_progress,
    get_level_progress,
    get_progress,
    get_validated_findings,
    mark_completed,
    record_submission,
)
from soc_features import (
    record_incorrect_attempt,
    set_case_completed_in_session,
)


flags_bp = Blueprint(
    "flags",
    __name__,
)


# -------------------------------------------------
# Flag recipes
# -------------------------------------------------

FLAG_RECIPES = {
    # Beginner
    "BF-2026-001": [
        "attacker_ip",
    ],

    "BF-2026-002": [
        "compromised_account",
        "attacker_ip",
    ],

    "BF-2026-003": [
        "uploaded_payload",
    ],

    "BF-2026-004": [
        "malware",
        "c2_domain",
    ],

    "BF-2026-005": [
        "attacker_ip",
        "c2_infrastructure",
    ],

    # Medium
    "BF-M-001": [
        "attacker_ip",
        "target_host",
    ],

    "BF-M-002": [
        "compromised_user",
        "attacker_ip",
    ],

    "BF-M-003": [
        "uploaded_file",
        "attacker_ip",
    ],

    "BF-M-004": [
        "compromised_host",
        "c2_domain",
    ],

    "BF-M-005": [
        "exfil_domain",
        "exfil_ip",
    ],

    # Hard
    "BF-H-001": [
        "attacker_ip",
        "primary_target",
        "secondary_target",
    ],

    "BF-H-002": [
        "initial_host",
        "pivot_host",
        "destination_host",
    ],

    "BF-H-003": [
        "attacker_ip",
        "payload",
        "execution_user",
    ],

    "BF-H-004": [
        "compromised_host",
        "c2_domain",
        "staged_archive",
    ],

    "BF-H-005": [
        "compromised_account",
        "c2_domain",
        "exfil_destination",
    ],
}


def require_login():
    return session.get(
        "logged_in"
    ) is True


# -------------------------------------------------
# Flag normalization
# -------------------------------------------------

def normalize_component(value):
    """
    Convert an investigation finding into a
    predictable flag component.

    Example:
        "Black Falcon.exe"
            ->
        "BLACK-FALCON.EXE"
    """

    value = str(value).strip()

    value = " ".join(
        value.split()
    )

    value = value.replace(
        " ",
        "-",
    )

    return value.upper()


def normalize_flag(flag):
    """
    Normalize the complete submitted flag.
    """

    return str(flag).strip().upper()


def hash_flag(flag):
    """
    Hash the normalized flag before comparing
    or storing it.
    """

    normalized = normalize_flag(flag)

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


# -------------------------------------------------
# Evidence-derived flag generation
# -------------------------------------------------

def build_case_flag(
    investigation_id,
    findings,
):
    """
    Construct the expected CTF flag from
    validated investigation findings.

    The correct plaintext flag is not stored
    in the investigation JSON or database.
    """

    recipe = FLAG_RECIPES.get(
        investigation_id
    )

    if not recipe:
        raise RuntimeError(
            "No flag recipe configured for "
            "{0}".format(
                investigation_id
            )
        )

    components = []

    for field in recipe:

        value = findings.get(field)

        if value is None or not str(
            value
        ).strip():

            raise RuntimeError(
                "Validated finding '{0}' "
                "is missing for {1}.".format(
                    field,
                    investigation_id,
                )
            )

        components.append(
            normalize_component(
                value
            )
        )

    return "FLAG{{{0}}}".format(
        "_".join(
            components
        )
    )


def get_flag_rule(
    investigation_id,
):
    """
    Produce a student-facing construction rule
    without exposing the correct answer.
    """

    recipe = FLAG_RECIPES.get(
        investigation_id,
        [],
    )

    if not recipe:
        return None

    placeholders = [
        field.upper()
        for field in recipe
    ]

    return "FLAG{{{0}}}".format(
        "_".join(
            placeholders
        )
    )


# -------------------------------------------------
# Flag submission
# -------------------------------------------------

def render_submit_flag(
    investigations,
    username,
):

    progress_map = get_progress(username)
    requested_case_id = (
        request.form.get("investigation_id", "").strip()
        or request.args.get("case_id", "").strip()
    )
    available_case_ids = {
        investigation["id"] for investigation in investigations
    }
    if requested_case_id not in available_case_ids:
        requested_case_id = ""

    return render_template(
        "submit_flag.html",
        investigations=investigations,
        progress_map=progress_map,
        selected_case_id=requested_case_id,
    )


@flags_bp.route(
    "/submit-flag",
    methods=[
        "GET",
        "POST",
    ],
)
def submit_flag():

    if not require_login():

        return redirect(
            url_for(
                "auth.login"
            )
        )

    username = session[
        "username"
    ]

    selected_level = session.get(
        "selected_level",
        "beginner",
    )

    selected_case_ids = set(
        get_level_cases(
            selected_level
        )
    )

    investigations = [
        investigation
        for investigation
        in load_all_investigations()
        if investigation.get(
            "id"
        ) in selected_case_ids
    ]

    if request.method == "POST":

        investigation_id = (
            request.form.get(
                "investigation_id",
                "",
            ).strip()
        )

        submitted_flag = (
            request.form.get(
                "flag",
                "",
            ).strip()
        )

        investigation = (
            load_investigation(
                investigation_id
            )
        )

        case_level = get_case_level(
            investigation_id
        )

        if (
            not investigation
            or not case_level
        ):

            flash(
                "Invalid investigation "
                "selected.",
                "error",
            )

            return render_submit_flag(
                investigations,
                username,
            )

        session[
            "selected_level"
        ] = case_level

        if not submitted_flag:

            flash(
                "Flag cannot be empty.",
                "error",
            )

            return render_submit_flag(
                investigations,
                username,
            )

        progress = (
            get_investigation_progress(
                username,
                investigation_id,
            )
        )

        if (
            not progress
            or not progress[
                "findings_validated"
            ]
        ):

            flash(
                "Validate the investigation "
                "findings before submitting "
                "its flag.",
                "error",
            )

            return render_submit_flag(
                investigations,
                username,
            )

        findings = (
            get_validated_findings(
                username,
                investigation_id,
            )
        )

        if not findings:

            flash(
                "Validated findings could not "
                "be loaded. Revalidate the "
                "investigation.",
                "error",
            )

            return render_submit_flag(
                investigations,
                username,
            )

        try:

            expected_flag = (
                build_case_flag(
                    investigation_id,
                    findings,
                )
            )

        except RuntimeError as exc:

            current_app.logger.error(
                "%s",
                exc,
            )

            flash(
                "Flag construction failed. "
                "Revalidate the investigation.",
                "error",
            )

            return render_submit_flag(
                investigations,
                username,
            )

        expected_hash = hash_flag(
            expected_flag
        )

        submitted_hash = hash_flag(
            submitted_flag
        )

        is_correct = (
            hmac.compare_digest(
                submitted_hash,
                expected_hash,
            )
        )

        # Only the SHA-256 hash of the submitted
        # flag is stored.
        record_submission(
            username,
            investigation_id,
            submitted_hash,
            is_correct,
        )

        if is_correct:

            mark_completed(
                username,
                investigation_id,
            )

            set_case_completed_in_session(
                investigation_id
            )

            current_app.logger.info(
                "Correct flag submitted "
                "by %s for %s",
                username,
                investigation_id,
            )

            level_progress = (
                get_level_progress(
                    username,
                    case_level,
                )
            )

            if level_progress[
                "is_complete"
            ]:

                return redirect(
                    url_for(
                        "soc_features."
                        "level_completed",
                        level_name=(
                            case_level
                        ),
                    )
                )

            return redirect(
                url_for(
                    "flags.completed",
                    investigation_id=(
                        investigation_id
                    ),
                )
            )

        record_incorrect_attempt(
            investigation_id
        )

        current_app.logger.warning(
            "Incorrect flag submitted "
            "by %s for %s",
            username,
            investigation_id,
        )

        flash(
            "Incorrect flag. Review your "
            "validated findings and the "
            "flag construction rule.",
            "error",
        )

    return render_submit_flag(
        investigations,
        username,
    )


# -------------------------------------------------
# Completed page
# -------------------------------------------------

@flags_bp.route(
    "/completed/<investigation_id>"
)
def completed(
    investigation_id
):

    if not require_login():

        return redirect(
            url_for(
                "auth.login"
            )
        )

    investigation = (
        load_investigation(
            investigation_id
        )
    )

    if not investigation:

        return redirect(
            url_for(
                "dashboard.dashboard"
            )
        )

    username = session[
        "username"
    ]

    progress = (
        get_investigation_progress(
            username,
            investigation_id,
        )
    )

    if (
        not progress
        or not progress[
            "completed"
        ]
    ):

        return redirect(
            url_for(
                "flags.submit_flag"
            )
        )

    case_level = get_case_level(
        investigation_id
    )

    if not case_level:

        return redirect(
            url_for(
                "dashboard.dashboard"
            )
        )

    session[
        "selected_level"
    ] = case_level

    level_progress = (
        get_level_progress(
            username,
            case_level,
        )
    )

    return render_template(
        "completed.html",
        investigation=investigation,
        level_name=case_level,
        completed_count=(
            level_progress[
                "completed"
            ]
        ),
        total_investigations=(
            level_progress[
                "total"
            ]
        ),
        score_percent=(
            level_progress[
                "percentage"
            ]
        ),
    )
