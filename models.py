from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from database import get_db
from level_config import (
    LEVELS,
    get_all_cases,
    get_level_cases,
)


DEFAULT_USERS = (
    ("analyst", "Analyst@123", "student"),
)


def get_user(username):
    return get_db().execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()


def is_password_hash(value):
    if not value:
        return False

    return value.startswith(
        (
            "scrypt:",
            "pbkdf2:",
        )
    )


def verify_user_password(user, password):
    if not user:
        return False

    stored_password = user["password"]

    if not is_password_hash(stored_password):
        return False
    try:
        return check_password_hash(stored_password, password)
    except (ValueError, TypeError):
        return False


def create_default_users():
    db = get_db()
    for username, password, role in DEFAULT_USERS:
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,),
        ).fetchone()
        if existing:
            continue
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
    db.commit()


def get_progress(username):
    rows = get_db().execute(
        """
        SELECT *
        FROM progress
        WHERE username = ?
        """,
        (username,),
    ).fetchall()

    return {
        row["investigation_id"]: dict(row)
        for row in rows
    }


def get_level_progress(
    username,
    level_name,
):
    progress = get_progress(username)
    normalized_level = str(level_name).lower()
    case_ids = get_level_cases(normalized_level)

    completed_cases = [
        case_id
        for case_id in case_ids
        if progress.get(
            case_id,
            {},
        ).get(
            "completed",
            False,
        )
    ]

    total = len(case_ids)
    completed = len(completed_cases)
    percentage = 0

    if total:
        percentage = int(
            completed / total * 100
        )

    return {
        "level": normalized_level,
        "total": total,
        "completed": completed,
        "remaining": total - completed,
        "percentage": percentage,
        "completed_cases": completed_cases,
        "is_complete": (
            total > 0
            and completed == total
        ),
    }


def get_overall_progress(username):
    progress = get_progress(username)
    case_ids = get_all_cases()

    completed_cases = [
        case_id
        for case_id in case_ids
        if progress.get(
            case_id,
            {},
        ).get(
            "completed",
            False,
        )
    ]

    total = len(case_ids)
    completed = len(completed_cases)
    percentage = 0

    if total:
        percentage = int(
            completed / total * 100
        )

    level_status = {
        level_name: get_level_progress(
            username,
            level_name,
        )
        for level_name in LEVELS
    }

    return {
        "total": total,
        "completed": completed,
        "remaining": total - completed,
        "percentage": percentage,
        "is_complete": (
            total > 0
            and completed == total
        ),
        "completed_cases": completed_cases,
        "levels": level_status,
    }


def get_investigation_progress(
    username,
    investigation_id,
):
    return get_db().execute(
        """
        SELECT *
        FROM progress
        WHERE username = ?
        AND investigation_id = ?
        """,
        (
            username,
            investigation_id,
        ),
    ).fetchone()


def ensure_progress(
    username,
    investigation_id,
):
    db = get_db()

    progress = get_investigation_progress(
        username,
        investigation_id,
    )

    if not progress:
        db.execute(
            """
            INSERT INTO progress (
                username,
                investigation_id
            )
            VALUES (?, ?)
            """,
            (
                username,
                investigation_id,
            ),
        )

        db.commit()

    return get_investigation_progress(
        username,
        investigation_id,
    )


def mark_findings_validated(
    username,
    investigation_id,
):
    db = get_db()

    ensure_progress(
        username,
        investigation_id,
    )

    db.execute(
        """
        UPDATE progress
        SET findings_validated = 1
        WHERE username = ?
        AND investigation_id = ?
        """,
        (
            username,
            investigation_id,
        ),
    )

    db.commit()


def save_validated_findings(
    username,
    investigation_id,
    submitted_answers,
):
    """Store the answers after the complete finding set is validated."""
    db = get_db()

    db.execute(
        """
        DELETE FROM validated_findings
        WHERE username = ?
        AND investigation_id = ?
        """,
        (
            username,
            investigation_id,
        ),
    )

    db.executemany(
        """
        INSERT INTO validated_findings (
            username,
            investigation_id,
            field,
            value
        )
        VALUES (?, ?, ?, ?)
        """,
        [
            (
                username,
                investigation_id,
                str(field),
                str(value).strip(),
            )
            for field, value in submitted_answers.items()
        ],
    )

    db.commit()


def get_validated_findings(
    username,
    investigation_id,
):
    rows = get_db().execute(
        """
        SELECT field, value
        FROM validated_findings
        WHERE username = ?
        AND investigation_id = ?
        ORDER BY field
        """,
        (
            username,
            investigation_id,
        ),
    ).fetchall()

    return {
        row["field"]: row["value"]
        for row in rows
    }


def record_submission(
    username,
    investigation_id,
    submitted_flag_hash,
    is_correct,
):
    """
    Record only the SHA-256 hash of a submitted flag.

    Plaintext flag values must never be stored in SQLite.
    """
    db = get_db()

    db.execute(
        """
        INSERT INTO submissions (
            username,
            investigation_id,
            submitted_flag,
            is_correct
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            username,
            investigation_id,
            submitted_flag_hash,
            int(is_correct),
        ),
    )

    db.commit()


def mark_completed(
    username,
    investigation_id,
):
    db = get_db()

    ensure_progress(
        username,
        investigation_id,
    )

    db.execute(
        """
        UPDATE progress
        SET completed = 1,
            completed_at = CURRENT_TIMESTAMP
        WHERE username = ?
        AND investigation_id = ?
        """,
        (
            username,
            investigation_id,
        ),
    )

    db.commit()


def get_submission_history(username):
    return get_db().execute(
        """
        SELECT *
        FROM submissions
        WHERE username = ?
        ORDER BY submitted_at DESC
        """,
        (username,),
    ).fetchall()


def reset_user_progress(username):
    db = get_db()

    db.execute(
        """
        DELETE FROM validated_findings
        WHERE username = ?
        """,
        (username,),
    )

    db.execute(
        """
        DELETE FROM submissions
        WHERE username = ?
        """,
        (username,),
    )

    db.execute(
        """
        DELETE FROM progress
        WHERE username = ?
        """,
        (username,),
    )

    db.commit()
