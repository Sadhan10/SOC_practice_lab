import hashlib
import hmac
import json

from flask import current_app

from investigation_loader import (
    normalize_answer,
)


def hash_answer(value):
    normalized = normalize_answer(
        value
    )

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


def load_solution_store():
    path = current_app.config[
        "SOLUTION_STORE_PATH"
    ]

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:
            return json.load(file)

    except (OSError, json.JSONDecodeError):
        current_app.logger.exception(
            "Unable to load solution store."
        )
        return {}


def validate_case_answer(
    investigation_id,
    field,
    submitted_value,
):
    store = load_solution_store()

    case = store.get(
        investigation_id,
        {}
    )

    accepted_hashes = case.get(
        field,
        []
    )

    submitted_hash = hash_answer(
        submitted_value
    )

    return any(
        hmac.compare_digest(
            submitted_hash,
            expected_hash,
        )
        for expected_hash
        in accepted_hashes
    )
