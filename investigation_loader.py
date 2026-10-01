import json
import os
import re

from flask import current_app


def load_investigation(investigation_id):
    """
    Load one investigation JSON file.
    """
    safe_id = os.path.basename(investigation_id)

    file_path = os.path.join(
        current_app.config["INVESTIGATION_DIR"],
        f"{safe_id}.json",
    )

    if not os.path.isfile(file_path):
        return None

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
        ) as investigation_file:
            return json.load(investigation_file)

    except (OSError, json.JSONDecodeError):
        current_app.logger.exception(
            "Unable to load investigation: %s",
            safe_id,
        )

        return None


def load_all_investigations():
    """
    Load all investigation JSON files.
    """
    investigation_dir = current_app.config[
        "INVESTIGATION_DIR"
    ]

    investigations = []

    if not os.path.isdir(investigation_dir):
        return investigations

    for filename in sorted(
        os.listdir(investigation_dir)
    ):
        if not filename.endswith(".json"):
            continue

        investigation_id = filename[:-5]

        investigation = load_investigation(
            investigation_id
        )

        if investigation:
            investigations.append(investigation)

    return investigations


def normalize_answer(value):
    """
    Normalize student answers before comparison.

    This makes validation tolerant of:
    - Uppercase and lowercase differences
    - Extra whitespace
    - Commas
    - Hyphens surrounded by spaces
    """
    if value is None:
        return ""

    normalized = str(value).strip().lower()

    # Replace commas with spaces.
    normalized = normalized.replace(",", " ")

    # Normalize whitespace around hyphens.
    normalized = re.sub(
        r"\s*-\s*",
        "-",
        normalized,
    )

    # Collapse repeated whitespace.
    normalized = re.sub(
        r"\s+",
        " ",
        normalized,
    )

    # Normalize common SQL injection formatting.
    normalized = normalized.replace(
        "1 = 1",
        "1=1",
    )

    normalized = normalized.replace(
        "'or",
        "' or",
    )

    normalized = normalized.replace(
        "1=1--",
        "1=1 --",
    )

    # Remove accidental spaces inside long cryptographic hashes.
    if re.fullmatch(
        r"[a-f0-9\s]{32,128}",
        normalized,
    ):
        normalized = normalized.replace(" ", "")

    return normalized.strip()


def validate_findings(
    investigation,
    submitted_answers,
):
    from solution_store import validate_case_answer

    validation_results = {}
    all_correct = True

    investigation_id = investigation.get("id")

    if not investigation_id:
        return False, {}

    for question in investigation.get(
        "questions",
        []
    ):
        field = question.get("field")

        submitted_value = submitted_answers.get(
            field,
            "",
        )

        is_correct = validate_case_answer(
            investigation_id,
            field,
            submitted_value,
        )

        validation_results[field] = is_correct

        if not is_correct:
            all_correct = False

    return all_correct, validation_results
