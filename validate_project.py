from __future__ import print_function

import io
import json
import os
import sys

from level_config import LEVELS
from config import Config


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

INVESTIGATION_DIR = os.path.join(
    BASE_DIR,
    "investigations"
)

EVIDENCE_DIR = os.path.join(
    BASE_DIR,
    "evidence"
)

SOURCE_SOLUTION_FILE = os.path.join(
    BASE_DIR,
    "private",
    "solutions.json"
)

SOLUTION_FILE = SOURCE_SOLUTION_FILE


try:
    string_types = (basestring,)
except NameError:
    string_types = (str,)


errors = []
warnings = []


def error(message):
    errors.append(message)


def warning(message):
    warnings.append(message)


def load_json(path):

    try:
        with io.open(
            path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except IOError:

        error(
            "Missing file: {0}".format(path)
        )

    except ValueError as exc:

        line_number = getattr(
            exc,
            "lineno",
            "unknown"
        )

        error(
            "Invalid JSON: {0} "
            "(line {1})".format(
                path,
                line_number
            )
        )

    return None


print()
print("=" * 65)
print(" OPERATION BLACK FALCON")
print(" PROJECT VALIDATION")
print("=" * 65)
print()


# ------------------------------------------------
# Load solutions
# ------------------------------------------------

solutions = load_json(
    SOLUTION_FILE
)

if solutions is None:
    solutions = {}


# ------------------------------------------------
# Validate levels
# ------------------------------------------------

configured_cases = []


for level_name, level in LEVELS.items():

    print(
        "[LEVEL] {0}".format(
            level_name.upper()
        )
    )

    cases = level.get(
        "cases",
        []
    )

    if len(cases) != 5:

        warning(
            "{0} contains {1} cases "
            "instead of 5.".format(
                level_name,
                len(cases)
            )
        )

    for case_id in cases:

        configured_cases.append(
            case_id
        )

        print(
            "   Checking {0}...".format(
                case_id
            )
        )

        investigation_path = os.path.join(
            INVESTIGATION_DIR,
            "{0}.json".format(case_id)
        )

        investigation = load_json(
            investigation_path
        )

        if not investigation:
            continue


        # ----------------------------------------
        # ID
        # ----------------------------------------

        if investigation.get(
            "id"
        ) != case_id:

            error(
                "{0}: JSON id does not match "
                "configured case ID.".format(
                    case_id
                )
            )


        # ----------------------------------------
        # Level
        # ----------------------------------------

        investigation_level = (
            investigation.get(
                "level",
                ""
            ).lower()
        )

        if investigation_level != level_name:

            error(
                "{0}: level is '{1}' but should "
                "be '{2}'.".format(
                    case_id,
                    investigation_level,
                    level_name
                )
            )


        # ----------------------------------------
        # Required metadata
        # ----------------------------------------

        required_fields = [
            "title",
            "story",
            "objective",
            "difficulty",
        ]

        for field in required_fields:

            if not investigation.get(
                field
            ):

                error(
                    "{0}: missing '{1}'.".format(
                        case_id,
                        field
                    )
                )


        # ----------------------------------------
        # Evidence resources
        # ----------------------------------------

        resources = investigation.get(
            "resources",
            []
        )

        if not resources:

            warning(
                "{0}: no evidence resources "
                "configured.".format(case_id)
            )


        for resource in resources:

            evidence_path = resource.get(
                "path"
            )

            if not evidence_path:

                error(
                    "{0}: evidence resource "
                    "missing path.".format(case_id)
                )

                continue

            full_evidence_path = os.path.join(
                EVIDENCE_DIR,
                *evidence_path.replace(
                    "\\",
                    "/"
                ).split("/")
            )

            if not os.path.isfile(
                full_evidence_path
            ):

                error(
                    "{0}: missing evidence "
                    "'{1}'".format(
                        case_id,
                        evidence_path
                    )
                )


        # ----------------------------------------
        # Questions
        # ----------------------------------------

        questions = investigation.get(
            "questions",
            []
        )

        if not questions:

            error(
                "{0}: no investigation questions "
                "configured.".format(case_id)
            )

            continue


        question_fields = []


        for question in questions:

            field = question.get(
                "field"
            )

            label = question.get(
                "label"
            )

            if not field:

                error(
                    "{0}: question missing "
                    "field name.".format(case_id)
                )

                continue

            if not label:

                error(
                    "{0}: '{1}' has no question "
                    "label.".format(
                        case_id,
                        field
                    )
                )


            if field in question_fields:

                error(
                    "{0}: duplicate question "
                    "field '{1}'.".format(
                        case_id,
                        field
                    )
                )

            question_fields.append(
                field
            )


        # ----------------------------------------
        # Solutions
        # ----------------------------------------

        case_solutions = solutions.get(
            case_id
        )

        if not case_solutions:

            error(
                "{0}: no entry in the "
                "configured solution store".format(
                    case_id
                )
            )

            continue


        for field in question_fields:

            hashes = case_solutions.get(
                field
            )

            if not hashes:

                error(
                    "{0}: solution missing for "
                    "'{1}'.".format(
                        case_id,
                        field
                    )
                )

                continue


            if not isinstance(
                hashes,
                list
            ):

                error(
                    "{0}: solution for '{1}' must "
                    "be a list.".format(
                        case_id,
                        field
                    )
                )

                continue


            for value in hashes:

                if not isinstance(
                    value,
                    string_types
                ):

                    error(
                        "{0}: invalid solution "
                        "value for '{1}'.".format(
                            case_id,
                            field
                        )
                    )

                    continue

                if len(value) != 64:

                    warning(
                        "{0}: '{1}' contains a "
                        "value that does not look "
                        "like SHA-256.".format(
                            case_id,
                            field
                        )
                    )


    print()


# ------------------------------------------------
# Duplicate case IDs
# ------------------------------------------------

duplicates = {
    case_id
    for case_id in configured_cases
    if configured_cases.count(case_id) > 1
}

for case_id in duplicates:

    error(
        "Duplicate configured case: "
        "{0}".format(case_id)
    )


# ------------------------------------------------
# Check unknown solutions
# ------------------------------------------------

for case_id in solutions:

    if case_id not in configured_cases:

        warning(
            "solutions.json contains "
            "unconfigured case '{0}'.".format(
                case_id
            )
        )


# ------------------------------------------------
# Summary
# ------------------------------------------------

print("=" * 65)
print(" VALIDATION SUMMARY")
print("=" * 65)

print()
print(
    "Configured cases : {0}".format(
        len(configured_cases)
    )
)

print(
    "Errors           : {0}".format(
        len(errors)
    )
)

print(
    "Warnings         : {0}".format(
        len(warnings)
    )
)

print()


if warnings:

    print("WARNINGS")
    print("-" * 65)

    for item in warnings:
        print(
            "[!] {0}".format(item)
        )

    print()


if errors:

    print("ERRORS")
    print("-" * 65)

    for item in errors:
        print(
            "[X] {0}".format(item)
        )

    print()

    print(
        "PROJECT VALIDATION FAILED"
    )

    sys.exit(1)


print(
    "PROJECT VALIDATION PASSED"
)

print(
    "All configured investigations, "
    "evidence and solutions are valid."
)

sys.exit(0)
