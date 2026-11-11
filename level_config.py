LEVELS = {
    "beginner": {
        "name": "Beginner",
        "subtitle": "SOC Foundation",
        "difficulty": "Beginner",
        "description": (
            "Guided SOC investigations using "
            "prepared evidence and structured analysis."
        ),
        "cases": [
            "BF-2026-001",
            "BF-2026-002",
            "BF-2026-003",
            "BF-2026-004",
            "BF-2026-005",
        ],
        "tools": [
            "Suricata",
            "Zeek",
            "Wazuh",
            "Cowrie",
        ],
    },
    "medium": {
        "name": "Medium",
        "subtitle": "SOC Analyst",
        "difficulty": "Medium",
        "description": (
            "Practical SOC investigations requiring "
            "multi-source telemetry correlation and "
            "attack reconstruction."
        ),
        "cases": [
            "BF-M-001",
            "BF-M-002",
            "BF-M-003",
            "BF-M-004",
            "BF-M-005",
        ],
        "tools": [
            "Suricata",
            "Zeek",
            "Wazuh",
            "Log Correlation",
            "Incident Analysis",
        ],
    },
    "hard": {
        "name": "Hard",
        "subtitle": "Threat Hunter",
        "difficulty": "Hard",
        "description": (
            "Advanced threat hunting across noisy "
            "telemetry, benign activity, false positives "
            "and incomplete incident evidence."
        ),
        "cases": [
            "BF-H-001",
            "BF-H-002",
            "BF-H-003",
            "BF-H-004",
            "BF-H-005",
        ],
        "tools": [
            "Suricata",
            "Zeek",
            "Wazuh",
            "Threat Hunting",
            "Attack Reconstruction",
        ],
    },
}


def get_level(level_name):
    return LEVELS.get(
        str(level_name).lower()
    )


def get_level_cases(level_name):
    level = get_level(level_name)

    if not level:
        return []

    return level["cases"]


def get_case_level(case_id):
    for level_name, level in LEVELS.items():
        if case_id in level["cases"]:
            return level_name

    return None


def get_all_cases():
    cases = []

    for level in LEVELS.values():
        cases.extend(
            level["cases"]
        )

    return cases
