import os
from datetime import timedelta


BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)


class Config:
    # Assessment mode is the release default; practice requires explicit opt-in.
    FINAL_SOC_SHOW_ANSWERS = (
        os.environ.get("BLACK_FALCON_SHOW_ASSESSMENT_ANSWERS", "0") == "1"
    )
    FINAL_SOC_PASS_PERCENTAGE = 70
    SOC_FEATURE_DATABASE_PATH = None
    CERTIFICATE_SOFFICE_PATH = os.environ.get("BLACK_FALCON_SOFFICE")
    # Instructors explicitly open registration during local training enrollment.
    STUDENT_REGISTRATION_ENABLED = (
        os.environ.get("BLACK_FALCON_REGISTRATION_ENABLED", "0") == "1"
    )
    AUTH_RATE_WINDOW_SECONDS = 900
    REGISTRATION_RATE_LIMIT = 10
    LOGIN_IP_RATE_LIMIT = 30
    LOGIN_USERNAME_RATE_LIMIT = 10

    SECRET_KEY = os.environ.get(
        "BLACK_FALCON_SECRET_KEY"
    )

    DATABASE_DIR = os.path.join(
        BASE_DIR,
        "database"
    )

    DATABASE_PATH = os.path.join(
        DATABASE_DIR,
        "black_falcon.db"
    )

    INVESTIGATION_DIR = os.path.join(
        BASE_DIR,
        "investigations"
    )

    EVIDENCE_DIR = os.path.join(
        BASE_DIR,
        "evidence"
    )

    EVIDENCE_FOLDER = EVIDENCE_DIR

    LOG_DIR = os.path.join(
        BASE_DIR,
        "logs"
    )

    LOG_FILE = os.path.join(
        LOG_DIR,
        "ctf.log"
    )

    SOLUTION_STORE_PATH = os.environ.get(
        "BLACK_FALCON_SOLUTION_STORE",
        "/var/lib/black-falcon/solutions.json",
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(
        hours=8
    )

    MAX_CONTENT_LENGTH = (
        5 * 1024 * 1024
    )
