import os
from datetime import timedelta


BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)


class Config:
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
