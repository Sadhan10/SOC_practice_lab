import os
import sqlite3

from flask import current_app, g


USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
);
"""


SUBMISSIONS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    submitted_flag TEXT NOT NULL,
    is_correct INTEGER NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


PROGRESS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    findings_validated INTEGER DEFAULT 0,
    completed INTEGER DEFAULT 0,
    completed_at TIMESTAMP,
    UNIQUE (username, investigation_id)
);
"""


VALIDATED_FINDINGS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS validated_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    field TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (
        username,
        investigation_id,
        field
    )
);
"""


def ensure_dir(path):
    os.makedirs(
        path,
        exist_ok=True,
    )


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config[
                "DATABASE_PATH"
            ]
        )

        g.db.row_factory = sqlite3.Row

    return g.db


def close_db(error=None):
    del error

    db = g.pop(
        "db",
        None,
    )

    if db is not None:
        db.close()


def create_tables(db):
    db.execute(
        USERS_TABLE_SQL
    )

    db.execute(
        SUBMISSIONS_TABLE_SQL
    )

    db.execute(
        PROGRESS_TABLE_SQL
    )

    db.execute(
        VALIDATED_FINDINGS_TABLE_SQL
    )

    db.commit()


def init_db(app):
    ensure_dir(
        app.config["DATABASE_DIR"]
    )

    ensure_dir(
        app.config["INVESTIGATION_DIR"]
    )

    ensure_dir(
        app.config["EVIDENCE_DIR"]
    )

    ensure_dir(
        app.config["LOG_DIR"]
    )

    # Register cleanup before the initialization context opens a connection.
    app.teardown_appcontext(
        close_db
    )

    with app.app_context():
        db = get_db()

        create_tables(db)
