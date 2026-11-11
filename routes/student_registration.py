"""Instructor-controlled student registration and read-only student profiles."""

import re
import sqlite3
import unicodedata
from datetime import datetime, timezone

from flask import (
    Blueprint, current_app, flash, redirect, render_template, request, session, url_for,
)
from werkzeug.security import generate_password_hash

from auth_limits import limit_attempts
from database import get_db
from routes.soc_operations import analyst_required, csrf_token, validate_csrf


registration_bp = Blueprint("registration", __name__)
USERNAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{3,31}$")
RESERVED_USERNAMES = {"analyst", "admin", "administrator", "instructor", "root"}
USN_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9/-]{2,31}$")
MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128
# A basic local safeguard. Expand this blocklist before production deployment.
COMMON_PASSWORDS = frozenset({
    "passwordpassword", "passwordpassword1", "passwordpassword123",
    "password123456789", "123456789012345", "1234567890123456",
    "12345678901234567890", "qwertyuiopasdfgh", "qwertyuiopasdfghjkl",
    "letmeinletmeinletmein", "correct horse battery staple",
})


def normalize_usn(value):
    """Store optional USNs in uppercase; blank values become NULL."""
    value = value.strip().upper()
    if not value:
        return None
    if not USN_PATTERN.fullmatch(value):
        raise ValueError("USN must contain 3-32 letters, numbers, hyphens or forward slashes, starting with a letter or number.")
    return value


def validate_student_password(password, confirmation):
    if password != confirmation:
        return "Passwords do not match."
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        return "Your password must contain 15 to 128 characters. Passphrases and spaces are supported."
    if password.strip().casefold() in COMMON_PASSWORDS or not password.strip():
        return "Choose a less common password or a longer, unique passphrase."
    return None


def initialize_student_profiles(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS student_profiles (
            username TEXT PRIMARY KEY REFERENCES users(username),
            full_name TEXT NOT NULL CHECK (length(full_name) BETWEEN 2 AND 100),
            usn TEXT,
            created_at TEXT NOT NULL,
            name_locked INTEGER NOT NULL DEFAULT 0 CHECK (name_locked IN (0, 1))
        )
    """)
    existing_columns = {row["name"] for row in db.execute("PRAGMA table_info(student_profiles)")}
    if "usn" not in existing_columns:
        db.execute("ALTER TABLE student_profiles ADD COLUMN usn TEXT")
    db.execute("""
        CREATE TRIGGER IF NOT EXISTS student_certificate_identity_locked
        BEFORE UPDATE OF username, full_name, name_locked ON student_profiles
        WHEN OLD.name_locked = 1 AND (
            NEW.username != OLD.username OR NEW.full_name != OLD.full_name OR NEW.name_locked != 1
        )
        BEGIN
            SELECT RAISE(ABORT, 'Certificate identity is locked');
        END
    """)
    # Existing certificates retain their original names and bytes. Do not
    # invent profiles for legacy/shared accounts during migration.
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='soc_certificates'").fetchone():
        db.execute("""
            UPDATE student_profiles SET name_locked=1
            WHERE username IN (SELECT username FROM soc_certificates)
        """)
    db.commit()


def valid_full_name(value):
    if (not isinstance(value, str) or not 2 <= len(value.strip()) <= 100
            or any(unicodedata.category(char).startswith("C") for char in value)
            or any(char in "<>" for char in value)
            or not any(char.isalpha() for char in value)):
        return None
    return " ".join(value.split())


def student_profile():
    return get_db().execute(
        "SELECT username, full_name, usn, created_at, name_locked FROM student_profiles WHERE username=?",
        (session["username"],),
    ).fetchone()


@registration_bp.after_request
def private_identity_response(response):
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.vary.add("Cookie")
    return response


@registration_bp.route("/student/register", methods=["GET", "POST"])
@registration_bp.route("/register", methods=["GET", "POST"])
def register():
    if session.get("logged_in") is True and session.get("username"):
        return redirect(url_for("registration.profile"))
    enabled = current_app.config.get("STUDENT_REGISTRATION_ENABLED") is True
    errors = []
    values = {"full_name": "", "username": "", "usn": ""}
    status = 200 if enabled else 503
    if enabled and request.method == "POST":
        limit_attempts([("registration_ip", request.remote_addr or "unknown",
                         current_app.config["REGISTRATION_RATE_LIMIT"])])
        validate_csrf()
        fields = ("full_name", "username", "password", "confirm_password")
        submitted = {field: request.form.getlist(field) for field in fields}
        submitted_usns = request.form.getlist("usn")
        if any(len(items) != 1 for items in submitted.values()) or len(submitted_usns) > 1:
            errors.append("Provide each required field once.")
        else:
            full_name = valid_full_name(submitted["full_name"][0])
            username = submitted["username"][0].strip().lower()
            password = submitted["password"][0]
            confirmation = submitted["confirm_password"][0]
            supplied_usn = submitted_usns[0] if submitted_usns else ""
            values = {"full_name": submitted["full_name"][0][:100], "username": username[:32],
                      "usn": supplied_usn[:32]}
            try:
                usn = normalize_usn(supplied_usn)
            except ValueError as exc:
                errors.append(str(exc))
            if full_name is None:
                errors.append("Enter a full name of 2 to 100 characters without control characters or angle brackets.")
            if not USERNAME_RE.fullmatch(username) or username in RESERVED_USERNAMES:
                errors.append("Choose a username of 4 to 32 lowercase letters, digits, dots, hyphens or underscores, starting with a letter. Reserved account names are unavailable.")
            password_error = validate_student_password(password, confirmation)
            if password_error:
                errors.append(password_error)
            if not errors:
                db = get_db()
                if db.execute("SELECT 1 FROM users WHERE lower(username)=?", (username,)).fetchone():
                    errors.append("That username is unavailable. Choose another username.")
                    status = 409
                else:
                    password_hash = generate_password_hash(password)
                    try:
                        with db:
                            db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'student')",
                                       (username, password_hash))
                            db.execute("INSERT INTO student_profiles (username, full_name, usn, created_at) VALUES (?, ?, ?, ?)",
                                       (username, full_name, usn, datetime.now(timezone.utc).isoformat()))
                    except sqlite3.IntegrityError as error:
                        if "UNIQUE constraint failed: users.username" not in str(error):
                            raise
                        errors.append("That username is unavailable. Choose another username.")
                        status = 409
                    else:
                        session.clear()
                        flash("Your student account is ready. Sign in with your new username and password.", "success")
                        return redirect(url_for("auth.login"))
        if errors and status == 200:
            status = 400
    return render_template(
        "student_register.html", registration_enabled=enabled, errors=errors,
        values=values, csrf_token=csrf_token(),
    ), status


@registration_bp.get("/profile")
@analyst_required
def profile():
    return render_template("student_profile.html", student=student_profile())
