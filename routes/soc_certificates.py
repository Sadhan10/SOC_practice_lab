"""Independent final SOC certificate preview, immutable issuance and download."""

import hashlib
import io
import secrets
import uuid
from datetime import datetime, timezone

from flask import (
    Blueprint, abort, current_app, redirect, render_template, request,
    send_file, session, url_for,
)

from certificate_generator import (
    CertificateGenerationError, TEMPLATE, generate_certificate_pdf,
    validate_certificate_pdf,
)
from database import get_db
from routes.final_soc_challenge import CASE_ID
from routes.soc_operations import analyst_required, csrf_token, validate_csrf
from routes.student_registration import student_profile, valid_full_name


certificate_bp = Blueprint("soc_certificates", __name__)
COURSE_KEY = "final_soc"
COURSE_NAME = "Operation Black Falcon - SOC Investigation"
PASS_SCORE = 70
DRAFT_KEY = "soc_certificate_preview"


def initialize_certificates(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS soc_certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_id TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            course_key TEXT NOT NULL,
            course_name TEXT NOT NULL,
            student_name TEXT NOT NULL,
            score INTEGER NOT NULL CHECK (score BETWEEN 70 AND 100),
            source_attempt_id INTEGER NOT NULL REFERENCES final_soc_attempts(id),
            issued_at TEXT NOT NULL,
            pdf_blob BLOB NOT NULL CHECK (length(pdf_blob) > 0),
            pdf_sha256 TEXT NOT NULL,
            UNIQUE (username, course_key)
        )
    """)
    db.commit()


@certificate_bp.after_request
def private_certificate_response(response):
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.vary.add("Cookie")
    return response


def existing_certificate(include_pdf=False):
    fields = "*" if include_pdf else (
        "certificate_id, student_name, course_name, score, issued_at, source_attempt_id"
    )
    return get_db().execute(
        "SELECT " + fields + " FROM soc_certificates WHERE username = ? AND course_key = ?",
        (session["username"], COURSE_KEY),
    ).fetchone()


def qualifying_attempt(attempt_id=None):
    query = """
        SELECT id, score, percentage, submitted_at FROM final_soc_attempts
        WHERE username = ? AND case_id = ? AND passed = 1
            AND score >= ? AND percentage >= ?
    """
    parameters = [session["username"], CASE_ID, PASS_SCORE, PASS_SCORE]
    if attempt_id is not None:
        query += " AND id = ?"
        parameters.append(attempt_id)
    query += " ORDER BY score DESC, id DESC LIMIT 1"
    return get_db().execute(query, parameters).fetchone()


def render_certificate(*, preview=None, error=None, status=200):
    return render_template(
        "soc_certificate.html", certificate=existing_certificate(),
        qualifying_result=qualifying_attempt(), course_name=COURSE_NAME,
        csrf_token=csrf_token(), preview=preview, error=error, profile=student_profile(),
    ), status


@certificate_bp.get("/soc/final/certificate")
@analyst_required
def certificate_page():
    return render_certificate()


@certificate_bp.post("/soc/final/certificate/preview")
@analyst_required
def preview_certificate():
    validate_csrf()
    if existing_certificate():
        return redirect(url_for("soc_certificates.certificate_page"))
    attempt = qualifying_attempt()
    if attempt is None:
        abort(403)
    profile = student_profile()
    if profile is None:
        abort(403)
    full_name = valid_full_name(profile["full_name"])
    if full_name is None:
        abort(400)
    draft = {
        "username": session["username"], "student_name": full_name,
        "attempt_id": attempt["id"], "score": attempt["score"],
        "percentage": attempt["percentage"], "token": secrets.token_urlsafe(32),
    }
    session[DRAFT_KEY] = draft
    return render_certificate(preview=dict(draft, score=attempt["score"]))


@certificate_bp.post("/soc/final/certificate/issue")
@analyst_required
def issue_certificate():
    validate_csrf()
    if existing_certificate():
        return redirect(url_for("soc_certificates.certificate_page"))
    draft = session.get(DRAFT_KEY, {})
    token = request.form.get("preview_token", "")
    expected = draft.get("token", "")
    if (draft.get("username") != session["username"] or not expected or len(token) > 128
            or not secrets.compare_digest(token.encode(), expected.encode())):
        abort(400)
    attempt = qualifying_attempt(draft["attempt_id"])
    if (attempt is None or attempt["score"] != draft["score"]
            or attempt["percentage"] != draft["percentage"]):
        session.pop(DRAFT_KEY, None)
        abort(403)

    profile = student_profile()
    if profile is None:
        abort(403)
    full_name = valid_full_name(profile["full_name"])
    if full_name is None:
        abort(400)
    if full_name != draft["student_name"]:
        session.pop(DRAFT_KEY, None)
        abort(403)

    now = datetime.now(timezone.utc)
    certificate_id = "OBF-" + now.strftime("%Y%m%d") + "-" + uuid.uuid4().hex.upper()
    try:
        pdf = generate_certificate_pdf(
            name=full_name, course=COURSE_NAME,
            score=f"{attempt['score']}/100", certificate_id=certificate_id,
            date=now.strftime("%d %B %Y"),
            template_path=current_app.config.get("CERTIFICATE_TEMPLATE_PATH", TEMPLATE),
            soffice_path=current_app.config.get("CERTIFICATE_SOFFICE_PATH"),
        )
        validate_certificate_pdf(pdf)
    except CertificateGenerationError:
        current_app.logger.exception("Final SOC certificate generation failed")
        return render_certificate(
            preview=dict(draft, score=attempt["score"]), status=503,
            error="Certificate generation is temporarily unavailable. Your certificate has not been issued. Please try again later.",
        )

    db = get_db()
    # Conversion can be slow. Recheck the exact previewed attempt at insertion
    # and let the unique ownership constraint resolve simultaneous requests.
    with db:
        cursor = db.execute("""
            INSERT INTO soc_certificates
                (certificate_id, username, course_key, course_name, student_name,
                 score, source_attempt_id, issued_at, pdf_blob, pdf_sha256)
            SELECT ?, a.username, ?, ?, p.full_name, a.score, a.id, ?, ?, ?
            FROM final_soc_attempts a JOIN student_profiles p ON p.username=a.username
            WHERE a.id = ? AND a.username = ? AND a.case_id = ? AND a.passed = 1
                AND a.score = ? AND a.percentage = ? AND p.full_name = ?
            ON CONFLICT(username, course_key) DO NOTHING
        """, (certificate_id, COURSE_KEY, COURSE_NAME,
              now.isoformat(), pdf, hashlib.sha256(pdf).hexdigest(),
              attempt["id"], session["username"], CASE_ID, attempt["score"], attempt["percentage"], full_name))
        inserted = cursor.rowcount
        db.execute("""
            UPDATE student_profiles SET name_locked=1 WHERE username=?
            AND EXISTS (SELECT 1 FROM soc_certificates WHERE username=? AND course_key=?)
        """, (session["username"], session["username"], COURSE_KEY))
    if not inserted and existing_certificate() is None:
        abort(403)
    session.pop(DRAFT_KEY, None)
    return redirect(url_for("soc_certificates.certificate_page"))


@certificate_bp.get("/soc/final/certificate/download")
@analyst_required
def download_certificate():
    certificate = existing_certificate(include_pdf=True)
    if certificate is None:
        abort(404)
    return send_file(
        io.BytesIO(certificate["pdf_blob"]), mimetype="application/pdf", as_attachment=True,
        download_name=certificate["certificate_id"] + ".pdf", max_age=0,
    )
