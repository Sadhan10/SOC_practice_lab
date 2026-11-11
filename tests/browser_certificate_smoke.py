"""Opt-in enrollment/eligibility checks with optional real local conversion."""

import argparse
import hashlib
import io
import json
import secrets
import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlparse
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def run(executable=None, soffice=None, output_directory=None, eligibility_only=False):
    from playwright.sync_api import sync_playwright, expect
    from pypdf import PdfReader
    from werkzeug.serving import WSGIRequestHandler, make_server
    from app import create_app
    from database import get_db
    from routes.final_soc_challenge import QUESTIONS
    from models import mark_completed

    class QuietHandler(WSGIRequestHandler):
        def log(self, *args, **kwargs):
            pass

    artifact_directory = "dist/windows-eligibility-validation" if eligibility_only else "dist/student-identity-validation"
    output = Path(output_directory or ROOT / artifact_directory)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="certificate-browser-") as directory:
        runtime = Path(directory)
        app = create_app({
            "TESTING": True, "SECRET_KEY": secrets.token_urlsafe(32),
            "DATABASE_DIR": str(runtime), "DATABASE_PATH": str(runtime / "main.db"),
            "SOC_FEATURE_DATABASE_PATH": str(runtime / "features.db"),
            "LOG_DIR": str(runtime), "LOG_FILE": str(runtime / "test.log"),
            "CERTIFICATE_SOFFICE_PATH": soffice,
            "STUDENT_REGISTRATION_ENABLED": True,
        })
        password = secrets.token_urlsafe(24)
        with app.app_context():
            db = get_db()
            mark_completed("analyst", "BF-2026-001")
            original_progress = [tuple(row) for row in db.execute("SELECT * FROM progress ORDER BY id")]
            original_user = tuple(db.execute("SELECT * FROM users WHERE username='analyst'").fetchone())
        server = make_server("127.0.0.1", 0, app, request_handler=QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        errors = []
        conversion_guard = patch(
            "routes.soc_certificates.generate_certificate_pdf",
            side_effect=AssertionError("PDF conversion must not run in eligibility-only mode"),
        ) if eligibility_only else None
        converter = conversion_guard.start() if conversion_guard else None
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True, **({"executable_path": executable} if executable else {})
                )
                context = browser.new_context(accept_downloads=True)
                context.route("**/*", lambda route: route.continue_()
                              if urlparse(route.request.url).hostname == "127.0.0.1" else route.abort())
                page = context.new_page()
                page.set_default_timeout(90000)
                page.on("pageerror", lambda error: errors.append(str(error)))

                def login(username, secret):
                    page.goto(base + "/login")
                    page.locator('[name="username"]').fill(username)
                    page.locator('[name="password"]').fill(secret)
                    page.get_by_role("button", name="Enter SOC Console", exact=True).click()
                    page.wait_for_url("**/levels")

                def register(username, full_name):
                    page.goto(base + "/student/register")
                    if username == "certificate_a":
                        for width in (1280, 390, 320):
                            page.set_viewport_size({"width": width, "height": 900})
                            layout = page.evaluate("""() => {
                                const card = document.querySelector('.bf-register-card').getBoundingClientRect();
                                const submit = document.querySelector('.bf-register-submit').getBoundingClientRect();
                                return {width: card.width, center: card.x + card.width / 2,
                                    submit: submit.width, overflow: document.documentElement.scrollWidth > innerWidth};
                            }""")
                            assert layout["width"] <= 560 and not layout["overflow"], layout
                            assert abs(layout["center"] - width / 2) <= 1, layout
                            if width == 1280:
                                assert layout["submit"] < 300, layout
                            page.screenshot(path=str(output / f"registration-{width}.png"), full_page=True)
                        page.set_viewport_size({"width": 1280, "height": 900})
                    for field, value in (
                        ("full_name", full_name), ("username", username),
                        ("password", password), ("confirm_password", password),
                        ("usn", "1BF/2026-001" if username == "certificate_a" else ""),
                    ):
                        page.locator(f'[name="{field}"]').fill(value)
                    if username == "certificate_a":
                        assert page.locator('[name="username"]').evaluate("input => input.validity.valid")
                        for field, label in (("password", "password"), ("confirm_password", "confirmation password")):
                            toggle = page.locator(f'.bf-password-toggle[data-target="{field}"]')
                            expect(toggle).to_have_attribute("aria-label", f"Show {label}")
                            toggle.click()
                            expect(page.locator(f'#{field}')).to_have_attribute("type", "text")
                            expect(toggle).to_have_attribute("aria-pressed", "true")
                            page.get_by_role("button", name=f"Hide {label}", exact=True).click()
                            expect(page.locator(f'#{field}')).to_have_attribute("type", "password")
                        for field in ("password", "confirm_password"):
                            page.locator(f'#{field}').fill("passwordpassword")
                        page.get_by_role("button", name="Create Student Account").click()
                        expect(page.get_by_role("alert")).to_contain_text("less common password")
                        expect(page.locator('[name="full_name"]')).to_have_value(full_name)
                        expect(page.locator('[name="usn"]')).to_have_value("1BF/2026-001")
                        assert page.locator("#registration-errors").evaluate("el => el === document.activeElement")
                        for field in ("password", "confirm_password"):
                            expect(page.locator(f'#{field}')).to_have_value("")
                            page.locator(f'#{field}').fill(password)
                    page.get_by_role("button", name="Create Student Account").click()
                    page.wait_for_url("**/login")

                def download(filename):
                    with page.expect_download() as pending:
                        page.get_by_role("link", name="Download Certificate (PDF)").click()
                    target = output / filename
                    pending.value.save_as(target)
                    return target.read_bytes()

                def submit_assessment(correct_indices):
                    page.goto(base + "/soc/final")
                    token = page.locator('[name="csrf_token"]').input_value()
                    for index, question in enumerate(QUESTIONS):
                        value = question["answer"] if index in correct_indices else next(
                            key for key, _ in question["options"] if key != question["answer"]
                        )
                        page.locator(f'input[name="{question["id"]}"][value="{value}"]').check()
                    page.get_by_role("button", name="Submit Final Assessment").click()
                    page.wait_for_url("**/soc/final/result/*")
                    return urlparse(page.url).path, token

                register("certificate_a", "Alice Certificate Student")
                login("certificate_a", password)
                page.goto(base + "/profile")
                expect(page.get_by_role("heading", name="Alice Certificate Student")).to_be_visible()
                expect(page.locator("body")).to_contain_text("1BF/2026-001")
                page.goto(base + "/soc/final/certificate")
                expect(page.get_by_role("heading", name="Certificate Locked")).to_be_visible()
                if eligibility_only:
                    _, token = submit_assessment((0, 1, 2, 3))
                    expect(page.locator("body")).to_contain_text("64/100")
                    assert page.get_by_role("link", name="View / Generate Certificate").count() == 0
                    page.goto(base + "/soc/final/certificate")
                    expect(page.get_by_role("heading", name="Certificate Locked")).to_be_visible()
                    assert page.get_by_role("button", name="Preview Certificate Details").count() == 0
                    assert context.request.post(base + "/soc/final/certificate/preview", form={
                        "csrf_token": token, "score": "100", "student_name": "Forged Name",
                    }).status == 403
                    page.screenshot(path=str(output / "certificate-locked.png"), full_page=True)
                result_path, _ = submit_assessment((0, 1, 2, 3, 5))
                page.get_by_role("link", name="View / Generate Certificate").click()
                assert page.locator('[name="student_name"]').count() == 0
                expect(page.locator("body")).to_contain_text("Alice Certificate Student")
                page.get_by_role("button", name="Preview Certificate Details").click()
                expect(page.get_by_role("heading", name="Preview Certificate Details")).to_be_visible()
                page.screenshot(path=str(output / "browser-preview.png"), full_page=True)
                if eligibility_only:
                    page.goto(base + "/logout")
                    register("certificate_b", "Bob Certificate Student")
                    login("certificate_b", password)
                    page.goto(base + "/profile?username=certificate_a")
                    expect(page.get_by_role("heading", name="Bob Certificate Student")).to_be_visible()
                    expect(page.locator("body")).to_contain_text("Not provided")
                    expect(page.locator("body")).not_to_contain_text("1BF/2026-001")
                    assert page.goto(base + result_path).status == 404
                    page.goto(base + "/soc/final/certificate")
                    expect(page.get_by_role("heading", name="Certificate Locked")).to_be_visible()
                    assert context.request.get(base + "/soc/final/certificate/download?username=certificate_a").status == 404
                    page.goto(base + "/soc/final")
                    other_token = page.locator('[name="csrf_token"]').input_value()
                    assert context.request.post(base + "/soc/final/certificate/preview", form={
                        "csrf_token": other_token, "score": "100", "username": "certificate_a",
                    }).status == 403
                    page.goto(base + "/logout")
                    login("certificate_a", password)
                    page.goto(base + "/soc/final/certificate")
                    expect(page.locator("body")).to_contain_text("74/100")
                    expect(page.locator("body")).to_contain_text("Alice Certificate Student")
                    with app.app_context():
                        db = get_db()
                        assert db.execute("SELECT COUNT(*) FROM soc_certificates").fetchone()[0] == 0
                        assert [tuple(row) for row in db.execute("SELECT * FROM progress ORDER BY id")] == original_progress
                        assert tuple(db.execute("SELECT * FROM users WHERE username='analyst'").fetchone()) == original_user
                        profiles = {row["username"]: row["full_name"] for row in db.execute("SELECT * FROM student_profiles")}
                        assert profiles == {"certificate_a": "Alice Certificate Student", "certificate_b": "Bob Certificate Student"}
                        attempts = [tuple(row) for row in db.execute("SELECT username, score FROM final_soc_attempts ORDER BY id")]
                        assert attempts == [("certificate_a", 64), ("certificate_a", 74)]
                    assert converter.call_count == 0
                    assert not errors, errors
                    browser.close()
                    return {
                        "passed": True, "registered_students": 2, "failing_score": 64,
                        "optional_usn_registration": True, "registration_layout_widths": [1280, 390, 320],
                        "password_visibility_controls": True, "common_password_rejected": True,
                        "passing_score": 74, "below_70_locked": True,
                        "passing_profile_name_preview": True, "account_isolation": True,
                        "eligibility_persists_after_relogin": True, "pdf_conversion_calls": 0,
                        "certificate_records_created": 0,
                        "original_ctf_progress_and_legacy_account_unchanged": True,
                        "artifacts": str(output.resolve()),
                    }
                page.get_by_role("button", name="Confirm and Issue Certificate").click()
                expect(page.get_by_role("heading", name="Certificate Issued")).to_be_visible()
                page.screenshot(path=str(output / "browser-issued.png"), full_page=True)
                first = download("browser-certificate.pdf")
                pdf = PdfReader(io.BytesIO(first))
                assert len(pdf.pages) == 1
                assert float(pdf.pages[0].mediabox.width) > float(pdf.pages[0].mediabox.height)
                text = "".join(pdf.pages[0].extract_text().split())
                with app.app_context():
                    certificate = dict(get_db().execute("SELECT * FROM soc_certificates").fetchone())
                for value in ("Alice Certificate Student", certificate["course_name"],
                              "74/100", certificate["certificate_id"]):
                    assert "".join(value.split()) in text, value
                assert certificate["pdf_blob"] == first
                assert certificate["pdf_sha256"] == hashlib.sha256(first).hexdigest()
                page.goto(base + "/logout")
                register("certificate_b", "Bob Certificate Student")
                login("certificate_b", password)
                page.goto(base + "/profile?username=certificate_a")
                expect(page.get_by_role("heading", name="Bob Certificate Student")).to_be_visible()
                assert page.goto(base + result_path).status == 404
                page.goto(base + "/soc/final/certificate")
                expect(page.get_by_role("heading", name="Certificate Locked")).to_be_visible()
                assert context.request.get(base + "/soc/final/certificate/download?username=certificate_a").status == 404
                page.goto(base + "/logout")
                login("certificate_a", password)
                page.goto(base + "/soc/final/certificate")
                assert download("browser-repeat.pdf") == first
                with app.app_context():
                    db = get_db()
                    assert [tuple(row) for row in db.execute("SELECT * FROM progress ORDER BY id")] == original_progress
                    assert tuple(db.execute("SELECT * FROM users WHERE username='analyst'").fetchone()) == original_user
                    assert db.execute("SELECT name_locked FROM student_profiles WHERE username='certificate_a'").fetchone()[0] == 1
                assert not errors, errors
                browser.close()
                return {"passed": True, "identity_checklist_completed": 8, "identity_checklist_total": 8,
                        "optional_usn_registration": True, "registration_layout_widths": [1280, 390, 320],
                        "password_visibility_controls": True, "common_password_rejected": True,
                        "registered_students": 2, "score": 74, "real_pdf_conversion": True, "pdf_pages": 1,
                        "repeat_download_identical": True, "account_isolation": True,
                        "original_ctf_progress_and_legacy_account_unchanged": True,
                        "pdf_sha256": certificate["pdf_sha256"], "artifacts": str(output.resolve())}
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            if conversion_guard:
                conversion_guard.stop()
            for handler in list(app.logger.handlers):
                if getattr(handler, "baseFilename", "").startswith(str(runtime)):
                    app.logger.removeHandler(handler)
                    handler.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable")
    parser.add_argument("--soffice")
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument("--eligibility-only", action="store_true",
                        help="Check registration and eligibility without issuing or converting a PDF.")
    args = parser.parse_args()
    print(json.dumps(run(args.executable, args.soffice, args.output_directory, args.eligibility_only), indent=2))
