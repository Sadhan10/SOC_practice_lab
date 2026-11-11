"""Opt-in real-browser learner workflow checks using disposable local data."""
import argparse
import csv
import io
import json
import os
import secrets
import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def run_browser(executable=None, screenshot=None):
    from playwright.sync_api import sync_playwright, expect
    from werkzeug.security import generate_password_hash
    from werkzeug.serving import make_server, WSGIRequestHandler
    from app import create_app
    from database import get_db
    from level_config import get_case_level
    from routes.final_soc_challenge import QUESTIONS
    from routes.soc_operations import REPORT_FIELDS

    class QuietHandler(WSGIRequestHandler):
        def log(self, *args, **kwargs):
            pass

    with tempfile.TemporaryDirectory(prefix="black-falcon-browser-") as folder:
        runtime = Path(folder)
        config = {"TESTING": True, "SECRET_KEY": secrets.token_urlsafe(32), "FINAL_SOC_SHOW_ANSWERS": False,
                  "DATABASE_DIR": str(runtime), "DATABASE_PATH": str(runtime / "browser.db"),
                  "SOC_FEATURE_DATABASE_PATH": str(runtime / "features.db"),
                  "LOG_DIR": str(runtime / "logs"), "LOG_FILE": str(runtime / "logs/browser.log"),
                  "SOLUTION_STORE_PATH": str(ROOT / "private/solutions.json")}
        password = secrets.token_urlsafe(24)
        app = create_app(config)
        with app.app_context():
            db = get_db()
            db.execute("INSERT INTO users(username,password,role) VALUES (?,?,?)",
                       ("browser_other", generate_password_hash(password), "student"))
            db.commit()
        server = None
        thread = None
        applications = [app]
        def start(application):
            service = make_server("127.0.0.1", 0, application, request_handler=QuietHandler)
            worker = threading.Thread(target=service.serve_forever, daemon=True)
            worker.start()
            return service, worker, f"http://127.0.0.1:{service.server_port}"
        def stop():
            if server:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
        try:
            server, thread, base = start(app)
            with sync_playwright() as playwright:
                launch = {"headless": True}
                if executable:
                    launch["executable_path"] = executable
                browser = playwright.chromium.launch(**launch)
                errors = []
                own = browser.new_context(accept_downloads=True)
                other = browser.new_context(accept_downloads=True)
                for context in (own, other):
                    context.route("**/*", lambda route: route.continue_() if urlparse(route.request.url).hostname == "127.0.0.1" else route.abort())
                page = own.new_page()
                page.on("pageerror", lambda error: errors.append(str(error)))
                def login(tab, username, secret):
                    tab.goto(base + "/login")
                    tab.locator('[name="username"]').fill(username)
                    tab.locator('[name="password"]').fill(secret)
                    tab.locator('button[type="submit"]').click()
                    tab.wait_for_url("**/levels")
                login(page, "analyst", "Analyst@123")
                page.goto(base + "/soc/dashboard")
                expect(page.get_by_role("heading", name="Security Operations Center", exact=True)).to_be_visible()
                for number in range(1, 5):
                    page.goto(base + f"/soc/labs/{number}")
                    link = page.get_by_role("link", name="Open Investigation", exact=True)
                    href = link.get_attribute("href")
                    assert href
                    import re
                    case_id = re.search(r"BF-(?:2026|[MH])-\d{3}", page.locator("body").inner_text()).group()
                    page.goto(base + "/level/" + get_case_level(case_id))
                    response = page.goto(base + href)
                    assert response.status == 200 and urlparse(page.url).path == urlparse(href).path
                page.goto(base + "/investigations/BF-H-005")
                expect(page.get_by_role("heading", name="Evidence Chronology Advisory — BF-H-005")).to_be_visible()
                expect(page.locator("body")).to_contain_text("use the Wazuh and Suricata event chronology as the primary reference")
                page.goto(base + "/siem")
                page.locator('[name="case"]').fill("BF-H-005")
                page.locator('[name="source"]').select_option("suricata")
                page.locator('[name="start_date"]').fill("2026-08-21")
                page.locator('[name="end_date"]').fill("2026-08-21")
                page.get_by_role("button", name="Search Events", exact=True).click()
                expect(page.locator("body")).to_contain_text("Suspicious Periodic HTTPS Beacon")
                page.locator('[name="source"]').select_option("wazuh")
                page.get_by_role("button", name="Search Events", exact=True).click()
                expect(page.locator("body")).to_contain_text("Successful password authentication")
                page.locator('[name="source"]').select_option("zeek")
                page.locator('[name="q"]').fill("drop.blackfalcon-c2.local")
                # The original Zeek epoch dates are 2025, as disclosed in the advisory.
                page.locator('[name="start_date"]').fill("2025-08-21")
                page.locator('[name="end_date"]').fill("2025-08-21")
                page.get_by_role("button", name="Search Events", exact=True).click()
                results_region = page.get_by_role("region", name="Investigation results", exact=True)
                event_rows = results_region.locator("tbody tr")
                expect(event_rows).to_have_count(2)
                for event_row in event_rows.all():
                    expect(event_row).to_contain_text("ZEEK")
                    expect(event_row).to_contain_text("drop.blackfalcon-c2.local")
                page.locator('[name="start_date"]').fill("2026-08-21")
                page.locator('[name="end_date"]').fill("2026-08-21")
                page.get_by_role("button", name="Search Events", exact=True).click()
                expect(results_region.locator("tbody")).not_to_contain_text("drop.blackfalcon-c2.local")

                page.goto(base + "/soc/triage")
                form = page.locator('#BF-H-005 form')
                for field, value in (("severity", "High"), ("verdict", "True Positive"),
                                     ("status", "Escalated"), ("response", "Isolate affected host")):
                    form.locator(f'[name="{field}"]').select_option(value)
                form.locator('[name="findings"]').fill("Browser-owned case triage: correlated endpoint and network evidence.")
                form.get_by_role("button", name="Save Alert Triage").click()

                page.goto(base + "/soc/alerts?case=BF-H-005&source=suricata")
                alert_href = page.locator('a[href^="/soc/alerts/BF-H-005/"]').first.get_attribute("href")
                page.goto(base + alert_href)
                for field, value in (("verdict", "True Positive"), ("priority", "High"),
                                     ("status", "Escalated"), ("response_action", "Isolate affected endpoint")):
                    page.locator(f'[name="{field}"]').select_option(value)
                alert_note = "Browser-owned alert evidence: preserve logs and investigate compromise."
                page.locator('[name="findings"]').fill(alert_note)
                page.get_by_role("button", name="Save Alert Triage").click()
                expect(page.locator('[name="findings"]')).to_have_value(alert_note)

                page.goto(base + "/soc/assessment/BF-H-005")
                expect(page.get_by_role("heading", name="Evidence Chronology Advisory — BF-H-005")).to_be_visible()
                report_note = "Browser-owned incident narrative with evidence requiring instructor review."
                page.locator('[name="incident_summary"]').fill(report_note)
                page.locator('button[value="draft"]').click()
                expect(page.locator('[name="incident_summary"]')).to_have_value(report_note)
                for field in REPORT_FIELDS:
                    page.locator(f'[name="{field}"]').fill(report_note)
                for field in page.locator('input[name^="answer_"]').all():
                    field.fill("Evidence finding awaiting instructor review")
                page.locator('button[value="submit"]').click()
                expect(page.locator("body")).to_contain_text("Submitted")

                page.goto(base + "/soc/final")
                expect(page.get_by_role("heading", name="Evidence Chronology Advisory — BF-H-005")).to_be_visible()
                assert page.locator('fieldset.soc-final-question').count() == 7
                for index, question in enumerate(QUESTIONS):
                    value = question["answer"] if index in (0, 1, 2, 3, 5) else next(v for v, _ in question["options"] if v != question["answer"])
                    page.locator(f'input[name="{question["id"]}"][value="{value}"]').check()
                page.get_by_role("button", name="Submit Final Assessment").click()
                page.wait_for_url("**/soc/final/result/*")
                result_path = urlparse(page.url).path
                expect(page.locator("body")).to_contain_text("74/100")
                expect(page.locator("body")).not_to_contain_text("Expected Answer:")
                expect(page.locator("body")).not_to_contain_text("Supporting Evidence:")
                assert page.locator(".soc-final-feedback").count() == 7
                assert "no-store" in page.reload().headers["cache-control"]
                if screenshot:
                    page.screenshot(path=str(screenshot), full_page=True)
                with page.expect_download() as pending:
                    page.get_by_role("link", name="Export My Assessment Results (CSV)").click()
                rows = list(csv.DictReader(io.StringIO(Path(pending.value.path()).read_text(encoding="utf-8"))))
                assert len(rows) == 1 and rows[0]["score"] == "74" and rows[0]["username"] == "analyst"

                second = other.new_page()
                login(second, "browser_other", password)
                assert second.goto(base + result_path).status == 404
                second.goto(base + "/soc/assessment/BF-H-005")
                expect(second.locator('[name="incident_summary"]')).to_have_value("")
                second.goto(base + alert_href)
                expect(second.locator('[name="findings"]')).to_have_value("")
                other_rows = list(csv.DictReader(io.StringIO(other.request.get(base + "/soc/final/export").text())))
                assert other_rows == []
                second.goto(base + "/soc/triage")
                expect(second.locator('#BF-H-005 [name="findings"]')).to_have_value("")

                stop()
                app = create_app(config)
                applications.append(app)
                server, thread, base = start(app)
                page.goto(base + result_path)
                expect(page.locator("body")).to_contain_text("74/100")
                assert second.goto(base + result_path).status == 404
                page.goto(base + "/soc/assessment/BF-H-005")
                expect(page.locator('[name="incident_summary"]')).to_have_value(report_note)
                page.goto(base + alert_href)
                expect(page.locator('[name="findings"]')).to_have_value(alert_note)
                page.goto(base + "/soc/triage")
                expect(page.locator('#BF-H-005 [name="findings"]')).to_have_value("Browser-owned case triage: correlated endpoint and network evidence.")
                page.goto(base + "/logout")
                page.wait_for_url("**/login")
                page.goto(base + result_path)
                page.wait_for_url("**/login")
                login(page, "analyst", "Analyst@123")
                page.goto(base + result_path)
                expect(page.locator("body")).to_contain_text("74/100")
                page.goto(base + "/soc/assessment/BF-H-005")
                expect(page.locator('[name="incident_summary"]')).to_have_value(report_note)
                expect(page.locator("body")).to_contain_text("Submitted")
                page.goto(base + alert_href)
                expect(page.locator('[name="findings"]')).to_have_value(alert_note)
                page.goto(base + "/soc/triage")
                expect(page.locator('#BF-H-005 [name="findings"]')).to_have_value("Browser-owned case triage: correlated endpoint and network evidence.")
                app.config["FINAL_SOC_SHOW_ANSWERS"] = True
                page.goto(base + result_path)
                expect(page.locator("body")).to_contain_text("Expected Answer:")
                expect(page.locator("body")).to_contain_text("Supporting Evidence:")
                app.config["FINAL_SOC_SHOW_ANSWERS"] = False
                page.reload()
                expect(page.locator("body")).not_to_contain_text("Expected Answer:")
                assert not errors, errors
                browser.close()
        finally:
            stop()
            for application in applications:
                for handler in list(application.logger.handlers):
                    if getattr(handler, "baseFilename", "").startswith(str(runtime)):
                        application.logger.removeHandler(handler)
                        handler.close()
    return {"passed": True, "browser_checklist_completed": 9, "browser_checklist_total": 9,
            "checks": ["real login and SOC dashboard", "four lab investigation links", "BF-H-005 chronology advisories",
            "Wazuh, Suricata and Zeek search and date filters",
            "case triage", "individual alert triage", "report draft and submission", "weighted final assessment",
            "assessment/practice mode", "CSV download", "cross-analyst isolation", "restart persistence", "logout/login persistence",
            "browser JavaScript errors"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", default=os.environ.get("BLACK_FALCON_BROWSER_EXECUTABLE"))
    parser.add_argument("--screenshot", type=Path)
    args = parser.parse_args()
    print(json.dumps(run_browser(args.executable, args.screenshot), indent=2))
