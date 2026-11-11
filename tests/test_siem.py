import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask import template_rendered

import soc_features
from app import create_app
from routes import siem


class SIEMSearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="siem-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        feature_patch = patch.object(
            soc_features, "feature_database_path",
            return_value=str(self.root / "features.db"),
        )
        feature_patch.start()
        self.addCleanup(feature_patch.stop)
        project = Path(__file__).resolve().parents[1]
        self.app = create_app({
            "TESTING": True,
            "SECRET_KEY": "siem-test",
            "DATABASE_DIR": str(self.root / "database"),
            "DATABASE_PATH": str(self.root / "database" / "test.db"),
            "LOG_DIR": str(self.root / "logs"),
            "LOG_FILE": str(self.root / "logs" / "test.log"),
            "EVIDENCE_DIR": str(self.evidence),
            "EVIDENCE_FOLDER": str(self.evidence),
            "SOLUTION_STORE_PATH": str(project / "private" / "solutions.json"),
        })
        self.addCleanup(self.close_logging)
        self.client = self.app.test_client()
        self.context = {}

        def capture(sender, template, context, **extra):
            self.context = context

        template_rendered.connect(capture, self.app, weak=False)
        self.addCleanup(template_rendered.disconnect, capture, self.app)
        with self.client.session_transaction() as user_session:
            user_session.update(logged_in=True, username="analyst", selected_level="medium")
        self.write("suricata/BF-M-002_eve.json", json.dumps({
            "timestamp": "2026-08-20T14:28:03Z",
            "alert": {"signature": "Suspicious Recon"},
            "src_ip": "192.168.56.104",
        }) + "\n")
        self.write("system/BF-H-002_auth.log", "Aug 20 sshd: Failed password from 192.168.56.104\n")

    def close_logging(self):
        for handler in list(self.app.logger.handlers):
            if getattr(handler, "baseFilename", "").startswith(str(self.root)):
                self.app.logger.removeHandler(handler)
                handler.close()

    def write(self, filename, content):
        path = self.evidence / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def search(self, **params):
        return self.client.get("/siem", query_string=params)

    def test_authentication_requires_boolean_true(self):
        for value in (None, False, "true", 1):
            with self.client.session_transaction() as user_session:
                user_session["logged_in"] = value
            response = self.search()
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.location.endswith("/login"))

    def test_keyword_source_and_case_filters_combine(self):
        response = self.search(q="SUSPICIOUS recon", source="SURICATA", case="bf-m-002")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.context["results"]), 1)
        row = self.context["results"][0]
        self.assertEqual(row["timestamp"], "2026-08-20T14:28:03Z")
        self.assertEqual(row["case"], "BF-M-002")
        self.search(q="192.168.56.104")
        self.assertEqual(len(self.context["results"]), 2)
        self.search(q="192.168.56.104", source="system", case="BF-M-002")
        self.assertEqual(self.context["results"], [])

    def test_case_matching_is_exact(self):
        self.write("system/BF-M-0020_auth.log", "prefix collision\n")
        self.search(case="BF-M-002")
        self.assertEqual(len(self.context["results"]), 1)

    def test_raw_event_and_query_are_html_escaped(self):
        payload = '<script>alert("xss")</script>'
        self.write("web/BF-M-002_access.log", payload + "\n")
        response = self.search(q=payload)
        self.assertNotIn(b"<script>alert", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)
        self.assertEqual(len(self.context["results"]), 1)

    def test_evidence_link_downloads_original_file(self):
        response = self.search(source="suricata")
        filename = self.context["results"][0]["relative_path"]
        self.assertIn(("/evidence/download/" + filename).encode(), response.data)
        download = self.client.get("/evidence/download/" + filename)
        try:
            self.assertEqual(download.status_code, 200)
            self.assertIn("attachment", download.headers["Content-Disposition"])
            self.assertEqual(download.data, (self.evidence / filename).read_bytes())
        finally:
            download.close()

    def test_zeek_fields_and_original_line_number(self):
        self.write("zeek/BF-M-002_conn.log", "#separator \\x09\n#fields\tts\tuid\tid.orig_h\n1768466712.442100\tCxA001\t192.168.56.104\n")
        self.search(source="zeek", q="CxA001")
        row, = self.context["results"]
        self.assertEqual(row["timestamp"], "1768466712.442100")
        self.assertEqual(row["line"], 3)

    def test_multiline_wazuh_objects_are_complete_events(self):
        events = [{"timestamp": "first", "rule": {"description": "SSH failure"}},
                  {"timestamp": "second", "rule": {"description": "SSH success"}}]
        self.write("wazuh/BF-M-002_alerts.log", "\n\n".join(json.dumps(event, indent=2) for event in events))
        self.search(source="wazuh", q="success")
        row, = self.context["results"]
        self.assertEqual(row["timestamp"], "second")
        self.assertEqual(row["summary"], "SSH success")
        self.assertIn('"rule":', row["raw"])
        self.assertGreater(row["line"], 1)

    def test_malformed_and_non_object_json_are_safe(self):
        self.write("cowrie/general.jsonl", '{broken\n[]\nnull\n{"alert": "bad", "event_type": "login"}\n')
        self.search(source="cowrie")
        self.assertEqual(len(self.context["results"]), 4)
        self.assertEqual(self.context["results"][-1]["summary"], "login")
        self.assertTrue(all(row["case"] == "General" for row in self.context["results"]))

    def test_text_wazuh_filters_use_one_complete_alert_and_lab_date(self):
        raw = ('2026 Aug 21 00:32:04 blackfalcon-app\nrule.level=8\n'
               'description="Web application spawned shell"\n'
               'process=/bin/sh\nsrcip=192.0.2.10\ndstip=192.0.2.20\n')
        self.write("wazuh/BF-M-002_alerts.log", raw + raw.replace("rule.level=8", "rule.level=3"))
        response = self.search(source="wazuh", case="BF-M-002", severity="High",
                               q="/bin/sh", start_date="2026-08-21", end_date="2026-08-21")
        row, = self.context["results"]
        self.assertEqual(row["summary"], "Web application spawned shell")
        self.assertEqual(row["line"], 1)
        self.assertEqual(row["raw"].replace("\r\n", "\n"), raw.rstrip())
        self.assertEqual((row["source_ip"], row["destination_ip"]), ("192.0.2.10", "192.0.2.20"))
        self.assertIn(b"timezone unspecified", response.data)
        self.assertIsNone(siem.parse_timestamp(row["timestamp"]).tzinfo)
        self.search(source="wazuh", end_date="2026-08-20")
        self.assertEqual(self.context["results"], [])

    def test_invalid_filters_and_missing_sources_are_safe(self):
        self.search(source="../../private", case="../../secrets")
        self.assertEqual(self.context["source"], "")
        self.assertEqual(self.context["case"], "")
        response = self.search(source="web")
        self.assertIn(b"No matching security events found.", response.data)

    def test_result_limit_and_notice(self):
        self.write("web/events.log", "event\n" * (siem.LIMIT + 1))
        response = self.search(source="web")
        self.assertEqual(len(self.context["results"]), siem.LIMIT)
        self.assertTrue(self.context["limited"])
        self.assertIn(b"Search or display limit reached", response.data)

    def test_scan_limits_and_display_truncation(self):
        self.write("web/a.log", "first\nsecond\nthird\n")
        with patch.object(siem, "MAX_FILE_BYTES", 10):
            self.search(source="web")
            self.assertTrue(self.context["limited"])
            self.assertEqual(len(self.context["results"]), 1)
        with patch.object(siem, "MAX_LINES", 1):
            self.search(source="web")
            self.assertTrue(self.context["limited"])
            self.assertEqual(len(self.context["results"]), 1)
        self.write("web/a.log", "x" * 1700 + " tail-indicator\n")
        self.search(source="web", q="tail-indicator")
        row, = self.context["results"]
        self.assertEqual(len(row["raw"]), 1500)
        self.assertEqual(len(row["summary"]), 300)

    def test_total_byte_and_file_limits(self):
        self.write("web/a.log", "first\n")
        self.write("web/b.log", "second\n")
        with patch.object(siem, "MAX_FILES", 1):
            self.search(source="web")
            self.assertEqual(len(self.context["results"]), 1)
            self.assertTrue(self.context["limited"])
        with patch.object(siem, "MAX_SCAN_BYTES", 6):
            self.search(source="web")
            self.assertEqual(len(self.context["results"]), 1)
            self.assertTrue(self.context["limited"])

    def test_binary_and_nested_files_are_excluded(self):
        self.write("web/secret.pcap", "should-not-be-indexed")
        self.write("web/nested/secret.log", "should-not-be-indexed")
        self.search(q="should-not-be-indexed")
        self.assertEqual(self.context["results"], [])

    def test_symlinks_outside_evidence_are_excluded(self):
        outside = self.root / "outside.log"
        outside.write_text("outside-secret", encoding="utf-8")
        link = self.evidence / "system" / "linked.log"
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("Creating symlinks is unavailable for this Windows account")
        self.search(q="outside-secret")
        self.assertEqual(self.context["results"], [])

    def test_bundled_evidence_renders(self):
        self.app.config["EVIDENCE_DIR"] = str(Path(__file__).resolve().parents[1] / "evidence")
        for source in siem.SOURCES:
            with self.subTest(source=source):
                self.assertEqual(self.search(source=source).status_code, 200)
                self.assertTrue(self.context["results"])

    def test_advanced_severity_uses_explicit_source_scales(self):
        for level, expected in ((0, "Informational"), (4, "Low"), (5, "Medium"), (8, "High"), (12, "Critical"), (16, "Unknown")):
            self.assertEqual(siem.event_severity({"rule": {"level": level}}, "wazuh", ""), expected)
        for level, expected in ((1, "High"), (2, "Medium"), (3, "Low"), (0, "Unknown")):
            self.assertEqual(siem.event_severity({"alert": {"severity": level}}, "suricata", ""), expected)
        self.assertEqual(siem.event_severity({}, "system", "Critical attack exploit"), "Unknown")
        self.assertEqual(siem.event_severity({}, "wazuh", "rule.level=12"), "Critical")
        self.assertEqual(siem.event_severity({"severity": True}, "suricata", ""), "Unknown")
        self.assertEqual(siem.event_severity({}, "wazuh", "level=" + "9" * 5000), "Unknown")

    def test_advanced_date_filter_uses_inclusive_utc_dates(self):
        events = [
            {"timestamp": "2026-08-21T00:30:00+0530", "severity": "High"},
            {"timestamp": "2026-08-21T00:00:00Z", "severity": "High"},
            {"timestamp": "unrecognized", "severity": "High"},
            {"timestamp": "2026-08-20T23:59:59Z", "severity": "Low"},
        ]
        self.write("suricata/BF-M-002_eve.json", "\n".join(json.dumps(event) for event in events))
        self.search(source="suricata", severity="high", start_date="2026-08-20", end_date="2026-08-20")
        row, = self.context["results"]
        self.assertEqual(row["timestamp_utc"], "2026-08-20T19:00:00Z")
        self.assertEqual(self.context["severity_counts"], {"High": 1})
        self.search(source="suricata", start_date="2026-08-21")
        self.assertEqual(len(self.context["results"]), 1)
        self.search(source="suricata", end_date="2026-08-20")
        self.assertEqual(len(self.context["results"]), 2)

    def test_advanced_timestamp_formats_and_missing_year(self):
        for raw, expected in (
            ("192.168.56.104 - - [21/Aug/2026:00:30:00 +0530] GET", "2026-08-20T19:00:00+00:00"),
            ("2026-08-20 10:32:04 command=whoami", "2026-08-20T10:32:04"),
            ("2026 Aug 20 15:34:41 agent:", "2026-08-20T15:34:41"),
        ):
            self.assertEqual(siem.event_time({}, raw).isoformat(), expected)
        self.assertIsNone(siem.event_time({}, "Aug 20 10:04:00 sshd: failed"))
        self.assertIsNotNone(siem.event_time({"ts": "1768466712.442100"}, ""))
        self.assertIsNone(siem.parse_timestamp("0001-01-01T00:00:00+05:30"))

    def test_advanced_invalid_dates_do_not_broaden_search(self):
        for params in (dict(start_date="bad"), dict(end_date="2026-02-30"),
                       dict(start_date="2026-08-21", end_date="2026-08-20"),
                       dict(start_date="2026-08-20-extra")):
            self.assertEqual(self.search(**params).status_code, 200)
            self.assertTrue(self.context["filter_errors"])
            self.assertEqual(self.context["results"], [])

    def test_advanced_ip_validation_roles_and_correlation(self):
        source, destination, ips = siem.event_ips(
            {"source_ip": "2001:db8::1", "destination": {"ip": "2001:db8::2"}},
            "999.10.20.30 192.168.56.104 192.168.56.104",
        )
        self.assertEqual((source, destination), ("2001:db8::1", "2001:db8::2"))
        self.assertNotIn("999.10.20.30", ips)
        self.search(case="BF-M-002")
        self.assertEqual(self.context["correlations"], [])
        self.search()
        item, = self.context["correlations"]
        self.assertEqual(item["ip"], "192.168.56.104")
        self.assertEqual(item["event_count"], 2)
        self.assertEqual(item["sources"], "SURICATA, SYSTEM")
        self.assertEqual(siem.event_ips({}, "peer 192.168.56.104")[0], "")

    def test_advanced_statistics_and_correlations_use_displayed_events(self):
        self.write("wazuh/BF-M-002_alerts.log", "\n".join(
            json.dumps({"rule": {"level": 12}, "src_ip": "192.168.56.104"}) for _ in range(4)))
        with patch.object(siem, "LIMIT", 2):
            self.search(source="wazuh")
        self.assertEqual(self.context["severity_counts"], {"Critical": 2})
        self.assertTrue(self.context["truncated"])
        self.assertEqual(self.context["correlations"], [])

    def test_advanced_correlation_link_preserves_filters(self):
        self.write("system/BF-M-002_auth.log", "2026-08-20T14:00:00Z severity=high src_ip=192.168.56.104\n")
        self.write("suricata/BF-M-002_eve.json", json.dumps({
            "timestamp": "2026-08-20T14:00:00Z", "severity": "High", "src_ip": "192.168.56.104"}))
        response = self.search(case="BF-M-002", severity="High", start_date="2026-08-20", end_date="2026-08-20")
        for value in (b"severity=High", b"start_date=2026-08-20", b"end_date=2026-08-20"):
            self.assertIn(value, response.data)
        self.assertEqual(self.context["severity_counts"], {"High": 2})
        self.assertEqual(len(self.context["correlations"]), 1)


if __name__ == "__main__":
    unittest.main()
