import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import soc_features
from app import create_app
from database import get_db
from routes.alert_triage import alert_events, initialize_alert_triage


class AlertTriageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="alert-triage-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        feature_patch = patch.object(soc_features, "feature_database_path", return_value=str(self.root / "features.db"))
        feature_patch.start()
        self.addCleanup(feature_patch.stop)
        self.config = {
            "TESTING": True, "SECRET_KEY": "alert-test",
            "DATABASE_DIR": str(self.root / "database"),
            "DATABASE_PATH": str(self.root / "database" / "test.db"),
            "LOG_DIR": str(self.root / "logs"), "LOG_FILE": str(self.root / "logs" / "test.log"),
            "EVIDENCE_DIR": str(self.root / "evidence"),
        }
        self.app = create_app(self.config)
        self.addCleanup(self.close_logging)
        self.client = self.app.test_client()
        self.login(self.client)
        self.evidence = self.root / "evidence" / "suricata" / "BF-M-003_events.json"
        self.evidence.parent.mkdir()
        self.records = [
            {"timestamp": "2026-01-01T12:00:00Z", "event_type": "alert", "alert": {"signature": "Suspicious request", "severity": 1},
             "src_ip": "192.0.2.1", "dest_ip": "192.0.2.2"},
            {"timestamp": "2026-01-01T12:01:00Z", "event_type": "flow"},
        ]
        self.evidence.write_text("\n".join(json.dumps(row) for row in self.records), encoding="utf-8")
        with self.app.app_context():
            self.events = list(alert_events("BF-M-003"))
        self.url = "/soc/alerts/BF-M-003/" + self.events[0]["alert_id"]

    def close_logging(self):
        for handler in list(self.app.logger.handlers):
            if getattr(handler, "baseFilename", "").startswith(str(self.root)):
                self.app.logger.removeHandler(handler)
                handler.close()

    def login(self, client, username="analyst"):
        with client.session_transaction() as sess:
            sess.clear()
            sess.update(logged_in=True, username=username)

    def data(self):
        self.assertEqual(self.client.get(self.url).status_code, 200)
        with self.client.session_transaction() as sess:
            token = sess["operations_csrf"]
        return {"csrf_token": token, "verdict": "Inconclusive", "priority": "Medium",
                "status": "Investigating", "response_action": "Continue monitoring",
                "findings": "Evidence requires further investigation."}

    def rows(self):
        with self.app.app_context():
            return [dict(row) for row in get_db().execute("SELECT * FROM soc_alert_triage")]

    def test_authentication_and_csrf(self):
        anonymous = self.app.test_client()
        for url in ("/soc/alerts", self.url):
            self.assertEqual(anonymous.get(url).status_code, 302)
        self.assertEqual(anonymous.post(self.url).status_code, 302)
        with anonymous.session_transaction() as sess:
            sess["logged_in"] = True
        self.assertEqual(anonymous.get("/soc/alerts").status_code, 302)
        data = self.data()
        for token in ("", "forged", "x" * 129, "\u2603"):
            data["csrf_token"] = token
            self.assertEqual(self.client.post(self.url, data=data).status_code, 403)
        self.assertEqual(self.rows(), [])

    def test_queue_filters_traceability_and_identity(self):
        self.evidence.write_text("\n".join(json.dumps(row) for row in
                                           [self.records[0], self.records[0], self.records[1]]), encoding="utf-8")
        with self.app.app_context():
            self.events = list(alert_events("BF-M-003"))
        response = self.client.get("/soc/alerts?case=BF-M-003&source=suricata")
        self.assertIn(b"Suspicious request", response.data)
        self.assertIn(self.events[0]["alert_id"][:12].encode(), response.data)
        self.assertNotIn(b"Suspicious request", self.client.get("/soc/alerts?case=BF-M-003&source=wazuh").data)
        self.assertNotIn(b"Suspicious request", self.client.get("/soc/alerts?case=BF-M-002").data)
        self.assertEqual(self.client.get("/soc/alerts?case=invalid").status_code, 404)
        self.assertEqual(self.client.get("/soc/alerts?source=system").status_code, 400)
        self.assertNotEqual(self.events[0]["alert_id"], self.events[1]["alert_id"])
        detail = self.client.get(self.url)
        self.assertIn(b"suricata/BF-M-003_events.json", detail.data)
        download = self.client.get("/evidence/download/suricata/BF-M-003_events.json")
        self.assertEqual(download.data, self.evidence.read_bytes())
        download.close()
        with self.app.app_context():
            self.assertEqual(list(alert_events("BF-M-003")), self.events)
        # Changing content beyond the SIEM preview also invalidates the identifier.
        self.records[0]["padding"] = "x" * 1600
        self.evidence.write_text(json.dumps(self.records[0]), encoding="utf-8")
        with self.app.app_context():
            first = next(alert_events("BF-M-003"))
        self.records[0]["padding"] += "y"
        self.evidence.write_text(json.dumps(self.records[0]), encoding="utf-8")
        with self.app.app_context():
            second = next(alert_events("BF-M-003"))
        self.assertNotEqual(first["alert_id"], second["alert_id"])
        self.assertGreater(len(second["raw"]), 1500)
        self.assertEqual(self.client.get(self.url).status_code, 404)

    def test_save_update_isolation_persistence_and_progress(self):
        with self.app.app_context():
            before = {table: [tuple(row) for row in get_db().execute("SELECT * FROM " + table)]
                      for table in ("progress", "submissions", "validated_findings", "operations_triage")}
        data = self.data()
        data.update(username="someone_else", findings="<script>alert('x')</script> analyst finding")
        self.assertEqual(self.client.post(self.url, data=data).status_code, 302)
        self.assertEqual(self.rows()[0]["username"], "analyst")
        self.assertIn(b"&lt;script&gt;", self.client.get(self.url).data)
        self.assertIn(b"Investigating", self.client.get("/soc/alerts?case=BF-M-003").data)
        other = self.app.test_client()
        self.login(other, "other")
        self.assertNotIn(b"analyst finding", other.get(self.url).data)
        data["status"] = "Resolved"
        self.client.post(self.url, data=data)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0]["status"], "Resolved")
        recreated = create_app(self.config)
        client = recreated.test_client()
        self.login(client)
        self.assertIn(b"analyst finding", client.get(self.url).data)
        with self.app.app_context():
            initialize_alert_triage(get_db())
            for table, expected in before.items():
                self.assertEqual([tuple(row) for row in get_db().execute("SELECT * FROM " + table)], expected)

    def test_invalid_input_preserves_saved_decision(self):
        data = self.data()
        self.client.post(self.url, data=data)
        original = self.rows()
        for field, value in (("verdict", "invalid"), ("priority", "invalid"), ("status", "invalid"),
                             ("response_action", "invalid"), ("findings", " " * 30),
                             ("findings", "x" * 19), ("findings", "x" * 3001)):
            invalid = dict(data, **{field: value})
            response = self.client.post(self.url, data=invalid)
            self.assertEqual(response.status_code, 400)
            self.assertIn(b'role="alert"', response.data)
            self.assertEqual(self.rows(), original)
        self.assertEqual(self.client.get("/soc/alerts/BF-M-002/" + self.events[0]["alert_id"]).status_code, 404)
        self.assertEqual(self.client.get("/soc/alerts/BF-M-003/" + "0" * 64).status_code, 404)

    def test_queue_bound_does_not_prevent_detail_lookup(self):
        self.evidence.write_text("\n".join(json.dumps(self.records[0]) for _ in range(102)), encoding="utf-8")
        response = self.client.get("/soc/alerts?case=BF-M-003")
        self.assertEqual(response.data.count(b"Investigate\n"), 100)
        self.assertIn(b"limit was reached", response.data)
        with self.app.app_context():
            last = list(alert_events("BF-M-003"))[-1]
        self.assertEqual(self.client.get("/soc/alerts/BF-M-003/" + last["alert_id"]).status_code, 200)

    def test_wazuh_json_entries_keep_original_lines_and_evidence(self):
        directory = self.root / "evidence" / "wazuh"
        directory.mkdir()
        record = {"timestamp": "2026-01-01T12:00:00Z",
                  "rule": {"level": 12, "description": "Endpoint detection"},
                  "data": {"srcip": "192.0.2.3"}}
        raw = json.dumps(record, indent=2)
        (directory / "BF-M-003_alerts.log").write_bytes((raw + "\n\n" + raw).encode("utf-8"))
        with self.app.app_context():
            events = list(alert_events("BF-M-003", "wazuh"))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["raw"], raw)
        self.assertEqual(events[0]["line"], 1)
        self.assertEqual(events[1]["line"], raw.count("\n") + 3)
        self.assertEqual(events[0]["severity"], "Critical")
        self.assertEqual(events[0]["source_ip"], "192.0.2.3")
        self.assertNotEqual(events[0]["alert_id"], events[1]["alert_id"])
        page = self.client.get("/soc/alerts?case=BF-M-003&source=wazuh")
        self.assertIn(b"Endpoint detection", page.data)
        self.assertNotIn(b"Suspicious request", page.data)
        self.assertNotIn(b"may appear as separate entries", page.data)

    def test_flow_records_are_excluded_from_queue_and_detail(self):
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0]["event_type"], "alert")
        # A security-looking signature does not turn a connection into an alert.
        self.records[1]["alert"] = {"signature": "Ordinary flow"}
        self.evidence.write_text("\n".join(json.dumps(row) for row in self.records), encoding="utf-8")
        page = self.client.get("/soc/alerts?case=BF-M-003")
        self.assertIn(b"Suspicious request", page.data)
        self.assertNotIn(b"Ordinary flow", page.data)

    def test_text_wazuh_triage_reuses_full_siem_record(self):
        from routes.siem import iter_events

        directory = self.root / "evidence" / "wazuh"
        directory.mkdir()
        raw = ('2026 Aug 21 10:32:04 blackfalcon-app\nrule.level=8\n'
               'description="Web application spawned shell"\nprocess=/bin/sh\n')
        (directory / "BF-M-003_alerts.log").write_text(raw + raw, encoding="utf-8")
        with self.app.app_context():
            siem = list(iter_events("wazuh", "BF-M-003"))
            events = list(alert_events("BF-M-003", "wazuh"))
        self.assertEqual(len(events), 2)
        for event, row in zip(events, siem):
            self.assertEqual(event["raw"], row["search_text"])
            self.assertEqual(event["line"], row["line"])
            self.assertEqual(event["severity"], "High")
        self.assertNotEqual(events[0]["alert_id"], events[1]["alert_id"])
        page = self.client.get("/soc/alerts/BF-M-003/" + events[0]["alert_id"])
        self.assertIn(b"process=/bin/sh", page.data)
        self.assertNotIn(b"may appear as separate entries", page.data)


if __name__ == "__main__":
    unittest.main()
