"""Regression coverage for complete Wazuh evidence records."""

import json
import tempfile
import unittest
from pathlib import Path

from routes.wazuh_parser import iter_wazuh_alerts, parse_text_alert, parse_wazuh_time


TEXT = ('2026 Aug 21 10:32:04 blackfalcon-app\n'
        'rule.id=92010 rule.level=8\n'
        'description="Web application spawned shell"\n'
        'user=www-data\nprocess=/bin/sh\nsrcip=192.0.2.1\n')


class WazuhParserTests(unittest.TestCase):
    def test_multiline_alert(self):
        record = parse_text_alert(TEXT)
        self.assertEqual(record["rule"], {"id": "92010", "level": 8,
                                         "description": "Web application spawned shell"})
        self.assertEqual(record["data"]["process"], "/bin/sh")
        self.assertEqual(record["data"]["user"], "www-data")
        self.assertEqual(record["agent"]["name"], "blackfalcon-app")

    def test_adjacent_alerts_keep_original_lines_and_full_raw(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.log"
            original = ("\n" + TEXT + TEXT).encode()
            path.write_bytes(original)
            events = list(iter_wazuh_alerts(path))
            self.assertEqual([event[0] for event in events], [2, TEXT.count("\n") + 2])
            self.assertEqual([event[1] for event in events], [TEXT.rstrip(), TEXT.rstrip()])
            self.assertEqual(path.read_bytes(), original)

    def test_mixed_json_text_and_malformed_entries(self):
        record = {"timestamp": "2026-01-15T09:34:52.104+0000",
                  "rule": {"level": 5, "description": "SSH failure"},
                  "data": {"srcip": "192.0.2.2"}}
        raw = json.dumps(record, indent=2)
        content = TEXT + '\n{broken\n\n' + raw + '\n' + json.dumps(record) + '\n' + TEXT
        events = list(iter_wazuh_alerts(content.encode().splitlines(keepends=True)))
        self.assertEqual(len(events), 5)
        self.assertEqual(events[2][2], record)
        self.assertEqual(events[2][1], raw)
        self.assertEqual(events[2][0], content[:content.index(raw)].count("\n") + 1)
        self.assertEqual(events[3][2], record)
        self.assertEqual(events[4][2]["rule"]["level"], 8)

    def test_timestamps_preserve_unspecified_timezone(self):
        self.assertEqual(parse_wazuh_time("2026 Aug 21 10:32:04"), "2026-08-21 10:32:04")
        self.assertEqual(parse_wazuh_time("2026-01-15T09:34:52.104+0000"), "2026-01-15T09:34:52.104000Z")
        self.assertEqual(parse_wazuh_time("2026-08-21T00:30:00+0530"), "2026-08-20T19:00:00Z")
        self.assertIsNone(parse_wazuh_time("invalid"))
        self.assertIsNone(parse_wazuh_time(None))


if __name__ == "__main__":
    unittest.main()
