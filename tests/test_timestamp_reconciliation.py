"""Evidence integrity and cross-source chronology regressions."""
import csv
import hashlib
import json
import shutil
import tempfile
import unittest
from datetime import timezone
from pathlib import Path

from reconcile_bf_h_005 import ROOT, SOURCE_FILES, SURICATA_FILE, epoch_datetime, reconcile


class TimestampReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bf-h-005-reconciliation-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in SOURCE_FILES:
            target = self.root / "evidence" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / "evidence" / name, target)

    def test_complete_report_preserves_bytes_and_verifiable_source_hashes(self):
        before = {name: (self.root / "evidence" / name).read_bytes() for name in SOURCE_FILES}
        rows, manifest = reconcile(self.root)
        self.assertEqual((len(rows), manifest["candidate_comparisons"], manifest["unanchored_records"]), (30, 9, 21))
        self.assertTrue(manifest["evidence_unchanged"])
        for source in manifest["sources"]:
            name = source["path"].removeprefix("evidence/")
            self.assertEqual((self.root / source["path"]).read_bytes(), before[name])
            self.assertEqual(source["sha256_before"], hashlib.sha256(before[name]).hexdigest())
            self.assertEqual(source["sha256_before"], source["sha256_after"])
        report = self.root / manifest["report"]["path"]
        with report.open(newline="", encoding="utf-8") as handle:
            exported = list(csv.DictReader(handle))
        self.assertEqual(len(exported), 30)
        self.assertEqual(hashlib.sha256(report.read_bytes()).hexdigest(), manifest["report"]["sha256"])
        disk_manifest = json.loads((report.parent / "BF-H-005_timestamp_reconciliation_sources.json").read_text())
        self.assertEqual(disk_manifest, manifest)
        first_report = report.read_bytes()
        self.assertEqual(reconcile(self.root)[1], manifest)
        self.assertEqual(report.read_bytes(), first_report)

    def test_nonuniform_deltas_and_candidate_correlations_are_explicit(self):
        rows, _ = reconcile(self.root)
        lookup = {(row["zeek_path"], row["uid"]): row for row in rows}
        for key, residual in ((('conn', 'R01'), '-2.409000'), (('conn', 'R05'), '-1.791000'),
                              (('http', 'H02'), '0.000000'), (('conn', 'C01'), '419.799000'),
                              (('http', 'H03'), '419.799000'), (('conn', 'C03'), '600.000000'),
                              (('http', 'H05'), '600.000000'), (('conn', 'X01'), '600.000000'),
                              (('http', 'H06'), '600.000000')):
            with self.subTest(key=key):
                row = lookup[key]
                self.assertEqual(row["year_difference"], 1)
                self.assertEqual(row["diagnostic_clock_difference_seconds_after_year_alignment"], residual)
                self.assertEqual(row["status"], "candidate_reference_time_conflict")
                self.assertIn("not a validated correction", row["notes"])
        self.assertEqual(lookup['http', 'H02']["zeek_minus_reference_seconds"], "-31536000.000000")
        self.assertEqual(lookup['http', 'H06']["zeek_minus_reference_seconds"], "-31535400.000000")
        self.assertEqual(lookup['conn', 'R01']["destination_port_matches"], "false")
        self.assertEqual(lookup['conn', 'R05']["destination_port_matches"], "true")
        self.assertEqual(lookup['dns', 'D03']["status"], "unanchored")
        self.assertEqual(lookup['dns', 'D03']["supporting_time_ist"], "")
        self.assertEqual(lookup['dns', 'D03']["diagnostic_clock_difference_seconds_after_year_alignment"], "")

    def test_epoch_conversion_has_explicit_timezone_and_exact_fraction(self):
        self.assertEqual(epoch_datetime("1755752529.301").isoformat(), "2025-08-21T05:02:09.301000+00:00")
        self.assertIs(epoch_datetime("0").tzinfo, timezone.utc)
        self.assertEqual(epoch_datetime("-0.000001").isoformat(), "1969-12-31T23:59:59.999999+00:00")
        for invalid in ("NaN", "Infinity", "0.0000001", "invalid"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                epoch_datetime(invalid)

    def test_report_reads_reference_timestamp_instead_of_inventing_one(self):
        source = self.root / "evidence" / SURICATA_FILE
        source.write_bytes(source.read_bytes().replace(b"10:32:09.301", b"10:32:08.301"))
        rows, _ = reconcile(self.root)
        injection = next(row for row in rows if row["uid"] == "H02")
        self.assertEqual(injection["diagnostic_clock_difference_seconds_after_year_alignment"], "1.000000")
        self.assertEqual(injection["supporting_original_timestamp"], "2026-08-21T10:32:08.301+0530")

    def test_missing_source_cannot_produce_a_success_report(self):
        (self.root / "evidence" / SOURCE_FILES[-1]).unlink()
        with self.assertRaises(OSError):
            reconcile(self.root)
        self.assertFalse((self.root / "reports").exists())

    def test_missing_anchor_or_malformed_zeek_fails_without_partial_report(self):
        path = self.root / "evidence" / "zeek/BF-H-005_http.log"
        original = path.read_bytes()
        for changed in (original.replace(b"\tH02\t", b"\tUNKNOWN\t"),
                        original.replace(b"1755752529.301\tH02", b"1755752529.301\tEXTRA\tH02")):
            with self.subTest(changed=changed[:20]):
                path.write_bytes(changed)
                with self.assertRaises(ValueError):
                    reconcile(self.root)
                self.assertFalse((self.root / "reports").exists())

    def test_changed_endpoint_or_ambiguous_reference_fails(self):
        source = self.root / "evidence" / SURICATA_FILE
        original = source.read_bytes()
        for changed in (original.replace(b'"src_ip":"192.168.56.104"', b'"src_ip":"192.168.56.105"'),
                        original + b"\n" + original.splitlines()[0]):
            with self.subTest(changed=changed[:20]):
                source.write_bytes(changed)
                with self.assertRaises(ValueError):
                    reconcile(self.root)
                self.assertFalse((self.root / "reports").exists())


if __name__ == "__main__":
    unittest.main()
