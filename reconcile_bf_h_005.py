"""BF-H-005 chronology reconciliation (Python 3, standard library only).

Read-only with respect to evidence. Writes derived reports under reports/.
Candidate correlations are comparison anchors, never replacement timestamps.
"""
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path

ROOT = Path(__file__).resolve().parent
IST = timezone(timedelta(hours=5, minutes=30))
ZEEK_FILES = [f"zeek/BF-H-005_{kind}.log" for kind in ("conn", "dns", "http")]
SURICATA_FILE = "suricata/BF-H-005_eve.json"
SOURCE_FILES = ZEEK_FILES + [SURICATA_FILE, "wazuh/BF-H-005_wazuh_alerts.log",
                            "system/BF-H-005_auth.log", "system/BF-H-005_process.log"]
SCAN = "ET SCAN Suspicious TCP Port Sweep"
INJECTION = "ET WEB_SERVER Possible Command Injection"
BEACON = "ET MALWARE Suspicious Periodic HTTPS Beacon"
EXFIL = "ET POLICY Unusually Large Outbound HTTPS POST"

# Suricata timestamps are loaded from the source, not supplied as corrections.
ANCHORS = {
    ("conn", "R01"): ("Reconnaissance traffic", SCAN,
        "Same host pair and scan sequence; R01 targets port 21, alert targets 445. Not the same packet."),
    ("conn", "R05"): ("Reconnaissance traffic (port 445)", SCAN,
        "Same host pair and destination port; candidate within the scan sequence."),
    ("http", "H02"): ("Command injection request", INJECTION,
        "Same host pair and port; HTTP URI fetches the staging script through command injection."),
    ("conn", "C01"): ("Suspected C2 activity (first connection)", BEACON,
        "Same host pair and port; recurring connections do not identify which beacon raised the alert."),
    ("http", "H03"): ("Suspected C2 activity (first HTTP request)", BEACON,
        "Same host pair and port; POST to api.blackfalcon-c2.local/api/status; beacon instance uncertain."),
    ("conn", "C03"): ("Suspected C2 activity (third connection)", BEACON,
        "Same host pair and port; fractional seconds agree, but this does not prove event identity."),
    ("http", "H05"): ("Suspected C2 activity (third HTTP request)", BEACON,
        "Same host pair and port; periodic POST and matching fractional seconds; beacon instance uncertain."),
    ("conn", "X01"): ("Data exfiltration connection", EXFIL,
        "Same host pair and port; large outbound transfer; HTTP H06 corroborates the upload."),
    ("http", "H06"): ("Data exfiltration request", EXFIL,
        "Same host pair and port; large POST to drop.blackfalcon-c2.local/upload."),
}
FIELDS = (
    "zeek_file", "zeek_line", "zeek_path", "uid", "original_epoch", "zeek_time_utc",
    "zeek_time_ist", "src_ip", "src_port", "dest_ip", "dest_port", "application_detail",
    "status", "supporting_event", "supporting_file", "supporting_line",
    "supporting_original_timestamp", "supporting_time_ist", "supporting_event_json",
    "destination_port_matches", "year_difference", "zeek_minus_reference_seconds",
    "diagnostic_clock_difference_seconds_after_year_alignment", "notes",
)


def epoch_datetime(value):
    """Convert exactly to microseconds without binary float rounding."""
    try:
        micros = Decimal(value) * 1_000_000
    except InvalidOperation as error:
        raise ValueError(f"Invalid Unix epoch: {value}") from error
    if not micros.is_finite() or micros != micros.to_integral_value():
        raise ValueError("Epoch must be finite with at most microsecond precision")
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(micros))


def seconds(delta):
    micros = ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds)
    return format(Decimal(micros) / 1_000_000, ".6f")


def parse_zeek(content, filename):
    fields = None
    seen = set()
    for number, line in enumerate(content.decode("utf-8-sig").splitlines(), 1):
        if line.startswith("#fields\t"):
            fields = line.split("\t")[1:]
        elif line.strip() and not line.startswith("#"):
            if not fields or len(line.split("\t")) != len(fields):
                raise ValueError(f"Invalid Zeek fields at {filename}:{number}")
            record = dict(zip(fields, line.split("\t")))
            if record["uid"] in seen:
                raise ValueError(f"Duplicate UID in {filename}: {record['uid']}")
            seen.add(record["uid"])
            yield number, record


def reconcile(root=ROOT):
    evidence = root / "evidence"
    snapshots = {name: (evidence / name).read_bytes() for name in SOURCE_FILES}
    references = {}
    for number, line in enumerate(snapshots[SURICATA_FILE].decode("utf-8-sig").splitlines(), 1):
        if line.strip():
            event = json.loads(line)
            signature = event["alert"]["signature"]
            if signature in references:
                raise ValueError(f"Ambiguous Suricata anchor: {signature}")
            references[signature] = (number, event)

    rows = []
    found_anchors = set()
    for filename in ZEEK_FILES:
        kind = Path(filename).stem.removeprefix("BF-H-005_")
        for number, record in parse_zeek(snapshots[filename], filename):
            observed = epoch_datetime(record["ts"])
            local = observed.astimezone(IST)
            row = dict.fromkeys(FIELDS, "")
            row.update(zeek_file="evidence/" + filename, zeek_line=number, zeek_path=kind,
                uid=record["uid"], original_epoch=record["ts"], zeek_time_utc=observed.isoformat(),
                zeek_time_ist=local.isoformat(), src_ip=record["id.orig_h"], src_port=record["id.orig_p"],
                dest_ip=record["id.resp_h"], dest_port=record["id.resp_p"],
                application_detail=json.dumps({key: record[key] for key in
                    ("service", "orig_bytes", "method", "host", "uri", "query", "answers") if key in record}, sort_keys=True),
                status="unanchored", notes="No independent comparison anchor selected; timestamp is not verified.")
            key = (kind, record["uid"])
            if key in ANCHORS:
                label, signature, basis = ANCHORS[key]
                ref_line, event = references[signature]
                expected = datetime.fromisoformat(event["timestamp"])
                if expected.utcoffset() is None:
                    raise ValueError(f"Suricata anchor has no timezone: {signature}")
                expected = expected.astimezone(IST)
                if (event["src_ip"], event["dest_ip"]) != (row["src_ip"], row["dest_ip"]):
                    raise ValueError(f"Anchor endpoints changed for {key}")
                ports_match = str(event["dest_port"]) == row["dest_port"]
                if not ports_match and key != ("conn", "R01"):
                    raise ValueError(f"Anchor destination port changed for {key}")
                # Hypothetical comparison only. Never persisted as an event time.
                diagnostic = local.replace(year=expected.year)
                row.update(status="candidate_reference_time_conflict" if local != expected else "candidate_reference_time_agreement",
                    supporting_event=label, supporting_file="evidence/" + SURICATA_FILE,
                    supporting_line=ref_line, supporting_original_timestamp=event["timestamp"],
                    supporting_time_ist=expected.isoformat(), supporting_event_json=json.dumps(event, sort_keys=True),
                    destination_port_matches=str(ports_match).lower(), year_difference=expected.year - local.year,
                    zeek_minus_reference_seconds=seconds(local - expected),
                    diagnostic_clock_difference_seconds_after_year_alignment=seconds(diagnostic - expected),
                    notes=basis + " Year alignment is diagnostic only, not a validated correction.")
                found_anchors.add(key)
            rows.append(row)
    if found_anchors != set(ANCHORS):
        raise ValueError(f"Missing Zeek anchors: {sorted(set(ANCHORS) - found_anchors)}")

    sources = [{"path": "evidence/" + name, "size_bytes": len(content),
                "sha256_before": hashlib.sha256(content).hexdigest()}
               for name, content in snapshots.items()]
    output = root / "reports"
    output.mkdir(exist_ok=True)
    report_path = output / "BF-H-005_timestamp_reconciliation.csv"
    with report_path.open("w", newline="", encoding="utf-8") as report:
        writer = csv.DictWriter(report, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    for source in sources:
        source["sha256_after"] = hashlib.sha256((root / source["path"]).read_bytes()).hexdigest()
        if source["sha256_after"] != source["sha256_before"]:
            raise ValueError(f"Evidence changed during reconciliation: {source['path']}")
    manifest = {
        "case_id": "BF-H-005", "zeek_records": len(rows), "candidate_comparisons": len(found_anchors),
        "unanchored_records": len(rows) - len(found_anchors), "evidence_unchanged": True,
        "method": "Exact Unix epochs converted to UTC and IST (+05:30). All deltas are Zeek minus reference. "
                  "Year alignment is hypothetical analysis only. Candidate correlations do not prove event identity. "
                  "Unanchored rows are not independently verified. No corrected timestamps are produced.",
        "grading_chronology": "Use Wazuh and Suricata. System logs without timezone/year remain as supplied; "
                              "no timezone or year is inferred for them.",
        "sources": sources,
        "report": {"path": "reports/" + report_path.name,
                   "sha256": hashlib.sha256(report_path.read_bytes()).hexdigest()},
    }
    manifest_path = output / "BF-H-005_timestamp_reconciliation_sources.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return rows, manifest


def main():
    try:
        rows, manifest = reconcile()
    except (OSError, ValueError, KeyError, OverflowError) as error:
        print(f"Reconciliation failed: {error}", file=sys.stderr)
        return 1
    print(f"Report: {ROOT / manifest['report']['path']}")
    print(f"Records: {len(rows)}; candidate comparisons: {manifest['candidate_comparisons']}; "
          f"unanchored: {manifest['unanchored_records']}")
    print("Diagnostic residual seconds after hypothetical year alignment (Zeek minus Suricata):")
    for row in rows:
        if row["supporting_event"]:
            print(f"  {row['zeek_path']}/{row['uid']}: {row['diagnostic_clock_difference_seconds_after_year_alignment']} "
                  f"({row['supporting_event']})")
    print(f"Evidence unchanged: SHA-256 verified for all {len(manifest['sources'])} source files.")
    print("Source hashes: reports/BF-H-005_timestamp_reconciliation_sources.json")
    print("Discrepancies remain unresolved; no timestamps corrected. Use Wazuh/Suricata for graded chronology.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
