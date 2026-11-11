"""Bounded, read-only search of the bundled offline security logs."""

import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from itertools import islice
from pathlib import Path

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for

from routes.wazuh_parser import iter_wazuh_alerts


siem_bp = Blueprint("siem", __name__)
SOURCES = ("wazuh", "suricata", "zeek", "system", "web", "cowrie")
CASE_PATTERN = re.compile(r"BF-(?:2026|M|H)-\d{3}")
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational", "Unknown")
MAX_MATCHES = 250
LIMIT = MAX_MATCHES
MAX_FILES = 200
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_SCAN_BYTES = 8 * MAX_FILE_BYTES
MAX_LINES_PER_FILE = 50000
MAX_LINES = 200000
TEXT_EXTENSIONS = {".log", ".json", ".jsonl", ".ndjson", ".txt", ".tsv", ".csv"}
IP_PATTERN = re.compile(r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.:])")
LEVEL_PATTERN = re.compile(r'\b(?:rule\.level|level|severity|priority)\s*[=:]\s*["\']?([\w]+)', re.I)
ISO_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")


def nested(record, *keys):
    for key in keys:
        if not isinstance(record, dict):
            return None
        record = record.get(key)
    return record


def event_severity(record, source, raw):
    """Normalize explicit fields using the source's severity scale."""
    value = nested(record, "alert", "severity") if source == "suricata" else None
    if source == "wazuh":
        value = nested(record, "rule", "level")
    if value is None:
        value = record.get("severity", record.get("level", record.get("priority")))
    if value is None and not record:
        match = LEVEL_PATTERN.search(raw)
        value = match.group(1) if match else None
    label = str(value).strip().title()
    if label in SEVERITIES:
        return label
    aliases = {"Info": "Informational", "Warning": "Medium", "Warn": "Medium", "Error": "High", "Fatal": "Critical"}
    if label in aliases:
        return aliases[label]
    if isinstance(value, bool) or not re.fullmatch(r"\d{1,2}", str(value)):
        return "Unknown"
    level = int(value)
    if source == "suricata":
        return {1: "High", 2: "Medium", 3: "Low"}.get(level, "Unknown")
    if source == "wazuh" and 0 <= level <= 15:
        return ("Critical" if level >= 12 else "High" if level >= 8 else
                "Medium" if level >= 5 else "Low" if level >= 1 else "Informational")
    return "Unknown"


def parse_timestamp(value):
    """Normalize known offsets to UTC and preserve timezone-free lab clocks."""
    text = str(value).strip()
    try:
        if re.fullmatch(r"\d{9,11}(?:\.\d+)?", text):
            return datetime.fromtimestamp(float(text), timezone.utc)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        parsed = None
        for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y %b %d %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed
    try:
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def event_time(record, raw):
    value = record.get("timestamp", record.get("ts"))
    if value is not None:
        return parse_timestamp(value)
    match = ISO_PATTERN.match(raw)
    if match:
        return parse_timestamp(match.group())
    apache = re.search(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]", raw)
    if apache:
        return parse_timestamp(apache.group(1))
    dated_syslog = re.match(r"\d{4} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}", raw)
    return parse_timestamp(dated_syslog.group()) if dated_syslog else None


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return ""


def event_ips(record, raw):
    source = next((ip for value in (record.get("src_ip"), record.get("source_ip"), record.get("srcip"),
                                   record.get("id.orig_h"), nested(record, "data", "srcip"), nested(record, "source", "ip"))
                   if (ip := valid_ip(value))), "")
    destination = next((ip for value in (record.get("dest_ip"), record.get("dst_ip"), record.get("destination_ip"),
                                        record.get("dstip"), record.get("id.resp_h"), nested(record, "data", "dstip"), nested(record, "data", "destination"), nested(record, "destination", "ip"))
                        if (ip := valid_ip(value))), "")
    if not record:
        src_match = re.search(r"\b(?:src_ip|srcip|source_ip|source)\s*=\s*([^\s,]+)|\bfrom\s+([^\s,]+)|^((?:\d{1,3}\.){3}\d{1,3})\s", raw)
        dst_match = re.search(r"\b(?:dest_ip|dst_ip|dstip|destination_ip)\s*=\s*([^\s,]+)", raw)
        source = valid_ip(next((value for value in src_match.groups() if value), "")) if src_match else ""
        destination = valid_ip(dst_match.group(1)) if dst_match else ""
    ips = {ip for candidate in IP_PATTERN.findall(raw) if (ip := valid_ip(candidate))}
    ips.update(ip for ip in (source, destination) if ip)
    return source, destination, sorted(ips)


def correlate_events(results):
    shared = defaultdict(lambda: {"sources": set(), "event_count": 0})
    for row in results:
        for ip in set(row["ips"]):
            shared[ip]["sources"].add(row["source"])
            shared[ip]["event_count"] += 1
    return [
        {"ip": ip, "sources": ", ".join(sorted(item["sources"])).upper(), "event_count": item["event_count"]}
        for ip, item in sorted(shared.items(), key=lambda pair: (-pair[1]["event_count"], pair[0]))
        if len(item["sources"]) >= 2
    ]


def parse_records(lines):
    """Recognize JSON lines, concatenated pretty JSON, and Zeek/plain text."""
    text = b"".join(lines).decode("utf-8-sig", errors="replace")
    decoder = json.JSONDecoder()
    records = []
    offset = 0
    lineno = 1
    try:
        while offset < len(text):
            start = offset
            while offset < len(text) and text[offset].isspace():
                offset += 1
            lineno += text.count("\n", start, offset)
            if offset == len(text):
                break
            record, end = decoder.raw_decode(text, offset)
            if not isinstance(record, dict):
                raise ValueError("Not a JSON event object")
            raw = text[offset:end]
            records.append((lineno, raw, record))
            lineno += raw.count("\n")
            offset = end
    except (ValueError, RecursionError):
        records = []
    if records:
        yield from records
        return
    fields = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except (ValueError, RecursionError):
            record = dict(zip(fields, line.split("\t"))) if fields else {}
        yield lineno, line, record if isinstance(record, dict) else {}


def build_event(category, path, lineno, line, record, case_id):
    """Build shared SIEM and triage metadata from one complete evidence entry."""
    if not isinstance(record, dict):
        record = {}
    alert = record.get("alert")
    alert = alert if isinstance(alert, dict) else {}
    rule = record.get("rule")
    rule = rule if isinstance(rule, dict) else {}
    occurred_at = event_time(record, line)
    source_ip, destination_ip, ips = event_ips(record, line)
    return {
        "source": category,
        "event_type": record.get("event_type", ""),
        "case": case_id,
        "file": path.name,
        "line": lineno,
        "timestamp": str(record.get("timestamp") or record.get("ts") or line[:23])[:45],
        "timestamp_utc": occurred_at.isoformat().replace("+00:00", "Z") if occurred_at else "Unrecognized",
        "timestamp_display": (occurred_at.isoformat().replace("+00:00", "Z")
                              + (" (lab time; timezone unspecified)" if occurred_at.tzinfo is None else ""))
                             if occurred_at else "Unrecognized",
        "event_date": occurred_at.date() if occurred_at else None,
        "severity": event_severity(record, category, line),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "ips": ips,
        "summary": str(alert.get("signature") or rule.get("description") or record.get("event_type") or record.get("eventid") or line)[:300],
        "raw": line[:1500],
        "search_text": line,
        "relative_path": category + "/" + path.name,
    }


def iter_events(source="", case="", status=None):
    """Only inspect allowlisted text files that resolve inside the evidence root."""
    if status is None:
        status = {}
    root = Path(current_app.config["EVIDENCE_DIR"]).resolve()
    remaining = MAX_SCAN_BYTES
    lines_left = MAX_LINES
    files_left = MAX_FILES
    for category in (source,) if source else SOURCES:
        directory = root / category
        try:
            if directory.is_symlink() or not directory.is_dir():
                continue
            paths = sorted(islice(directory.iterdir(), MAX_FILES + 1))
            if len(paths) > MAX_FILES:
                status["limited"] = True
                paths = paths[:MAX_FILES]
        except OSError:
            continue
        for path in paths:
            case_id = path.name.split("_")[0]
            case_id = case_id if CASE_PATTERN.fullmatch(case_id) else "General"
            if case and case_id != case:
                continue
            if path.suffix.lower() not in TEXT_EXTENSIONS:
                continue
            try:
                if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
                    continue
                if remaining <= 0 or lines_left <= 0 or files_left <= 0:
                    status["limited"] = True
                    return
                files_left -= 1
                allowance = min(MAX_FILE_BYTES, remaining)
                with path.open("rb") as evidence:
                    data = evidence.read(allowance)
                remaining -= len(data)
                truncated = path.stat().st_size > len(data)
                status["limited"] = status.get("limited", False) or truncated
            except OSError:
                continue
            lines = data.splitlines(keepends=True)
            if truncated and lines and not lines[-1].endswith((b"\n", b"\r")):
                lines.pop()
            file_line_limit = min(lines_left, MAX_LINES_PER_FILE)
            if len(lines) > file_line_limit:
                status["limited"] = True
                lines = lines[:file_line_limit]
            lines_left -= len(lines)
            records = iter_wazuh_alerts(lines) if category == "wazuh" else parse_records(lines)
            for lineno, line, record in records:
                yield build_event(category, path, lineno, line, record, case_id)


@siem_bp.route("/siem", methods=["GET"])
def search_events():
    if session.get("logged_in") is not True:
        return redirect(url_for("auth.login"))
    query = request.args.get("q", "").strip()[:120]
    source = request.args.get("source", "").strip().lower()
    case = request.args.get("case", "").strip().upper()
    if source not in SOURCES:
        source = ""
    if not CASE_PATTERN.fullmatch(case):
        case = ""
    severity = request.args.get("severity", "").strip().title()
    if severity not in SEVERITIES:
        severity = ""
    dates = {}
    errors = []
    for name in ("start_date", "end_date"):
        value = request.args.get(name, "").strip()[:32]
        try:
            dates[name] = date.fromisoformat(value) if value else None
            if value and dates[name].isoformat() != value:
                raise ValueError("Expected YYYY-MM-DD")
        except ValueError:
            dates[name] = None
            errors.append("Enter a valid start and end date in YYYY-MM-DD format.")
    if dates["start_date"] and dates["end_date"] and dates["start_date"] > dates["end_date"]:
        errors.append("Start date must be on or before end date.")
    results = []
    status = {}
    for row in (() if errors else iter_events(source, case, status)):
        if query.casefold() not in row.pop("search_text").casefold():
            continue
        if severity and row["severity"] != severity:
            continue
        event_date = row["event_date"]
        if (dates["start_date"] or dates["end_date"]) and event_date is None:
            continue
        if dates["start_date"] and event_date < dates["start_date"]:
            continue
        if dates["end_date"] and event_date > dates["end_date"]:
            continue
        if len(results) == LIMIT:
            status["limited"] = True
            status["truncated"] = True
            break
        results.append(row)
    return render_template(
        "siem.html", query=query, source=source, case=case,
        sources=SOURCES, results=results, limit=LIMIT,
        limited=status.get("limited", False),
        truncated=status.get("truncated", False), severity=severity,
        severities=SEVERITIES, start_date=dates["start_date"].isoformat() if dates["start_date"] else "",
        end_date=dates["end_date"].isoformat() if dates["end_date"] else "",
        severity_counts=Counter(row["severity"] for row in results),
        source_counts=Counter(row["source"] for row in results),
        correlations=correlate_events(results), filter_errors=list(dict.fromkeys(errors)),
    )
