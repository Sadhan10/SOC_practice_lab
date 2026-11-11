"""Reconstruct Wazuh text and JSON evidence without changing source files."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path


HEADER = re.compile(r"^(\d{4}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)(.*)$")
KEY_VALUE = re.compile(r'''([\w.]+)=("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\S+)''')


def parse_wazuh_time(value):
    """Normalize known timestamps, preserving clocks with no timezone."""
    if not value:
        return None
    text = str(value).strip()
    try:
        return datetime.strptime(text, "%Y %b %d %H:%M:%S").isoformat(sep=" ")
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError):
        return None


def parse_text_alert(raw):
    """Extract rule and data fields from a complete plain-text alert."""
    record = {"rule": {}, "data": {}}
    header = HEADER.match(raw.splitlines()[0]) if raw else None
    if header:
        record["timestamp"] = parse_wazuh_time(header.group(1))
        record["agent"] = {"name": header.group(2)}
    for match in KEY_VALUE.finditer(raw):
        key, value = match.groups()
        if value[:1] in ('"', "'"):
            # Strip the enclosing quotes without shell-unescaping evidence paths.
            value = value[1:-1]
        if key in ("description", "rule.description"):
            record["rule"]["description"] = value
        elif key.startswith("rule."):
            field = key[5:]
            if field == "level" and re.fullmatch(r"\d{1,2}", value):
                value = int(value)
            record["rule"][field] = value
        elif key in ("timestamp", "ts", "severity", "level", "priority"):
            record[key] = value
        else:
            record["data"][key.removeprefix("data.")] = value
    if "srcip" not in record["data"]:
        source = re.search(r"\bfrom\s+([\d.]+)\b", raw)
        if source:
            record["data"]["srcip"] = source.group(1)
    return record


def iter_wazuh_alerts(source):
    """Yield (starting line, full raw text, fields) from a path or bounded lines.

    JSON is decoded one object at a time so a malformed entry does not split
    other valid objects into individual lines. Text headers delimit alerts even
    when no blank separator is present.
    """
    if isinstance(source, (str, Path)):
        text = Path(source).read_bytes().decode("utf-8-sig", errors="replace")
    else:
        lines = list(source)
        if lines and isinstance(lines[0], bytes):
            text = b"".join(lines).decode("utf-8-sig", errors="replace")
        else:
            text = "".join(lines).lstrip("\ufeff")
    decoder = json.JSONDecoder()
    offset, lineno = 0, 1
    while offset < len(text):
        start = offset
        while offset < len(text) and text[offset].isspace():
            offset += 1
        lineno += text.count("\n", start, offset)
        if offset == len(text):
            break
        start, first_line = offset, lineno
        if text[offset] == "{":
            try:
                record, end = decoder.raw_decode(text, offset)
            except (ValueError, RecursionError):
                pass
            else:
                raw = text[offset:end]
                yield first_line, raw, record
                lineno += raw.count("\n")
                offset = end
                continue
        # Collect continuations up to the next header, JSON object or blank line.
        end = text.find("\n", offset)
        end = len(text) if end < 0 else end + 1
        while end < len(text):
            next_end = text.find("\n", end)
            next_end = len(text) if next_end < 0 else next_end + 1
            line = text[end:next_end]
            if not line.strip() or HEADER.match(line) or line.lstrip().startswith("{"):
                break
            end = next_end
        raw = text[start:end].rstrip("\r\n")
        yield first_line, raw, parse_text_alert(raw)
        lineno += text.count("\n", start, end)
        offset = end
