"""Structured log import, validation, and normalization; independent of Streamlit."""

import csv
import hashlib
import io
import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ("event_id", "timestamp", "event_type", "username", "source_ip",
          "session_id", "resource", "status", "details")
MANDATORY = FIELDS[:5]
EVENT_TYPES = {"LOGIN_FAILED", "LOGIN_SUCCESS", "FILE_ACCESSED", "LOGOUT",
               "FILE_MODIFIED", "ACCESS_DENIED"}
MAX_FILE_BYTES = 10 * 1024 * 1024
ISO_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:0\d|1\d|2[0-3]):[0-5]\d)\Z")


@dataclass
class ImportResult:
    filename: str
    size_bytes: int
    sha256: str
    original_bytes: bytes
    total_records: int = 0
    valid_records: list[dict] = field(default_factory=list)
    invalid_records: list[dict] = field(default_factory=list)
    file_errors: list[str] = field(default_factory=list)


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_csv(text):
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    header = next(reader, None)
    if header is None:
        raise ValueError("CSV is empty; a header with the standard columns is required.")
    if len(set(header)) != len(header):
        raise ValueError("CSV contains duplicate column names.")
    missing = set(FIELDS) - set(header)
    if missing:
        raise ValueError("Missing CSV columns: " + ", ".join(sorted(missing)))
    rows = []
    # CSV source_row is the physical starting line, including the header.
    while True:
        source_row = reader.line_num + 1
        values = next(reader, None)
        if values is None:
            break
        if len(values) != len(header):
            rows.append((source_row, {"columns": header.copy(), "values": values},
                         [f"Expected {len(header)} CSV values, found {len(values)}."]))
        else:
            rows.append((source_row, dict(zip(header, values)), []))
    return rows


def _read_json(text):
    parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    if isinstance(parsed, dict):
        parsed = parsed.get("events")
    if not isinstance(parsed, list):
        raise ValueError("JSON must be an array of event objects or an object containing an events array.")
    # JSON source_row is a 1-based array position, not a physical text line.
    return [(index, row, []) for index, row in enumerate(parsed, 1)]


def _validate_row(original):
    errors = []
    if not isinstance(original, dict):
        return {}, ["Each JSON event must be an object."]
    missing = set(FIELDS) - set(original)
    if missing:
        errors.append("Missing schema fields: " + ", ".join(sorted(missing)))
    values = {}
    for name in FIELDS:
        value = original.get(name)
        if value is not None and not isinstance(value, str):
            errors.append(f"{name} must be a string or null.")
            value = None
        value = value.strip() if isinstance(value, str) else None
        values[name] = value or None
        if name in MANDATORY and not values[name]:
            errors.append(f"{name} must not be empty.")

    kind = values["event_type"]
    if kind:
        values["event_type"] = kind.upper()
        if values["event_type"] not in EVENT_TYPES:
            errors.append(f"Unsupported event_type: {kind}")
    time = values["timestamp"]
    if time:
        try:
            if not ISO_TIMESTAMP.fullmatch(time):
                raise ValueError
            parsed = datetime.fromisoformat(time.replace("Z", "+00:00"))
            values["timestamp"] = parsed.astimezone(timezone.utc)
        except ValueError:
            errors.append("timestamp must be a valid ISO 8601 datetime with Z or an explicit timezone offset.")
    ip = values["source_ip"]
    if ip:
        try:
            if "%" in ip:
                raise ValueError
            values["source_ip"] = str(ipaddress.ip_address(ip))
        except ValueError:
            errors.append("source_ip must be a valid IPv4 or IPv6 address without a zone identifier.")
    if values["event_type"] in {"FILE_ACCESSED", "FILE_MODIFIED", "ACCESS_DENIED"} and not values["resource"]:
        errors.append("resource is required for file activity and ACCESS_DENIED.")
    # Missing sessions are retained, but cannot support session-based correlation.
    values["session_correlation_eligible"] = bool(values["session_id"]) and values["event_type"] != "LOGIN_FAILED"
    return values, errors


def parse_logs(original_bytes: bytes, filename: str) -> ImportResult:
    """Hash exact bytes first, then validate a CSV/JSON import without modifying it."""
    result = ImportResult(filename, len(original_bytes), hashlib.sha256(original_bytes).hexdigest(), original_bytes)
    if len(original_bytes) > MAX_FILE_BYTES:
        result.file_errors.append("File exceeds the 10 MiB limit (10,485,760 bytes).")
        return result
    extension = Path(filename).suffix.lower()
    if extension not in {".csv", ".json"}:
        result.file_errors.append("Unsupported file format; choose .csv or .json.")
        return result
    try:
        text = original_bytes.decode("utf-8-sig")
        rows = _read_csv(text) if extension == ".csv" else _read_json(text)
    except (UnicodeDecodeError, csv.Error, ValueError, RecursionError) as error:
        result.file_errors.append(f"Cannot read {extension[1:].upper()} file: {error}")
        return result
    result.total_records = len(rows)
    # Reject every occurrence of a duplicate, so no ambiguous ID reaches detection.
    ids = Counter(row.get("event_id", "").strip() for _, row, _ in rows
                  if isinstance(row, dict) and isinstance(row.get("event_id"), str) and row["event_id"].strip())
    for source_row, original, structure_errors in rows:
        values, errors = _validate_row(original)
        errors = structure_errors + errors
        if values.get("event_id") and ids[values["event_id"]] > 1:
            errors.append(f"Duplicate event_id: {values['event_id']} (all occurrences rejected).")
        if errors:
            result.invalid_records.append({"source_row": source_row, "original_values": original, "errors": errors})
        else:
            values["source_row"] = source_row
            result.valid_records.append(values)
    result.valid_records.sort(key=lambda event: event["timestamp"])
    return result


def filter_events(events, *, usernames=(), source_ips=(), event_types=()):
    """Return matching events; empty selections mean all values."""
    users, ips, kinds = set(usernames), set(source_ips), set(event_types)
    return [event for event in events
            if (not users or event["username"] in users)
            and (not ips or event["source_ip"] in ips)
            and (not kinds or event["event_type"] in kinds)]


def export_events_csv(events):
    """Export the nine normalized schema columns; original evidence stays unchanged."""
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FIELDS, lineterminator="\n")
    writer.writeheader()
    for event in events:
        row = {name: event[name] if event[name] is not None else "" for name in FIELDS}
        row["timestamp"] = event["timestamp"].astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        writer.writerow(row)
    return output.getvalue().encode("utf-8")
