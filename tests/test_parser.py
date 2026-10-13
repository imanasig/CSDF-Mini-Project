"""Parser correctness, rejection behavior, and import integrity tests."""

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cybertrail.parser import FIELDS, MAX_FILE_BYTES, export_events_csv, filter_events, parse_logs

SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"


def example():
    return json.loads((SAMPLES / "sample_events.json").read_text())[0]


def as_json(rows):
    return json.dumps(rows).encode()


def as_csv(rows, fields=FIELDS):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


@pytest.mark.parametrize("name", sorted(path.name for path in SAMPLES.iterdir() if path.suffix in {".csv", ".json"}))
def test_all_sample_datasets(name):
    result = parse_logs((SAMPLES / name).read_bytes(), name)
    assert not result.file_errors
    assert result.total_records == len(result.valid_records) + len(result.invalid_records)
    if name == "invalid_logs.csv":
        assert len(result.valid_records) == 1  # Empty status is optional in Stage 3.
        assert len(result.invalid_records) == 5
        assert result.valid_records[0]["status"] is None
        assert result.invalid_records[0]["source_row"] == 2
        assert result.invalid_records[0]["original_values"]["timestamp"] == "not-a-timestamp"
    elif name == "edge_duplicate_ids.csv":
        assert not result.valid_records
        assert len(result.invalid_records) == 2
        assert all("Duplicate event_id" in " ".join(row["errors"]) for row in result.invalid_records)
    else:
        assert not result.invalid_records
        assert result.valid_records
        assert all(row["timestamp"].tzinfo == timezone.utc for row in result.valid_records)


def test_equivalent_formats_preserve_ids_rows_and_hash():
    csv_bytes = (SAMPLES / "file_access_incident.csv").read_bytes()
    json_bytes = (SAMPLES / "sample_events.json").read_bytes()
    left, right = parse_logs(csv_bytes, "events.csv"), parse_logs(json_bytes, "events.json")
    assert [{key: value for key, value in row.items() if key != "source_row"} for row in left.valid_records] == [
        {key: value for key, value in row.items() if key != "source_row"} for row in right.valid_records]
    assert [row["event_id"] for row in left.valid_records] == [f"EVT-{i:03d}" for i in range(1, 8)]
    assert [row["source_row"] for row in left.valid_records] == list(range(2, 9))
    assert [row["source_row"] for row in right.valid_records] == list(range(1, 8))
    assert left.sha256 == hashlib.sha256(csv_bytes).hexdigest()
    assert left.original_bytes is csv_bytes
    filtered = filter_events(left.valid_records, event_types=["FILE_ACCESSED"])
    assert len(filtered) == 1
    exported = export_events_csv(left.valid_records)
    assert export_events_csv(filtered) != csv_bytes
    assert left.original_bytes == csv_bytes
    assert left.sha256 == hashlib.sha256(csv_bytes).hexdigest()
    assert not parse_logs(exported, "export.csv").invalid_records
    assert parse_logs(exported, "export.csv").valid_records == left.valid_records


@pytest.mark.parametrize("field,value,reason", [
    ("timestamp", "2026-02-30T10:00:00Z", "timestamp"),
    ("timestamp", "2026-10-13T10:00:00", "timestamp"),
    ("timestamp", "2026-10-13 10:00:00Z", "timestamp"),
    ("timestamp", "2026-10-13T10:00:00+05:99", "timestamp"),
    ("source_ip", "999.0.0.1", "source_ip"),
    ("source_ip", "fe80::1%en0", "source_ip"),
    ("event_type", "LOGIN-SUCCESS", "Unsupported"),
    ("username", " ", "username"),
    ("event_id", None, "event_id"),
    ("details", ["unstructured"], "details"),
])
def test_invalid_values_retain_originals(field, value, reason):
    row = example()
    row[field] = value
    result = parse_logs(as_json([row]), "logs.json")
    assert not result.valid_records
    assert result.invalid_records[0]["original_values"] == row
    assert reason in " ".join(result.invalid_records[0]["errors"])


@pytest.mark.parametrize("field", FIELDS)
def test_missing_schema_fields(field):
    row = example()
    del row[field]
    result = parse_logs(as_json([row]), "logs.json")
    assert "Missing schema fields" in " ".join(result.invalid_records[0]["errors"])
    result = parse_logs(as_csv([row], [key for key in FIELDS if key != field]), "logs.csv")
    assert "Missing CSV columns" in result.file_errors[0]


@pytest.mark.parametrize("field", FIELDS[:5])
def test_empty_mandatory_fields(field):
    row = example()
    row[field] = ""
    assert parse_logs(as_json([row]), "logs.json").invalid_records


@pytest.mark.parametrize("data,name", [
    (b"", "empty.csv"), (b"{bad json", "logs.json"),
    (b'{"events": {}}', "logs.json"), (b"[]", "logs.txt"),
    (b"\xff\xfe", "logs.csv"),
    (b'{"events": [], "events": []}', "logs.json"),
    (b"[" * 2000, "logs.json"),
    (b'event_id,event_id\n1,2', "logs.csv"),
    ((",".join(FIELDS) + '\n"unterminated').encode(), "logs.csv"),
])
def test_file_errors(data, name):
    result = parse_logs(data, name)
    assert result.file_errors
    assert not result.valid_records
    assert result.sha256 == hashlib.sha256(data).hexdigest()


def test_size_limit():
    data = b" " * (MAX_FILE_BYTES + 1)
    result = parse_logs(data, "large.json")
    assert "10 MiB" in result.file_errors[0]
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    # Exactly the limit is allowed; whitespace around an empty JSON array is valid.
    result = parse_logs(b"[]" + b" " * (MAX_FILE_BYTES - 2), "limit.json")
    assert not result.file_errors


def test_normalization_and_optional_sessions():
    row = example()
    row.update(timestamp="2026-10-13T15:30:00+05:30", event_type=" file_accessed ",
               source_ip="2001:0db8:0000::1", resource="notes.txt", session_id="", status=None, details="")
    result = parse_logs(as_json({"events": [row]}), "logs.JSON")
    assert not result.file_errors and not result.invalid_records
    event = result.valid_records[0]
    assert event["timestamp"] == datetime(2026, 10, 13, 10, tzinfo=timezone.utc)
    assert event["event_type"] == "FILE_ACCESSED"
    assert event["source_ip"] == "2001:db8::1"
    assert event["session_id"] is None
    assert not event["session_correlation_eligible"]
    assert event["status"] is None and event["details"] is None
    row["resource"] = ""
    assert "resource" in " ".join(parse_logs(as_json([row]), "logs.json").invalid_records[0]["errors"])


def test_duplicate_ids_all_rejected_even_when_one_is_otherwise_invalid():
    row, bad = example(), example()
    bad.update(event_id=" EVT-001 ", source_ip="bad")
    result = parse_logs(as_json([row, bad]), "logs.json")
    assert len(result.invalid_records) == 2 and not result.valid_records


def test_mixed_json_nonobjects_and_valid_records():
    result = parse_logs(as_json([None, example(), 12]), "logs.json")
    assert result.total_records == 3
    assert len(result.valid_records) == 1 and len(result.invalid_records) == 2
    assert result.valid_records[0]["source_row"] == 2


def test_csv_row_lengths_and_multiline_source_locations():
    row = example()
    row["details"] = "two\nlines"
    data = as_csv([row]) + b"too,few\n"
    result = parse_logs(data, "logs.csv")
    assert result.valid_records[0]["source_row"] == 2
    assert result.invalid_records[0]["source_row"] == 4
    assert result.invalid_records[0]["original_values"]["values"] == ["too", "few"]


def test_out_of_order_and_filtering():
    result = parse_logs((SAMPLES / "edge_out_of_order.csv").read_bytes(), "logs.csv")
    assert [row["event_id"] for row in result.valid_records] == [f"EVT-{i:03d}" for i in range(1, 8)]
    assert result.valid_records[0]["source_row"] == 5
    assert len(filter_events(result.valid_records, usernames=["demo_admin"],
                             source_ips=["203.0.113.50"], event_types=["LOGIN_FAILED"])) == 5
    assert not filter_events(result.valid_records, usernames=["missing"])


def test_empty_structured_inputs_and_bom():
    assert parse_logs(as_csv([]), "empty.csv").total_records == 0
    assert not parse_logs(b"[]", "empty.json").file_errors
    assert len(parse_logs(b"\xef\xbb\xbf" + as_csv([example()]), "bom.csv").valid_records) == 1


def test_five_thousand_records():
    rows = []
    for i in range(5000):
        row = example()
        row["event_id"] = f"LOAD-{i}"
        rows.append(row)
    result = parse_logs(as_json(rows), "load.json")
    assert len(result.valid_records) == 5000
    assert not result.file_errors and not result.invalid_records
