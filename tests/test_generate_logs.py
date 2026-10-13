"""Validate synthetic fixtures, without implementing the application detector."""

import csv
import importlib.util
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "data" / "samples"
MANIFEST = json.loads((Path(__file__).with_name("expected_results.json")).read_text())
FIELDS = ["event_id", "timestamp", "event_type", "username", "source_ip",
          "session_id", "resource", "status", "details"]
TYPES = {"LOGIN_FAILED", "LOGIN_SUCCESS", "FILE_ACCESSED", "LOGOUT", "FILE_MODIFIED", "ACCESS_DENIED"}


def read_rows(name, directory=SAMPLES):
    path = directory / name
    if path.suffix == ".json":
        return json.loads(path.read_text())
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames == FIELDS
        return list(reader)


def timestamp(row):
    return datetime.strptime(row["timestamp"], "%Y-%m-%dT%H:%M:%SZ")


def generator():
    spec = importlib.util.spec_from_file_location("generate_logs", ROOT / "scripts" / "generate_logs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", MANIFEST)
def test_dataset_structure(name):
    rows = read_rows(name)
    assert len(rows) == MANIFEST[name]["records"]
    assert all(list(row) == FIELDS for row in rows)
    if MANIFEST[name].get("invalid"):
        return
    assert len({row["event_id"] for row in rows}) == len(rows)
    sessions = {row["session_id"]: row for row in rows if row["event_type"] == "LOGIN_SUCCESS"}
    for row in rows:
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", row["timestamp"])
        timestamp(row)
        assert row["event_type"] in TYPES
        assert row["username"].startswith("demo_")
        ip = ipaddress.ip_address(row["source_ip"])
        assert any(ip in ipaddress.ip_network(network) for network in
                   ["192.168.0.0/16", "198.51.100.0/24", "203.0.113.0/24"])
        assert all(row[field] for field in ["event_id", "timestamp", "event_type", "username", "source_ip", "status", "details"])
        assert row["status"] == {"LOGIN_FAILED": "FAILURE", "ACCESS_DENIED": "DENIED"}.get(row["event_type"], "SUCCESS")
        if row["event_type"] == "LOGIN_FAILED":
            assert row["session_id"] == ""
        else:
            assert row["session_id"]
        if row["event_type"] in {"FILE_ACCESSED", "FILE_MODIFIED", "ACCESS_DENIED"}:
            assert row["resource"]
        if row["event_type"] not in {"LOGIN_FAILED", "LOGIN_SUCCESS"}:
            login = sessions[row["session_id"]]
            assert (login["username"], login["source_ip"]) == (row["username"], row["source_ip"])
            assert timestamp(login) <= timestamp(row)


def test_generation_reproducible_and_preserves_unrelated_files(tmp_path):
    unrelated = tmp_path / "personal_notes.txt"
    unrelated.write_bytes(b"Leave this alone")
    names = generator().generate(tmp_path)
    assert set(names) == set(MANIFEST)
    first = {name: (tmp_path / name).read_bytes() for name in names}
    generator().generate(tmp_path)
    assert first == {name: (tmp_path / name).read_bytes() for name in names}
    assert first == {name: (SAMPLES / name).read_bytes() for name in names}
    assert unrelated.read_bytes() == b"Leave this alone"


@pytest.mark.parametrize("name", [name for name, expected in MANIFEST.items() if expected["sequence"] or expected.get("groups")])
def test_intended_sequences(name):
    rows = {row["event_id"]: row for row in read_rows(name)}
    expected = MANIFEST[name]
    groups = expected.get("groups", [expected["sequence"]])
    for numbers in groups:
        sequence = [rows[f"EVT-{number:03d}"] for number in numbers]
        failures = sequence[:5]
        assert all(row["event_type"] == "LOGIN_FAILED" for row in failures)
        assert len({(row["username"], row["source_ip"]) for row in sequence}) == 1
        assert 0 <= (timestamp(failures[-1]) - timestamp(failures[0])).total_seconds() <= 120
        if len(sequence) >= 6:
            success = sequence[5]
            assert success["event_type"] == "LOGIN_SUCCESS"
            assert 0 <= (timestamp(success) - timestamp(failures[-1])).total_seconds() <= 120
        if len(sequence) == 7:
            access = sequence[6]
            assert access["event_type"] == "FILE_ACCESSED"
            assert access["resource"] == "confidential.pdf"
            assert access["session_id"] == success["session_id"] != ""
            assert 0 <= (timestamp(access) - timestamp(success)).total_seconds() <= 300


def test_negative_and_boundary_fixtures():
    normal = read_rows("normal_activity.csv")
    assert max(Counter((row["username"], row["source_ip"]) for row in normal if row["event_type"] == "LOGIN_FAILED").values()) == 1
    assert all(row["resource"] != "confidential.pdf" for row in normal)
    assert len(read_rows("edge_four_failures.csv")) == 4
    boundary = read_rows("edge_five_boundary.csv")
    outside = read_rows("edge_outside_window.csv")
    assert (timestamp(boundary[-1]) - timestamp(boundary[0])).total_seconds() == 120
    assert (timestamp(outside[-1]) - timestamp(outside[0])).total_seconds() == 121
    for name in ["edge_multiple_ips.csv", "edge_multiple_users.csv"]:
        rows = read_rows(name)
        assert sorted(Counter((row["username"], row["source_ip"]) for row in rows).values()) == [3, 3]
    unordered = read_rows("edge_out_of_order.csv")
    assert unordered != sorted(unordered, key=lambda row: row["timestamp"])
    assert sorted(unordered, key=lambda row: row["timestamp"]) == read_rows("file_access_incident.csv")
    assert [row["event_type"] for row in read_rows("edge_success_only.csv")] == ["LOGIN_SUCCESS"]
    mismatch = read_rows("edge_session_mismatch.csv")
    qualifying_login = next(row for row in mismatch if row["event_id"] == "EVT-006")
    assert mismatch[-1]["session_id"] != qualifying_login["session_id"]
    other_login = mismatch[0]
    assert timestamp(other_login) < timestamp(mismatch[1])
    assert read_rows("sample_events.json") == read_rows("file_access_incident.csv")
    assert {row["event_type"] for row in read_rows("brute_force.csv")} == {"LOGIN_FAILED"}
    assert not any(row["event_type"] == "FILE_ACCESSED" for row in read_rows("suspicious_login.csv"))


def test_intentionally_invalid_records():
    rows = read_rows("invalid_logs.csv")
    with pytest.raises(ValueError):
        timestamp(rows[0])
    assert rows[1]["username"] == ""
    with pytest.raises(ValueError):
        ipaddress.ip_address(rows[2]["source_ip"])
    assert rows[3]["event_type"] not in TYPES
    assert rows[4]["event_id"] == ""
    assert rows[5]["status"] == ""
    duplicate = read_rows("edge_duplicate_ids.csv")
    assert duplicate[0]["event_id"] == duplicate[1]["event_id"]
    assert duplicate[0]["timestamp"] != duplicate[1]["timestamp"]
