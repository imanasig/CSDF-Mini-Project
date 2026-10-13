"""Detection boundaries, sequence policies, evidence, and sample integration."""

import copy
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cybertrail.detector import (analyze_security_events, detect_repeated_failed_logins,
                                 detect_sensitive_file_access, detect_suspicious_successful_logins)
from cybertrail.parser import parse_logs

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((Path(__file__).with_name("expected_results.json")).read_text())
BASE = datetime(2026, 10, 13, 10, tzinfo=timezone.utc)


def event(number, seconds, kind="LOGIN_FAILED", **changes):
    row = dict(event_id=f"E{number:03d}", timestamp=BASE + timedelta(seconds=seconds),
               event_type=kind, username="demo_admin", source_ip="203.0.113.50",
               session_id="SES-A" if kind != "LOGIN_FAILED" else None,
               resource="confidential.pdf" if kind == "FILE_ACCESSED" else None,
               status=None, details=None, source_row=number + 1,
               session_correlation_eligible=kind != "LOGIN_FAILED")
    row.update(changes)
    return row


def failures(times=(0, 20, 40, 60, 80)):
    return [event(i, seconds) for i, seconds in enumerate(times, 1)]


def sequence():
    return failures() + [event(6, 110, "LOGIN_SUCCESS"), event(7, 170, "FILE_ACCESSED")]


def rules(findings):
    return Counter(row["rule_id"] for row in findings)


@pytest.mark.parametrize("name", MANIFEST)
def test_dataset_manifest_integration(name):
    parsed = parse_logs((ROOT / "data/samples" / name).read_bytes(), name)
    assert not parsed.file_errors
    findings = analyze_security_events(parsed.valid_records)
    assert set(rules(findings)) == set(MANIFEST[name]["rules"])
    valid_ids = {row["event_id"] for row in parsed.valid_records}
    assert all(set(finding["supporting_event_ids"]) <= valid_ids for finding in findings)
    if name == "mixed_activity.csv":
        assert rules(findings) == {"R1": 3, "R2": 2, "R3": 1}
    elif not MANIFEST[name].get("invalid"):
        assert all(count == 1 for count in rules(findings).values())


@pytest.mark.parametrize("times,expected", [
    ([0, 30, 60, 90], 0), ([0, 30, 60, 90, 120], 1),
    ([0, 30, 60, 90, 121], 0), ([0, 0, 0, 0, 0], 1),
    (list(range(0, 200, 20)), 1),
    ([0, 20, 40, 60, 80, 300, 320, 340, 360, 380], 2),
])
def test_r1_windows_and_sequence_separation(times, expected):
    rows = failures(times)
    findings = detect_repeated_failed_logins(rows)
    assert len(findings) == expected
    assert findings == detect_repeated_failed_logins(list(reversed(rows)))
    if len(times) == 10 and expected == 1:
        assert findings[0]["supporting_event_ids"] == [row["event_id"] for row in rows]
        assert (findings[0]["end_time"] - findings[0]["start_time"]).total_seconds() == 180


@pytest.mark.parametrize("field,value", [("username", "demo_other"), ("source_ip", "198.51.100.12")])
def test_account_and_ip_separation(field, value):
    rows = failures([0, 20, 40, 60, 80, 100])
    for row in rows[3:]:
        row[field] = value
    assert not analyze_security_events(rows)


@pytest.mark.parametrize("time,expected", [(80, 0), (79, 0), (81, 1), (200, 1), (201, 0)])
def test_r2_strict_start_inclusive_end(time, expected):
    rows = failures() + [event(6, time, "LOGIN_SUCCESS")]
    assert len(detect_suspicious_successful_logins(rows)) == expected


@pytest.mark.parametrize("field,value", [("username", "demo_other"), ("source_ip", "198.51.100.12")])
def test_r2_requires_same_account_ip(field, value):
    rows = failures() + [event(6, 110, "LOGIN_SUCCESS", **{field: value})]
    assert rules(analyze_security_events(rows)) == {"R1": 1}


def test_success_without_qualifying_failures():
    assert not analyze_security_events([event(1, 110, "LOGIN_SUCCESS")])
    assert not detect_suspicious_successful_logins(failures([0, 20, 40, 60]) + [event(6, 110, "LOGIN_SUCCESS")])


def test_r2_consumes_sequence_once_and_excludes_future_failures():
    rows = failures(list(range(0, 200, 20))) + [event(11, 90, "LOGIN_SUCCESS"), event(12, 200, "LOGIN_SUCCESS")]
    findings = analyze_security_events(rows)
    assert rules(findings) == {"R1": 1, "R2": 1}
    r2 = next(row for row in findings if row["rule_id"] == "R2")
    assert r2["supporting_event_ids"] == [f"E{i:03d}" for i in range(1, 6)] + ["E011"]
    assert r2["login_event_id"] == "E011"


def test_nonqualifying_trailing_failure_does_not_extend_r2_window():
    rows = failures() + [event(6, 150), event(7, 260, "LOGIN_SUCCESS")]
    assert rules(analyze_security_events(rows)) == {"R1": 1}


def test_multiple_separate_sequences_each_allow_one_success():
    rows = failures()
    rows += [event(6, 110, "LOGIN_SUCCESS"), event(7, 120, "LOGIN_SUCCESS")]
    rows += [event(i + 8, 400 + i * 20) for i in range(5)]
    rows += [event(13, 510, "LOGIN_SUCCESS"), event(14, 520, "LOGIN_SUCCESS")]
    findings = analyze_security_events(rows)
    assert rules(findings) == {"R1": 2, "R2": 2}
    assert [row["login_event_id"] for row in findings if row["rule_id"] == "R2"] == ["E006", "E013"]


@pytest.mark.parametrize("changes,expected", [
    ({}, 1), ({"timestamp": BASE + timedelta(seconds=410)}, 1),
    ({"timestamp": BASE + timedelta(seconds=411)}, 0),
    ({"timestamp": BASE + timedelta(seconds=110)}, 0),
    ({"timestamp": BASE + timedelta(seconds=109)}, 0),
    ({"session_id": "OTHER"}, 0), ({"session_id": None}, 0),
    ({"resource": "notes.txt"}, 0), ({"resource": "Confidential.pdf"}, 0),
    ({"resource": "folder/confidential.pdf"}, 0),
    ({"username": "demo_other"}, 0), ({"source_ip": "198.51.100.11"}, 0),
    ({"event_type": "FILE_MODIFIED"}, 0),
])
def test_r3_boundaries_and_identity_policy(changes, expected):
    rows = sequence()
    rows[-1].update(changes)
    assert len(detect_sensitive_file_access(rows)) == expected


def test_r3_requires_r2_login_and_login_session():
    assert not analyze_security_events([event(1, 110, "LOGIN_SUCCESS"), event(2, 170, "FILE_ACCESSED")])
    rows = sequence()
    rows[-2]["session_id"] = None
    assert rules(analyze_security_events(rows)) == {"R1": 1, "R2": 1}


def test_configurable_exact_sensitive_policy():
    rows = sequence()
    rows[-1]["resource"] = "/synthetic/private.txt"
    assert rules(analyze_security_events(rows)) == {"R1": 1, "R2": 1}
    assert rules(analyze_security_events(rows, sensitive_resources={"/synthetic/private.txt"})) == {"R1": 1, "R2": 1, "R3": 1}
    rows[-1]["resource"] = "confidential.pdf"
    assert rules(analyze_security_events(rows, sensitive_resources=set())) == {"R1": 1, "R2": 1}


def test_each_distinct_sensitive_access_has_one_finding():
    rows = sequence() + [event(8, 180, "FILE_ACCESSED")]
    findings = analyze_security_events(rows)
    assert rules(findings) == {"R1": 1, "R2": 1, "R3": 2}
    assert {row["file_event_id"] for row in findings if row["rule_id"] == "R3"} == {"E007", "E008"}


def test_r3_selects_most_recent_r2_login_when_session_is_reused():
    rows = failures() + [event(6, 110, "LOGIN_SUCCESS")]
    rows += [event(i + 7, 400 + 20 * i) for i in range(5)]
    rows += [event(12, 510, "LOGIN_SUCCESS"), event(13, 550, "FILE_ACCESSED")]
    r3 = detect_sensitive_file_access(rows)
    assert len(r3) == 1 and r3[0]["login_event_id"] == "E012"
    assert "E001" not in r3[0]["supporting_event_ids"]


def test_determinism_evidence_severity_and_nonmutation():
    rows = sequence()
    before = copy.deepcopy(rows)
    findings = analyze_security_events(rows)
    shuffled = rows.copy()
    random.Random(42).shuffle(shuffled)
    assert findings == analyze_security_events(shuffled) == analyze_security_events(rows)
    assert rows == before
    assert len({row["finding_id"] for row in findings}) == 3
    by_rule = {row["rule_id"]: row for row in findings}
    for rule, count in [("R1", 5), ("R2", 6), ("R3", 7)]:
        finding = by_rule[rule]
        assert finding["supporting_event_ids"] == [f"E{i:03d}" for i in range(1, count + 1)]
        assert finding["severity"] == ("Medium" if rule == "R1" else "High")
        assert finding["explanation"] and finding["rule_name"]
        assert finding["username"] == "demo_admin" and finding["source_ip"] == "203.0.113.50"
        assert finding["start_time"] == BASE and finding["end_time"] == rows[count - 1]["timestamp"]
    assert by_rule["R2"]["related_finding_ids"] == [by_rule["R1"]["finding_id"]]
    assert by_rule["R3"]["related_finding_ids"] == [by_rule["R1"]["finding_id"], by_rule["R2"]["finding_id"]]


def test_equal_timestamp_tiebreakers_do_not_allow_simultaneous_success_or_access():
    rows = failures([0] * 5) + [event(6, 0, "LOGIN_SUCCESS"), event(7, 1, "LOGIN_SUCCESS"),
                               event(8, 1, "FILE_ACCESSED"), event(9, 2, "FILE_ACCESSED")]
    findings = analyze_security_events(rows)
    assert findings == analyze_security_events(list(reversed(rows)))
    assert rules(findings) == {"R1": 1, "R2": 1, "R3": 1}
    assert next(row for row in findings if row["rule_id"] == "R3")["file_event_id"] == "E009"


def test_empty_and_malformed_input_contract():
    assert not analyze_security_events([])
    for rows in [[{}], [event(1, 0, timestamp="invalid")], [event(1, 0), event(1, 20)],
                 [event(1, 0, timestamp=datetime(2026, 10, 13))]]:
        with pytest.raises(ValueError):
            analyze_security_events(rows)


def test_invalid_parser_records_excluded():
    raw = json.loads((ROOT / "data/samples/sample_events.json").read_text())
    raw[0]["source_ip"] = "bad-ip"
    parsed = parse_logs(json.dumps(raw).encode(), "logs.json")
    assert len(parsed.invalid_records) == 1
    assert not analyze_security_events(parsed.valid_records)  # Four remaining failures cannot qualify.


def test_large_overlapping_sequence():
    rows = failures(range(5000))
    findings = analyze_security_events(rows)
    assert rules(findings) == {"R1": 1}
    assert len(findings[0]["supporting_event_ids"]) == 5000
