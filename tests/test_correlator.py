import copy
from pathlib import Path

import pytest

from cybertrail.correlator import correlate_findings
from cybertrail.detector import analyze_security_events
from cybertrail.parser import parse_logs

SAMPLES = Path(__file__).resolve().parents[1] / "data/samples"


def analyzed(name="file_access_incident.csv"):
    events = parse_logs((SAMPLES / name).read_bytes(), name).valid_records
    return events, analyze_security_events(events)


@pytest.mark.parametrize("name,count,priorities", [
    ("normal_activity.csv", 0, []), ("brute_force.csv", 1, ["Medium"]),
    ("suspicious_login.csv", 1, ["High"]), ("file_access_incident.csv", 1, ["High"]),
    ("mixed_activity.csv", 3, ["Medium", "High", "High"]),
])
def test_sample_cases(name, count, priorities):
    events, findings = analyzed(name)
    before = copy.deepcopy((events, findings))
    cases = correlate_findings(findings, events)
    assert len(cases) == count
    assert [row["priority"] for row in cases] == priorities
    assert cases == correlate_findings(list(reversed(findings)), list(reversed(events)))
    assert (events, findings) == before
    assert findings == analyze_security_events(events)
    for case in cases:
        assert len(set(case["related_event_ids"])) == len(case["timeline"])
        assert case["timeline"] == sorted(case["timeline"], key=lambda row: (row["timestamp"], row["event_id"]))
        assert set(case["related_finding_ids"]) <= {row["finding_id"] for row in findings}
        assert all(row["included_by_finding_ids"] for row in case["timeline"])


def test_evidence_and_lineage():
    events, findings = analyzed()
    # Repeated IDs inside supporting lists do not duplicate timeline events.
    findings[0]["supporting_event_ids"].append(findings[0]["supporting_event_ids"][0])
    case = correlate_findings(findings, events)[0]
    assert case["related_event_ids"] == [f"EVT-{i:03d}" for i in range(1, 8)]
    assert len(case["related_finding_ids"]) == 3
    assert len(case["timeline"][0]["included_by_finding_ids"]) == 3


def test_unrelated_same_account_ip_remain_separate():
    events, findings = analyzed("brute_force.csv")
    more = [{**row, "event_id": "OTHER-" + row["event_id"]} for row in events]
    other = copy.deepcopy(findings[0])
    other.update(finding_id="OTHER-FINDING", supporting_event_ids=[row["event_id"] for row in more])
    assert len(correlate_findings(findings + [other], events + more)) == 2
    other["username"] = "demo_other"
    assert len(correlate_findings(findings + [other], events + more)) == 2


def test_missing_events_parents_and_invalid_session_are_explicit_errors():
    events, findings = analyzed()
    with pytest.raises(ValueError, match="missing"):
        correlate_findings(findings, events[:-1])
    broken = copy.deepcopy(findings)
    broken[1]["related_finding_ids"] = ["DOES-NOT-EXIST"]
    with pytest.raises(ValueError, match="reference"):
        correlate_findings(broken, events)
    broken = copy.deepcopy(events)
    broken[-1]["session_id"] = "OTHER"
    with pytest.raises(ValueError, match="session"):
        correlate_findings(findings, broken)


def test_shared_evidence_without_parent_refs_still_connects():
    events, findings = analyzed()
    for finding in findings:
        finding["related_finding_ids"] = []
    assert len(correlate_findings(findings, events)) == 1


def test_empty():
    assert correlate_findings([], []) == []
