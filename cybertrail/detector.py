"""Deterministic, explainable rules over parser-validated events."""

import hashlib
import json
from bisect import bisect_left
from collections import defaultdict
from datetime import datetime, timedelta

from cybertrail.parser import EVENT_TYPES, FIELDS

SENSITIVE_RESOURCES = frozenset({"confidential.pdf", "employee_records.csv", "financial_report.xlsx"})
FAILURE_WINDOW = timedelta(seconds=120)
FILE_WINDOW = timedelta(seconds=300)
RULE_NAMES = {
    "R1": "Repeated Failed Login Attempts",
    "R2": "Successful Login After Failures",
    "R3": "Sensitive File Access Following Suspicious Login",
}


def _ordered(events):
    """Check the normalized-input contract; never silently discard input."""
    rows = list(events)
    ids = set()
    for row in rows:
        if not isinstance(row, dict) or any(name not in row for name in FIELDS):
            raise ValueError("Detection requires normalized valid records from parse_logs().")
        time = row["timestamp"]
        if (not isinstance(time, datetime) or time.utcoffset() != timedelta(0)
                or not isinstance(row["event_type"], str) or row["event_type"] not in EVENT_TYPES
                or any(row[name] is not None and not isinstance(row[name], str) for name in FIELDS[5:])
                or any(not isinstance(row[name], str) or not row[name] for name in ("event_id", "username", "source_ip"))
                or row["event_id"] in ids):
            raise ValueError("Detection requires unique IDs and valid UTC-normalized events.")
        ids.add(row["event_id"])
    return sorted(rows, key=lambda row: (row["timestamp"], row["event_id"]))


def _finding(rule, evidence, explanation, *, session_id=None, parents=()):
    evidence = sorted(evidence, key=lambda row: (row["timestamp"], row["event_id"]))
    ids = [row["event_id"] for row in evidence]
    identity = json.dumps([rule, evidence[0]["username"], evidence[0]["source_ip"],
                           session_id, [(row["event_id"], row["timestamp"].isoformat()) for row in evidence]],
                          separators=(",", ":"), ensure_ascii=False)
    return {
        "finding_id": f"{rule}-{hashlib.sha256(identity.encode()).hexdigest()}",
        "rule_id": rule, "rule_name": RULE_NAMES[rule],
        "severity": "Medium" if rule == "R1" else "High",
        "username": evidence[0]["username"], "source_ip": evidence[0]["source_ip"],
        "start_time": evidence[0]["timestamp"], "end_time": evidence[-1]["timestamp"],
        "supporting_event_ids": ids, "explanation": explanation,
        "session_id": session_id, "related_finding_ids": list(parents),
    }


def _sort_findings(findings):
    return sorted(findings, key=lambda item: (item["start_time"], item["end_time"],
                                             item["rule_id"], item["finding_id"]))


def detect_repeated_failed_logins(events):
    """R1: merge qualifying inclusive windows sharing at least one failure."""
    groups = defaultdict(list)
    for event in _ordered(events):
        if event["event_type"] == "LOGIN_FAILED":
            groups[(event["username"], event["source_ip"])].append(event)
    findings = []
    for failures in groups.values():
        left = 0
        sequences = []
        for right, event in enumerate(failures):
            while event["timestamp"] - failures[left]["timestamp"] > FAILURE_WINDOW:
                left += 1
            if right - left + 1 < 5:
                continue
            if sequences and left <= sequences[-1]["end"]:
                sequences[-1]["end"] = right
                sequences[-1]["qualifiers"].append(event["event_id"])
            else:
                sequences.append({"start": left, "end": right, "qualifiers": [event["event_id"]]})
        for sequence in sequences:
            evidence = failures[sequence["start"]:sequence["end"] + 1]
            finding = _finding("R1", evidence,
                               f"At least 5 failed logins for the same account and IP fit an inclusive 120-second window. "
                               f"Merged overlapping qualifying windows contain {len(evidence)} failure events; "
                               "the full merged sequence may span more than 120 seconds.")
            # Endpoints identify when qualification occurred, avoiding future evidence in R2.
            finding["qualifying_end_event_ids"] = sequence["qualifiers"]
            findings.append(finding)
    return _sort_findings(findings)


def detect_suspicious_successful_logins(events, r1_findings=None):
    """R2: earliest eligible success consumes a merged R1 sequence once."""
    ordered = _ordered(events)
    r1_findings = detect_repeated_failed_logins(ordered) if r1_findings is None else r1_findings
    by_id = {row["event_id"]: row for row in ordered}
    candidates = defaultdict(list)
    evidence_by_finding = {}
    for finding in r1_findings:
        evidence = [by_id[event_id] for event_id in finding["supporting_event_ids"]]
        evidence_by_finding[finding["finding_id"]] = evidence
        positions = {row["event_id"]: index for index, row in enumerate(evidence)}
        for event_id in finding["qualifying_end_event_ids"]:
            event = by_id[event_id]
            candidates[(finding["username"], finding["source_ip"])].append(
                (event["timestamp"], event_id, finding["finding_id"], positions[event_id]))
    times = {}
    for key, endpoints in candidates.items():
        endpoints.sort()
        times[key] = [item[0] for item in endpoints]
    consumed = set()
    findings = []
    for success in ordered:
        if success["event_type"] != "LOGIN_SUCCESS":
            continue
        key = (success["username"], success["source_ip"])
        index = bisect_left(times.get(key, []), success["timestamp"]) - 1
        if index < 0:
            continue
        end_time, _, parent_id, end_index = candidates[key][index]
        if parent_id in consumed or success["timestamp"] - end_time > FAILURE_WINDOW:
            continue
        # Distinct R1 groups' qualifying endpoints cannot overlap a 120-second
        # eligibility interval: otherwise their qualifying windows would share failures.
        evidence = evidence_by_finding[parent_id][:end_index + 1] + [success]
        consumed.add(parent_id)
        finding = _finding("R2", evidence,
                           "Successful login for the same account and IP occurs strictly after an R1-qualified "
                           f"failure endpoint, {(success['timestamp'] - end_time).total_seconds():g} seconds later "
                           "(maximum 120 seconds). This failure sequence is used for only one R2 finding.",
                           session_id=success["session_id"], parents=[parent_id])
        finding["login_event_id"] = success["event_id"]
        findings.append(finding)
    return _sort_findings(findings)


def detect_sensitive_file_access(events, r2_findings=None, *, sensitive_resources=None):
    """R3: exact policy matches after an R2 login in the same session/account/IP."""
    ordered = _ordered(events)
    r2_findings = detect_suspicious_successful_logins(ordered) if r2_findings is None else r2_findings
    policy = SENSITIVE_RESOURCES if sensitive_resources is None else frozenset(sensitive_resources)
    by_id = {row["event_id"]: row for row in ordered}
    logins = defaultdict(list)
    for finding in r2_findings:
        login = by_id[finding["login_event_id"]]
        if login["session_id"]:
            logins[(login["username"], login["source_ip"], login["session_id"])].append(
                (login["timestamp"], login["event_id"], finding))
    times = {}
    for key, matches in logins.items():
        matches.sort(key=lambda item: (item[0], item[1]))
        times[key] = [item[0] for item in matches]
    findings = []
    for access in ordered:
        if access["event_type"] != "FILE_ACCESSED" or not access["session_id"] or access["resource"] not in policy:
            continue
        key = (access["username"], access["source_ip"], access["session_id"])
        index = bisect_left(times.get(key, []), access["timestamp"]) - 1
        if index < 0:
            continue
        login_time, _, parent = logins[key][index]
        delta = access["timestamp"] - login_time
        if delta > FILE_WINDOW:
            continue
        evidence = [by_id[event_id] for event_id in parent["supporting_event_ids"]] + [access]
        finding = _finding("R3", evidence,
                           f"Resource {access['resource']!r} exactly matches the sensitive-resource policy. "
                           f"Access follows the R2 login by {delta.total_seconds():g} seconds (maximum 300), "
                           "with the same account, IP, and nonempty session ID. This is a logged pattern, not proof of compromise.",
                           session_id=access["session_id"],
                           parents=parent["related_finding_ids"] + [parent["finding_id"]])
        finding["login_event_id"] = parent["login_event_id"]
        finding["file_event_id"] = access["event_id"]
        findings.append(finding)
    return _sort_findings(findings)


def analyze_security_events(events, *, sensitive_resources=None):
    """Coordinate R1 → R2 → R3 without modifying events or consulting fixtures."""
    ordered = _ordered(events)
    r1 = detect_repeated_failed_logins(ordered)
    r2 = detect_suspicious_successful_logins(ordered, r1)
    r3 = detect_sensitive_file_access(ordered, r2, sensitive_resources=sensitive_resources)
    return _sort_findings(r1 + r2 + r3)
