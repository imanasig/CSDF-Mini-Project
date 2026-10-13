"""Group findings by explicit evidence using union-find; reconstruct source timelines."""

import copy
import hashlib
import json
from collections import defaultdict


def correlate_findings(findings, events):
    """Return deterministic investigation cases, or fail on missing evidence/references."""
    findings = sorted(findings, key=lambda row: row["finding_id"])
    event_by_id = {row["event_id"]: row for row in events}
    if len(event_by_id) != len(events):
        raise ValueError("Timeline source contains duplicate event IDs.")
    by_id = {row["finding_id"]: row for row in findings}
    if len(by_id) != len(findings):
        raise ValueError("Duplicate finding IDs cannot be correlated reliably.")
    parent = {identifier: identifier for identifier in by_id}

    def root(identifier):
        while parent[identifier] != identifier:
            parent[identifier] = parent[parent[identifier]]
            identifier = parent[identifier]
        return identifier

    def union(left, right):
        left, right = root(left), root(right)
        if left != right:
            parent[max(left, right)] = min(left, right)

    owners = defaultdict(list)
    evidence_sets = {}
    for finding in findings:
        identifier = finding["finding_id"]
        evidence = set(finding["supporting_event_ids"])
        if not evidence or not evidence <= event_by_id.keys():
            raise ValueError(f"Finding {identifier} has missing or empty supporting evidence.")
        evidence_sets[identifier] = evidence
        for event_id in evidence:
            if owners[event_id]:
                union(identifier, owners[event_id][0])
            owners[event_id].append(identifier)
    for finding in findings:
        for reference in finding.get("related_finding_ids", []):
            if reference not in by_id:
                raise ValueError("A parent finding reference is missing.")
            if not evidence_sets[finding["finding_id"]] & evidence_sets[reference]:
                raise ValueError("A parent reference has no shared source evidence.")
            referenced = by_id[reference]
            if finding["rule_id"] == "R3" and referenced["rule_id"] == "R2":
                login = event_by_id.get(finding.get("login_event_id"))
                access = event_by_id.get(finding.get("file_event_id"))
                if (not login or not access or finding.get("login_event_id") != referenced.get("login_event_id")
                        or not login.get("session_id") or login["session_id"] != access.get("session_id")
                        or (login["username"], login["source_ip"]) != (access["username"], access["source_ip"])):
                    raise ValueError("R3 parent relationship has inconsistent login/session evidence.")
            union(finding["finding_id"], reference)
    components = defaultdict(list)
    for identifier in by_id:
        components[root(identifier)].append(identifier)
    cases = []
    for finding_ids in components.values():
        finding_ids.sort()
        event_ids = set().union(*(evidence_sets[identifier] for identifier in finding_ids))
        timeline = []
        for event_id in sorted(event_ids, key=lambda identifier: (event_by_id[identifier]["timestamp"], identifier)):
            event = copy.deepcopy(event_by_id[event_id])
            event["included_by_finding_ids"] = sorted(owners[event_id])
            timeline.append(event)
        rule_ids = sorted({by_id[identifier]["rule_id"] for identifier in finding_ids})
        identity = json.dumps(finding_ids, separators=(",", ":"))
        cases.append({
            "incident_id": "INC-" + hashlib.sha256(identity.encode()).hexdigest(),
            "title": "Investigation case: " + ", ".join(rule_ids),
            "priority": "High" if any(rule in {"R2", "R3"} for rule in rule_ids) else "Medium",
            "start_time": timeline[0]["timestamp"], "end_time": timeline[-1]["timestamp"],
            "affected_usernames": sorted({row["username"] for row in timeline}),
            "source_ips": sorted({row["source_ip"] for row in timeline}),
            "related_finding_ids": finding_ids,
            "related_event_ids": [row["event_id"] for row in timeline],
            "summary": f"{len(finding_ids)} rule findings linked by shared evidence or checked parent references; "
                       f"{len(timeline)} observed events. This case is an investigation grouping, not a confirmed crime.",
            "timeline": timeline,
        })
    return sorted(cases, key=lambda row: (row["start_time"], row["incident_id"]))
