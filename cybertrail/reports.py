"""Escaped, printable HTML reports; no scripts or network resources."""

import html
import json
from datetime import datetime, timezone


def _text(value):
    if isinstance(value, datetime):
        value = value.isoformat().replace("+00:00", "Z")
    elif isinstance(value, (list, dict)):
        value = json.dumps(value, default=str, ensure_ascii=False)
    return html.escape("" if value is None else str(value), quote=True)


def _table(rows, columns):
    if not rows:
        return "<p>None recorded.</p>"
    header = "".join(f"<th>{_text(name)}</th>" for name in columns)
    body = "".join("<tr>" + "".join(f"<td>{_text(row.get(name))}</td>" for name in columns) + "</tr>" for row in rows)
    return f"<table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table>"


def generate_html_report(investigation, verification, *, generated_at=None):
    """Render a saved snapshot and the supplied actual verification results."""
    generated_at = generated_at or datetime.now(timezone.utc)
    checks = {row["evidence_id"]: row for row in verification}
    evidence = [{**row, "integrity_status": checks.get(row["evidence_id"], {}).get("status", "Not checked"),
                 "actual_sha256": checks.get(row["evidence_id"], {}).get("actual_sha256"),
                 "checked_at": checks.get(row["evidence_id"], {}).get("checked_at")}
                for row in investigation["evidence"]]
    sections = ["<h1>CyberTrail</h1><h2>Academic Digital Forensic Investigation Report</h2>",
                f"<p>Investigation ID: {_text(investigation['investigation_id'])}<br>Title: {_text(investigation['title'])}<br>Generated (UTC): {_text(generated_at)}</p>",
                "<h2>Investigation summary</h2>",
                f"<p>{investigation['total_records']} imported records; {len(investigation['events'])} valid, "
                f"{len(investigation['invalid_records'])} invalid; {len(investigation['findings'])} rule findings; {len(investigation['cases'])} investigation cases.</p>",
                "<h2>Preserved evidence and integrity</h2>",
                _table(evidence, ["evidence_id", "original_filename", "size_bytes", "sha256", "integrity_status", "actual_sha256", "checked_at"]),
                "<h2>Rule-generated findings (interpretations)</h2>",
                _table(investigation["findings"], ["finding_id", "rule_id", "rule_name", "severity", "username", "source_ip", "session_id", "start_time", "end_time", "supporting_event_ids", "related_finding_ids", "explanation"]),
                "<h2>Correlated investigation cases</h2>"]
    if not investigation["cases"]:
        sections.append("<p>No matching cases were generated.</p>")
    for case in investigation["cases"]:
        sections.extend([f"<h3>{_text(case['incident_id'])}</h3><p>{_text(case['summary'])}</p>",
                         _table([case], ["title", "priority", "affected_usernames", "source_ips", "related_finding_ids"]),
                         "<h4>Observed event timeline (UTC)</h4>",
                         _table([{**row, "evidence_id": investigation["event_evidence_ids"].get(row["event_id"])} for row in case["timeline"]],
                                ["event_id", "timestamp", "event_type", "username", "source_ip", "session_id", "resource", "source_row", "evidence_id", "included_by_finding_ids"])])
    sections.extend(["<h2>Rejected records</h2>",
                     _table(investigation["invalid_records"], ["original_filename", "source_row", "errors"]),
                     "<h2>Chain-of-custody activity (local/demo)</h2>",
                     _table(investigation["custody_events"], ["audit_event_id", "timestamp", "action", "actor", "evidence_id", "details"]),
                     "<h2>Algorithms and thresholds</h2><p>R1: at least five failures for one account/IP in an inclusive 120-second sliding window; shared windows merge. "
                     "R2: strictly later success within 120 seconds of qualification; one success per failure sequence. "
                     "R3: strictly later FILE_ACCESSED within 300 seconds of R2, same account/IP/nonempty session, exact sensitive-resource policy. "
                     "Cases: union-find connected components of shared supporting evidence and checked parent references.</p>",
                     f"<p>Sensitive-resource policy: {_text(investigation['policy'])}</p>",
                     "<h2>Limitations and conclusion</h2><p>These findings describe observed logged patterns and unverified interpretations. "
                     "Legitimate activity may match these rules; incomplete logs, inaccurate clocks, or missing sessions may hide activity. "
                     "No matching findings does not establish the absence of an incident. No crime, password compromise, or attacker identity has been conclusively established. "
                     "A matching SHA-256 verifies byte equality against the stored fingerprint, not authenticity or legal admissibility. "
                     "The local database, audit history, and files are not independently tamper-proof. The demo actor label is not authenticated identity. "
                     "Failed integrity verification means the stored evidence should be investigated before relying on the saved analysis.</p>"])
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>CyberTrail Investigation Report</title>
<style>body{font:14px system-ui,sans-serif;max-width:1200px;margin:32px auto;padding:0 20px;color:#172033}
table{border-collapse:collapse;width:100%;margin:12px 0}td,th{border:1px solid #ccd3dc;padding:7px;text-align:left;overflow-wrap:anywhere}th{background:#eef2f6}
h2{margin-top:28px}@media print{body{margin:0;font-size:10px}h2,h3,h4{break-after:avoid}tr{break-inside:avoid}}</style></head><body>""" + "".join(sections) + "</body></html>"


def generate_saved_report(store, investigation_id, *, actor="Demo Investigator"):
    """Reverify evidence, render successfully, record generation, include that audit entry."""
    checks = store.verify_investigation(investigation_id, actor=actor)
    generated_at = datetime.now(timezone.utc)
    generate_html_report(store.load_investigation(investigation_id), checks, generated_at=generated_at)
    store.record_report(investigation_id, actor=actor)
    return generate_html_report(store.load_investigation(investigation_id), checks, generated_at=generated_at), checks
