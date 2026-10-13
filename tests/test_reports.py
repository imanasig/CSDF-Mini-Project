from pathlib import Path

import pytest

from cybertrail.database import InvestigationStore
from cybertrail.reports import generate_html_report
from tests.test_database import save_sample


@pytest.mark.parametrize("name", ["file_access_incident.csv", "normal_activity.csv"])
def test_actual_report_contents_and_zero_findings(tmp_path, name):
    store = InvestigationStore(tmp_path / "case.db", tmp_path / "evidence")
    identifier, imported, findings, cases = save_sample(store, name)
    checks = store.verify_investigation(identifier)
    store.record_report(identifier)
    report = generate_html_report(store.load_investigation(identifier), checks)
    assert "Academic Digital Forensic Investigation Report" in report
    assert identifier in report and imported.sha256 in report and name in report
    assert "Verified" in report and "Investigation report generated" in report
    for finding in findings:
        assert finding["finding_id"] in report
        assert all(event_id in report for event_id in finding["supporting_event_ids"])
    if not cases:
        assert "No matching cases" in report


def test_html_escaping_and_failed_integrity(tmp_path):
    store = InvestigationStore(tmp_path / "case.db", tmp_path / "evidence")
    identifier, *_ = save_sample(store, title='<script>alert("x")</script>')
    loaded = store.load_investigation(identifier)
    loaded["findings"][0]["explanation"] = '<img src=x onerror="bad">'
    loaded["evidence"][0]["original_filename"] = "<svg onload=bad>"
    report = generate_html_report(loaded, [{"evidence_id": loaded["evidence"][0]["evidence_id"], "status": "Modified"}])
    assert "<script>" not in report and "<img" not in report and "<svg" not in report
    assert "&lt;script&gt;" in report and "&lt;img" in report and "Modified" in report
