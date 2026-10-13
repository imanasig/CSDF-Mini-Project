"""Full forensic workflow using disposable files and SQLite databases."""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

import pytest

from cybertrail.database import InvestigationStore
from cybertrail.evidence import evidence_path
from cybertrail.reports import generate_saved_report
from tests.test_database import save_sample


@pytest.mark.parametrize("name,findings,cases", [
    ("normal_activity.csv", 0, 0), ("brute_force.csv", 1, 1),
    ("suspicious_login.csv", 2, 1), ("file_access_incident.csv", 3, 1),
    ("mixed_activity.csv", 6, 3), ("invalid_logs.csv", 0, 0),
])
def test_full_workflow_and_restart(tmp_path, name, findings, cases):
    store = InvestigationStore(tmp_path / "investigations.db", tmp_path / "evidence")
    start = datetime.now(timezone.utc)
    identifier, imported, detected, correlated = save_sample(store, name)
    assert len(detected) == findings and len(correlated) == cases
    restarted = InvestigationStore(store.database_path, store.evidence_directory)
    loaded = restarted.load_investigation(identifier)
    assert loaded["findings"] == detected and loaded["cases"] == correlated
    assert loaded["events"] == imported.valid_records
    evidence = loaded["evidence"][0]
    assert evidence_path(tmp_path / "evidence", evidence["evidence_id"]).read_bytes() == imported.original_bytes
    assert evidence["sha256"] == hashlib.sha256(imported.original_bytes).hexdigest()
    report, checks = generate_saved_report(restarted, identifier)
    assert checks[0]["status"] == "Verified"
    assert identifier in report and evidence["sha256"] in report
    for case in loaded["cases"]:
        assert all(event_id in report for event_id in case["related_event_ids"])
    custody = restarted.load_investigation(identifier)["custody_events"]
    assert {row["action"] for row in custody} == {"Evidence imported", "Evidence hash calculated", "Investigation analysis completed", "Evidence integrity checked", "Investigation report generated"}
    assert all(start <= datetime.fromisoformat(row["timestamp"]) <= datetime.now(timezone.utc) for row in custody)


@pytest.mark.parametrize("action,status", [("modify", "Modified"), ("remove", "Missing")])
def test_changed_or_missing_disposable_evidence(tmp_path, action, status):
    store = InvestigationStore(tmp_path / "investigations.db", tmp_path / "evidence")
    identifier, *_ = save_sample(store)
    evidence = store.load_investigation(identifier)["evidence"][0]
    path = evidence_path(store.evidence_directory, evidence["evidence_id"])
    if action == "modify":
        path.write_bytes(b"deliberately changed disposable test evidence")
    else:
        path.unlink()
    report, checks = generate_saved_report(store, identifier)
    assert checks[0]["status"] == status
    assert status in report
    assert json.loads(store.load_investigation(identifier)["custody_events"][-2]["details"])["status"] == status


def test_damaged_saved_payload_is_rejected(tmp_path):
    store = InvestigationStore(tmp_path / "investigations.db", tmp_path / "evidence")
    identifier, *_ = save_sample(store)
    with store.connection() as connection:
        connection.execute("UPDATE incident_cases SET payload = ? WHERE investigation_id = ?", ('{"incident_id":"damaged"}', identifier))
    with pytest.raises(ValueError, match="damaged"):
        store.load_investigation(identifier)


def test_cross_investigation_evidence_reference_rejected(tmp_path):
    store = InvestigationStore(tmp_path / "investigations.db", tmp_path / "evidence")
    first, *_ = save_sample(store)
    second, *_ = save_sample(store)
    second_evidence = store.load_investigation(second)["evidence"][0]["evidence_id"]
    with store.connection() as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE events SET evidence_id = ? WHERE investigation_id = ?", (second_evidence, first))
