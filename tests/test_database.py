import sqlite3
from pathlib import Path

import pytest

from cybertrail.correlator import correlate_findings
from cybertrail.database import InvestigationStore
from cybertrail.detector import SENSITIVE_RESOURCES, analyze_security_events
from cybertrail.parser import parse_logs

SAMPLES = Path(__file__).resolve().parents[1] / "data/samples"


def save_sample(store, name="file_access_incident.csv", **kwargs):
    imported = parse_logs((SAMPLES / name).read_bytes(), name)
    findings = analyze_security_events(imported.valid_records)
    cases = correlate_findings(findings, imported.valid_records)
    identifier = store.save_investigation(imported, findings, cases, policy=SENSITIVE_RESOURCES, **kwargs)
    return identifier, imported, findings, cases


def test_restart_relationships_parameterization_and_audit(tmp_path):
    store = InvestigationStore(tmp_path / "case.db", tmp_path / "evidence")
    identifier, imported, findings, cases = save_sample(store, title="'; DROP TABLE events; --")
    reopened = InvestigationStore(store.database_path, store.evidence_directory)
    loaded = reopened.load_investigation(identifier)
    assert loaded["findings"] == findings and loaded["cases"] == cases
    assert loaded["events"] == imported.valid_records
    assert loaded["title"] == "'; DROP TABLE events; --"
    assert len(loaded["custody_events"]) == 3
    assert reopened.verify_investigation(identifier)[0]["status"] == "Verified"
    reopened.record_report(identifier)
    assert len(reopened.load_investigation(identifier)["custody_events"]) == 5
    with reopened.connection() as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM finding_events").fetchone()[0] == 18
        assert connection.execute("SELECT count(*) FROM case_events").fetchone()[0] == 7
        assert connection.execute("SELECT count(*) FROM case_findings").fetchone()[0] == 3
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM custody_events")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE custody_events SET actor = 'replacement'")
    second, *_ = save_sample(store)
    assert second != identifier and len(store.list_investigations()) == 2


def test_transaction_and_file_rollback(tmp_path, monkeypatch):
    store = InvestigationStore(tmp_path / "case.db", tmp_path / "evidence")
    original = store._audit

    def fail_on_completion(connection, investigation_id, action, *args, **kwargs):
        if action == "Investigation analysis completed":
            raise sqlite3.OperationalError("simulated transaction failure")
        return original(connection, investigation_id, action, *args, **kwargs)

    monkeypatch.setattr(store, "_audit", fail_on_completion)
    with pytest.raises(sqlite3.OperationalError):
        save_sample(store)
    assert store.list_investigations() == []
    assert list(store.evidence_directory.iterdir()) == []
    with store.connection() as connection:
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 0


def test_multiple_evidence_files_and_duplicate_event_ids(tmp_path):
    store = InvestigationStore(tmp_path / "case.db", tmp_path / "evidence")
    one = parse_logs((SAMPLES / "brute_force.csv").read_bytes(), "one.csv")
    two = parse_logs((SAMPLES / "brute_force.csv").read_bytes(), "two.csv")
    # Ambiguous source IDs across evidence files are rejected, not silently merged.
    with pytest.raises(ValueError, match="duplicate"):
        store.save_investigation([one, two], [], [], policy=[])
    empty = parse_logs(b"[]", "empty.json")
    findings = analyze_security_events(one.valid_records)
    cases = correlate_findings(findings, one.valid_records)
    identifier = store.save_investigation([one, empty], findings, cases, policy=[])
    assert len(store.load_investigation(identifier)["evidence"]) == 2


def test_unknown_investigation_and_corrupt_import_hash(tmp_path):
    store = InvestigationStore(tmp_path / "case.db", tmp_path / "evidence")
    store.initialize()
    with pytest.raises(ValueError, match="not found"):
        store.load_investigation("unknown")
    imported = parse_logs(b"[]", "empty.json")
    imported.sha256 = "bad"
    with pytest.raises(ValueError, match="fingerprint"):
        store.save_investigation(imported, [], [], policy=[])
