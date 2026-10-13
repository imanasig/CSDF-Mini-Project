"""Local SQLite investigations with relational evidence links and append-only audit."""

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from cybertrail.correlator import correlate_findings
from cybertrail.evidence import evidence_path, preserve_evidence, verify_evidence


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _json(value):
    return json.dumps(value, default=lambda item: item.isoformat() if isinstance(item, datetime) else str(item), ensure_ascii=False)


def _event(row):
    row = dict(row)
    row["timestamp"] = datetime.fromisoformat(row["timestamp"])
    return row


SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
 investigation_id TEXT PRIMARY KEY, title TEXT NOT NULL, created_at TEXT NOT NULL,
 policy_json TEXT NOT NULL, total_records INTEGER NOT NULL, invalid_records_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_files (
 evidence_id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL REFERENCES investigations,
 original_filename TEXT NOT NULL, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, stored_name TEXT NOT NULL UNIQUE,
 UNIQUE(investigation_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS events (
 investigation_id TEXT NOT NULL REFERENCES investigations, event_id TEXT NOT NULL,
 evidence_id TEXT NOT NULL REFERENCES evidence_files, payload TEXT NOT NULL,
 PRIMARY KEY(investigation_id, event_id),
 FOREIGN KEY(investigation_id, evidence_id) REFERENCES evidence_files(investigation_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS findings (
 investigation_id TEXT NOT NULL REFERENCES investigations, finding_id TEXT NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(investigation_id, finding_id)
);
CREATE TABLE IF NOT EXISTS incident_cases (
 investigation_id TEXT NOT NULL REFERENCES investigations, incident_id TEXT NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(investigation_id, incident_id)
);
CREATE TABLE IF NOT EXISTS finding_events (
 investigation_id TEXT NOT NULL, finding_id TEXT NOT NULL, event_id TEXT NOT NULL,
 PRIMARY KEY(investigation_id, finding_id, event_id),
 FOREIGN KEY(investigation_id, finding_id) REFERENCES findings,
 FOREIGN KEY(investigation_id, event_id) REFERENCES events
);
CREATE TABLE IF NOT EXISTS case_findings (
 investigation_id TEXT NOT NULL, incident_id TEXT NOT NULL, finding_id TEXT NOT NULL,
 PRIMARY KEY(investigation_id, incident_id, finding_id),
 FOREIGN KEY(investigation_id, incident_id) REFERENCES incident_cases,
 FOREIGN KEY(investigation_id, finding_id) REFERENCES findings
);
CREATE TABLE IF NOT EXISTS case_events (
 investigation_id TEXT NOT NULL, incident_id TEXT NOT NULL, event_id TEXT NOT NULL,
 PRIMARY KEY(investigation_id, incident_id, event_id),
 FOREIGN KEY(investigation_id, incident_id) REFERENCES incident_cases,
 FOREIGN KEY(investigation_id, event_id) REFERENCES events
);
CREATE TABLE IF NOT EXISTS custody_events (
 audit_event_id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL REFERENCES investigations,
 evidence_id TEXT REFERENCES evidence_files, timestamp TEXT NOT NULL,
 action TEXT NOT NULL, actor TEXT NOT NULL, details TEXT NOT NULL,
 FOREIGN KEY(investigation_id, evidence_id) REFERENCES evidence_files(investigation_id, evidence_id)
);
CREATE TRIGGER IF NOT EXISTS custody_no_update BEFORE UPDATE ON custody_events
 BEGIN SELECT RAISE(ABORT, 'Audit entries are append-only'); END;
CREATE TRIGGER IF NOT EXISTS custody_no_delete BEFORE DELETE ON custody_events
 BEGIN SELECT RAISE(ABORT, 'Audit entries are append-only'); END;
"""


class InvestigationStore:
    def __init__(self, database_path, evidence_directory):
        self.database_path = Path(database_path)
        self.evidence_directory = Path(evidence_directory)

    @contextmanager
    def connection(self):
        self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.database_path.is_symlink():
            raise ValueError("Database must not be a symlink.")
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        os.chmod(self.database_path, 0o600)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self):
        with self.connection() as connection:
            connection.executescript(SCHEMA)

    def _audit(self, connection, investigation_id, action, actor, details, evidence_id=None):
        connection.execute("INSERT INTO custody_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (uuid.uuid4().hex, investigation_id, evidence_id, utc_now(), action, actor, details))

    def save_investigation(self, imports, findings, cases, *, policy, title="Local investigation", actor="Demo Investigator"):
        """Create a fresh snapshot; roll back database and newly created files on failure."""
        if not isinstance(imports, list):
            imports = [imports]
        if not imports or any(result.file_errors for result in imports):
            raise ValueError("Only successfully parsed imports can be saved.")
        events = [event for result in imports for event in result.valid_records]
        expected_cases = correlate_findings(findings, events)
        if expected_cases != cases:
            raise ValueError("Cases do not match the supplied findings and events.")
        for result in imports:
            if hashlib.sha256(result.original_bytes).hexdigest() != result.sha256:
                raise ValueError("Import fingerprint no longer matches original bytes.")
        investigation_id = "INV-" + uuid.uuid4().hex
        created_files = []
        self.initialize()
        try:
            with self.connection() as connection:
                invalid = [{**row, "original_filename": result.filename, "import_index": index}
                           for index, result in enumerate(imports, 1) for row in result.invalid_records]
                connection.execute("INSERT INTO investigations VALUES (?, ?, ?, ?, ?, ?)",
                                   (investigation_id, title, utc_now(), _json(sorted(policy)),
                                    sum(result.total_records for result in imports), _json(invalid)))
                for result in imports:
                    metadata = preserve_evidence(result.original_bytes, result.filename, self.evidence_directory)
                    created_files.append(metadata["evidence_id"])
                    connection.execute("INSERT INTO evidence_files VALUES (?, ?, ?, ?, ?, ?)",
                                       (metadata["evidence_id"], investigation_id, metadata["original_filename"],
                                        metadata["sha256"], metadata["size_bytes"], metadata["stored_name"]))
                    self._audit(connection, investigation_id, "Evidence imported", actor,
                                "Original bytes preserved at save time; local/demo actor label.", metadata["evidence_id"])
                    self._audit(connection, investigation_id, "Evidence hash calculated", "CyberTrail",
                                metadata["sha256"], metadata["evidence_id"])
                    for event in result.valid_records:
                        connection.execute("INSERT INTO events VALUES (?, ?, ?, ?)",
                                           (investigation_id, event["event_id"], metadata["evidence_id"], _json(event)))
                for finding in findings:
                    connection.execute("INSERT INTO findings VALUES (?, ?, ?)",
                                       (investigation_id, finding["finding_id"], _json(finding)))
                    connection.executemany("INSERT INTO finding_events VALUES (?, ?, ?)",
                                           [(investigation_id, finding["finding_id"], event_id) for event_id in set(finding["supporting_event_ids"])])
                for case in cases:
                    connection.execute("INSERT INTO incident_cases VALUES (?, ?, ?)",
                                       (investigation_id, case["incident_id"], _json(case)))
                    connection.executemany("INSERT INTO case_findings VALUES (?, ?, ?)",
                                           [(investigation_id, case["incident_id"], finding_id) for finding_id in case["related_finding_ids"]])
                    connection.executemany("INSERT INTO case_events VALUES (?, ?, ?)",
                                           [(investigation_id, case["incident_id"], event_id) for event_id in case["related_event_ids"]])
                self._audit(connection, investigation_id, "Investigation analysis completed", actor,
                            f"Snapshot saved: {len(events)} valid events, {len(findings)} findings, {len(cases)} cases; policy={sorted(policy)}")
        except BaseException:
            for evidence_id in created_files:
                evidence_path(self.evidence_directory, evidence_id).unlink(missing_ok=True)
            raise
        return investigation_id

    def list_investigations(self):
        self.initialize()
        with self.connection() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT investigation_id, title, created_at, total_records FROM investigations ORDER BY created_at DESC, investigation_id")]

    def load_investigation(self, investigation_id):
        try:
            result = self._load_investigation(investigation_id)
            if result["total_records"] != len(result["events"]) + len(result["invalid_records"]):
                raise ValueError("Saved record counts are inconsistent.")
            if any(event["timestamp"].utcoffset().total_seconds() != 0 for event in result["events"]):
                raise ValueError("Saved timestamps must be UTC.")
            if correlate_findings(result["findings"], result["events"]) != result["cases"]:
                raise ValueError("Saved case timelines or relationships are inconsistent.")
            if set(result["event_evidence_ids"]) != {row["event_id"] for row in result["events"]}:
                raise ValueError("Saved evidence references are inconsistent.")
            return result
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError("Saved investigation data is inconsistent or damaged.") from error

    def _load_investigation(self, investigation_id):
        with self.connection() as connection:
            row = connection.execute("SELECT * FROM investigations WHERE investigation_id = ?", (investigation_id,)).fetchone()
            if row is None:
                raise ValueError("Saved investigation was not found.")
            result = dict(row)
            result["policy"] = json.loads(result.pop("policy_json"))
            result["invalid_records"] = json.loads(result.pop("invalid_records_json"))
            result["evidence"] = [dict(row) for row in connection.execute(
                "SELECT * FROM evidence_files WHERE investigation_id = ? ORDER BY evidence_id", (investigation_id,))]
            result["event_evidence_ids"] = {row["event_id"]: row["evidence_id"] for row in connection.execute(
                "SELECT event_id, evidence_id FROM events WHERE investigation_id = ?", (investigation_id,))}
            for table in ["events", "findings", "incident_cases"]:
                result[table] = [json.loads(row["payload"]) for row in connection.execute(
                    f"SELECT payload FROM {table} WHERE investigation_id = ?", (investigation_id,))]
            result["events"] = sorted([_event(row) for row in result["events"]], key=lambda row: (row["timestamp"], row["event_id"]))
            for finding in result["findings"]:
                for name in ["start_time", "end_time"]:
                    finding[name] = datetime.fromisoformat(finding[name])
            result["findings"].sort(key=lambda row: (row["start_time"], row["end_time"], row["rule_id"], row["finding_id"]))
            result["cases"] = result.pop("incident_cases")
            for case in result["cases"]:
                case["timeline"] = [_event(event) for event in case["timeline"]]
                for name in ["start_time", "end_time"]:
                    case[name] = datetime.fromisoformat(case[name])
            result["cases"].sort(key=lambda row: (row["start_time"], row["incident_id"]))
            result["custody_events"] = [dict(row) for row in connection.execute(
                "SELECT * FROM custody_events WHERE investigation_id = ? ORDER BY timestamp, audit_event_id", (investigation_id,))]
        return result

    def verify_investigation(self, investigation_id, *, actor="Demo Investigator"):
        investigation = self.load_investigation(investigation_id)
        checks = [verify_evidence(metadata, self.evidence_directory) for metadata in investigation["evidence"]]
        with self.connection() as connection:
            for check in checks:
                self._audit(connection, investigation_id, "Evidence integrity checked", actor,
                            _json(check), check["evidence_id"])
        return checks

    def record_report(self, investigation_id, *, actor="Demo Investigator"):
        with self.connection() as connection:
            self._audit(connection, investigation_id, "Investigation report generated", actor,
                        "HTML report generated for preview/download; generation does not prove a download occurred.")
