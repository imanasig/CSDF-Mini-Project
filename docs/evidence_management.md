# Evidence management — Stage 6

`evidence.py` preserves exact original bytes using exclusive creation, generated hexadecimal IDs, and 0600 file permissions. Original filenames are metadata, never paths. Unsafe IDs and evidence-file symlinks are rejected. SHA-256 is calculated before parsing in the importer and again from exact bytes when saving; verification reads the actual stored file and reports Verified, Modified, Missing, or Unavailable with an actual UTC check time.

The UI uses `runtime/cybertrail.db` and `runtime/evidence/` by default. Set `CYBERTRAIL_DATA_DIR` before launching to configure another root. `InvestigationStore(database_path, evidence_directory)` allows independent paths for tests or programmatic use. Runtime files are ignored by Git. No upload is automatically preserved: preservation happens when the investigator explicitly saves the analyzed snapshot.

SQLite stores investigations, evidence_files, events, findings, incident_cases, finding_events, case_findings, case_events, and custody_events. Normalized object details use JSON payloads while foreign-key-enforced junction tables preserve event/finding/case relationships. IDs are scoped to an investigation; the evidence-to-investigation association is also enforced. Every connection enables foreign keys; all variable values use SQL parameters. Each save creates a fresh UUID investigation ID, never overwriting an earlier investigation. The API accepts one or more imports, but event IDs must be unique across them; the UI currently saves one import per investigation.

Saving checks case/evidence consistency and uses a database transaction. Handled failures roll back database changes and remove only evidence files newly created by that failed save. An abrupt process/machine crash between filesystem creation and database commit can leave an unreferenced evidence file; file storage and SQLite cannot share one atomic transaction. Do not delete evidence automatically to resolve ambiguity.

Load operations restore UTC datetimes and return saved findings/cases rather than rerunning detection. The UI prevents repeated clicks from saving the same active snapshot again; intentionally rerunning analysis permits a new investigation. Evidence verification and report generation append custody entries with actual UTC operation times. Import/hash entries describe preservation at save time; they do not backdate custody to the original upload. The local/demo investigator label is not authenticated identity.

Custody rows cannot be updated/deleted through normal SQLite operations because application-created triggers reject those operations. A database administrator can drop triggers or edit the underlying database/files. This is an educational audit mechanism, not independently tamper-proof chain of custody or legal authentication.

## Backup and restore

Stop CyberTrail, then copy the entire configured runtime directory to a private backup location. The SQLite database and evidence directory must be backed up/restored together; a database-only copy can leave missing evidence. If separately configured through the API, copy both locations while the application is stopped. Do not commit backups or private evidence to Git. Keep filenames under the evidence directory unchanged when restoring. After restart, reopen an investigation and verify each file's hash.

Verification does not modify evidence. The tampering tests alter only disposable files in pytest temporary directories. Matching hashes show byte equality against the stored fingerprint, not authenticity, completeness, or admissibility.
