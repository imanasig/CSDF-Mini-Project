# CyberTrail

**Cybercrime Investigation Using Log Analysis and Event Correlation**

Local academic mini-project for SPPU B.E. Computer Engineering (2019 Pattern), Laboratory Practice IV, Cyber Security and Digital Forensics — 410244(C), academic year 2026–27. Stages 1–7 are implemented; Stage 8 submission writing and viva preparation are outside this build.

## Problem and objectives

Large security logs make it difficult to reconstruct suspicious sequences manually. CyberTrail imports structured logs, rejects malformed records visibly, applies explainable rules, connects findings through source evidence, preserves an investigation snapshot, and produces an academic report. It helps investigate available records; findings do not confirm crimes or identify attackers.

## Features and navigation

The sidebar chooses **Current import** or a **Saved investigation**. Six tabs share that selected context:

| Section | Implemented behavior |
| --- | --- |
| Dashboard | Actual event counts, finding distribution, case priorities, recent events, last integrity-check status. |
| Log Import / Log Viewer | CSV/JSON upload or sample selection, validation, UTC normalization, filters, error table, normalized CSV download. |
| Security Analysis | Explicit R1/R2/R3 run, configurable sensitive-resource policy, rule/severity filters, supporting source events. |
| Investigation Cases | Evidence-based connected components, priority/account filters, chronological timelines, source references. |
| Evidence Management | Save snapshots, reopen from SQLite, verify preserved evidence, review local custody actions. |
| Reports | Fresh evidence verification, escaped HTML report preview/download, printable formatting. |

Analysis runs only when requested. Viewer filters do not change analysis. File/policy changes hide stale findings until rerun. Reopening restores saved findings/cases rather than rerunning detection. Repeated rerenders do not duplicate investigations, custody entries, or reports. A completed snapshot cannot be saved again through the same button; intentional re-analysis permits a new investigation.

## Architecture and technologies

```text
CSV/JSON original bytes
  → parser.py: hash, validate, normalize
  → detector.py: R1/R2/R3 findings
  → correlator.py: investigation cases and source timelines
  → database.py + evidence.py: SQLite snapshot and exact preserved bytes
  → reports.py: escaped academic HTML report

app.py: local Streamlit interface over these independent modules
```

Python 3.11+ is required. Streamlit renders the UI; Pandas supports its tables; pytest verifies behavior. SQLite, hashlib, csv, json, ipaddress, and datetime are Python standard libraries. No external security engine, cloud service, paid API, machine learning, Docker, or separate JavaScript frontend is required. Dependency ranges are in requirements.txt; they are not a frozen environment lockfile.

| Technology | Role |
| --- | --- |
| Python | Parsing, rule detection, correlation, evidence and reports. |
| Streamlit / Pandas | Local browser interface and event tables. |
| SQLite / sqlite3 | Persistent investigations and evidence relationships. |
| hashlib | Original-byte SHA-256 fingerprints and integrity checks. |
| csv / json / ipaddress / datetime | Structured input, address validation and UTC time handling. |
| pytest | Existing automated checks; not required for personal manual testing. |

## Installation and execution: macOS

**On this Mac, the project and `.venv` already exist.** Open Terminal and run:

```sh
cd "/Volumes/Work/CSDF Mini Project"
source .venv/bin/activate
python -m streamlit run app.py
```

Open http://localhost:8501 in your browser, or use the local URL printed in Terminal if the port differs. Keep Terminal running while using CyberTrail. To stop, return to Terminal and press **Control+C**. Optionally run `deactivate` afterward to leave the virtual environment. No test, benchmark, or sample-generation command is needed to start the app.

For a fresh macOS installation only, enter the copied project directory and create/install its environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open the local URL printed by Streamlit (normally http://localhost:8501). Control+C stops the server. When returning later, activate `.venv` and run the final command again.

### Windows: setup and startup commands

Install Python 3.11 or newer, copy the source project, and create a new virtual environment on Windows; do not copy the Mac's `.venv`. In **Command Prompt**, substitute your actual project location:

```bat
cd /d "C:\Projects\CyberTrail"
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

On later launches, only change directory, activate, and run Streamlit. In **PowerShell**, activation is `./.venv/Scripts/Activate.ps1`; if local policy blocks it, use Command Prompt. Browse to the printed local URL and press Control+C in the terminal to stop.

**Existing compatibility limit:** preservation/verification uses the POSIX `os.O_NOFOLLOW` flag, which is unavailable on Windows. The startup commands allow viewing and analysis, but the complete evidence save/verification workflow requires macOS/POSIX in the current implementation. Windows end-to-end support has not been established.

Default persistent storage is `runtime/cybertrail.db` plus `runtime/evidence/`. To configure another private directory before launch:

```sh
export CYBERTRAIL_DATA_DIR="/path/to/private/cybertrail-runtime"
python -m streamlit run app.py
```

## Supported input and errors

UTF-8 `.csv` and `.json` files may be up to **10 MiB** (10,485,760 bytes). JSON accepts an array of event objects or an object with an `events` array. All nine columns/keys must exist:

```text
event_id,timestamp,event_type,username,source_ip,session_id,resource,status,details
```

The first five fields require nonempty values. FILE_ACCESSED, FILE_MODIFIED, and ACCESS_DENIED also need a resource. Session, status, and details may be empty; unavailable sessions are not invented. Supported event types are LOGIN_FAILED, LOGIN_SUCCESS, FILE_ACCESSED, LOGOUT, FILE_MODIFIED, and ACCESS_DENIED. ISO timestamps require `Z` or an explicit timezone offset; both IPv4 and IPv6 are supported.

Invalid rows remain available with original values and errors, while other valid rows continue. Missing CSV schema, malformed/undecodable files, unsupported formats, and oversized files cause file-level errors. Every occurrence of a duplicate ID is rejected. CSV source positions are physical starting lines, including the header; JSON positions are 1-based array indexes. Normalized exports contain the nine standard fields and all valid events irrespective of filters.

## Algorithms

- **R1:** Five or more failures for the same account/IP within an inclusive 120-second sliding window. Windows sharing failures merge transitively; independent sequences remain separate.
- **R2:** Strictly later success within 120 seconds of an R1 qualifying endpoint. Each failure sequence supplies at most one R2; evidence excludes later failures.
- **R3:** Strictly later sensitive read within 300 seconds of R2, requiring matching account/IP and nonempty session ID. Sensitive resources match exactly and case-sensitively.
- **Cases:** Union-find over shared source-event IDs and checked parent references. Account/IP/time proximity alone does not link findings. Timelines deduplicate events and sort by UTC time, then event ID.

Default sensitive resources are confidential.pdf, employee_records.csv, and financial_report.xlsx. Edit the one-resource-per-line policy before running analysis; an empty policy disables R3. R1-only cases are Medium priority; any R2/R3 makes a case High. These priorities are educational labels.

R1 uses a **two-pointer sliding window**: advance the oldest failure until the current window is no longer than 120 seconds, then count failures. R2 uses **event-sequence matching and binary search** over qualifying endpoints. R3 uses **temporal matching** indexed by account, IP and session. Case grouping uses **union-find with path compression**, and timelines use sorting and deduplication. Deterministic SHA-256-based finding/case IDs make results reproducible; those IDs are distinct from the source-file integrity hash.

## Available samples and personal manual tests

Every listed file already exists under `data/samples/`. In the sidebar select **Current import**, then Log Import / Log Viewer → **Synthetic sample** → the filename. Use **Run security analysis** in Security Analysis. For screenshots and the expected R3 results, retain the three default sensitive-resource policy entries above. You can also upload the same files using Upload a file to demonstrate the uploader.

| Test case | Existing filename(s) | Actions after selection | Expected result | Screenshot |
| --- | --- | --- | --- | --- |
| Normal activity | normal_activity.csv | Run analysis; inspect Dashboard and Cases. | 30 valid; no findings/cases. | Yes: no-match result. |
| R1 failure burst | brute_force.csv | Run; select R1; inspect its evidence. | 1 R1, five supporting failures; 1 Medium case. | Yes: R1 evidence. |
| R2 login after failures | suspicious_login.csv | Run; select R2. | R1 + R2; six supporting events; 1 High case. | Yes: R2 explanation. |
| R3 and complete timeline | file_access_incident.csv | Run; select R3; open its case/timeline. | R1 + R2 + R3; 1 High case; seven ordered, unique events. | Yes: R3 and timeline, separately. |
| Independent cases | mixed_activity.csv | Run; inspect case list; filter priority/account. | 48 valid; 3 R1, 2 R2, 1 R3; 3 cases, 2 High/1 Medium. | Yes: dashboard/case overview. |
| JSON and filtering/export | sample_events.json | Import; filter event type/account/IP; download normalized CSV. | Seven valid; same analysis as file_access_incident.csv; CSV export contains all seven valid rows despite filters. | No: avoid repeating the CSV scenario. |
| Insufficient failures and boundary | edge_four_failures.csv; edge_five_boundary.csv; edge_outside_window.csv | Run each separately. | Four failures: no findings; exactly five over 120 seconds: 1 R1; span 121 seconds: no findings. | No. |
| Separate IPs/accounts | edge_multiple_ips.csv; edge_multiple_users.csv | Run each; inspect accounts/IPs. | Three failures per account/IP grouping; no findings or cases. | No. |
| Different session / clean login | edge_session_mismatch.csv; edge_success_only.csv | Run each; inspect sessions. | Mismatch: R1/R2 only, no R3; clean success: no findings. | No. |
| Out-of-order records | edge_out_of_order.csv | Run; inspect case timeline. | Same R1/R2/R3 case as the full incident; seven chronologically ordered events. | No: timeline already covered. |
| Invalid logs / duplicate IDs | invalid_logs.csv; edge_duplicate_ids.csv | Review error table; run analysis where enabled. | Invalid sample: 1 valid/5 invalid, no findings. Duplicate sample: 0 valid/2 invalid; analysis disabled. | Yes: invalid-row explanations. |
| Save, restart, reopen and verify | file_access_incident.csv | Analyze → Evidence Management → Save; stop/restart → sidebar Saved investigation → select snapshot → Verify stored evidence. | Same 3 findings/1 case; original hash; Verified status and audit entries. | Yes: evidence status and custody. |
| Forensic report | file_access_incident.csv | Save/reopen → Reports → Generate HTML report → preview/download. | Correct investigation ID, hash, findings, seven-event timeline, verification status and limitations. | Yes: report overview. |
| Evidence alteration | file_access_incident.csv, saved in disposable runtime only | Follow the isolated-runtime procedure below; edit that saved evidence file; click Verify stored evidence. | Modified status, integrity warning and audit entry; regeneration records failed verification. Editing only a sample copy does not tamper with its already-preserved evidence. | Yes: integrity warning. |

### Disposable manual integrity experiment (macOS)

Use a separate temporary runtime so your normal saved investigations remain untouched. In another Terminal, activate this project's environment and start a separate instance:

```sh
cd "/Volumes/Work/CSDF Mini Project"
source .venv/bin/activate
CYBERTRAIL_DATA_DIR="/private/tmp/CyberTrail-manual-tamper" python -m streamlit run app.py --server.port 8502
```

1. Open http://localhost:8502, select file_access_incident.csv, analyze, and save a clearly labelled disposable investigation.
2. Open Evidence Management and verify it first: expect Verified. Note its `evidence_id`.
3. In Finder, use Go → Go to Folder → `/private/tmp/CyberTrail-manual-tamper/evidence/`. The file is `<evidence_id>.evidence`; edit only that disposable file with a text editor, adding a character and saving it.
4. Click Verify stored evidence again: expect Modified and a warning. Generate a fresh report to see the failed status recorded.
5. Stop this instance with Control+C. The ordinary `runtime/` directory has not been used by this separate instance.

For an uncovered case such as a missing session, copy file_access_incident.csv to a separate personal testing folder, empty the `session_id` cell of its FILE_ACCESSED row, and upload that copy. Expect the record to remain valid but produce no R3. Keep existing project samples unchanged. Other useful copy-only variants are R2 success at 120/121 seconds after the final failure, or file access at 300/301 seconds after the success; exact limits qualify, one second beyond does not.

### Recommended academic screenshots (10)

1. Mixed-activity Dashboard with actual event/finding/case information.
2. Normal-activity no-findings result.
3. R1 explanation with five supporting failures.
4. R2 explanation with the successful login.
5. R3 explanation with the matching session and sensitive file.
6. Full seven-event case timeline.
7. Invalid-log errors with source rows and explanations.
8. Reopened saved investigation showing Verified evidence and expanded custody history.
9. Generated HTML report overview with investigation ID/hash and findings.
10. Disposable altered-evidence warning.

Capture screenshots only after personally confirming the displayed results. These ten views demonstrate distinct functionality without repeating CSV/JSON or every edge case.

## Demonstration workflow

1. Choose Current import → Log Import → Synthetic sample → file_access_incident.csv. Verify 7 valid records and its SHA-256 fingerprint.
2. Click Run security analysis. Expect 3 findings: one each of R1, R2, R3. Inspect a finding's supporting IDs.
3. Open Investigation Cases. Expect one High-priority case with seven observed events; compare the timeline with the rule explanations.
4. In Evidence Management, enter an investigation title and demo actor label, then Save current investigation.
5. Restart CyberTrail. In the sidebar select Saved investigation and reopen that snapshot. All sections now show its stored analysis.
6. Click Verify stored evidence, then Generate HTML report in Reports. Preview and download the result; browser print-to-PDF is optional.
7. Compare mixed_activity.csv: 6 findings and 3 separate cases. Compare normal_activity.csv: no findings or cases. invalid_logs.csv has 1 valid and 5 invalid rows because empty status is permitted.

For personal alteration testing, use the separate temporary-runtime procedure above. Do not alter the preserved evidence of an actual investigation or the project's original sample files.

## Evidence, audit, and backup

Preservation uses generated identifiers, exclusive creation, protected file permissions, and exact original bytes. Uploaded filenames are metadata only. Verification recomputes SHA-256 from the actual stored file and shows Verified, Modified, Missing, or Unavailable. Reports always perform a fresh check.

SQLite stores investigations, evidence metadata, events, findings, cases, their relational links, and custody actions. Foreign keys and parameterized queries preserve associations. Saves use transactions and remove newly created evidence files on handled failure. The API supports multiple imports per investigation when event IDs are unique across them; the UI saves one import per snapshot.

Custody entries use actual UTC times and record preservation/import at save time, hashing, analysis snapshot completion, verification, and report generation. Normal operations cannot update/delete history. Actor labels are local/demo labels, not authenticated people. A database administrator can still alter files or records; matching hashes and local audit history do not establish legal authenticity or admissibility.

**Backup:** stop CyberTrail and copy the entire configured runtime directory. Restore the database and evidence directory together, then reopen and verify. Never commit private evidence, runtime databases, secrets, or backups to Git.

## Tests and measured performance

```sh
source .venv/bin/activate
python -m pytest -q
python -m pytest tests/test_integration.py tests/test_app.py -v
python scripts/generate_logs.py
python scripts/benchmark.py
```

Previously recorded implementation verification: **194 tests passed, 0 failed**, including Streamlit AppTest and complete temporary-database workflows. Stage 5 was verified with 165 passing tests; Stage 6 with 179. Tests never use the real local evidence directory or database. These are historical results; personal manual testing does not require rerunning them.

Measured on Apple M4, macOS 26.5.2 arm64, Python 3.14.2, on 13 October 2026. Median milliseconds over five runs after warm-up:

| Events | Parsing | Detection | Correlation |
| ---: | ---: | ---: | ---: |
| 100 | 0.482 | 0.873 | 0.634 |
| 1,000 | 4.846 | 10.267 | 7.382 |
| 5,000 | 25.052 | 46.707 | 37.563 |
| 10,000 | 50.667 | 100.098 | 81.261 |

The benchmark uses deterministic independent suspicious sequences and excludes Streamlit rendering, storage, and report generation. Results depend on workload/hardware and are not a universal latency guarantee. See [final_testing.md](docs/final_testing.md) and [benchmark_results.json](docs/benchmark_results.json).

## Folder structure

```text
app.py                      Six-tab Streamlit application
cybertrail/
  parser.py                 Import validation and normalization
  detector.py               R1/R2/R3 algorithms
  correlator.py             Cases and chronological timelines
  evidence.py               Original-byte preservation and verification
  database.py               SQLite snapshots, relationships, custody
  reports.py                Escaped printable HTML reports
scripts/
  generate_logs.py          Deterministic sample generator
  benchmark.py              Repeated median core benchmarks
data/samples/               Explicitly synthetic CSV/JSON fixtures
tests/                      Unit, UI, and end-to-end tests
docs/                       Schema, algorithms, custody, reporting, results
requirements.txt            Dependencies
runtime/                    Created on save; excluded from Git
```

## CSDF syllabus alignment

This is a project-level mapping, not a claim that every lab assignment is completed. The consulted [SPPU 2019 curriculum, institution-hosted copy](https://www.kjei.edu.in/trinityacademy/assets/pdf/BE_Comp.pdf) covers evidence preservation/custody in Unit 4, forensic validation in Unit 5, and tool testing/reporting objectives around Unit 6. Group 1 Assignment 5 addresses logs and correlated events; CyberTrail imports logs rather than capturing live traffic. The cited CSDF Group 2 lists items 1 and 2, so the roadmap's “Group 2 Assignment 11” mapping is unverified.

| Syllabus area | CyberTrail demonstration |
| --- | --- |
| Unit 4 | Exact-byte preservation, custody actions, private local storage. |
| Unit 5 | Schema/IP/time validation, hash re-verification, source references. |
| Unit 6 / reporting objectives | Automated tool tests, observed-event timelines, qualified HTML conclusions. |
| Group 1 Assignment 5 | Structured-log import and evidence-based event correlation. |

## Known limitations and readiness

Automated checks pass and the application is ready for a local demonstration walkthrough. A real-browser visual review, actual browser upload/download, and printing check remain manual acceptance steps; screenshots are not fabricated. No native PDF generator is included.

Rules can flag legitimate retries and authorized sensitive reads. Missing/invalid records, inaccurate clocks, unavailable/reused sessions, and an incomplete resource policy affect conclusions. The project does not perform live capture, active prevention, attacker attribution, or independently authenticated chain of custody. Parsing is in memory up to the size limit, and the CSV reader's default individual-field limit remains. Normalized CSV can contain formula-like input strings; inspect untrusted exports as text before using spreadsheet software.

An abrupt crash between evidence-file creation and SQLite commit can leave an unreferenced file; handled failures are cleaned up. Reports reflect generation-time integrity and must be regenerated for a fresh status. No automatic Git commits, cloud deployment, or Stage 8 submission artifacts were created.

Further explanations: [dataset guide](docs/dataset_guide.md), [parsing](docs/log_parsing.md), [detection](docs/detection_algorithms.md), [correlation](docs/incident_correlation.md), [evidence management](docs/evidence_management.md), and [reporting](docs/forensic_reporting.md).
