# Synthetic dataset guide — Stage 2

All records are fictional. They use fixed times on 13 October 2026, invented `demo_` accounts, private IPs, or documentation-reserved addresses (`198.51.100.0/24` and `203.0.113.0/24`). No real credentials or personal information are included. Generation uses only Python's standard library and has no network access.

## Schema

CSV files have the following columns in this order. JSON is a top-level array of objects with exactly the same keys and string values. Every column/key is present; missing optional values are the empty string `""` (an empty CSV cell), never JSON null.

| Field | Meaning and requirements |
| --- | --- |
| event_id | Nonempty identifier, unique within a valid dataset. IDs may repeat across different datasets. |
| timestamp | Event time, strictly `YYYY-MM-DDTHH:MM:SSZ`; `Z` means UTC, not local Indian time. |
| event_type | One of the six supported types below. |
| username | Nonempty fictional account name. |
| source_ip | Valid IPv4 address recorded for the event. |
| session_id | Required for successful login and authenticated activity in these fixtures; empty for failed login. |
| resource | Required for file access, file modification, and access denial; empty for login and logout. |
| status | FAILURE for LOGIN_FAILED, DENIED for ACCESS_DENIED, SUCCESS for other types. |
| details | Nonempty human-readable fictional event description; not a detection instruction. |

`event_id`, `timestamp`, `event_type`, `username`, `source_ip`, `status`, and `details` are mandatory for every fixture row. Future input formats may permit unavailable session IDs; their absence must prevent confirmed R3 correlation.

| Event type | Additional fixture fields | Meaning |
| --- | --- | --- |
| LOGIN_FAILED | No session/resource | Authentication failed. |
| LOGIN_SUCCESS | session_id | Authentication established a session. |
| FILE_ACCESSED | session_id, resource | Authenticated file read. |
| FILE_MODIFIED | session_id, resource | Authenticated file update. |
| ACCESS_DENIED | session_id, resource | Authenticated account lacked permission. |
| LOGOUT | session_id | Session ended. |

## Intended future rule interpretation

- **R1:** At least five LOGIN_FAILED events for the same account and source IP within a rolling, inclusive 120-second window. A span of exactly 120 seconds qualifies; 121 seconds does not.
- **R2:** LOGIN_SUCCESS for that same account and IP after the qualifying sequence's last failure, no more than 120 seconds later.
- **R3:** FILE_ACCESSED for a sensitive resource within 300 seconds after the R2 login, with matching account, IP, and nonempty authenticated session ID. For these fixtures, `confidential.pdf` is the explicitly designated sensitive resource. Stage 4 will define the actual sensitivity configuration.

The listed rules describe fixture expectations, not precomputed alerts. Stage 4 now computes findings independently; see [detection_algorithms.md](detection_algorithms.md). Rules retain the original supporting event IDs. Sorting out-of-order input does not change its IDs. Duplicate IDs require validation errors before reliable evidence attribution.

## Main demonstration datasets

| File | Rows | Intentionally inserted behavior | Expected later result / demonstration |
| --- | --- | --- | --- |
| normal_activity.csv | 30 | Five employees each have one failed login, success, ordinary read/update, permission denial, and logout. | No R1/R2/R3; ordinary failures and permission refusals alone are not these scenarios. |
| brute_force.csv | 5 | Same account/IP fails at 0, 20, 40, 60, 80 seconds. | R1 only; inspect five supporting failures. |
| suspicious_login.csv | 6 | Same failures, then success at 110 seconds with SES-A001. | R1 and R2; success occurs 30 seconds after the fifth failure. |
| file_access_incident.csv | 7 | Same failures and success, then confidential.pdf read at 170 seconds in SES-A001. | R1, R2, R3; trace five failures → success → file access. |
| mixed_activity.csv | 48 | Thirty normal rows plus independent failure-only, failure/success, and failure/success/file groups. | Three R1 sequences, two R2 logins, one R3 access. Inspect accounts/IPs separately. No alert-merging policy is prescribed. |
| invalid_logs.csv | 6 | One defect per row: bad timestamp, missing username, invalid IP, unsupported event type, missing ID, missing status. | Stage 3 validation errors; no trustworthy alert expectation. Headers remain intact; required cell values are missing. |
| sample_events.json | 7 | Same records and IDs as file_access_incident.csv. | Same future rules, demonstrating CSV/JSON equivalence. These are alternate representations of one sample, not independent evidence. |

Stage 3 clarification: its parser permits an empty `status` value. The last row of `invalid_logs.csv` therefore imports as valid under Stage 3; the other five rows remain invalid. This does not change the original Stage 2 data. See [log_parsing.md](log_parsing.md) for the implemented input contract.

In mixed_activity.csv, supporting groups are EVT-031–035 (`demo_guest`, 198.51.100.21), EVT-036–041 (`demo_operator`, 203.0.113.22), and EVT-042–048 (`demo_admin`, 198.51.100.23). Chronological sorting interleaves ordinary events without changing these IDs.

## Edge-case datasets

| File | Fixture detail | Expected later result |
| --- | --- | --- |
| edge_four_failures.csv | Four failures over 90 seconds. | No R1. |
| edge_five_boundary.csv | Five failures at 0, 30, 60, 90, 120 seconds. | R1, inclusive boundary; no success or file event. |
| edge_outside_window.csv | Five failures at 0, 30, 60, 90, 121 seconds. | No R1; only four fit within any 120-second window. |
| edge_multiple_ips.csv | Six failures, three each from two IPs, same account. | No R1; IPs must not be combined. |
| edge_multiple_users.csv | Six failures, three each for two accounts, same IP. | No R1; accounts must not be combined. |
| edge_out_of_order.csv | Shuffled exact file-access incident. | R1/R2/R3 after chronological normalization. |
| edge_success_only.csv | One successful login, no preceding failures. | No R1/R2/R3. |
| edge_session_mismatch.csv | Earlier SES-OTHER login, then R1/R2 sequence using SES-A001, then sensitive read in SES-OTHER. | R1/R2 only. File read may be shown as possibly related later; matching account/IP/time cannot confirm R3 across sessions. |
| edge_duplicate_ids.csv | Two different failed events share EVT-001. | Stage 3 duplicate-ID validation error; excluded from valid-schema uniqueness checks. |

## Regeneration and tests

From the project directory:

```sh
source .venv/bin/activate
python scripts/generate_logs.py
python -m pytest -v
```

To generate a separate copy without changing the checked-in samples:

```sh
python scripts/generate_logs.py --output-dir /tmp/cybertrail-samples
```

The generator rewrites only its 16 named outputs, with fixed timestamps, IDs, record order, UTF-8 encoding, and LF line endings. It does not delete files or overwrite unrelated filenames and rejects output-file symlinks. No random seed is needed because no randomness is used.

`tests/expected_results.json` is a test-only manifest of row counts, expected rule names, and supporting event numbers. Invalid datasets have `invalid: true`. Neither the generator nor the application reads this manifest. It contains fixture expectations, not fabricated production alerts.

`tests/test_generate_logs.py` checks schema, uniqueness, UTC dates, types, status/session consistency, IP ranges, byte-for-byte reproducibility, unrelated-file preservation, known sequence timings, malformed rows, and negative fixtures. These are fixture-specific assertions, not a reusable detection engine. Future Stage 4 tests must execute the actual algorithms against these expectations.

## Executed verification

On 13 October 2026, using Python 3.14.2 and pytest 9.1.1:

- `python scripts/generate_logs.py`: generated all 16 named synthetic datasets.
- `python -m pytest -v`: **28 passed in 0.65 seconds**, including the unchanged Stage 1 Streamlit home-page smoke test.
- The regeneration test produced identical bytes on two runs in a temporary directory and matched the checked-in samples; unrelated content was preserved.

No browser visual review or future parser/detector testing was performed in this stage. No dependencies were added.
