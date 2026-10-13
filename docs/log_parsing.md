# Log parsing and validation — Stage 3

Parsing turns uploaded text into individual event records. Validation checks whether those records are usable. Normalization gives valid records a consistent form so later algorithms can compare times and identifiers reliably. None of these steps detects an attack.

## How the parser works

`parse_logs(original_bytes, filename)` in `cybertrail/parser.py`:

1. Calculates SHA-256 from the exact supplied bytes and retains those immutable bytes in its result.
2. Checks the `.csv`/`.json` extension and 10 MiB size limit (10,485,760 bytes; equality is allowed).
3. Decodes UTF-8, accepting an optional UTF-8 byte-order mark. It does not evaluate content or contact addresses in logs.
4. Reads CSV records or a JSON array of event objects. JSON may also wrap the array in an `events` key.
5. Checks each record's schema and values and counts IDs across the entire file. Every occurrence of a repeated ID is invalid, including when another occurrence has a different validation problem.
6. Keeps invalid original records with errors and source positions. Valid records are sorted chronologically; equal timestamps retain input order.

`ImportResult` contains import metadata, original bytes, total count, valid records, invalid records, and file-level errors. `filter_events()` selects events by exact username, source IP, and event type. `export_events_csv()` writes all supplied valid events using the nine standard schema fields, UTC timestamps, empty optional cells, and UTF-8 encoding.

## Schema and validation policy

All nine keys/columns must exist: `event_id`, `timestamp`, `event_type`, `username`, `source_ip`, `session_id`, `resource`, `status`, and `details`. Extra keys/columns are allowed but are not included in normalized events. JSON field values must be strings or null; lists, objects, numbers, and booleans are not coerced into invented text.

The first five fields must have nonempty values. String values have surrounding whitespace trimmed. Empty optional strings and JSON null become `None`. IDs and usernames remain case-sensitive. Event types are case-normalized to uppercase, accepting exactly LOGIN_FAILED, LOGIN_SUCCESS, FILE_ACCESSED, LOGOUT, FILE_MODIFIED, and ACCESS_DENIED; aliases and misspellings are rejected.

Timestamp format is `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` or the same datetime with an explicit `±HH:MM` offset. Valid offsets are converted to timezone-aware UTC datetime objects. No timezone is assumed for naive timestamps. Invalid dates, timezone offsets, or malformed text are rejected. Fractional seconds may have one to six digits; leap seconds are not supported.

IPv4/IPv6 syntax is checked with `ipaddress.ip_address()`. Valid addresses are rendered canonically; IPv6 zone identifiers are rejected. Addresses are never contacted.

FILE_ACCESSED, FILE_MODIFIED, and ACCESS_DENIED require a nonempty resource. Session, status, and details values are optional for every event. Missing sessions are preserved rather than invented. The additional `session_correlation_eligible` flag means a nonempty session identifier is available for a non-failed-login event; it does **not** prove authentication, a match to a login, or a suspicious connection. Later correlation must verify those conditions independently.

Every normalized event also retains `source_row`. CSV uses the physical starting line (header is line 1), including for quoted multiline records. JSON uses a 1-based array position. Exports contain the nine schema fields only; source positions and eligibility remain visible in the viewer. Original source positions cannot be reconstructed from a normalized export alone.

## Error behavior and examples

For example, `2026-10-13T15:30:00+05:30` becomes `2026-10-13T10:00:00Z`, while `not-a-timestamp` is invalid. `999.1.1.1` is an invalid IP address. A file-access row without a resource is invalid; one with a resource but no session remains valid and ineligible for session-based correlation.

Record-level errors do not prevent other records from being imported. CSV rows with a wrong number of cells retain their original column list and values. Non-object JSON entries remain available as invalid original values. Duplicate event IDs are rejected rather than silently deduplicated.

File-level failures include unsupported formats, excessive size, invalid encoding, missing CSV headers/columns, duplicate CSV headers, malformed CSV/JSON, duplicate JSON object keys, and incorrect JSON top-level structure. If reading fails, no partial analysis is returned. Header-only CSV and an empty JSON array are valid imports with zero records. A completely empty CSV has no schema and is rejected.

The Stage 2 `invalid_logs.csv` has **6 total, 1 valid, 5 invalid** records under Stage 3 rules: its final row has an empty status, which Stage 3 explicitly permits. The Stage 2 fixture contract remains unchanged. `edge_duplicate_ids.csv` has **2 total, 0 valid, 2 invalid** records. All other supplied samples are valid.

## Viewer and integrity

Choose Upload a file or Synthetic sample. The viewer shows the filename, byte size, SHA-256 fingerprint, actual record counts, and a UTC event table. Empty filter selections show all events. The error table includes original values and explanations. Download exports **all valid events**, regardless of current filters.

Original bytes stay in memory during the import. Filtering and normalization never mutate them; exports are derived files. A fingerprint helps compare byte integrity but does not establish authenticity, completeness, ownership, or chain of custody. Persistent evidence storage belongs to Stage 6.

## Complexity and limits

For n records and b input bytes, reading/hashing/validation uses O(b + n) work (assuming bounded field lengths); duplicate counting is O(n), and chronological sorting is O(n log n). Memory is O(b + n), including raw and normalized data. The parser processes files in memory up to the size limit and has a test with 5,000 events. The standard-library CSV reader also has its default field-length limit; excessively long individual CSV fields produce a file-level error.

The parser performs no timestamp inference, session fabrication, detection, or storage. Stage 4's independent detector now applies R1/R2/R3; see [detection_algorithms.md](detection_algorithms.md). The parser does not validate whether a claimed session genuinely authenticated. Normalized CSV retains user-provided strings; inspect untrusted exports as text because spreadsheet applications may interpret formula-like cells.

## Reproduce verification

```sh
source .venv/bin/activate
python -m pytest -v
python -m pytest tests/test_parser.py tests/test_app.py -v
python -m streamlit run app.py
```

Parser tests exercise all 16 samples, schema/value failures, malformed files, size boundaries, duplicates, UTC/IPv6 normalization, source tracing, hash preservation, export round trips, filters, and 5,000 records. AppTest covers the home page, sample import, combined filters, JSON import, validation errors, and a mocked UploadedFile path (AppTest does not directly supply uploader bytes). A real-browser upload/download check is still a manual acceptance step.

Executed on 13 October 2026 with Python 3.14.2 and pytest 9.1.1: `python -m pytest -v` completed with **90 passed in 1.04 seconds**. An earlier run had one incorrect test assertion that assumed normalized export must differ from an already-normalized source; that assertion was corrected. Stage 2 reproducibility tests also passed, and no sample bytes or dependencies were changed.
