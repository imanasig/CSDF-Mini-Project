# Stages 5–7 verification record

Executed on 13 October 2026 on Apple M4 (CPU checked with `sysctl -n machdep.cpu.brand_string`), macOS 26.5.2 arm64, Python 3.14.2, pytest 9.1.1. Results below were measured/executed, not inferred from expected outputs.

## Sequential stage verification

| Stage | Executed command | Actual outcome |
| --- | --- | --- |
| 5: correlation and timeline UI | `python -m pytest -q` | 165 passed in 2.00 seconds. |
| 6: preservation, SQLite, HTML, restart UI | `python -m pytest -q` | 179 passed in 2.67 seconds. |
| 7: complete final build | `python -m pytest -q` | **194 passed in 3.36 seconds; 0 failed.** |

Stage 5 was completed and checked before Stage 6. Stage 6 persistence/reporting was completed and checked before Stage 7. Original R1/R2/R3 semantics, original sample bytes, and dependency requirements were preserved.

## Verified scenarios

| Scenario | Expected and verified result |
| --- | --- |
| Normal activity | 30 valid events; 0 findings; 0 cases; saves/reopens and generates a zero-finding report. |
| Brute force | 5 valid events; 1 R1; 1 Medium case; save/reopen preserves references. |
| Suspicious login | 6 valid events; R1 + R2; 1 High case and chronological timeline. |
| Sensitive file access | 7 valid events; R1 + R2 + R3; 1 High case; seven original event IDs retained in report. |
| Mixed activity | 48 valid events; 3 R1, 2 R2, 1 R3; 3 separate cases (2 High, 1 Medium). |
| Malformed sample | 6 total, 1 valid, 5 invalid; errors/original values retained; no findings/cases. |
| Duplicate IDs | Both occurrences rejected; no fabricated evidence. |
| Missing support/invalid parent session | Correlation raises an explicit error rather than inventing relationships. |
| Rerun/order stability | Event/finding/case IDs, chronology, evidence, and severity remain deterministic; objects are not mutated. |
| SQLite restart | Fresh store connection and fresh AppTest session reopen original findings/cases and normalized events. |
| Save failure | Simulated transaction failure leaves no partial investigation/events or newly created evidence. |
| Path/injection handling | Generated IDs prevent filename traversal; exclusive files prevent overwrites; SQL values are parameterized; report HTML escapes untrusted text. |
| Evidence alteration/removal | Only disposable test files are changed; actual hash verification reports Modified/Missing and records audit actions. |
| Special/symlink evidence | Unavailable status; no following symlinks or blocking on a FIFO. |
| Custody | Real UTC operations; normal update/delete rejected; report-generation entry accurately labelled. |
| Damaged storage | Invalid database produces a helpful UI error; inconsistent saved payload is rejected. |
| Multi-investigation isolation | Selecting normal/attack snapshots updates every section; cross-investigation evidence FK violation is rejected. |
| UI filters/state | Event/rule/severity/case filters, explanations, evidence, stale-policy invalidation, and previous current import/custom policy after saved-workspace switch all verified. |

All persistence tests use pytest temporary databases and evidence directories. `tests/conftest.py` directs UI runtime storage to a unique temporary directory. The normal real runtime directory is never modified by automated tests.

## Problems found and fixed

Read-only Streamlit dataframes do not expose their keys to AppTest; UI tests now locate tables within their workflow tabs. A changing default sample index could reset a widget after repeated selections; explicit widget keys and persistent preferences now preserve the user's choice. Regression tests also preserve the current source and custom policy across a saved/current investigation switch.

Fresh integrity checks invalidate earlier report previews, preventing the UI from offering a known-stale verified report after detection of altered evidence. Verification also rejects non-regular files without blocking. SQLite load checks catch inconsistent counts/timelines rather than silently displaying damaged snapshots. None of these changes alters detection semantics.

## Benchmark methodology and actual results

Command executed:

```sh
python scripts/benchmark.py --hardware-label 'Apple M4 (verified with sysctl)' --output docs/benchmark_results.json
```

Core-only measurements use `time.perf_counter()`, one warm-up pass, and five timed repetitions per size. Data is deterministic JSON consisting of independent seven-event suspicious sequences (with a partial final sequence as needed). Dataset generation is outside timed intervals. Parsing, detection, and correlation are measured separately; medians are milliseconds. Persistence, report generation, browser/UI rendering, and resource consumption are not benchmarked.

| Events | Findings | Cases | Parsing ms | Detection ms | Correlation ms |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 42 | 14 | 0.482 | 0.873 | 0.634 |
| 1,000 | 428 | 143 | 4.846 | 10.267 | 7.382 |
| 5,000 | 2,142 | 714 | 25.052 | 46.707 | 37.563 |
| 10,000 | 4,284 | 1,428 | 50.667 | 100.098 | 81.261 |

The recorded environment and measurement time are in [benchmark_results.json](benchmark_results.json). Hardware auto-discovery was restricted in the sandbox, so the CPU was independently read using the approved read-only command and supplied as an explicit label. On an ordinary local terminal `python scripts/benchmark.py` attempts automatic CPU discovery; if unavailable it says Unknown. Results describe this workload and run, not all possible input distributions.

## Reproduce tests and launch

```sh
source .venv/bin/activate
python -m pytest -q
python -m pytest tests/test_integration.py tests/test_app.py -v
python scripts/benchmark.py
python -m streamlit run app.py
```

## Manual acceptance still to perform

Automated Streamlit smoke/UI checks passed. A real browser was not driven or visually reviewed; AppTest's upload path uses a mock UploadedFile because direct uploader injection is unavailable.

1. Upload file_access_incident.csv in a real browser and check the source hash and seven valid rows.
2. Run analysis; inspect R1/R2/R3, one High case, and its seven-event timeline.
3. Save, restart, reopen from the sidebar, verify original evidence, and preview/download HTML.
4. Open the downloaded file and check browser printing; optionally print to PDF.
5. Repeat mixed and normal samples and check table/chart readability on the presentation display.

The automated build is ready for that walkthrough; full manual academic-demonstration acceptance is pending. Stage 8 report writing, screenshots, GitHub submission, and viva preparation have not begun.

## Remaining limits

Reports are HTML with optional browser print-to-PDF, not native PDF output. Audit storage and file hashes do not establish legal authenticity. One evidence import per UI snapshot is supported; multiple imports are available through the API only with unambiguous event IDs. Live capture, prevention, attribution, and real session authentication are absent. In-memory uploads are limited to 10 MiB and the CSV reader has its standard field-length limit. Abrupt save-time crashes can leave orphan files; handled transaction failures are rolled back and cleaned up. Back up the stopped database and evidence directory together.
