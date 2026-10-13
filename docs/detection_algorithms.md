# Stage 4 — Suspicious activity detection

An observed event is a statement recorded in a log. A finding is a pattern calculated from those events using an explicit rule. A confirmed security incident requires further investigation and supporting context; these rules do not establish unauthorized access, password compromise, attacker identity, or criminal activity.

The detector consumes only `parse_logs(...).valid_records`. Invalid rows remain visible in the viewer and never enter analysis. Detection is local, deterministic, independent of Streamlit, and uses the standard library. The expected-results manifest is read only by tests. Neither the detector nor the application reads it.

## Functions and findings

`detect_repeated_failed_logins()` implements R1. `detect_suspicious_successful_logins()` uses R1 to implement R2. `detect_sensitive_file_access()` uses R2 to implement R3. `analyze_security_events()` runs all three and returns one stable list of findings. The standalone functions can calculate their preceding rules when those findings are not supplied. Supplied preceding findings must come from this detector and the same event collection.

Events are sorted by `(timestamp, event_id)` without changing the supplied dictionaries. The input contract requires normalized UTC datetimes, all standard fields, supported event types, nonempty account/IP/ID values, and unique event IDs. Raw, unparsed records are not supported. Parsing remains the single source of value validation.

Each finding is a dictionary containing `finding_id`, `rule_id`, `rule_name`, `severity`, `username`, `source_ip`, `start_time`, `end_time`, `supporting_event_ids`, `explanation`, `session_id`, and `related_finding_ids`. Times are UTC datetimes. Evidence IDs are sorted by time and ID; source rows remain in the imported events.

Finding IDs consist of the rule prefix and full SHA-256 digest of the rule, account/IP, session, and supporting IDs/timestamps. They are stable under input reordering. Treat them as identifiers for findings in an import, not globally unique forensic case IDs or evidence hashes. Ordering is by start time, end time, rule, and finding ID. Medium (R1) and High (R2/R3) are academic demonstration priorities, not standardized risk assessments.

R1 adds `qualifying_end_event_ids`, recording every failure endpoint at which the rolling window qualified. R2 adds `login_event_id`; R3 adds `login_event_id` and `file_event_id`. Parent finding references preserve rule lineage without implementing a case-management or incident-reconstruction system.

## R1: Sliding-window failure detection

R1 detects at least five LOGIN_FAILED events for exactly the same `(username, source_ip)` within **120 seconds inclusive**. Separate accounts and IPs are never combined. For example, failures at 0, 30, 60, 90, and 120 seconds qualify; changing the last time to 121 seconds leaves only four events in any window.

A left pointer moves forward while the oldest failure is more than 120 seconds behind the current failure. If at least five remain, the current window qualifies. Each failure is visited by both pointers at most once.

```text
group sorted LOGIN_FAILED events by account and IP
for each group:
    left = 0
    for each failure at position right:
        advance left while time[right] - time[left] > 120 seconds
        if right - left + 1 >= 5:
            if this window shares a failure with the previous merged sequence:
                extend that sequence through right
            otherwise:
                start a new sequence covering left through right
            record right as a qualifying endpoint
    emit one R1 finding per merged sequence
```

**Grouping policy:** windows merge if their failure-index ranges overlap (share at least one failure), including transitively. They do not merge merely because they belong to one account/IP. A new qualifying window with no shared failure starts a distinct finding. Nonqualifying trailing failures do not extend evidence or the eligibility time. Non-failure events, including successful logins, do not split an R1 group.

Ten failures spaced 20 seconds apart produce one merged R1 finding, not six redundant findings. Its full evidence spans 180 seconds: each constituent qualifying window satisfies the 120-second rule, even though their union spans longer. Two failure bursts separated by several minutes produce two findings.

## R2: Sequence matching

R2 requires a LOGIN_SUCCESS from the same account/IP, **strictly later** than a qualifying failure endpoint and **at most 120 seconds later**. Success at the identical timestamp does not qualify, even if its event ID sorts later.

The detector indexes all R1 qualifying endpoints by account/IP, then uses binary search to select the latest endpoint strictly preceding each success. The earliest eligible success consumes its merged R1 sequence; further successes cannot reuse that sequence, even if the merged failure burst continues. Different R1 groups can each yield one R2.

```text
index qualifying endpoints for each account/IP, sorted by time and event ID
for each LOGIN_SUCCESS in deterministic chronological order:
    find the latest qualifying endpoint strictly before success
    if no endpoint, endpoint is older than 120 seconds, or sequence is consumed:
        skip
    collect the merged sequence's failure evidence through that endpoint only
    emit R2 with those failures and this success
    mark the sequence consumed
```

Distinct R1 groups cannot have qualifying endpoints whose eligibility intervals overlap: if a later qualifying window were within 120 seconds of the previous group's last failure, that failure would still belong to its maximal window, merging the groups. Thus an eligible latest endpoint identifies the applicable group; a consumed group does not require rescanning older groups.

**No future evidence:** a success midway through a long merged failure burst uses only the failure prefix that already qualified before that success. Later failures remain in the retrospective R1 finding but not in R2's supporting IDs. The parent reference identifies that R1 group; it does not mean every event in the parent preceded the login.

## R3: Session and time matching

R3 detects a FILE_ACCESSED event **strictly after** an R2-flagged login and **no more than 300 seconds later**, including exactly 300. It requires the same username, source IP, and exact nonempty session ID. Missing/different sessions cannot qualify, even if account/IP/time match.

The default case-sensitive, exact resource set is:

- `confidential.pdf`
- `employee_records.csv`
- `financial_report.xlsx`

There is no substring, basename, wildcard, or path inference: `folder/confidential.pdf` requires its own explicit policy entry. The API accepts `sensitive_resources`; the interface accepts one filename/path per line. An empty set disables R3.

```text
index R2 logins by account, IP, and nonempty session ID
for each FILE_ACCESSED whose resource exactly matches the policy:
    find the latest matching R2 login strictly before this access
    if elapsed time is at most 300 seconds:
        emit R3 with the R2 supporting events plus this access
        retain R1 and R2 parent references
```

One distinct file-access event produces at most one R3, selecting the most recent matching R2 login if the session identifier was reused. Several distinct sensitive reads may produce several R3 findings; those are distinct evidence events, not overlapping-window duplicates. FILE_MODIFIED and ACCESS_DENIED do not trigger R3.

## Interface

Import a file or choose a synthetic sample, then click **Run security analysis**. Analysis uses every valid event, irrespective of Log Viewer filters. The result displays total findings, R1/R2/R3 counts, a rule-count chart, rule/severity filters, and a selectable finding with its explanation and supporting imported events.

Changing the source fingerprint or sensitive-resource policy hides previous results until analysis is rerun. Filtering findings or the event table does not alter the calculated results. Source IDs and row positions are available when inspecting evidence. Original bytes and the import hash remain unchanged. No-match messages apply only to the imported valid records and chosen policy.

## Complexity

For n events, sorting is O(n log n). R1's sliding window and component merging are O(n) after sorting. R2/R3 build indexes and use O(log n) binary searches per relevant event. The coordinating function performs a constant number of sorts; it does not scan the complete event list separately for every success or access.

Let E be the total number of supporting-ID references in output findings. Including evidence sorting, a general upper bound is O((n + E) log(n + 1)) work, with O(n + E) memory. Evidence is already chronological when assembled, so Python's adaptive sort is near-linear for those lists. Numerous R3 reads can each repeat extensive R2 evidence, so output size itself can become large. Tests exercise a 5,000-failure overlapping sequence without redundant R1 findings.

## Limitations and false positives

Repeated password mistakes, test scripts, or legitimate logins after failures may match R1/R2. A permitted sensitive-file read may match R3. Shared IPs do not identify people, and a logged session ID is not independently verified authentication evidence. The rules do not infer session termination from LOGOUT or track unflagged subsequent logins; complete reconstruction belongs to later stages. R2's one-use policy deliberately suppresses repeated successes from a merged burst and may omit another suspicious login in that same burst.

Missing/invalid records, incomplete logs, inaccurate clocks, manipulated source data, and an incomplete sensitive-resource policy can hide patterns or produce misleading associations. Additional investigation is needed. No risk scoring, machine learning, active scanning, incident grouping, SQLite persistence, chain of custody, or reporting is implemented in Stage 4.

## Verification

```sh
source .venv/bin/activate
python -m pytest -q
python -m pytest tests/test_detector.py -q
python -m streamlit run app.py
```

Executed on 13 October 2026 with Python 3.14.2 and pytest 9.1.1:

- Detector tests: **57 passed in 0.08 seconds**.
- Complete suite: **154 passed in 2.40 seconds**. This includes Stage 2 reproducibility, Stage 3 parser checks, and Streamlit AppTest coverage of all six demonstration datasets, evidence inspection, rule/severity filters, and invalidation of stale results.

| Sample | R1 | R2 | R3 | Total |
| --- | --- | --- | --- | --- |
| normal_activity.csv | 0 | 0 | 0 | 0 |
| brute_force.csv | 1 | 0 | 0 | 1 |
| suspicious_login.csv | 1 | 1 | 0 | 2 |
| file_access_incident.csv | 1 | 1 | 1 | 3 |
| mixed_activity.csv | 3 | 2 | 1 | 6 |
| invalid_logs.csv | 0 | 0 | 0 | 0 |

All 16 Stage 2 samples are covered by parser-to-detector tests against the test-only manifest. No fixture corrections or new dependencies were needed. AppTest executes the page, but a real-browser upload/download and visual review remain manual checks.
