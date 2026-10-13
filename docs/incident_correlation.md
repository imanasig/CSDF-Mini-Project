# Incident correlation — Stage 5

An event is observed log data; a finding is a rule-generated interpretation; a case groups findings for investigation. A case does not confirm a crime. `correlate_findings(findings, events)` links findings only through common source event IDs and parent references backed by shared evidence. R3-to-R2 references additionally check the matching login, account/IP, and nonempty session ID.

The implementation uses union-find with path compression. Event IDs index the findings that include them, avoiding a pairwise scan of every finding. Missing events, duplicate input IDs, missing parent findings, and inconsistent session relationships cause explicit errors. No events are invented. Account, IP, or time proximity alone never create an edge.

```text
create one union-find node per finding
for each supporting event ID:
    union findings that cite the same actual source event
validate parent references and union their endpoints
collect connected components
for each component:
    deduplicate supporting event IDs
    sort actual events by UTC timestamp, then event ID
    annotate each event with findings that included it
    emit a deterministic case
```

For file_access_incident.csv, R1 cites EVT-001–005, R2 cites EVT-001–006, and R3 cites EVT-001–007. Shared evidence joins all three into one High-priority case with seven timeline events. Mixed activity produces three independent cases. R1-only cases are Medium; any R2/R3 makes a case High. These are demonstration priorities.

IDs are `INC-` plus SHA-256 of sorted component finding IDs. Cases are stable across input reordering. They are scoped to an investigation, not global case identifiers. Each timeline event retains its source row and adds `included_by_finding_ids`; observed values and rule explanations are displayed separately.

For n source events, f findings, and e supporting references, grouping uses O(n + f + e α(f)) work plus timeline sorting (at most O(e log e)) and O(n + f + e) memory. α is the near-constant union-find factor. This is basic evidence correlation, not actor attribution or complete authentication-session reconstruction. Genuine reused/incorrect event IDs in upstream data could create false associations; the parser rejects duplicates within an import.
