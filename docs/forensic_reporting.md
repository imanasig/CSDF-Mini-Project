# Forensic reports — Stage 6

`generate_html_report()` renders a printable academic HTML report from a saved investigation snapshot and actual integrity-check results. `generate_saved_report()` re-verifies every preserved file, renders successfully, appends a generation audit entry, and includes that entry in the returned report.

Reports include investigation ID, actual generation time in UTC, original filename/hash, verification status/check time, record counts, findings with supporting IDs and explanations, cases and chronological observed-event timelines, evidence/source-row references, custody activity, algorithms/thresholds, sensitive-resource policy, limitations, and an evidence-based conclusion. Zero-finding investigations are valid reports. Failed/missing evidence is reported explicitly and never described as verified.

Every variable inserted into HTML is escaped with `html.escape`, including filenames, usernames, descriptions, policy entries, and custody text. Reports contain no JavaScript, remote fonts, or remote assets. The UI previews the generated document and offers an HTML download. Browser print-to-PDF is optional; no native PDF dependency is required. Reports are derived documents and do not replace original evidence.

Audit history records report generation for preview/download, not an unobserved browser download. Cached reports reflect their generation-time check and history; regenerate to obtain fresh verification. Sensitive account/IP/resource references are included where needed for evidence interpretation; raw log details and rejected original values are omitted from the report to avoid unnecessary disclosure.

The report distinguishes observed events from automated interpretations. Legitimate retries/logins/file reads can match the rules. A hash match does not prove authenticity or crime; an integrity failure requires further review. Custody activity is a local educational record, not legal certification.
