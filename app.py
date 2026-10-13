"""CyberTrail: one selected investigation across six Streamlit workflow tabs."""

import hashlib
import json
import os
import sqlite3
from pathlib import Path

import streamlit as st

from cybertrail.correlator import correlate_findings
from cybertrail.database import InvestigationStore
from cybertrail.detector import SENSITIVE_RESOURCES, analyze_security_events
from cybertrail.parser import MAX_FILE_BYTES, export_events_csv, filter_events, parse_logs
from cybertrail.reports import generate_saved_report

STORAGE_ERRORS = (OSError, sqlite3.Error, ValueError, KeyError, TypeError)


def apply_visual_style():
    """Small presentation improvements that respect Streamlit's light/dark theme."""
    st.html("""
    <style>
      .stMainBlockContainer { max-width: 1480px; padding-top: 2rem; }
      h1 { letter-spacing: -0.045em; }
      h2, h3 { letter-spacing: -0.02em; }
      [data-testid="stSidebar"] { border-right: 1px solid rgba(128,128,128,.18); }
      [data-testid="stMetric"] {
        background: var(--secondary-background-color);
        border: 1px solid rgba(128,128,128,.18);
        border-radius: 14px;
        padding: 1rem 1.2rem;
      }
      [data-testid="stMetricValue"] { font-weight: 650; }
      [data-baseweb="tab-list"] { gap: .35rem; }
      [data-baseweb="tab"] { padding: .7rem 1rem; border-radius: 9px 9px 0 0; }
      [data-baseweb="tab"][aria-selected="true"] {
        background: var(--secondary-background-color);
        box-shadow: inset 0 -3px #0f766e;
      }
      [data-testid="stDataFrame"], [data-testid="stExpander"] {
        border-radius: 10px; overflow: hidden;
      }
      [data-testid="stAlert"] { border-radius: 10px; }
      button[kind="primary"] { background-color: #0f766e; border-color: #0f766e; color: white; }
      button[kind="primary"]:hover { background-color: #115e59; border-color: #115e59; color: white; }
      @media (max-width: 768px) {
        .stMainBlockContainer { padding-top: 1rem; }
        [data-baseweb="tab"] { padding: .6rem .7rem; }
        [data-testid="stMetric"] { padding: .75rem; }
      }
    </style>
    """)


def local_store():
    directory = Path(os.environ.get("CYBERTRAIL_DATA_DIR", Path(__file__).resolve().parent / "runtime"))
    return InvestigationStore(directory / "cybertrail.db", directory / "evidence")


def table(rows, *, key=None):
    if rows:
        st.dataframe(rows, hide_index=True, width="stretch", key=key)


def select_import():
    sources = ["Upload a file", "Synthetic sample"]
    source = st.radio("Import source", sources,
                      index=sources.index(st.session_state.get("import_source_preference", sources[0])), horizontal=True, key="import-source-widget")
    st.session_state["import_source_preference"] = source
    data, filename = None, None
    if source == "Upload a file":
        uploaded = st.file_uploader("Choose CSV or JSON logs (maximum 10 MiB)", type=["csv", "json"])
        if uploaded is not None:
            if uploaded.size > MAX_FILE_BYTES:
                st.error("File exceeds the 10 MiB limit (10,485,760 bytes).")
                return None
            filename, data = uploaded.name, uploaded.getvalue()
    else:
        samples = Path(__file__).resolve().parent / "data/samples"
        choices = sorted(path.name for path in samples.iterdir() if path.suffix in {".csv", ".json"}
                         and not path.is_symlink()) if samples.is_dir() else []
        choices = ["Choose a sample…"] + choices
        previous = st.session_state.get("sample_preference", choices[0])
        filename = st.selectbox("Synthetic dataset", choices, index=choices.index(previous) if previous in choices else 0, key="sample-widget")
        st.session_state["sample_preference"] = filename
        if filename != "Choose a sample…":
            try:
                data = (samples / filename).read_bytes()
            except OSError:
                st.error("Cannot read the selected synthetic sample.")
                return None
    if data is None:
        previous = st.session_state.get("current_import")
        if source == "Upload a file" and previous is not None and st.session_state.get("last_import_source") == source:
            st.info("The previous upload is retained in memory. Upload another file to replace it, or clear it below.")
            if st.button("Clear retained upload"):
                st.session_state.pop("current_import", None)
                st.session_state.pop("current_analysis", None)
                st.rerun()
            data, filename = previous.original_bytes, previous.filename
        else:
            st.info("Upload a log file or select a synthetic sample to begin.")
            return None
    st.session_state["last_import_source"] = source
    old = st.session_state.get("current_import")
    digest = hashlib.sha256(data).hexdigest()
    if old is None or old.sha256 != digest or old.filename != filename:
        with st.spinner("Validating and normalizing logs…"):
            old = parse_logs(data, filename)
        st.session_state["current_import"] = old
    st.caption(f"File: {filename} · {old.size_bytes:,} bytes · SHA-256 of original bytes")
    st.code(old.sha256, language=None)
    for error in old.file_errors:
        st.error(error)
    return old if not old.file_errors else None


def current_context(imported):
    if imported is None:
        return None
    return {"events": imported.valid_records, "invalid_records": imported.invalid_records,
            "total_records": imported.total_records, "findings": None, "cases": None,
            "result": imported, "saved_id": None, "scope": imported.sha256,
            "evidence": [{"original_filename": imported.filename, "sha256": imported.sha256,
                          "size_bytes": imported.size_bytes}]}


def saved_context(snapshot):
    return {**snapshot, "saved_id": snapshot["investigation_id"], "scope": snapshot["investigation_id"],
            "snapshot": snapshot, "result": None}


def log_viewer(context):
    if context is None:
        return
    for column, label, value in zip(st.columns(3), ["Total records", "Valid records", "Invalid records"],
                                     [context["total_records"], len(context["events"]), len(context["invalid_records"])]):
        column.metric(label, value)
    events, scope = context["events"], context["scope"]
    users = st.multiselect("Username", sorted({row["username"] for row in events}), key=f"users-{scope}")
    ips = st.multiselect("Source IP", sorted({row["source_ip"] for row in events}), key=f"ips-{scope}")
    kinds = st.multiselect("Event type", sorted({row["event_type"] for row in events}), key=f"types-{scope}")
    filtered = filter_events(events, usernames=users, source_ips=ips, event_types=kinds)
    st.caption(f"Showing {len(filtered)} of {len(events)} valid events. All timestamps are UTC.")
    table(filtered, key="log-events")
    if not filtered:
        st.info("No valid events match the current filters.")
    if any(row["event_type"] == "FILE_ACCESSED" and not row["session_id"] for row in events):
        st.warning("File accesses without session IDs cannot support session-based correlation.")
    st.download_button("Download normalized valid events (all rows)", export_events_csv(events),
                       file_name="normalized_events.csv", mime="text/csv", disabled=not events)
    st.caption("Export includes all valid rows, irrespective of filters, without changing original evidence.")
    st.subheader("Validation errors")
    table([{"source_row": row["source_row"], "errors": "; ".join(row["errors"]),
            "original_values": json.dumps(row["original_values"], ensure_ascii=False)}
           for row in context["invalid_records"]], key="log-errors")
    if not context["invalid_records"]:
        st.write("No invalid records found.")
    st.caption("CSV source rows are physical starting lines (header is line 1); JSON rows are 1-based array positions.")


def security_analysis(context):
    if context is None:
        st.info("Import logs or select a saved investigation first.")
        return
    if context["result"] is not None:
        policy_text = st.text_area("Sensitive resources (one exact filename or path per line)",
                                   value=st.session_state.get("resource_policy_preference", "\n".join(sorted(SENSITIVE_RESOURCES))), key="resource-policy")
        st.session_state["resource_policy_preference"] = policy_text
        policy = tuple(sorted({line.strip() for line in policy_text.splitlines() if line.strip()}))
        st.caption("Exact, case-sensitive matches. Empty policy disables R3. Analysis uses all valid events.")
        fingerprint = (context["result"].sha256, context["result"].filename, policy)
        if st.button("Run security analysis", disabled=not context["events"], type="primary"):
            with st.spinner("Detecting patterns and correlating evidence…"):
                findings = analyze_security_events(context["events"], sensitive_resources=policy)
                cases = correlate_findings(findings, context["events"])
            st.session_state["current_analysis"] = {"fingerprint": fingerprint, "findings": findings,
                                                     "cases": cases, "policy": policy, "saved_id": None}
        analysis = st.session_state.get("current_analysis")
        if not analysis or analysis["fingerprint"] != fingerprint:
            st.info("Run analysis for this file and resource policy.")
            return
        context.update({key: analysis[key] for key in ["findings", "cases", "policy", "saved_id"]})
    else:
        st.caption("Stored findings and policy loaded from SQLite; reopening does not rerun detection.")
        st.write("Sensitive-resource policy: " + ", ".join(context["policy"]))
    if context["invalid_records"]:
        st.warning(f"{len(context['invalid_records'])} invalid records are excluded from detection.")
    findings = context["findings"]
    counts = {rule: sum(row["rule_id"] == rule for row in findings) for rule in ["R1", "R2", "R3"]}
    for column, label, value in zip(st.columns(4), ["Findings", "R1", "R2", "R3"], [len(findings), *counts.values()]):
        column.metric(label, value)
    if not findings:
        st.info("No matching suspicious activity detected in the valid imported records.")
        return
    st.bar_chart({"Rule": list(counts), "Findings": list(counts.values())}, x="Rule", y="Findings")
    scope = context["scope"]
    rules = st.multiselect("Finding rule", ["R1", "R2", "R3"], key=f"finding-rules-{scope}")
    priorities = st.multiselect("Finding severity", ["Medium", "High"], key=f"finding-severity-{scope}")
    visible = [row for row in findings if (not rules or row["rule_id"] in rules)
               and (not priorities or row["severity"] in priorities)]
    if not visible:
        st.info("No findings match the selected filters.")
        return
    table([{key: value for key, value in row.items() if key in {"finding_id", "rule_id", "rule_name", "severity", "username", "source_ip", "start_time", "end_time", "supporting_event_ids"}}
           for row in visible], key="findings-table")
    by_id = {row["finding_id"]: row for row in visible}
    selected = st.selectbox("Inspect finding", list(by_id), key=f"finding-selection-{scope}",
                            format_func=lambda key: f"{by_id[key]['rule_id']} · {by_id[key]['username']} · {key[:16]}")
    finding = by_id[selected]
    st.write(finding["explanation"])
    st.caption(f"Finding ID: {selected}")
    st.write("Preceding findings: " + ", ".join(finding["related_finding_ids"]))
    by_event = {row["event_id"]: row for row in context["events"]}
    st.write("Supporting imported events (original IDs and source rows)")
    table([by_event[identifier] for identifier in finding["supporting_event_ids"]], key="finding-evidence")


def investigation_cases(context):
    if context is None or context["cases"] is None:
        st.info("Run analysis or open a saved investigation to view cases.")
        return
    cases, findings, scope = context["cases"], context["findings"], context["scope"]
    st.caption("Cases link shared source evidence and checked parent references; account/IP alone do not merge cases.")
    for column, label, value in zip(st.columns(3), ["Cases", "High-priority cases", "Medium-priority cases"],
                                     [len(cases), sum(row["priority"] == "High" for row in cases),
                                      sum(row["priority"] == "Medium" for row in cases)]):
        column.metric(label, value)
    if not cases:
        st.info("No investigation cases were generated.")
        return
    priorities = st.multiselect("Case priority", ["High", "Medium"], key=f"case-priority-{scope}")
    users = st.multiselect("Case username", sorted({user for row in cases for user in row["affected_usernames"]}), key=f"case-users-{scope}")
    visible = [row for row in cases if (not priorities or row["priority"] in priorities)
               and (not users or set(users) & set(row["affected_usernames"]))]
    if not visible:
        st.info("No cases match these filters.")
        return
    table([{key: value for key, value in row.items() if key != "timeline"} for row in visible], key="cases-table")
    by_id = {row["incident_id"]: row for row in visible}
    selected = st.selectbox("Inspect case", list(by_id), key=f"case-selection-{scope}",
                            format_func=lambda key: f"{by_id[key]['title']} · {key[:16]}")
    case = by_id[selected]
    st.write(case["summary"])
    st.caption(case["incident_id"])
    st.write("Rule-based interpretations")
    for finding in findings:
        if finding["finding_id"] in case["related_finding_ids"]:
            st.write(f"{finding['rule_id']}: {finding['explanation']}")
    st.write("Observed event timeline (UTC)")
    table(case["timeline"], key="case-timeline")
    with st.expander("Supporting event details and source references"):
        st.json(case["timeline"])


def evidence_management(context, store):
    if context is None:
        st.info("Select an import or saved investigation to manage its evidence.")
        return
    if context["result"] is not None and context["findings"] is not None:
        title = st.text_input("Investigation title", value="Local investigation")
        actor = st.text_input("Local/demo investigator label", value="Demo Investigator")
        if st.button("Save current investigation", disabled=bool(context["saved_id"]), type="primary"):
            if not title.strip() or not actor.strip():
                st.error("Provide a title and a local/demo investigator label.")
            else:
                try:
                    with st.spinner("Preserving original bytes and saving the snapshot…"):
                        identifier = store.save_investigation(context["result"], context["findings"], context["cases"],
                                                              policy=context["policy"], title=title.strip(), actor=actor.strip())
                    st.session_state["current_analysis"]["saved_id"] = identifier
                    st.rerun()
                except STORAGE_ERRORS:
                    st.error("Save failed. Check local storage permissions and data consistency. No partial database save was retained.")
    if not context["saved_id"]:
        st.info("Analyze and save this import to preserve its original evidence and audit history.")
        return
    try:
        snapshot = store.load_investigation(context["saved_id"])
        st.write(f"Saved investigation: {context['saved_id']}")
        table([{key: value for key, value in row.items() if key != "stored_name"} for row in snapshot["evidence"]], key="evidence-metadata")
        if st.button("Verify stored evidence"):
            with st.spinner("Recomputing stored evidence hashes…"):
                checks = store.verify_investigation(context["saved_id"])
            st.session_state["integrity_checks"] = {"id": context["saved_id"], "checks": checks}
            st.session_state.pop("generated_report", None)
        checked = st.session_state.get("integrity_checks", {})
        if checked.get("id") == context["saved_id"]:
            table(checked["checks"], key="integrity-checks")
            if any(row["status"] != "Verified" for row in checked["checks"]):
                st.error("Evidence integrity check failed. Review missing, altered, or unavailable evidence before relying on this snapshot.")
        else:
            st.info("Evidence has not been verified in this session.")
        st.caption("Local/demo actor labels are not authenticated identity. Audit records and files are not independently tamper-proof.")
        with st.expander("Local chain-of-custody activity"):
            table(store.load_investigation(context["saved_id"])["custody_events"], key="custody-events")
    except STORAGE_ERRORS:
        st.error("Saved evidence metadata could not be read or updated. Check storage and restore a complete backup if needed.")


def reports(context, store):
    if context is None or not context["saved_id"]:
        st.info("Save an analyzed investigation before generating its report.")
        return
    if st.button("Generate HTML report", type="primary"):
        try:
            with st.spinner("Verifying evidence and generating an academic report…"):
                report, checks = generate_saved_report(store, context["saved_id"])
            st.session_state["generated_report"] = {"id": context["saved_id"], "html": report}
            st.session_state["integrity_checks"] = {"id": context["saved_id"], "checks": checks}
            if any(row["status"] != "Verified" for row in checks):
                st.error("Report includes failed evidence verification. Review the preserved evidence.")
        except STORAGE_ERRORS:
            st.error("Report generation failed. Review saved data and storage availability.")
    generated = st.session_state.get("generated_report", {})
    if generated.get("id") == context["saved_id"]:
        st.caption("Preview and download reflect the generation-time integrity check. Regenerate for a fresh check.")
        st.download_button("Download investigation report", generated["html"].encode(),
                           file_name=f"{context['saved_id']}.html", mime="text/html")
        with st.expander("HTML report preview"):
            st.html(generated["html"])


def dashboard(context):
    if context is None:
        st.info("Choose a sample/upload in Log Import, or reopen an investigation from the sidebar. No investigation is selected.")
        return
    for column, label, value in zip(st.columns(3), ["Imported events", "Accepted events", "Rejected events"],
                                     [context["total_records"], len(context["events"]), len(context["invalid_records"])]):
        column.metric(label, value)
    if context["findings"] is None:
        st.info("Import ready. Run security analysis to calculate findings and cases.")
    else:
        st.caption(f"{len(context['findings'])} findings · {len(context['cases'])} cases · "
                   f"{sum(row['priority'] == 'High' for row in context['cases'])} High / "
                   f"{sum(row['priority'] == 'Medium' for row in context['cases'])} Medium priority cases")
        counts = {rule: sum(row["rule_id"] == rule for row in context["findings"]) for rule in ["R1", "R2", "R3"]}
        st.bar_chart({"Rule": list(counts), "Findings": list(counts.values())}, x="Rule", y="Findings")
    checks = st.session_state.get("integrity_checks", {})
    if not context["saved_id"]:
        st.caption("Evidence status: not preserved yet.")
    elif checks.get("id") != context["saved_id"]:
        st.caption("Evidence status: preserved; not checked in this session.")
    else:
        status = "Verified at last check" if all(row["status"] == "Verified" for row in checks["checks"]) else "Integrity check failed"
        st.warning(status) if status == "Integrity check failed" else st.success(status)
    st.write("Recent imported events (UTC)")
    table(sorted(context["events"], key=lambda row: (row["timestamp"], row["event_id"]), reverse=True)[:10], key="recent-events")


def main():
    st.set_page_config(page_title="CyberTrail", page_icon="🔎", layout="wide")
    apply_visual_style()
    st.caption("DIGITAL FORENSICS · INVESTIGATION WORKSPACE")
    st.title("CyberTrail")
    st.caption("Cybercrime Investigation Using Log Analysis and Event Correlation · SPPU · 410244(C)")
    st.write("Local academic investigation tool. Findings are suspicious patterns, not confirmed crimes or attacker attribution.")
    st.divider()
    store = local_store()
    st.sidebar.markdown("### 🔎 CyberTrail")
    st.sidebar.caption("Your local investigation workspace")
    st.sidebar.divider()
    workspace = st.sidebar.radio("Selected investigation", ["Current import", "Saved investigation"])
    selected = None
    if workspace == "Saved investigation":
        try:
            saved = store.list_investigations()
            if saved:
                by_id = {row["investigation_id"]: row for row in saved}
                identifier = st.sidebar.selectbox("Saved investigation", list(by_id),
                                                  format_func=lambda key: f"{by_id[key]['title']} · {by_id[key]['created_at']} · {key[:16]}")
                selected = saved_context(store.load_investigation(identifier))
            else:
                st.sidebar.info("No saved investigations yet.")
        except STORAGE_ERRORS:
            st.error("Saved investigations could not be loaded. Check storage or restore a complete backup.")
    st.sidebar.divider()
    st.sidebar.caption("Import → Analyze → Inspect → Preserve")
    tabs = st.tabs(["Dashboard", "Log Import / Log Viewer", "Security Analysis", "Investigation Cases", "Evidence Management", "Reports"])
    with tabs[1]:
        st.subheader("Log Import / Log Viewer")
        if workspace == "Current import":
            selected = current_context(select_import())
        elif selected:
            st.caption("Viewing saved normalized records. Select Current import in the sidebar to import another file.")
            table([{key: value for key, value in row.items() if key != "stored_name"} for row in selected["evidence"]], key="saved-source-metadata")
        log_viewer(selected)
    with tabs[2]:
        st.subheader("Security Analysis")
        security_analysis(selected)
    with tabs[3]:
        st.subheader("Investigation Cases")
        investigation_cases(selected)
    with tabs[4]:
        st.subheader("Evidence Management / Saved Investigations")
        evidence_management(selected, store)
    with tabs[5]:
        st.subheader("Reports")
        reports(selected, store)
    with tabs[0]:
        st.subheader("Dashboard")
        dashboard(selected)


if __name__ == "__main__":
    main()
