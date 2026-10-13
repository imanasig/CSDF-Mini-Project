"""Exercise the real six-tab UI with isolated local storage."""

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from cybertrail.database import InvestigationStore

ROOT = Path(__file__).resolve().parents[1]


def app():
    return AppTest.from_file(str(ROOT / "app.py")).run(timeout=60)


def widget(elements, label):
    return next(element for element in elements if element.label == label)


def metrics(application):
    return {item.label: item.value for item in application.metric}


def grid(application, key):
    # Read-only dataframes do not expose user keys through AppTest. Locate them
    # within their workflow tab, where their purpose and ordering are explicit.
    positions = {"log-events": (1, 0), "findings-table": (2, 0),
                 "finding-evidence": (2, 1), "cases-table": (3, 0), "case-timeline": (3, 1)}
    if key == "log-errors":
        return next(item.value for item in application.tabs[1].dataframe if "original_values" in item.value)
    tab, index = positions[key]
    return application.tabs[tab].dataframe[index].value


def sample(name):
    application = app()
    widget(application.radio, "Import source").set_value("Synthetic sample").run()
    widget(application.selectbox, "Synthetic dataset").select(name).run()
    return application


def click(application, label):
    widget(application.button, label).click().run()
    assert not application.exception


def test_home_page_renders_without_errors():
    application = app()
    assert not application.exception
    assert application.title[0].value == "CyberTrail"
    assert [tab.label for tab in application.tabs] == ["Dashboard", "Log Import / Log Viewer", "Security Analysis", "Investigation Cases", "Evidence Management", "Reports"]
    assert not application.metric
    assert any("No investigation is selected" in item.value for item in application.info)


def test_sample_import_filters_and_errors():
    application = sample("normal_activity.csv")
    assert metrics(application)["Valid records"] == "30"
    assert len(grid(application, "log-events")) == 30
    widget(application.multiselect, "Username").set_value(["demo_employee_1"]).run()
    widget(application.multiselect, "Source IP").set_value(["192.168.10.1"]).run()
    widget(application.multiselect, "Event type").set_value(["LOGIN_FAILED"]).run()
    assert len(grid(application, "log-events")) == 1
    widget(application.selectbox, "Synthetic dataset").select("sample_events.json").run()
    assert metrics(application)["Valid records"] == "7"
    assert len(grid(application, "log-events")) == 7
    widget(application.selectbox, "Synthetic dataset").select("invalid_logs.csv").run()
    assert not application.exception
    assert metrics(application)["Valid records"] == "1"
    assert metrics(application)["Invalid records"] == "5"
    assert len(grid(application, "log-errors")) == 5
    assert "original_values" in grid(application, "log-errors")


def test_duplicate_sample_empty_valid_table():
    application = sample("edge_duplicate_ids.csv")
    assert not application.exception
    assert metrics(application)["Valid records"] == "0"
    assert metrics(application)["Invalid records"] == "2"
    assert len(grid(application, "log-errors")) == 2
    assert widget(application.button, "Run security analysis").disabled


@pytest.mark.parametrize("name,data,expected", [
    ("uploaded.csv", (ROOT / "data/samples/brute_force.csv").read_bytes(), "5"),
    ("broken.json", b"{bad json", None),
], ids=["valid-upload", "malformed-upload"])
def test_uploaded_bytes_path(monkeypatch, name, data, expected):
    uploaded = SimpleNamespace(name=name, size=len(data), getvalue=lambda: data)
    monkeypatch.setattr(st, "file_uploader", lambda *args, **kwargs: uploaded)
    application = app()
    assert not application.exception
    if expected is None:
        assert "Cannot read JSON" in application.error[0].value
        assert not application.metric
    else:
        assert metrics(application)["Valid records"] == expected
    assert application.code[0].value == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("name,counts,cases", [
    ("normal_activity.csv", ["0", "0", "0", "0"], "0"),
    ("brute_force.csv", ["1", "1", "0", "0"], "1"),
    ("suspicious_login.csv", ["2", "1", "1", "0"], "1"),
    ("file_access_incident.csv", ["3", "1", "1", "1"], "1"),
    ("mixed_activity.csv", ["6", "3", "2", "1"], "3"),
    ("invalid_logs.csv", ["0", "0", "0", "0"], "0"),
])
def test_security_analysis_samples(name, counts, cases):
    application = sample(name)
    assert "Findings" not in metrics(application)
    click(application, "Run security analysis")
    assert [metrics(application)[label] for label in ["Findings", "R1", "R2", "R3"]] == counts
    assert metrics(application)["Cases"] == cases
    if counts[0] == "0":
        assert any("No matching suspicious activity detected" in item.value for item in application.info)
    else:
        assert len(grid(application, "findings-table")) == int(counts[0])
        assert len(grid(application, "finding-evidence")) == 5
        assert "source_row" in grid(application, "finding-evidence")
        widget(application.multiselect, "Username").set_value([widget(application.multiselect, "Username").options[0]]).run()
        assert [metrics(application)[label] for label in ["Findings", "R1", "R2", "R3"]] == counts


def test_finding_filters_evidence_and_stale_results():
    application = sample("file_access_incident.csv")
    click(application, "Run security analysis")
    widget(application.multiselect, "Finding rule").set_value(["R3"]).run()
    widget(application.multiselect, "Finding severity").set_value(["High"]).run()
    assert list(grid(application, "findings-table")["rule_id"]) == ["R3"]
    assert list(grid(application, "finding-evidence")["event_id"]) == [f"EVT-{i:03d}" for i in range(1, 8)]
    widget(application.multiselect, "Finding severity").set_value(["Medium"]).run()
    assert any("No findings match" in item.value for item in application.info)
    application.text_area[0].set_value("").run()
    assert "Findings" not in metrics(application)
    click(application, "Run security analysis")
    assert metrics(application)["R3"] == "0"
    widget(application.selectbox, "Synthetic dataset").select("normal_activity.csv").run()
    assert "Findings" not in metrics(application)
    click(application, "Run security analysis")
    assert metrics(application)["Findings"] == "0"


def test_case_timeline_and_independent_cases():
    application = sample("file_access_incident.csv")
    click(application, "Run security analysis")
    assert metrics(application)["Cases"] == "1"
    assert len(grid(application, "case-timeline")) == 7
    widget(application.selectbox, "Synthetic dataset").select("mixed_activity.csv").run()
    click(application, "Run security analysis")
    assert metrics(application)["Cases"] == "3"
    assert metrics(application)["High-priority cases"] == "2"
    widget(application.multiselect, "Case priority").set_value(["Medium"]).run()
    assert len(grid(application, "cases-table")) == 1


def test_save_restart_verify_and_report():
    application = sample("file_access_incident.csv")
    click(application, "Run security analysis")
    click(application, "Save current investigation")
    assert widget(application.button, "Save current investigation").disabled
    root = Path(os.environ["CYBERTRAIL_DATA_DIR"])
    store = InvestigationStore(root / "cybertrail.db", root / "evidence")
    assert len(store.list_investigations()) == 1
    restarted = app()
    widget(restarted.radio, "Selected investigation").set_value("Saved investigation").run()
    assert not restarted.exception
    assert metrics(restarted)["Findings"] == "3" and metrics(restarted)["Cases"] == "1"
    click(restarted, "Verify stored evidence")
    click(restarted, "Generate HTML report")
    generated = restarted.session_state["generated_report"]["html"]
    assert "Verified" in generated and "EVT-007" in generated
    assert "Investigation report generated" in generated
    next((root / "evidence").iterdir()).write_bytes(b"altered disposable test evidence")
    click(restarted, "Verify stored evidence")
    assert any("integrity check failed" in error.value for error in restarted.error)
    assert "generated_report" not in restarted.session_state


def test_saved_selection_does_not_mix_investigations():
    from tests.test_database import save_sample
    root = Path(os.environ["CYBERTRAIL_DATA_DIR"])
    store = InvestigationStore(root / "cybertrail.db", root / "evidence")
    normal, *_ = save_sample(store, "normal_activity.csv")
    attack, *_ = save_sample(store)
    application = app()
    widget(application.radio, "Selected investigation").set_value("Saved investigation").run()
    widget(application.selectbox, "Saved investigation").select(attack).run()
    assert metrics(application)["Imported events"] == "7"
    assert metrics(application)["Findings"] == "3"
    widget(application.selectbox, "Saved investigation").select(normal).run()
    assert not application.exception
    assert metrics(application)["Imported events"] == "30"
    assert metrics(application)["Findings"] == "0" and metrics(application)["Cases"] == "0"


@pytest.mark.parametrize("custom_policy,expected", [(None, "3"), ("", "2")])
def test_current_sample_retained_after_saved_workspace_switch(custom_policy, expected):
    application = sample("file_access_incident.csv")
    if custom_policy is not None:
        application.text_area[0].set_value(custom_policy).run()
    click(application, "Run security analysis")
    click(application, "Save current investigation")
    widget(application.radio, "Selected investigation").set_value("Saved investigation").run()
    assert metrics(application)["Findings"] == expected
    widget(application.radio, "Selected investigation").set_value("Current import").run()
    assert not application.exception
    assert widget(application.selectbox, "Synthetic dataset").value == "file_access_incident.csv"
    assert metrics(application)["Findings"] == expected and metrics(application)["Imported events"] == "7"


def test_corrupted_database_has_helpful_error():
    root = Path(os.environ["CYBERTRAIL_DATA_DIR"])
    root.mkdir(parents=True)
    (root / "cybertrail.db").write_bytes(b"not a database")
    application = app()
    widget(application.radio, "Selected investigation").set_value("Saved investigation").run()
    assert not application.exception
    assert any("could not be loaded" in item.value for item in application.error)
