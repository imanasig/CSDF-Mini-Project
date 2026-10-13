"""Generate only the named synthetic fixtures; no parsing or detection logic."""

import argparse
import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

FIELDS = ["event_id", "timestamp", "event_type", "username", "source_ip",
          "session_id", "resource", "status", "details"]
BASE_TIME = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "data" / "samples"


def event(number, seconds, kind, username="demo_admin", ip="203.0.113.50",
          session="", resource=""):
    """Build one fictional event with a fixed UTC timestamp."""
    statuses = {"LOGIN_FAILED": "FAILURE", "ACCESS_DENIED": "DENIED"}
    descriptions = {
        "LOGIN_FAILED": "Synthetic incorrect-password attempt",
        "LOGIN_SUCCESS": "Synthetic authenticated login",
        "FILE_ACCESSED": "Synthetic file read",
        "FILE_MODIFIED": "Synthetic file update",
        "ACCESS_DENIED": "Synthetic resource permission refusal",
        "LOGOUT": "Synthetic session ended",
    }
    return dict(zip(FIELDS, [
        f"EVT-{number:03d}", (BASE_TIME + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        kind, username, ip, session, resource, statuses.get(kind, "SUCCESS"),
        descriptions[kind],
    ]))


def failures(times, username="demo_admin", ip="203.0.113.50"):
    return [event(i, seconds, "LOGIN_FAILED", username, ip)
            for i, seconds in enumerate(times, 1)]


def normal_activity():
    rows = []
    # Separate fictional employees have isolated sessions and occasional failures.
    for employee in range(1, 6):
        start = (employee - 1) * 600
        user, ip, session = f"demo_employee_{employee}", f"192.168.10.{employee}", f"SES-N{employee:03d}"
        actions = [(0, "LOGIN_FAILED", "", ""),
                   (30, "LOGIN_SUCCESS", session, ""),
                   (60, "FILE_ACCESSED", session, "team_notes.txt"),
                   (90, "FILE_MODIFIED", session, "draft.txt"),
                   (120, "ACCESS_DENIED", session, "restricted_folder"),
                   (150, "LOGOUT", session, "")]
        for offset, kind, sid, resource in actions:
            rows.append(event(len(rows) + 1, start + offset, kind, user, ip, sid, resource))
    return rows


def build_datasets():
    brute = failures([0, 20, 40, 60, 80])
    login = brute + [event(6, 110, "LOGIN_SUCCESS", session="SES-A001")]
    incident = login + [event(7, 170, "FILE_ACCESSED", session="SES-A001", resource="confidential.pdf")]
    mixed = normal_activity()
    # Put three independent attack scenarios between ordinary employee events.
    for scenario, offset, user, ip, sid in [
        (brute, 200, "demo_guest", "198.51.100.21", ""),
        (login, 900, "demo_operator", "203.0.113.22", "SES-M002"),
        (incident, 1600, "demo_admin", "198.51.100.23", "SES-M003"),
    ]:
        for source in scenario:
            row = source.copy()
            seconds = int((datetime.strptime(row["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) - BASE_TIME).total_seconds())
            row.update(event_id=f"EVT-{len(mixed) + 1:03d}",
                       timestamp=(BASE_TIME + timedelta(seconds=seconds + offset)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                       username=user, source_ip=ip,
                       session_id=sid if row["session_id"] else "")
            mixed.append(row)
    mixed.sort(key=lambda row: row["timestamp"])

    invalid = [event(i, i * 10, "LOGIN_FAILED") for i in range(1, 7)]
    for row, field, value in zip(invalid,
                                 ["timestamp", "username", "source_ip", "event_type", "event_id", "status"],
                                 ["not-a-timestamp", "", "999.1.1.1", "UNKNOWN_EVENT", "", ""]):
        row[field] = value

    multiple_ips = failures([0, 20, 40, 60, 80, 100])
    multiple_users = failures([0, 20, 40, 60, 80, 100])
    for i in range(3, 6):
        multiple_ips[i]["source_ip"] = "198.51.100.51"
        multiple_users[i]["username"] = "demo_guest"
    mismatch = [event(7, -60, "LOGIN_SUCCESS", session="SES-OTHER")] + login + [
        event(8, 170, "FILE_ACCESSED", session="SES-OTHER", resource="confidential.pdf"),
    ]
    duplicate = failures([0, 20])
    duplicate[1]["event_id"] = duplicate[0]["event_id"]
    return {
        "normal_activity.csv": normal_activity(),
        "brute_force.csv": brute,
        "suspicious_login.csv": login,
        "file_access_incident.csv": incident,
        "mixed_activity.csv": mixed,
        "invalid_logs.csv": invalid,
        "edge_four_failures.csv": failures([0, 30, 60, 90]),
        "edge_five_boundary.csv": failures([0, 30, 60, 90, 120]),
        "edge_outside_window.csv": failures([0, 30, 60, 90, 121]),
        "edge_multiple_ips.csv": multiple_ips,
        "edge_multiple_users.csv": multiple_users,
        "edge_out_of_order.csv": [incident[i] for i in [6, 2, 5, 0, 4, 1, 3]],
        "edge_success_only.csv": [event(1, 0, "LOGIN_SUCCESS", session="SES-CLEAN")],
        "edge_session_mismatch.csv": mismatch,
        "edge_duplicate_ids.csv": duplicate,
        "sample_events.json": incident,
    }


def generate(output_dir=DEFAULT_OUTPUT):
    """Overwrite named fixtures only; leave unrelated files untouched."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    datasets = build_datasets()
    for name, rows in datasets.items():
        target = output_dir / name
        # Refuse symlinks so regeneration cannot write outside the sample directory.
        if target.is_symlink():
            raise ValueError(f"Refusing to overwrite symlink: {target}")
        if target.suffix == ".json":
            target.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
        else:
            with target.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
                writer.writeheader()
                writer.writerows(rows)
    return list(datasets)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    names = generate(args.output_dir)
    print(f"Generated {len(names)} synthetic datasets in {args.output_dir.resolve()}")
