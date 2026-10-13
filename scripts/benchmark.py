"""Measure median core processing times on deterministic synthetic log batches."""

import argparse
import json
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cybertrail.correlator import correlate_findings
from cybertrail.detector import analyze_security_events
from cybertrail.parser import parse_logs


def synthetic_bytes(count):
    """Independent seven-event sequences, with a partial final sequence if needed."""
    rows = []
    base = datetime(2026, 10, 13, 10, tzinfo=timezone.utc)
    for index in range(count):
        group, step = divmod(index, 7)
        kind = "LOGIN_FAILED" if step < 5 else "LOGIN_SUCCESS" if step == 5 else "FILE_ACCESSED"
        rows.append({"event_id": f"BENCH-{index:06d}",
                     "timestamp": (base + timedelta(seconds=group * 400 + [0, 20, 40, 60, 80, 110, 170][step])).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "event_type": kind, "username": f"demo_bench_{group}", "source_ip": "203.0.113.50",
                     "session_id": f"BENCH-SES-{group}" if step >= 5 else "", "resource": "confidential.pdf" if step == 6 else "",
                     "status": "FAILURE" if step < 5 else "SUCCESS", "details": "Deterministic benchmark event"})
    return json.dumps(rows, separators=(",", ":")).encode()


def run_benchmarks(repeats=5, hardware_label=None):
    if repeats < 1:
        raise ValueError("Repeats must be at least one.")
    hardware = "Unknown (platform metadata only)"
    if hardware_label:
        hardware = hardware_label
    elif platform.system() == "Darwin":
        try:
            hardware = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True, stderr=subprocess.DEVNULL).strip()
        except (OSError, subprocess.CalledProcessError):
            pass
    result = {"measured_at": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
              "platform": platform.platform(), "architecture": platform.machine(), "hardware": hardware,
              "repeats": repeats, "method": "Median milliseconds; deterministic independent seven-event sequences; excludes UI, persistence and reports.", "results": []}
    for count in [100, 1000, 5000, 10000]:
        data = synthetic_bytes(count)
        # Warm imports and allocator once; measure complete parse/detect/correlate calls.
        warmed = parse_logs(data, "benchmark.json")
        warm_findings = analyze_security_events(warmed.valid_records)
        correlate_findings(warm_findings, warmed.valid_records)
        timings = {name: [] for name in ["parsing_ms", "detection_ms", "correlation_ms"]}
        for _ in range(repeats):
            start = time.perf_counter()
            imported = parse_logs(data, "benchmark.json")
            parsed = time.perf_counter()
            findings = analyze_security_events(imported.valid_records)
            detected = time.perf_counter()
            cases = correlate_findings(findings, imported.valid_records)
            correlated = time.perf_counter()
            if imported.file_errors or imported.invalid_records or len(imported.valid_records) != count:
                raise ValueError("Benchmark fixture validation failed.")
            timings["parsing_ms"].append((parsed - start) * 1000)
            timings["detection_ms"].append((detected - parsed) * 1000)
            timings["correlation_ms"].append((correlated - detected) * 1000)
        result["results"].append({"events": count, "findings": len(findings), "cases": len(cases),
                                  **{key: round(statistics.median(values), 3) for key, values in timings.items()}})
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path, help="Optionally save the measured JSON result.")
    parser.add_argument("--hardware-label", help="Explicit hardware label if automatic identification is restricted; describe its verification source.")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be at least one")
    measured = run_benchmarks(args.repeats, args.hardware_label)
    serialized = json.dumps(measured, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
