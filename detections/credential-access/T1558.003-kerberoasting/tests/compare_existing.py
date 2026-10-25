#!/usr/bin/env python3
"""Compare this detection with existing public Kerberoasting rules on the same test cases.

  * SigmaHQ rules are converted and run exactly like ours (pySigma SQLite backend).
  * Splunk ESCU searches cannot run outside Splunk, so their logic is re-implemented below in
    Python from the published SPL. Treat those columns as an approximation and confirm them
    in Splunk (see README, "Lab validation").

Usage:
    python3 tests/compare_existing.py --sigmahq PATH/TO/sigma --escu PATH/TO/security_content

Prints a Markdown table: event rules show matching events, burst rules show fires/silent.
"""
from __future__ import annotations

import argparse
import statistics
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from run_tests import build_table, load_dataset, load_jsonl  # noqa: E402

SIGMAHQ_RULES = {
    "SigmaHQ 496a0e47 susp RC4": "rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml",
    "SigmaHQ d04ae2b8 activity": "rules/windows/builtin/security/win_security_kerberoasting_activity.yml",
}
OURS = {
    "ttp2rule effect (RC4)": ("854724c7-72d3-430a-8c1b-3c6005a2fe44", "events"),
    "ttp2rule attempt (burst)": ("ff9db41f-8fb0-4c26-af64-2dceddf3126b", "fires"),
}


def escu_spn_request_rc4(events: list[dict]) -> int:
    """ESCU 5cc67381 'Kerberoasting spn request with RC4 encryption' (event count)."""
    options = {"0x40810000", "0x40800000", "0x40810010"}
    return sum(
        1 for e in events
        if e.get("EventID") == 4769
        and not str(e.get("ServiceName", "")).endswith("$")
        and str(e.get("TicketOptions", "")).lower() in options
        and str(e.get("TicketEncryptionType", "")).lower() == "0x17"
    )


def escu_unusual_number(events: list[dict]) -> int:
    """ESCU eb3e6702 'Unusual Number of Kerberos Service Tickets Requested' (outlier rows).

    bucket span=2m | stats dc(ServiceName) by _time user src
    | eventstats avg, stdev by user src | unique > 2 and unique >= avg + 3*stdev
    Splunk stdev is the sample standard deviation; a single bucket is treated as stdev 0.
    """
    buckets: dict[tuple, set] = defaultdict(set)
    for e in events:
        if (e.get("EventID") != 4769 or str(e.get("ServiceName", "")).endswith("$")
                or str(e.get("TicketEncryptionType", "")).lower() != "0x17"):
            continue
        t = datetime.fromisoformat(e["timestamp"])
        bucket = int(t.timestamp()) // 120
        buckets[(bucket, e.get("TargetUserName", "").lower(), e.get("IpAddress"))].add(e.get("ServiceName"))
    per_entity: dict[tuple, list[int]] = defaultdict(list)
    for (_, user, src), services in buckets.items():
        per_entity[(user, src)].append(len(services))
    outliers = 0
    for values in per_entity.values():
        avg = statistics.fmean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        outliers += sum(1 for v in values if v > 2 and v >= avg + 3 * std)
    return outliers


ESCU = {
    "ESCU 5cc67381 SPN RC4": (escu_spn_request_rc4, "events"),
    "ESCU eb3e6702 unusual number": (escu_unusual_number, "fires"),
}


def ours_queries() -> dict[str, list[str]]:
    rules = sorted((HERE.parent / "rules").glob("*.yml"), key=lambda p: (p.name.startswith("correlation_"), p.name))
    collection = SigmaCollection.load_ruleset([str(p) for p in rules])
    backend = sqliteBackend()
    out = {}
    for rule in collection.rules:
        if type(rule).__name__ == "SigmaCorrelationRule":
            out[str(rule.id)] = backend.convert_correlation_rule(rule)
        else:
            out[str(rule.id)] = backend.convert_rule(rule)
    return out


def commit(path: Path) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(path), "rev-parse", "--short=12", "HEAD"], text=True).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sigmahq", required=True, type=Path)
    parser.add_argument("--escu", required=True, type=Path)
    args = parser.parse_args()

    spec = yaml.safe_load((HERE / "tests.yml").read_text(encoding="utf-8"))
    sigmahq = {k: sqliteBackend().convert(SigmaCollection.load_ruleset([str(args.sigmahq / v)]))
               for k, v in SIGMAHQ_RULES.items()}
    ours = ours_queries()
    columns = list(SIGMAHQ_RULES) + list(ESCU) + list(OURS)
    print(f"SigmaHQ @ {commit(args.sigmahq)}, security_content @ {commit(args.escu)}\n")
    print("| Case | " + " | ".join(columns) + " |")
    print("|---|" + "---:|" * len(columns))
    for case in spec["cases"]:
        if "dataset" in case:
            events = load_dataset(case["dataset"], spec["datasets"][case["dataset"]])
        else:
            events = load_jsonl(HERE / case["events"])
        overrides = (case.get("transform") or {}).get("set") or {}
        events = [{**e, **overrides} for e in events]
        conn = build_table(events)
        cells = []
        for name in SIGMAHQ_RULES:
            cells.append(str(sum(len(conn.execute(q).fetchall()) for q in sigmahq[name])))
        for name, (func, kind) in ESCU.items():
            value = func(events)
            cells.append(str(value) if kind == "events" else ("fires" if value else "silent"))
        for name, (rule_id, kind) in OURS.items():
            value = sum(len(conn.execute(q).fetchall()) for q in ours[rule_id])
            cells.append(str(value) if kind == "events" else ("fires" if value else "silent"))
        print(f"| {case['name']} | " + " | ".join(cells) + " |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
