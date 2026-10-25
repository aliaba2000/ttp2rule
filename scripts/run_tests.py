#!/usr/bin/env python3
"""Run detection test cases against sample events.

Every detection folder may contain tests/tests.yml:

    datasets:                       # public data, downloaded and verified at test time
      rubeus:
        url: https://...
        sha256: <hex>
        event_ids: [4769]           # optional filter applied when parsing
    cases:
      - name: Rubeus kerberoast (Splunk attack_data)
        dataset: rubeus             # or: events: synthetic/benign.jsonl (relative to tests/)
        transform:                  # optional: derive a variant at test time, nothing is stored
          set: {TicketEncryptionType: '0x12'}
        expect:
          <rule id>: 30             # exact number of matches
          <rule id>: ">=1"          # or a comparison: ">=N", "<=N", ">N", "<N"

Rules in the folder's rules/ directory are converted with the pySigma SQLite backend and run
against an in-memory table built from the events. For a single-event rule a match is one event;
for a correlation rule it is one alert row.

Usage:
    python3 scripts/run_tests.py [DETECTION_DIR ...]      # default: every folder under detections/
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import sys
import urllib.request
from pathlib import Path

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache" / "datasets"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from winevt_to_jsonl import iter_events  # noqa: E402

COMPARISON = re.compile(r"^\s*(>=|<=|>|<|==)?\s*(\d+)\s*$")


def load_dataset(name: str, spec: dict) -> list[dict]:
    CACHE.mkdir(parents=True, exist_ok=True)
    target = CACHE / f"{spec['sha256']}.log"
    if not target.exists():
        print(f"  downloading {name} ...", file=sys.stderr)
        with urllib.request.urlopen(spec["url"], timeout=120) as response:
            data = response.read()
        digest = hashlib.sha256(data).hexdigest()
        if digest != spec["sha256"]:
            raise SystemExit(f"checksum mismatch for dataset {name}: {digest}")
        target.write_bytes(data)
    events = list(iter_events(target.read_text(encoding="utf-8", errors="replace")))
    if spec.get("event_ids"):
        events = [e for e in events if e.get("EventID") in spec["event_ids"]]
    return events


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def build_table(events: list[dict]) -> sqlite3.Connection:
    columns = sorted({key for event in events for key in event} | {"timestamp"})
    conn = sqlite3.connect(":memory:")
    # Sigma string matching is case-insensitive: declare every text column NOCASE.
    ddl = ", ".join(
        f'"{c}" INTEGER' if c == "EventID" else f'"{c}" TEXT COLLATE NOCASE' for c in columns
    )
    conn.execute(f"CREATE TABLE logs ({ddl})")
    placeholders = ", ".join("?" for _ in columns)
    quoted = ", ".join(f'"{c}"' for c in columns)
    conn.executemany(
        f"INSERT INTO logs ({quoted}) VALUES ({placeholders})",
        [[event.get(c) for c in columns] for event in events],
    )
    return conn


def check(expected, actual: int) -> bool:
    match = COMPARISON.match(str(expected))
    if not match:
        raise SystemExit(f"invalid expectation: {expected!r}")
    op, number = match.group(1) or "==", int(match.group(2))
    return {
        "==": actual == number,
        ">=": actual >= number,
        "<=": actual <= number,
        ">": actual > number,
        "<": actual < number,
    }[op]


def run_folder(folder: Path) -> tuple[int, int]:
    spec_path = folder / "tests" / "tests.yml"
    if not spec_path.exists():
        return 0, 0
    spec = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    # Load base rules before correlation rules: the backend converts in collection order and a
    # correlation needs its base rule's conversion state to already exist.
    rule_files = sorted(
        (folder / "rules").glob("*.yml"),
        key=lambda p: (p.name.startswith("correlation_"), p.name),
    )
    collection = SigmaCollection.load_ruleset([str(p) for p in rule_files])
    # Convert each rule with one shared backend, base rules first, so a correlation finds its
    # base rule's conversion state. A base rule referenced only by a correlation is suppressed
    # (0 queries); reconvert it standalone from its own file so it can still be tested.
    backend = sqliteBackend()
    queries: dict[str, list[str]] = {}
    titles: dict[str, str] = {}
    for rule in collection.rules:
        if isinstance(rule, SigmaCorrelationRule):
            out = backend.convert_correlation_rule(rule)
        else:
            out = backend.convert_rule(rule)
            if not out:
                # Reload the file and convert this rule alone. Loading marks a referenced base rule
                # as non-output (_output = False); clear that flag for the standalone copy.
                fresh = SigmaCollection.load_ruleset([str(rule.source.path)])
                alone = [r for r in fresh.rules if str(r.id) == str(rule.id)]
                for r in alone:
                    r._output = True
                out = sqliteBackend().convert(SigmaCollection(alone))
        queries[str(rule.id)] = out
        titles[str(rule.id)] = rule.title
    passed = failed = 0
    print(f"\n{folder.relative_to(ROOT)}")
    for case in spec.get("cases", []):
        if "dataset" in case:
            events = load_dataset(case["dataset"], spec["datasets"][case["dataset"]])
        else:
            events = load_jsonl(folder / "tests" / case["events"])
        overrides = (case.get("transform") or {}).get("set") or {}
        if overrides:
            events = [{**event, **overrides} for event in events]
        conn = build_table(events)
        print(f"  case: {case['name']} ({len(events)} events)")
        for rule_id, expected in case["expect"].items():
            if rule_id not in queries:
                raise SystemExit(f"unknown rule id {rule_id} in {spec_path}")
            actual = sum(len(conn.execute(q).fetchall()) for q in queries[rule_id])
            ok = check(expected, actual)
            passed += ok
            failed += not ok
            mark = "PASS" if ok else "FAIL"
            print(f"    [{mark}] {titles[rule_id]}: expected {expected}, got {actual}")
        conn.close()
    return passed, failed


def main(argv: list[str]) -> int:
    folders = [Path(a).resolve() for a in argv] or sorted(
        p.parent.parent for p in (ROOT / "detections").glob("*/*/tests/tests.yml")
    )
    total_passed = total_failed = 0
    for folder in folders:
        passed, failed = run_folder(folder)
        total_passed += passed
        total_failed += failed
    print(f"\n{total_passed} passed, {total_failed} failed")
    return 1 if total_failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
