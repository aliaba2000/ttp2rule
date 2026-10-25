#!/usr/bin/env python3
"""Generate the ATT&CK coverage table in README.md from the rules themselves.

The table sits between <!-- coverage:start --> and <!-- coverage:end --> in README.md.
One row per detection folder (detections/<tactic>/<technique-name>/); technique and tactic come
from the rules' attack.* tags, names from MITRE ATT&CK data loaded by pySigma.

Usage:
    python3 scripts/coverage.py          # rewrite the table
    python3 scripts/coverage.py --check  # exit 1 if README.md is out of date (CI)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.data import mitre_attack

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
START, END = "<!-- coverage:start -->", "<!-- coverage:end -->"
STATUS_ORDER = ["unsupported", "deprecated", "experimental", "test", "stable"]
TECHNIQUE_TAG = re.compile(r"^t\d{4}(?:\.\d{3})?$")


def technique_label(tid: str) -> str:
    names = mitre_attack.mitre_attack_techniques
    name = names.get(tid, "?")
    if "." in tid:
        parent = names.get(tid.split(".")[0])
        if parent:
            name = f"{parent}: {name}"
    url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
    return f"[{tid}]({url}) {name}"


def row(folder: Path) -> tuple[str, str, str]:
    files = sorted((folder / "rules").glob("*.yml"))
    collection = SigmaCollection.load_ruleset([str(p) for p in files])
    techniques: set[str] = set()
    tactics: set[str] = set()
    sources: set[str] = set()
    statuses: list[str] = []
    alerting = 0
    for rule in collection.rules:
        for tag in rule.tags:
            if tag.namespace != "attack":
                continue
            if TECHNIQUE_TAG.match(tag.name):
                techniques.add(tag.name.upper())
            elif not re.match(r"^[gs]\d{4}$", tag.name):
                tactics.add(tag.name.replace("-", " ").title())
        logsource = getattr(rule, "logsource", None)
        if logsource is not None:
            parts = [p for p in (logsource.product, logsource.service or logsource.category) if p]
            sources.add("/".join(parts))
        if rule.status:
            statuses.append(rule.status.name.lower())
        if rule.level is None or rule.level.name != "INFORMATIONAL":
            alerting += 1
    spec_path = folder / "tests" / "tests.yml"
    tests = "—"
    if spec_path.exists():
        cases = yaml.safe_load(spec_path.read_text(encoding="utf-8")).get("cases", [])
        public = sum(1 for c in cases if "dataset" in c)
        tests = f"{public} public + {len(cases) - public} synthetic"
    status = min(statuses, key=STATUS_ORDER.index) if statuses else "—"
    link = folder.relative_to(ROOT).as_posix()
    cells = [
        ", ".join(sorted(tactics)),
        "<br>".join(technique_label(t) for t in sorted(techniques)),
        f"[{folder.name}]({link}/)",
        str(alerting),
        ", ".join(sorted(sources)),
        tests,
        f"`{status}`",
    ]
    return ", ".join(sorted(tactics)), ",".join(sorted(techniques)), "| " + " | ".join(cells) + " |"


def table() -> str:
    rows = [row(f) for f in sorted(p.parent for p in (ROOT / "detections").glob("*/*/rules"))]
    rows.sort(key=lambda r: (r[0], r[1]))
    header = (
        "| Tactic | Technique | Detection | Alerting rules | Data source | Test cases | Status |\n"
        "|---|---|---|---:|---|---|---|"
    )
    return "\n".join([header] + [r[2] for r in rows])


def main() -> int:
    text = README.read_text(encoding="utf-8")
    if START not in text or END not in text:
        raise SystemExit(f"README.md is missing {START} / {END}")
    before, rest = text.split(START, 1)
    _, after = rest.split(END, 1)
    updated = f"{before}{START}\n{table()}\n{END}{after}"
    if "--check" in sys.argv:
        if updated != text:
            print("README.md coverage table is out of date: run python3 scripts/coverage.py")
            return 1
        print("coverage table up to date")
        return 0
    README.write_text(updated, encoding="utf-8")
    print("README.md coverage table updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
