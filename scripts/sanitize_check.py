#!/usr/bin/env python3
"""Fail if the public repository contains private-environment identifiers or secrets.

Two layers:

1. Generic checks (always on, safe to publish):
   - private / link-local / CGNAT IPv4 addresses (RFC 1918, RFC 3927, RFC 6598);
     use documentation ranges instead: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737)
   - host names under internal-only TLDs (.local, .internal, .lan, .corp, .home, .intranet);
     use .test or .example (RFC 2606 / RFC 6761) instead
   - common secret shapes: private key blocks, AWS access keys, GitHub tokens, Splunk HEC-style
     "token = <uuid>", password/secret assignments

2. Local patterns (never committed): one regular expression per line in the file named by
   $SANITIZE_PATTERNS_FILE, or `.sanitize-patterns` at the repo root (git-ignored). Put your lab's
   host names, domain, account names, index names and address ranges there. Lines starting
   with '#' are comments. Matching is case-insensitive.

Usage:
    python3 scripts/sanitize_check.py            # scan the repository
    SANITIZE_PATTERNS_FILE=~/lab.patterns python3 scripts/sanitize_check.py
"""
from __future__ import annotations

import ipaddress
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".cache", "__pycache__", ".venv", "node_modules"}
SKIP_FILES = {Path(__file__).resolve()}
TEXT_SUFFIXES = {".yml", ".yaml", ".md", ".py", ".sh", ".spl", ".jsonl", ".json", ".txt", ".conf", ".csv", ""}

IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
    "169.254.0.0/16",                                    # RFC 3927 link-local
    "100.64.0.0/10",                                     # RFC 6598 CGNAT (Tailscale and similar)
)]
INTERNAL_HOST = re.compile(
    r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:local|internal|lan|corp|home|intranet)\b", re.IGNORECASE
)
SECRETS = [
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("token assignment", re.compile(
        r"(?i)\btoken\s*[:=]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
    ("password assignment", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret)\s*[:=]\s*['\"]?(?!<|\$\{|\$\(|changeme|example|\*)[^\s'\"]{6,}")),
]


def load_local_patterns() -> list[re.Pattern]:
    path = os.environ.get("SANITIZE_PATTERNS_FILE") or str(ROOT / ".sanitize-patterns")
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        return []
    patterns = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(re.compile(line, re.IGNORECASE))
    return patterns


def iter_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if path.resolve() in SKIP_FILES or name == ".sanitize-patterns":
                continue
            if path.suffix.lower() in TEXT_SUFFIXES:
                yield path


def scan(path: Path, local: list[re.Pattern]):
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return
    for number, line in enumerate(lines, 1):
        for match in IPV4.finditer(line):
            try:
                address = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            if any(address in net for net in PRIVATE_NETS):
                yield number, "private IPv4 address", match.group(1)
        for match in INTERNAL_HOST.finditer(line):
            yield number, "internal-TLD host name", match.group(0)
        for label, pattern in SECRETS:
            match = pattern.search(line)
            if match:
                yield number, label, match.group(0)[:40]
        for pattern in local:
            match = pattern.search(line)
            if match:
                # Do not echo the matched value: the output may end up in a public CI log.
                yield number, "local pattern", f"/{pattern.pattern[:3]}.../"


def main() -> int:
    local = load_local_patterns()
    findings = 0
    for path in iter_files():
        for number, label, value in scan(path, local):
            print(f"{path.relative_to(ROOT)}:{number}: {label}: {value}")
            findings += 1
    source = f"{len(local)} local pattern(s)" if local else "no local patterns (generic checks only)"
    print(f"sanitize check: {findings} finding(s), {source}", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
