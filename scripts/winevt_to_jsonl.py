#!/usr/bin/env python3
"""Convert Windows event log exports into flat JSONL test events.

Supported input formats (auto-detected per event):
  * XML rendering - one <Event ...>...</Event> per line, as produced by
    Splunk XmlWinEventLog (renderXml = true) and Splunk attack_data.
  * Classic rendering - Splunk WinEventLog text ("LogName=Security ..."),
    for a small set of events whose message labels are mapped to the XML
    field names below.

Each output line is one JSON object with Sigma taxonomy field names
(EventID, Provider_Name, Channel, Computer, <EventData fields>) plus a
`timestamp` field (ISO 8601, UTC) that the test harness uses for
correlation rules.

Usage:
    python3 scripts/winevt_to_jsonl.py INPUT [INPUT ...] [--event-id 4769] > events.jsonl
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Classic (text) rendering: message label -> XML field name, per EventID.
CLASSIC_LABELS: dict[int, dict[str, str]] = {
    4769: {
        "Account Name": "TargetUserName",
        "Account Domain": "TargetDomainName",
        "Service Name": "ServiceName",
        "Service ID": "ServiceSid",
        "Client Address": "IpAddress",
        "Client Port": "IpPort",
        "Ticket Options": "TicketOptions",
        "Ticket Encryption Type": "TicketEncryptionType",
        "Failure Code": "Status",
        "Transited Services": "TransmittedServices",
    },
}

XML_EVENT = re.compile(r"<Event[ >].*?</Event>", re.DOTALL)
CLASSIC_HEADER = re.compile(r"^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M)\s*$", re.MULTILINE)


def parse_xml_event(raw: str) -> dict | None:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    system = root.find(f"{NS}System")
    if system is None:
        return None
    event: dict = {}
    eid = system.findtext(f"{NS}EventID")
    event["EventID"] = int(eid) if eid and eid.isdigit() else eid
    provider = system.find(f"{NS}Provider")
    if provider is not None:
        event["Provider_Name"] = provider.get("Name")
    event["Channel"] = system.findtext(f"{NS}Channel")
    event["Computer"] = system.findtext(f"{NS}Computer")
    created = system.find(f"{NS}TimeCreated")
    if created is not None and created.get("SystemTime"):
        event["timestamp"] = normalize_time(created.get("SystemTime"))
    for data in root.iter(f"{NS}Data"):
        name = data.get("Name")
        if name:
            event[name] = (data.text or "").strip()
    return event


def normalize_time(value: str) -> str:
    # 2024-04-08T23:56:13.253708900Z -> 2024-04-08T23:56:13.253708+00:00
    value = value.rstrip("Z")
    if "." in value:
        head, frac = value.split(".", 1)
        value = f"{head}.{frac[:6]}"
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).isoformat()


def parse_classic_block(header_time: str, body: str) -> dict | None:
    match = re.search(r"^EventCode=(\d+)", body, re.MULTILINE)
    if not match:
        return None
    eid = int(match.group(1))
    labels = CLASSIC_LABELS.get(eid)
    if labels is None:
        return None
    event: dict = {
        "EventID": eid,
        "Provider_Name": "Microsoft-Windows-Security-Auditing",
        "timestamp": datetime.strptime(header_time, "%m/%d/%Y %I:%M:%S %p")
        .replace(tzinfo=timezone.utc)
        .isoformat(),
    }
    log = re.search(r"^LogName=(.+)$", body, re.MULTILINE)
    host = re.search(r"^ComputerName=(.+)$", body, re.MULTILINE)
    event["Channel"] = log.group(1).strip() if log else None
    event["Computer"] = host.group(1).strip() if host else None
    for line in body.splitlines():
        if ":" not in line:
            continue
        label, _, value = line.strip().partition(":")
        field = labels.get(label.strip())
        if field and field not in event:
            event[field] = value.strip()
    return event


def iter_events(text: str):
    for match in XML_EVENT.finditer(text):
        event = parse_xml_event(match.group(0))
        if event:
            yield event
    headers = list(CLASSIC_HEADER.finditer(text))
    for i, header in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        event = parse_classic_block(header.group(1), text[header.end():end])
        if event:
            yield event


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("--event-id", type=int, action="append", help="keep only these EventIDs (repeatable)")
    args = parser.parse_args()
    count = 0
    for path in args.inputs:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for event in iter_events(handle.read()):
                if args.event_id and event.get("EventID") not in args.event_id:
                    continue
                sys.stdout.write(json.dumps(event, ensure_ascii=False) + "\n")
                count += 1
    print(f"{count} events", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
