# ttp2rule

**From ATT&CK technique to tested, tuned detection.** Behavior-based Sigma rules with Splunk SPL —
each with rationale, test evidence and false-positive tuning.

This repository is not trying to be the biggest or the fastest rule set — SigmaHQ and Splunk ESCU
already are. Every detection here is a small case file: why the behaviour matters, what it leaves
in the logs, how the rule decides, what it was tested on, what it gets wrong and how to tune it.

## Approach

1. **Start from behaviour, not from an IOC.** Detections map to MITRE ATT&CK techniques and target
   what an attacker has to do, which changes far more slowly than tools and hashes. Fresh CVEs
   appear only as an occasional add-on.
2. **Two layers where possible.** An **attempt** layer (the action is being tried) and an **effect**
   layer (the action succeeded or produced something dangerous). They fail in different ways, so
   together they survive more environments than either alone.
3. **Test before claiming.** Every rule runs against public attack captures
   ([Splunk attack_data](https://github.com/splunk/attack_data),
   [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)) and synthetic benign and
   false-positive cases. Lab reproduction uses [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team).
   No exploit code lives here.
4. **Compare honestly.** Where public rules exist, the detection README shows them side by side on
   the same cases — including where this repository's rule is noisier.
5. **Document the false positives and the blind spots.** A rule without known false positives has
   not been run on real data yet.

## Coverage

Generated from the rules by `scripts/coverage.py` — do not edit by hand.

<!-- coverage:start -->
| Tactic | Technique | Detection | Alerting rules | Data source | Test cases | Status |
|---|---|---|---:|---|---|---|
| Credential Access | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Steal or Forge Kerberos Tickets: Kerberoasting | [T1558.003-kerberoasting](detections/credential-access/T1558.003-kerberoasting/) | 2 | windows/security | 5 public + 4 synthetic | `experimental` |
<!-- coverage:end -->

## Repository layout

```
detections/<tactic>/<technique-id>-<name>/
├── README.md        rationale, data, logic, threshold, false positives, bypasses, tests
├── rules/           Sigma rules (the source of truth); a correlation file carries its base rule
├── spl/             Splunk SPL generated from rules/ by scripts/convert.sh — never edited by hand
└── tests/
    ├── tests.yml    test cases: public datasets (URL + SHA-256) and synthetic events, expected counts
    └── synthetic/   hand-written JSONL events with reserved names and documentation addresses
pipelines/           pySigma processing pipelines (Splunk Windows logs, classic and XML rendering)
scripts/             convert, test, coverage and sanitize tooling
templates/           starting point for a new detection
docs/                workflow and conventions
```

## Using the rules

```bash
pip install -r requirements.txt

# Sigma -> Splunk SPL, the same way spl/ is produced
sigma convert -t splunk -p sysmon -p pipelines/splunk_windows_xml.yml detections/<...>/rules/<rule>.yml
```

The SPL has no index: prefix your own index or macro. `pipelines/splunk_windows_xml.yml` matches
both `WinEventLog:*` and `XmlWinEventLog:*` sources — the stock `splunk_windows` pipeline matches only
the classic rendering and returns nothing for `renderXml = true` inputs.

## Checks

Run all of them before a pull request; CI runs the same set.

```bash
sigma check --fail-on-error --fail-on-issues -c tests/sigma_cli_conf.sigmahq.yml detections/*/*/rules/
./scripts/convert.sh --check          # spl/ matches the rules
python3 scripts/run_tests.py          # every test case passes
python3 scripts/coverage.py --check   # coverage table is current
python3 scripts/sanitize_check.py     # no private identifiers or secrets
```

`tests/sigma_cli_conf.sigmahq.yml` is the validator configuration used by SigmaHQ's own CI, so a
rule that passes here is close to what a SigmaHQ pull request is checked against.

## Contributing a detection

Copy `templates/`, follow [`docs/workflow.md`](docs/workflow.md), and open a pull request with the
checks passing. Use reserved names (`example.test`) and documentation addresses (RFC 5737) in
synthetic events.

## License

Rules and documentation are released under the [Detection Rule License (DRL) 1.1](LICENSE), the
same license SigmaHQ uses. When you share a rule, keep its `author` field and a link back to this
repository.
