# Workflow

A detection is written and tuned in a **private lab**, then published here as a cleaned, tested
version. The lab repository is the workshop; this repository is the catalogue.

```
technique ──► telemetry ──► rule draft ──► public-data tests ──► lab reproduction ──► tuning ──► publish
 (ATT&CK)     (what the       (Sigma)      (attack_data, OTRF,   (Atomic Red Team)   (baseline,
              logs show)                    synthetic FP cases)                       allowlist)
```

## 1. Pick the behaviour

- One ATT&CK technique or sub-technique per detection folder.
- Write down the attempt and the effect: what does trying look like, what does success look like?
- Check what already exists (SigmaHQ, Splunk ESCU). If a good rule exists, the contribution is the
  test evidence, the tuning and an honest comparison — or a pull request to that project.

## 2. Find the trace

- Which event, which fields, which audit policy or sensor setting produces them?
- Get a real sample first: a public capture, or an export from the lab.

## 3. Write and test

- Start from `templates/`. One rule file per query; a correlation file carries its base rule.
- Add cases to `tests/tests.yml`: at least one public attack capture, one benign baseline, and one
  case per known false positive. A false-positive case documents behaviour that is understood — the
  expected count can be non-zero.
- `python3 scripts/run_tests.py <folder>` until every case matches what you predicted. When a count
  surprises you, find out why before changing the expectation.

## 4. Reproduce and tune in the lab

- Run the matching Atomic Red Team test; confirm each layer fires as predicted.
- Run the baseline queries from the detection README on real lab data; record the threshold and the
  allowlist decisions.
- Validate any hand-written SPL variant in Splunk before recommending it.

## 5. Clean and publish

Nothing from the lab is published: no addresses, host names, domain name, account names, index
names or secrets.

- Synthetic events: `example.test` / `EXAMPLE` for names, RFC 5737 documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) for addresses.
- Rules use Sigma taxonomy fields only; environment specifics (indexes, macros, allowlists) stay in
  the lab.
- Put your lab identifiers in `.sanitize-patterns` (one regular expression per line, git-ignored) in the
  lab clone, then run `python3 scripts/sanitize_check.py`. Matches are reported by file and line
  without echoing the value.
- Run every check listed in the main README; open a pull request; CI repeats them.

## Status ladder

| Status | Meaning here |
|---|---|
| `experimental` | Passes public-data and synthetic tests |
| `test` | Also reproduced in the lab and tuned on a baseline |
| `stable` | Ran in a real environment without unexplained false positives for at least 30 days |
