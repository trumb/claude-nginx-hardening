---
description: Respond to indicators of compromise — parse YARA rules, look up CVEs, poll threat feeds, cross-reference logs, and generate containment rules
---

## Context

- Threat feeds configured: !`python3 scripts/feed-poller.py --list 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{len([f for f in d[\"feeds\"] if f[\"status\"]==\"available\"])} available')" 2>/dev/null || echo "feed-poller not available"`
- Recent findings: !`ls outputs/run-*/findings.json 2>/dev/null | wc -l` run(s) with findings
- Log data: !`ls /var/log/nginx/*.log 2>/dev/null | wc -l` log files

## Operating Mode

**DEFAULT: R0 + R1 (Advisory — cross-reference only)**
With `--stage`: R1 (generate candidate rules)
With `--emergency`: W1 (emergency containment — Class A only, narrow scope)

Read @skills/nginx-hardening/EXECUTION-POLICY.md and @skills/nginx-hardening/RULE-CLASSES.md.

## Invocation

### Parse local IoC source
- `/harden-nginx ioc /path/to/rule.yar` — Parse YARA rule file
- `/harden-nginx ioc /path/to/indicators.txt` — Parse text indicator list
- `/harden-nginx ioc /path/to/stix.json` — Parse STIX JSON

### CVE lookup
- `/harden-nginx ioc CVE-2021-44228` — Look up CVE, generate rules for known exploit paths

### Interactive
- `/harden-nginx ioc` — Describe the IoC, paste indicators, or select a source

### Feed polling
- `/harden-nginx ioc --feed` — Poll all configured threat feeds
- `/harden-nginx ioc --feed cisa_kev,urlhaus` — Poll specific feeds

## Response Modes

### Advisory (default)
Cross-reference indicators against existing logs and rules.
Report: "Indicator X has been seen N times", "Indicator Y is already blocked by rule Z", "Indicator Z is NOT blocked".
No rule generation.

### Stage (--stage)
Everything in Advisory, plus:
- Generate candidate blocking rules for unblocked indicators
- Assign rule class (prefer Class A — Containment)
- Assign severity from source confidence and CVSS score
- Write proposals to outputs/<run-id>/ioc-proposed-rules/
- Create learning file in learnings/ioc-responses/

### Emergency Containment (--emergency)
Everything in Stage, plus:
- Apply Class A rules IMMEDIATELY (W1 execution)
- ONLY allowed when ALL of:
  - Rule class is A (Containment only)
  - Scope is narrow (exact-location or server-block)
  - Confidence >= 0.8
  - TTL is assigned (default: 7 days, not permanent)
  - All invariants pass
  - Source provenance recorded

Emergency mode MUST NOT:
- Modify TLS settings
- Alter security headers
- Change routing or proxy behavior
- Change location precedence
- Write broad regex rules
- Generate Class B, C, or D rules

## IoC Parsing

### YARA files (.yar)
1. Read the `strings:` section
2. Extract string patterns (remove YARA-specific syntax)
3. Classify as path pattern or UA pattern
4. Generate nginx `location` blocks for path patterns
5. Generate UA blocking rules for agent patterns

### CVE lookup
1. Query NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX`
2. Extract: description, CVSS score, references
3. Parse known exploit paths from references and description
4. Generate blocking rules for identified paths
5. Assign severity from CVSS: critical (9.0+), high (7.0+), medium (4.0+), low (<4.0)

### Plain text
One indicator per line. Auto-classify:
- Starts with `/` → path indicator
- Contains `User-Agent:` or similar → UA indicator
- IP address pattern → IP indicator (informational only — nginx IP blocking is separate)

### STIX JSON
Extract `indicator` objects with `pattern_type: stix`.
Map URL patterns to nginx paths. Map HTTP header patterns to UA rules.

## Log Cross-Reference

For each indicator:
1. Normalize via sanitizer.py pipeline (MUST sanitize even IoC data)
2. Search sanitized log data for matches
3. Report: indicator, match_count, first_seen, last_seen, blocked_by_rule (if any)

## Output Artifacts

In `outputs/<run-id>/`:
- `ioc-report.md` — Human-readable summary
- `ioc-findings.json` — Machine-readable findings
- `ioc-proposed-rules/` — Candidate rules (if --stage or --emergency)
- Learning: `learnings/ioc-responses/<date>-<ioc-id>.md`

## Safety

- ALL IoC data passes through sanitizer before LLM analysis (Invariant 5)
- Emergency mode requires explicit --emergency flag
- Emergency rules get a TTL (default 7 days) — they don't persist forever
- Source provenance is always recorded in the learning file
- Never generate rules from unverified indicators (confidence < 0.5)
