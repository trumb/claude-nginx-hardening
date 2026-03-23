---
description: Analyze nginx access logs for attack patterns, scanner activity, and new threats — sanitizes all data before analysis
---

## Context

- Log files: !`ls -la /var/log/nginx/*.log 2>/dev/null | head -10 || echo "no logs found"`
- Rotated logs: !`ls /var/log/nginx/*.gz 2>/dev/null | wc -l` compressed log files found
- Current learnings: !`wc -l < learnings/LEARNINGS.md 2>/dev/null || echo "0"` lines
- Profile: !`echo "${NH_PROFILE:-auto-detect}"`

## Operating Mode

**DEFAULT: R0 + R1 (Recommendation Mode)**
Log analysis NEVER writes active config. Findings are staged for review.

Read @skills/nginx-hardening/EXECUTION-POLICY.md for full policy.

## Your Task

Analyze nginx access logs to discover new attack patterns, scanner signatures, and threats.

### Pipeline

This command orchestrates the full security pipeline:

**Step 1: Detect Logs**
Auto-detect at standard locations or use user-specified paths:
- /var/log/nginx/access.log (and .1 through .14.gz)
- /var/log/nginx/*-access.log variants
- User-specified: `/analyze-nginx-logs /path/to/access.log`

Report what was found before proceeding.

**Step 2: Parse (Layer 1)**
Dispatch the log-parser agent:
- Read-only access to log files
- Hex-encodes all attacker-controlled fields
- Outputs structured JSON with aggregated counts
- Save raw parser output to `outputs/<run-id>/parsed-logs.json`

**Step 3: Sanitize (Layer 2)**
Run the deterministic sanitizer:
```bash
python3 scripts/sanitizer.py --input outputs/<run-id>/parsed-logs.json --output outputs/<run-id>/sanitized-findings.json --log-source <detected-path>
```
If sanitizer fails → stop analysis, report error (Failure Policy).

**Step 4: Analyze (Layer 3)**
Dispatch config-auditor agent with:
- sanitized-findings.json
- Current nginx config (if available)
- Current learnings and exceptions

Agent produces findings and proposed rules.

**Step 5: Present Findings**
Show the user:
- New attack patterns discovered (not already covered by existing rules)
- New scanner signatures detected
- Hit counts and severity assessments
- Proposed blocking rules for each finding

**Step 6: Interactive Review**
For each finding, the user can:
- **Accept** — Stage the proposed rule for deployment
- **Reject** — Discard the finding
- **Exception** — Mark as intentionally allowed (creates exception file)
- **Accept All** — Batch accept remaining findings
- **Reject All** — Batch reject remaining findings

**Step 7: Update Learnings**
For accepted findings, create learning files in `learnings/attack-patterns/` or `learnings/scanner-signatures/`. Append to CHANGELOG.md. Update LEARNINGS.md index.

### Output

Artifacts in `outputs/<run-id>/`:
- `parsed-logs.json` — Layer 1 output
- `sanitized-findings.json` — Layer 2 output
- `findings.json` — Layer 3 findings
- `proposed-rules/` — Accepted rules staged for deploy
- `run-summary.md` — Human-readable summary

## Profile Flag (--profile)

When `--profile <name>` is specified (or auto-detected), log analysis adjusts severity thresholds and scanner handling per profile:

| Profile | Behavior Adjustments |
|---|---|
| `edge-public` | Default thresholds; all scanner UAs flagged; aggressive pattern matching |
| `internal-only` | `go-http-client`, `python-requests`, `curl` UAs downgraded to **info** (common in microservice traffic); internal IP ranges excluded from scanner detection |
| `api-gateway` | Focus on auth bypass attempts, method abuse, payload size violations; lower threshold for path traversal detection |
| `static-site` | POST/PUT/DELETE requests elevated to **high** severity (unexpected on static sites); upload attempts flagged as **critical** |
| `reverse-proxy-app` | Upstream error correlation enabled; 502/503 spikes treated as potential DoS indicators |
| `high-risk-lockdown` | All **medium** findings promoted to **high**, all **high** to **critical**; single-hit anomalies flagged (not just patterns with repeat hits) |

**Profile affects:**
- Severity thresholds for findings (what counts as critical vs warning)
- Which scanner user-agents trigger findings vs are ignored
- Whether internal IPs are included in or excluded from analysis
- Minimum hit count thresholds for pattern detection

Pass `--profile` to the sanitizer for profile-aware filtering:
```bash
python3 scripts/sanitizer.py --input <input> --output <output> --log-source <path> --profile <profile>
```

## Machine-Readable Output (--json)

When invoked with the `--json` flag:

- **Suppress all human-readable output** — no interactive review prompts, no markdown summaries
- **Auto-accept all findings** (no interactive review step; use `--reject-all` to override)
- **Output a single JSON object to stdout** with the following top-level keys:
  - `run_id` — the generated run ID
  - `log_sources` — array of log file paths analyzed
  - `sanitized_events_summary` — object with total_events, unique_ips, unique_paths, unique_user_agents, time_range
  - `findings` — array of finding objects (id, severity, category, pattern, hit_count, first_seen, last_seen, proposed_rule)
  - `proposed_rules` — array of proposed rule objects staged for deployment
  - `learnings_delta` — array of new or updated learnings from this analysis run:
    - Each entry: learning_id, type, status, action (created/updated), path_class, hit_count_added
- **Exit code 0** on success, **non-zero** on pipeline failure (sanitizer error, parse error)
- **CI/CD friendly** — pipe to `jq` for filtering: `analyze-nginx-logs --json | jq '.findings[] | select(.severity == "critical")'`
