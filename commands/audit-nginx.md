---
description: Audit nginx config for security compliance — checks headers, TLS, blocking rules, and optionally verifies live behavior
---

## Context

- Nginx configs: !`ls /etc/nginx/sites-enabled/ 2>/dev/null || echo "no sites-enabled found"`
- Security snippet: !`test -f /etc/nginx/snippets/security-hardening.conf && echo "PRESENT" || echo "MISSING"`
- Profile: !`echo "${NH_PROFILE:-auto-detect}"`

## Operating Mode

**DEFAULT: R0 + R1 (Recommendation Mode)**
With `--apply`: escalates to W1
With `--deploy`: escalates to W1 + W2 + X1

Read @skills/nginx-hardening/EXECUTION-POLICY.md for full policy.

## Your Task

Audit nginx configuration for security compliance.

### Input

The user may provide:
- A specific config path: `/audit-nginx /path/to/nginx.conf`
- A URL for live testing: `/audit-nginx https://example.com`
- Nothing (auto-detect configs in /etc/nginx/sites-enabled/)

### Analysis Levels

**Level 1 — Static Config Analysis (always on)**
Dispatch the config-auditor agent to check:
- All 6 security headers present and correct
- TLS 1.2+ only, ECDHE ciphers
- server_tokens off, autoindex off
- client_max_body_size set
- Method restriction present
- Rate limiting present
- security-hardening.conf included
- Location precedence conflicts
- Duplicate/shadowed directives
- Coverage of all 35 attack categories

**Level 2 — Log Cross-Reference (if logs available)**
If nginx logs are found, also run the log analysis pipeline to enrich audit findings with actual traffic data.

**Level 3 — Live Verification (opt-in with --live or when URL provided)**
Use curl to verify:
- Security headers returned correctly
- TLS protocol/cipher negotiation
- Known blocked paths return 404 (sample from each of the 35 categories)
- Health endpoint responds
- Do NOT perform intrusive testing (no fuzzing, no brute-force, no high-rate)

### Output

Generate artifacts in `outputs/<run-id>/`:
- `audit-report.md` — Human-readable compliance report
- `findings.json` — Machine-readable findings
- `proposed-rules/` — Any recommended new rules

Present a summary to the user showing:
- PASS/FAIL/WARN for each check category
- Total findings by severity
- Recommended next steps

## Profile Flag (--profile)

When `--profile <name>` is specified (or auto-detected), the audit adjusts its behavior per profile:

| Profile | Behavior Adjustments |
|---|---|
| `edge-public` | All checks at default severity; rate limiting and scanner UA blocking are **critical** |
| `internal-only` | Rate limiting downgraded to **warning**; TLS checks downgraded to **warning** if on private subnet; scanner UA blocking is **info** only |
| `api-gateway` | Method restriction and `client_max_body_size` are **critical**; auth header forwarding checked |
| `static-site` | Proxy-related checks skipped; `try_files` and cache header checks elevated |
| `reverse-proxy-app` | Proxy header checks (`X-Forwarded-For`, `X-Real-IP`) are **critical**; upstream health checks verified |
| `high-risk-lockdown` | All **warning** findings promoted to **critical**; zero tolerance — any finding fails the audit |

**Profile affects:**
- Which compatibility checks are **critical** vs **warning** vs **info**
- What is considered "required" for a passing audit score
- The threshold for `audit_score` pass/fail (high-risk-lockdown requires 100; internal-only passes at 70)

Pass `--profile` to the compatibility checker and blast-radius analyzer:
```bash
python3 scripts/compatibility-checker.py --proposed <config> --current <current> --profile <profile>
python3 scripts/blast-radius.py --proposed <config> --current <current> --profile <profile>
```

## Machine-Readable Output (--json)

When invoked with the `--json` flag:

- **Suppress all human-readable output** — no markdown tables, no interactive prompts
- **Output a single JSON object to stdout** with the following top-level keys:
  - `run_id` — the generated run ID
  - `audit_score` — integer 0-100 representing overall compliance score
  - `pass` — boolean, true if all critical checks passed
  - `categories` — object keyed by check category name, each containing:
    - `status` — `"pass"`, `"fail"`, or `"warn"`
    - `findings` — array of finding objects for that category
    - `severity` — highest severity finding in this category
  - `findings` — flat array of all finding objects (severity, category, description, affected_file, line_number, proposed_fix)
  - `summary` — object with `total_findings`, `critical_count`, `high_count`, `medium_count`, `low_count`
  - `proposed_rules` — array of proposed rule objects
- **Exit code 0** if `pass` is true, **exit code 1** if any critical check fails
- **CI/CD friendly** — use as a gate: `audit-nginx --json | jq -e '.pass'`
