---
description: Audit nginx config for security compliance — checks headers, TLS, blocking rules, and optionally verifies live behavior
---

## Context

- Nginx configs: !`ls /etc/nginx/sites-enabled/ 2>/dev/null || echo "no sites-enabled found"`
- Security snippet: !`test -f /etc/nginx/snippets/security-hardening.conf && echo "PRESENT" || echo "MISSING"`

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
