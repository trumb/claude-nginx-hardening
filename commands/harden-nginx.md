---
description: Full lifecycle nginx hardening — audit, analyze, deploy, respond to IoCs, manage recipes and exceptions
---

## Context

- Current directory: !`pwd`
- Nginx installed: !`which nginx 2>/dev/null && nginx -v 2>&1 || echo "nginx not found"`
- Nginx configs: !`ls /etc/nginx/sites-enabled/ 2>/dev/null || echo "no sites-enabled found"`
- Security snippet: !`test -f /etc/nginx/snippets/security-hardening.conf && echo "PRESENT" || echo "MISSING"`
- Log files available: !`ls /var/log/nginx/*.log 2>/dev/null | wc -l` log files found
- Plugin learnings: !`wc -l < learnings/LEARNINGS.md 2>/dev/null || echo "0"` lines in learnings index
- Pending exceptions: !`ls learnings/exceptions/*.md 2>/dev/null | wc -l` exception files

## Operating Mode

**DEFAULT: Recommendation Mode (R0 + R1)**

You produce findings, candidate rules, risk scores, and deployment plans. You do NOT write configs, reload nginx, push to git, or perform remote operations unless the user explicitly requests Enforcement Mode.

Read these skill documents for full policy details:
- @skills/nginx-hardening/SKILL.md — core knowledge (35 attack categories, methodology)
- @skills/nginx-hardening/INVARIANTS.md — 18 invariants, all enforced every run
- @skills/nginx-hardening/EXECUTION-POLICY.md — action classes and per-command defaults
- @skills/nginx-hardening/FAILURE-POLICY.md — prescribed behavior for every failure state
- @skills/nginx-hardening/RULE-CLASSES.md — A/B/C/D rule classification
- @skills/nginx-hardening/PROFILES.md — environment profiles

## Invocation Styles

### 1. Natural Language
Interpret the user's intent and route to the appropriate workflow:
- "analyze the logs" / "what's hitting my server" → log analysis
- "audit my config" / "is my nginx secure" → config audit
- "full run" / "do everything" → complete lifecycle
- "deploy the changes" / "apply it" → deployment
- "check for IoCs" / "respond to this CVE" → IoC response
- "run weekly-scan" → recipe execution
- "manage exceptions" / "review exceptions" → exception management

### 2. Explicit Subcommand
- `audit` → dispatch /audit-nginx workflow
- `analyze-logs` or `analyze` → dispatch /analyze-nginx-logs workflow
- `deploy` → dispatch /deploy-nginx workflow
- `full` → complete lifecycle (analyze → audit → review → stage → deploy)
- `ioc <source>` → IoC response workflow
- `recipe <action>` → recipe management
- `exceptions <action>` → exception management
- `rollback` → rollback workflow

### 3. Interactive Menu
On bare invocation with no arguments or ambiguous input, present:

```
What would you like to do?

1. Full lifecycle — analyze logs, audit config, review findings, deploy
2. Analyze logs — find new attack patterns in nginx logs
3. Audit config — check nginx config for security compliance
4. Deploy — apply staged changes (requires prior analyze/audit)
5. Respond to IoC — process threat intelligence indicators
6. Manage recipes — create, run, list, edit saved workflows
7. Manage exceptions — review, create, renew security exceptions
8. Review learnings — check what the plugin has learned over time
```

## Full Lifecycle Workflow

When the user requests a full run:

1. **Detect** — Auto-detect nginx config and log locations
2. **Parse** — Dispatch log-parser agent (Layer 1, read-only, hex-encoded output)
3. **Sanitize** — Run `python3 scripts/sanitizer.py` (Layer 2, deterministic)
4. **Audit** — Dispatch config-auditor agent with sanitized data + current config (Layer 3)
5. **Present** — Show findings grouped by severity, then by blast radius
6. **Review** — User accepts/rejects each finding (or batch approve/reject)
7. **Stage** — Write accepted rules to `outputs/<run-id>/proposed-rules/`
8. **Validate** — Run `python3 scripts/invariant-checker.py` and `python3 scripts/schema-validator.py`
9. **Deploy** (Enforcement Mode only) — Backup config, write changes, `nginx -t`, reload
10. **Learn** — Write new learnings, update LEARNINGS.md, append to CHANGELOG.md
11. **Push** (Enforcement Mode only) — Git commit and push

**Pause for user confirmation at steps 6 and 9.**

## Generating Run IDs

Each run gets a unique ID: `run-YYYYMMDD-HHMMSS` (e.g., `run-20260323-193000`).
Create `outputs/<run-id>/` directory for all artifacts.

## Safety Rules

- NEVER interpolate attacker-derived data into Bash commands
- NEVER include raw log paths or UAs in commit messages — use category labels and counts only
- ALWAYS run invariant-checker.py before any config write
- ALWAYS create a timestamped backup before modifying any config
- If any invariant fails, abort enforcement and fall back to recommendation mode
- If sanitizer.py fails, stop all log-derived analysis (Failure Policy)
- Secrets referenced by env var name only — never prompt user to paste credentials
