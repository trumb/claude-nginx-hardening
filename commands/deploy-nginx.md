---
description: Deploy staged nginx hardening changes — backup, validate, write, test, reload, and optionally push to git
---

## Context

- Staged outputs: !`ls -d outputs/run-* 2>/dev/null | tail -1 || echo "no staged runs found"`
- Nginx status: !`systemctl is-active nginx 2>/dev/null || echo "unknown"`

## Operating Mode

**This command performs WRITES. Explicit approval required.**

Default: W1 (local write)
With `--push`: W1 + W2 (local + git push)
With `--remote`: W1 + W2 + X1 (local + git push + remote deploy)

Read @skills/nginx-hardening/EXECUTION-POLICY.md for full policy.
Read @skills/nginx-hardening/INVARIANTS.md — ALL invariants enforced.

## Your Task

Deploy previously staged and accepted changes from a run's output directory.

### Prerequisites

Before deploying, verify:
1. A staged run exists in `outputs/<run-id>/`
2. The run has accepted proposed rules
3. User has explicitly confirmed they want to deploy

### Deployment Steps

**Step 1: Identify Changes**
Read `outputs/<run-id>/proposed-rules/` and show the user exactly what will change.

**Step 2: Validate (Deterministic)**
```bash
# Run invariant checker against proposed changes
python3 scripts/invariant-checker.py --proposed <proposed-config> --backup <current-config> --require-backup

# Validate any new exceptions or learnings
python3 scripts/schema-validator.py --type <type> --file <file>
```
If ANY validation fails → abort deploy, show errors.

**Step 2b: Compatibility Check**
```bash
# Run all 9 compatibility checks against proposed config
python3 scripts/compatibility-checker.py --proposed <proposed-config> --current <current-config> --profile <profile>
```
- If any check returns **critical** severity → **abort deploy**, show the failing checks
- If checks return **warning** severity → display warnings, require explicit user confirmation to proceed
- See @skills/nginx-hardening/COMPATIBILITY-CHECKS.md for the full check reference

**Step 2c: Blast-Radius Analysis**
```bash
# Analyze which sites/upstreams are affected by the proposed changes
python3 scripts/blast-radius.py --proposed <proposed-config> --current <current-config>
```
- Present the blast-radius summary to the user before proceeding:
  - Number of server blocks affected
  - List of affected domains/listen directives
  - Upstream dependencies impacted
  - Estimated traffic scope (if log data available)
- **Pause for user confirmation** — user must explicitly approve after reviewing blast radius

**Step 3: Backup**
Create timestamped backup of every config file that will be modified:
```bash
sudo cp /etc/nginx/snippets/security-hardening.conf /etc/nginx/snippets/security-hardening.conf.bak.$(date +%Y%m%d-%H%M%S)
```

**Step 4: Write Config**
Apply the proposed changes to the target config file(s).

**Step 5: Test**
```bash
sudo nginx -t
```
If fails → restore from backup, abort, report error.

**Step 6: Reload**
```bash
sudo systemctl reload nginx
```
If fails → restore from backup, abort, report error.

**Step 7: Verify (optional)**
If the audit included live test findings, re-run key checks to confirm the deploy worked.

**Step 8: Git Operations (if --push)**
- Stage changed files
- Commit with category labels and counts (NEVER raw attacker data in commit messages)
- Push to configured remote
- Invariant 11: no force push, no hard reset

**Step 9: Remote Deploy (if --remote)**
- SSH to target host (credentials from env vars only: NH_SSH_HOST, NH_SSH_USER, NH_SSH_KEY or NH_SSH_PASS_ENV)
- Copy updated config
- Run remote nginx -t
- If pass: reload remote nginx
- If fail: abort, do NOT proceed to other hosts

**Step 10: Update Records**
- Append deployment record to CHANGELOG.md
- Update learnings status (draft → active for deployed rules)
- Write deployment summary to outputs/<run-id>/deployment-result.md

### Rollback

If anything goes wrong after Step 4:
1. Restore all config files from .bak copies
2. Run nginx -t to verify restoration
3. Reload nginx with restored config
4. Report failure details
5. Do NOT attempt to fix — recommend manual investigation

## Machine-Readable Output (--json)

When invoked with the `--json` flag:

- **Suppress all human-readable output** — no interactive confirmations (requires `--yes` for unattended use)
- **Output a single JSON object to stdout** with the following top-level keys:
  - `run_id` — the run ID being deployed
  - `success` — boolean, true if deployment completed successfully
  - `steps` — array of step objects, each containing:
    - `name` — step name (e.g., `"validate"`, `"compatibility_check"`, `"blast_radius"`, `"backup"`, `"write_config"`, `"nginx_test"`, `"reload"`, `"git_push"`)
    - `status` — `"pass"`, `"fail"`, or `"skipped"`
    - `duration_ms` — execution time in milliseconds
    - `details` — step-specific details object (errors, warnings, etc.)
  - `backup_ids` — array of backup file paths created during this deployment
  - `nginx_test_result` — object with `exit_code`, `stdout`, `stderr`
  - `reload_status` — object with `exit_code`, `timestamp`
  - `compatibility_results` — object with per-check pass/fail/warning status
  - `blast_radius` — object with affected_server_blocks, affected_domains, estimated_traffic_scope
  - `rollback_performed` — boolean, true if automatic rollback was triggered
  - `error` — error details if `success` is false (null otherwise)
- **Exit code 0** on successful deployment, **non-zero** on any failure
- **CI/CD friendly** — designed for deployment pipelines: `deploy-nginx --json --yes | jq -e '.success'`
