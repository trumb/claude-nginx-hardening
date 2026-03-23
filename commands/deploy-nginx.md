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

## Remote / Canary Deployment (--remote)

When `--remote` is specified, escalates to X1 execution class (remote command execution).

### Required Environment Variables

| Variable | Purpose |
|---|---|
| `NH_SSH_HOST` | Comma-separated list of target hosts (e.g., `web1.example.com,web2.example.com`) |
| `NH_SSH_USER` | SSH username for all target hosts |
| `NH_SSH_KEY` | Path to SSH private key (for key-based auth) |
| `NH_SSH_PASS_ENV` | Name of env var containing SSH password (for sshpass auth; mutually exclusive with NH_SSH_KEY) |

### Canary Deployment Workflow

**Step 1: Local Validation**
Run all local checks first — invariants, compatibility, blast-radius. If any fail, abort before touching remote hosts.

**Step 2: Generate Deployment Plan**
```bash
python3 scripts/deploy-planner.py \
  --hosts $NH_SSH_HOST \
  --config-file <config> \
  --remote-config-path <remote-path>
```
Present plan to user with per-host details (host, current config hash, proposed changes, rollback path).

**Step 3: User Approval**
Pause for explicit user confirmation. Show the full plan including canary strategy and rollback procedure.

**Step 4: Canary Execution**
```bash
python3 scripts/canary-deployer.py \
  --config-file <config> \
  --hosts $NH_SSH_HOST \
  --ssh-user $NH_SSH_USER \
  --ssh-key $NH_SSH_KEY \
  --remote-config-path <remote-path> \
  --health-endpoint /health \
  --verify-deny-paths "/.env,/wp-admin,/actuator/env"
```

The canary deployer:
1. Deploys to the **first host only** (canary)
2. Runs remote `nginx -t` on the canary
3. Reloads nginx on the canary
4. Verifies health endpoint returns 200
5. Verifies deny paths return 403/404
6. If canary passes → proceeds to remaining hosts one at a time
7. If canary fails → stops immediately, rolls back canary host

**Step 5: Report Results**
Report per-host results:
- Host name, deploy status (success/fail/skipped), nginx -t result, health check result, deny-path verification results

**Step 6: Partial Failure Handling**
On partial failure (some hosts succeeded, some failed):
- Show which hosts are in the new state vs old state
- Identify which hosts need rollback
- Offer rollback plan: roll back failed hosts, or roll back all hosts to restore consistency
- Never leave hosts in an inconsistent state without user awareness

### Safety

- **Credentials from env vars only** (Invariant 18) — never prompt user to paste passwords or keys
- **Canary verification before full fanout** — first host must pass all health/deny checks
- **Stop on first failure** — do not proceed to remaining hosts if any host fails
- **Per-host nginx -t before reload** — never reload without a passing config test
- **`--dry-run` available** — preview the full deployment plan without executing any remote commands
- **Audit trail** — all remote operations logged to `outputs/<run-id>/remote-deploy-log.json`

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
