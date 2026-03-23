---
description: Create, run, edit, list, install, and export reusable hardening workflow recipes
---

## Context

- Saved recipes: !`ls learnings/recipes/*.md 2>/dev/null | wc -l` recipes found
- Recent runs: !`ls -d outputs/run-* 2>/dev/null | wc -l` runs in outputs

## Operating Mode

**DEFAULT: R0 + R1 (create, list, show, export)**
With run: escalates per recipe's execution_class
With install: W1 (local) or X1 (remote)

Read @skills/nginx-hardening/RECIPES-SCHEMA.md for recipe format.

## Subcommands

### `create`
Interactive recipe builder:

1. **Name** — Prompt for kebab-case name (validate: ^[a-z0-9]+(-[a-z0-9]+)*$)
2. **Description** — What this recipe does
3. **Profile** — Select: edge-public, internal-only, api-gateway, static-site, reverse-proxy-app, high-risk-lockdown
4. **Steps** — Add steps one at a time:
   - `analyze-logs` — params: log paths, lookback days, include rotated
   - `audit-config` — params: config targets, analysis level (1/2/3)
   - `check-ioc-feeds` — params: feed names, advisory/stage mode
   - `deploy` — params: target configs, sync repos, auto-push
   - `compact-learnings` — params: threshold lines
   - `sync-repos` — params: repo paths
5. **Schedule** — manual, cron expression, or systemd timer
6. **Auto-approve threshold** — auto-accept findings at or below this severity (low, medium, or none)
7. **Confirmation checkpoints** — which steps pause for approval
8. **Max privilege level** — highest action class allowed (R0, R1, W1, W2, X1)
9. **Validate** — Run schema-validator.py
10. **Save** — Write to learnings/recipes/<name>.md

### `run <recipe-name>`
Execute a saved recipe:

1. Load recipe from learnings/recipes/
2. Verify all required_env_vars are set
3. **First execution**: always show privilege summary and require confirmation
4. Execute steps in order
5. Pause at confirmation_checkpoints
6. Auto-approve findings <= auto_approve severity threshold
7. Write run results to outputs/run-<id>/

### `list`
Show all recipes:
| Name | Description | Profile | Schedule | Last Run | Steps |

### `edit <recipe-name>`
Load existing recipe, present current values, allow modification. Re-validate and save.

### `install <recipe-name>`
Install schedule for automated execution.

**Local cron:**
```bash
# Show what would be installed
echo "0 9 * * 1 cd $(pwd) && python3 -m claude_code '/harden-nginx run <recipe-name>'"

# After confirmation, install
(crontab -l 2>/dev/null | grep -v 'harden-nginx run <recipe-name>'; echo "CRON_LINE") | crontab -
```

**Local systemd:**
Generate a .service and .timer unit file pair. Show to user, install on confirmation.

**Remote (SSH):**
- Requires: NH_SSH_HOST, NH_SSH_USER, NH_SSH_KEY or NH_SSH_PASS_ENV
- Copy recipe to remote
- Install crontab entry on remote via SSH
- Credentials from env vars only (Invariant 18)

**Generate-only:**
Output the crontab entry or systemd unit files for manual installation.

### `export <recipe-name>`
Output recipe as YAML to stdout for sharing/importing.

### `import <file>`
Import a recipe from YAML file. Validate via schema-validator.py before saving.

## Organic Capture

After any manual `/harden-nginx full` or `/harden-nginx analyze-logs` run, offer:
"Would you like to save this run as a reusable recipe?"

If yes, pre-fill the recipe from the steps that were just executed, prompt for name and schedule.

## Safety Rules

- First execution of any recipe always shows privilege summary
- Recipes cannot suppress invariants
- Recipes cannot embed secrets (credentials via env vars only)
- Write-capable recipes require confirmation unless marked non-interactive by operator
- auto_approve only works for low/medium findings — critical/high always require human review
