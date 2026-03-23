---
description: Rollback nginx config to a previous state — preview, restore, or list available backups
---

## Context

- Current config: !`ls /etc/nginx/snippets/security-hardening.conf 2>/dev/null && echo "PRESENT" || echo "MISSING"`
- Available backups: !`ls /etc/nginx/snippets/security-hardening.conf.bak.* 2>/dev/null | wc -l` backups found
- Latest backup: !`ls -t /etc/nginx/snippets/security-hardening.conf.bak.* 2>/dev/null | head -1 || echo "none"`

## Operating Mode

**DEFAULT: R0 + R1 (preview only)**
With `--apply`: W1 (local restore)
With `--remote`: W1 + X1 (local + remote restore)

Read @skills/nginx-hardening/EXECUTION-POLICY.md for full policy.

## Subcommands

### `/harden-nginx rollback` (bare)
Interactive mode — list recent backups and let user choose.

### `/harden-nginx rollback latest`
Preview what would change if restoring the most recent backup.
With `--apply`: actually restore it.

### `/harden-nginx rollback <backup-id>`
Preview what would change if restoring a specific backup.
With `--apply`: actually restore it.

### `/harden-nginx rollback --list`
Show all available backups with timestamps, sizes, and run IDs.

## Workflow

1. **List backups** — `python3 scripts/rollback-manager.py list --file <target>`
2. **Preview** — `python3 scripts/rollback-manager.py preview --file <target> --backup-id <id>`
   Show unified diff to user
3. **Confirm** — User must explicitly approve restore
4. **Safety backup** — Create backup of CURRENT state before restoring (so restore is reversible)
5. **Restore** — `python3 scripts/rollback-manager.py restore --file <target> --backup-id <id>`
6. **Validate** — `sudo nginx -t`
7. **Reload** — `sudo systemctl reload nginx`
8. **Git** — Optionally create revert commit (NO force push, NO hard reset — Invariant 11)
9. **Log** — Append rollback record to CHANGELOG.md

### On failure at step 6 or 7:
- Restore from the safety backup created in step 4
- Run nginx -t again to verify recovery
- Report failure, recommend manual investigation
