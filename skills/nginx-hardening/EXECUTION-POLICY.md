# Execution Policy

Defines the 5 action classes and the default permission matrix for every command in the nginx-hardening pipeline. All commands and agents load this policy on startup.

---

## Action Classes

### R0 — Read-only

Read configs, logs (via sanitizer), recipes, learnings, exceptions, feeds, and metadata. No filesystem writes, no network writes, no remote execution.

### R1 — Stage-only

Generate proposals, audit reports, JSON outputs, and deployment plans. Output goes to stdout or staging area only. No persistent writes.

### W1 — Local write

Write staged files to disk: backups, reports, learnings, exceptions, local config files, CHANGELOG.md entries. All writes subject to invariants 10 (backup first) and 15 (changelog append-only).

### W2 — Network write

Git push, feed polling state persistence, remote API writes (e.g., Cloudflare, GitHub). Requires W1 as a prerequisite (local state must be consistent before network propagation).

### X1 — Remote execution

SSH deploy to target hosts, remote `nginx -t` validation, remote `systemctl reload nginx`, cron/systemd job installation. Requires W1 as a prerequisite. Subject to invariant 9 (nginx -t gate) and invariant 10 (backup before write).

---

## Default Policy Matrix

Every command starts at its default permission level. Higher levels require explicit flags.

| Command | Default | `--apply` | `--deploy` |
|---------|---------|-----------|------------|
| `/harden-nginx` (bare) | R0+R1 | — | — |
| `/harden-nginx audit` | R0+R1 | W1 | W1+W2+X1 |
| `/harden-nginx analyze-logs` | R0+R1 | — | — |
| `/harden-nginx ioc` | R0+R1 | W1 | W1+X1 |
| `/harden-nginx deploy` | requires explicit target | W1 | W1+W2+X1 |
| `/harden-nginx rollback` | R0+R1 (preview) | W1 | W1+X1 |
| `/harden-nginx recipe` | R0+R1 | W1 | X1 |
| `/harden-nginx exceptions` | R0+R1 | W1 | — |

**Key:** A dash (—) means the flag is not applicable to that command.

---

## Flag Semantics

### No flags (default)

The command operates in **Recommendation mode**. It reads, analyzes, and produces output (proposals, reports, staged JSON). Nothing is written to disk or pushed to remote systems. Safe to run at any time.

### `--apply`

The command enters **Enforcement mode (local)**. In addition to recommendation output, it writes results to disk: config files, learnings, exceptions, backups, CHANGELOG.md. All invariants are enforced. No network or remote operations occur.

### `--deploy`

The command enters **Enforcement mode (full)**. Includes all `--apply` behavior plus network writes (git push, API calls) and/or remote execution (SSH deploy, reload). Requires an explicit target host or host group.

---

## Escalation Rules

### Recommendation to Enforcement

1. **Operator must explicitly opt in.** No command auto-escalates from R0+R1 to W1 or higher. The `--apply` or `--deploy` flag is the explicit gate.

2. **Invariant violations block escalation.** If any invariant check fails during the R0+R1 phase, the command cannot proceed to W1/W2/X1 even with `--apply` or `--deploy`. The operator must resolve the violation first.

3. **Staged output is always available.** Even when escalation is blocked, the R0+R1 output (proposals, reports) is preserved for operator review.

4. **Deploy requires apply.** The `--deploy` flag implies `--apply`. You cannot deploy without first writing locally. The pipeline ensures local state is consistent before remote propagation.

5. **Target validation before remote execution.** Before any X1 operation, the pipeline validates: target host is reachable, SSH credentials are available, remote nginx version is compatible. Failure at any step aborts the X1 phase without affecting local state.

---

## Per-Class Invariant Requirements

| Action Class | Required Invariants |
|--------------|-------------------|
| R0 | 5 (sanitized logs), 6 (no shell injection), 18 (no secrets in output) |
| R1 | All R0 invariants + 2 (no regex negation in proposals), 17 (narrow scope) |
| W1 | All R1 invariants + 1 (additive only), 3 (headers immutable), 4 (TLS floor), 8 (safe learnings), 10 (backup first), 12 (exception schema), 13 (exception scope), 14 (exception expiry), 15 (changelog append-only), 16 (compaction integrity) |
| W2 | All W1 invariants + 7 (safe commits), 11 (no destructive git) |
| X1 | All W1 invariants + 9 (nginx -t gate) |
