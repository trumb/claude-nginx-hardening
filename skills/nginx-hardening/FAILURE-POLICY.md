# Failure Policy

Every failure state the pipeline can encounter, with prescribed behavior. All commands and agents load this policy on startup. No failure is silently ignored.

---

## Failure States

### 1. Feed unavailable

**Trigger:** Threat intelligence feed (NVD, ExploitDB, RSS, or custom) is unreachable or returns an error.

**Behavior:** Continue the current operation without enrichment from that feed. Mark the result as `partial` with a clear indicator of which feed(s) were unavailable. Do not block the pipeline. Do not retry automatically.

**Operator action:** Informational warning. Operator may re-run with feed available for full enrichment.

---

### 2. Sanitizer failure

**Trigger:** `sanitizer.py` crashes, times out, or returns malformed output when processing log data.

**Behavior:** Stop ALL log-derived rule generation immediately. Preserve any artifacts generated before the failure. Do not deploy any rules derived from the failed sanitization run. Do not fall back to unsanitized data.

**Operator action:** Required. Sanitizer must be fixed before log-derived analysis can resume. This enforces Invariant 5.

---

### 3. Schema validation failure

**Trigger:** `schema-validator.py` rejects a learning, exception, recipe, or compaction operation due to schema or content violations.

**Behavior:** Stop promotion and deploy of the invalid artifact. Emit the exact validation error(s) with field path and expected vs. actual values. Preserve the invalid artifact in staging for operator review.

**Operator action:** Fix the schema violation and re-run. No override mechanism — schema compliance is mandatory.

---

### 4. Invariant failure

**Trigger:** `invariant-checker.py` detects a violation of any of the 18 invariants.

**Behavior:** Block enforcement (W1/W2/X1 operations). Fall back to recommendation mode (R0+R1) only. Emit the specific invariant ID, rule statement, and the violating content. Preserve the proposed changes in staging for review.

**Operator action:** Resolve the invariant violation. No exception can override invariants 1-11 (Invariant 13).

---

### 5. Compatibility failure

**Trigger:** Generated config uses directives or features not supported by the target nginx version.

**Behavior:**
- **Critical incompatibility** (would cause nginx -t failure): Block deploy entirely. Emit the incompatible directive(s) and the required minimum nginx version.
- **Non-critical incompatibility** (directive ignored but nginx starts): Stage the config with a warning. Do not auto-deploy. Let operator decide.

**Operator action:** Upgrade nginx or adjust the generated config.

---

### 6. nginx -t failure

**Trigger:** `nginx -t` returns a non-zero exit code after a config write.

**Behavior:** Do NOT reload nginx. Immediately restore the config file from the timestamped `.bak` backup created before the write (Invariant 10). Mark the run as failed. Preserve the failing config in staging for diagnosis. Emit the full `nginx -t` error output.

**Operator action:** Review the failing config, fix the issue, and re-run.

---

### 7. Reload failure

**Trigger:** `systemctl reload nginx` or `nginx -s reload` returns a non-zero exit code despite `nginx -t` passing.

**Behavior:** Immediately attempt rollback: restore the `.bak` backup and run `nginx -t` + reload with the restored config. Mark the entire run as failed. Preserve all artifacts (proposed config, backup, logs). Do not retry the original config.

**Operator action:** Required. Investigate why reload failed despite passing syntax check (e.g., resource limits, permission issues, SELinux).

---

### 8. Partial remote failure

**Trigger:** During a multi-host deploy (X1), one or more hosts fail while others succeed.

**Behavior:** Stop the fanout immediately — do not continue deploying to remaining hosts. Record host-level results: which hosts succeeded, which failed, and the failure reason for each. Offer a rollback plan for the hosts that received the update. Do not auto-rollback succeeded hosts.

**Operator action:** Review per-host status. Decide whether to rollback succeeded hosts or fix and retry failed hosts.

---

### 9. Git push failure

**Trigger:** `git push` returns a non-zero exit code (network error, auth failure, rejected push, etc.).

**Behavior:** Preserve the local commit — do NOT discard or amend it. Warn the operator with the exact git error message. Do not retry automatically. Do not attempt `git push --force` (Invariant 11).

**Operator action:** Resolve the push issue (auth, network, upstream conflict) and push manually or re-run.

---

### 10. Backup creation failure

**Trigger:** `backup-manager.py` cannot create a `.bak` copy of a config file (permission denied, disk full, path error).

**Behavior:** Abort ALL writes for this run. No config file is modified. Emit the backup failure reason. This enforces Invariant 10 — no write without a confirmed backup.

**Operator action:** Fix the backup path permissions or disk space, then re-run.

---

### 11. Log file permission denied

**Trigger:** The pipeline cannot read one or more log files due to filesystem permissions.

**Behavior:** Skip the inaccessible log file(s). Continue processing any remaining accessible logs. Emit a warning listing the skipped file(s) and the permission error. Mark the analysis result as `partial`.

**Operator action:** Fix file permissions or run the pipeline with appropriate privileges for full coverage.

---

### 12. Disk space low

**Trigger:** Available disk space falls below the threshold required for backups and staged output (checked before write operations).

**Behavior:** Abort all writes. Do not create backups, configs, learnings, or any other files. Emit the current available space and the required minimum. This is a hard stop — no partial writes.

**Operator action:** Free disk space and re-run. Consider archiving old backups and learnings.
