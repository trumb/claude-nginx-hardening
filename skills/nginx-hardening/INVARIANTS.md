# Security Invariants

All 18 invariants are loaded by every command and agent in the nginx-hardening pipeline. Violation of any invariant blocks the offending operation unless explicitly noted otherwise.

---

## Invariant 1: Additive-only for blocking rules

**Rule:** Generated rules can only ADD or TIGHTEN nginx blocking rules. Never remove, weaken, or comment out existing rules.

**Enforcement:** Deterministic — `invariant-checker.py` diff analysis compares before/after rule sets and rejects any net reduction in blocking coverage.

**Failure behavior:** Block write. Output recommendation only. Operator may manually override outside the pipeline.

---

## Invariant 2: No regex negation in generated rules

**Rule:** No negative lookaheads (`(?!...)`), `!~` operators, or patterns that ALLOW traffic. Every generated location/if block must terminate in `return 404;` or `deny all; return 404;`. Forbidden directives in generated rules: `proxy_pass`, `return 200`, `return 301`, `return 302`, `rewrite`.

**Enforcement:** Deterministic — `invariant-checker.py` regex scan of all generated nginx config content.

**Failure behavior:** Block write. Emit the offending line(s) with explanation.

---

## Invariant 3: Security headers are immutable

**Rule:** Cannot modify, remove, or weaken any of the following headers: `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Strict-Transport-Security` (HSTS), `Permissions-Policy`. New headers may be added.

**Enforcement:** Deterministic — `invariant-checker.py` header diff compares before/after header sets and rejects any removal or value weakening.

**Failure behavior:** Block write. Report which header(s) would be affected and the before/after values.

---

## Invariant 4: TLS floor at 1.2

**Rule:** `ssl_protocols` must not include `TLSv1.0` or `TLSv1.1`. The minimum accepted protocol version is `TLSv1.2`.

**Enforcement:** Deterministic — `invariant-checker.py` config scan parses `ssl_protocols` directives and rejects any containing TLSv1.0 or TLSv1.1.

**Failure behavior:** Block write. Report the offending `ssl_protocols` directive and its location.

---

## Invariant 5: Raw log data never enters LLM context

**Rule:** All log data passes through `sanitizer.py` before any LLM agent sees it. No exceptions. Layer 1 hex-encodes attacker-controlled fields; Layer 2 sanitizes for LLM consumption.

**Enforcement:** Pipeline architecture — the data flow enforces this structurally. `sanitizer.py` is the only gateway from raw logs to agent context.

**Failure behavior:** If `sanitizer.py` fails or is bypassed, stop ALL log-derived analysis immediately. No partial results.

---

## Invariant 6: No attacker-controlled strings in shell commands

**Rule:** Paths, User-Agent strings, or any log-derived data must never be interpolated into Bash commands. Use `grep -F` for literal matching or pre-sanitized regex patterns only.

**Enforcement:** Agent self-check before every Bash invocation + code review of scripts.

**Failure behavior:** Abort the operation. Log the attempted command pattern for review.

---

## Invariant 7: No attacker-controlled strings in commit messages

**Rule:** Git commit messages use category labels and aggregate counts only. Never embed raw request paths, User-Agent strings, or other attacker-controlled content.

**Enforcement:** Agent self-check before every `git commit`.

**Failure behavior:** Reject the commit. Rewrite the message using safe category labels and counts.

---

## Invariant 8: No attacker-controlled strings in learning content

**Rule:** Learning document bodies contain sanitized summaries and counts only. Raw paths and payloads are stored hex-encoded in designated fields with an `ATTACKER-CONTROLLED DATA` warning prefix.

**Enforcement:** Deterministic — `schema-validator.py` validates learning JSON structure and content field safety.

**Failure behavior:** Reject the learning write. Emit the specific field(s) that failed validation.

---

## Invariant 9: nginx -t before every reload

**Rule:** Every nginx configuration change must pass `nginx -t` syntax validation before any `systemctl reload nginx` or `nginx -s reload`. On failure, rollback from the pre-write backup and abort.

**Enforcement:** Deterministic — `invariant-checker.py` wraps all reload paths with a mandatory `nginx -t` gate.

**Failure behavior:** No reload occurs. Restore config from the timestamped `.bak` backup. Mark the run as failed with the `nginx -t` error output.

---

## Invariant 10: Backup before every write

**Rule:** A timestamped `.bak` copy of every config file is created before any modification. Backup filename format: `<original>.<ISO8601-timestamp>.bak`.

**Enforcement:** Deterministic — `backup-manager.py` creates the backup as the first step of any write operation.

**Failure behavior:** Abort the write entirely. No config modification occurs without a confirmed backup.

---

## Invariant 11: No destructive git operations

**Rule:** The following git operations are forbidden on config files and repositories managed by this pipeline: `git push --force`, `git reset --hard`, `git checkout .`, `git clean -f`. Only additive commits are permitted.

**Enforcement:** Agent self-check + blocked command list enforced by the pipeline runner.

**Failure behavior:** Abort the operation. Log the attempted destructive command.

---

## Invariant 12: Exceptions require reason + compensating control

**Rule:** Every exception file must contain both a `reason` field and a `compensating_control` field. Neither may be empty or placeholder text.

**Enforcement:** Deterministic — `schema-validator.py` validates exception JSON schema and field content.

**Failure behavior:** Reject the exception. Emit the specific missing or invalid field(s).

---

## Invariant 13: Exceptions cannot override invariants 1-11

**Rule:** An exception suppresses FINDINGS (specific audit results), not invariants. No exception can authorize: rule removal (inv 1), header weakening (inv 3), TLS downgrade (inv 4), sanitizer bypass (inv 5), or any other invariant 1-11 violation.

**Enforcement:** Deterministic — `invariant-checker.py` validates that exception targets reference finding IDs, not invariant IDs. `schema-validator.py` cross-checks exception scope.

**Failure behavior:** Reject the exception with an explanation of which invariant it attempts to override.

---

## Invariant 14: Exceptions expire (max 365 days)

**Rule:** Every exception must have a `review_by` date no more than 365 days from creation. Tiered enforcement:

| Severity | Warning schedule | Expiry behavior |
|----------|-----------------|-----------------|
| Critical | 90d, 60d, 30d before expiry | Blocks deploy after expiry date |
| High | 60d, 30d before expiry | Warning only |
| Low | 30d before expiry | Warning only |

**Enforcement:** Deterministic — `schema-validator.py` date validation on write. Nag schedule checked on every audit and deploy run.

**Failure behavior:** On write: reject exceptions with missing or out-of-range `review_by`. On expiry: flag (high/low) or block deploy (critical).

---

## Invariant 15: Changelog is append-only

**Rule:** `CHANGELOG.md` is never edited in-place or truncated. New entries are prepended to the top of the file. Existing content is never modified.

**Enforcement:** Deterministic — git diff check confirms that all changes to CHANGELOG.md are pure additions (no deletions or modifications of existing lines).

**Failure behavior:** Abort the commit. Report the specific lines that would be modified or deleted.

---

## Invariant 16: Compaction preserves counts and first-seen dates

**Rule:** When merging or compacting learning entries, the total hit count must be the sum of all merged entries, and the `first_seen` / `discovered` date must be the earliest date from all merged entries.

**Enforcement:** Deterministic — `schema-validator.py` validates pre/post compaction totals and dates.

**Failure behavior:** Reject the compaction. Emit the expected vs. actual counts and dates.

---

## Invariant 17: Generated changes scoped as narrowly as possible

**Rule:** Prefer exact-location blocks over server-block-level rules. Prefer server-block-level over include-file-level. Global scope (http-block or main config) requires elevated warning and operator acknowledgment.

**Enforcement:** Deterministic — `blast-radius.py` analyzes the scope of each generated change and assigns a blast-radius tier.

**Failure behavior:** Exact-location and server-block: proceed normally. Include-file: emit warning. Global scope: escalate to operator, require explicit confirmation before write.

---

## Invariant 18: Secrets never enter chat, learnings, changelog, recipes, commits, or artifacts

**Rule:** Credentials, API keys, tokens, and private keys must never appear in any pipeline output. Only redacted placeholders (e.g., `[REDACTED]`) or environment variable references (e.g., `$CF_API_TOKEN`) are permitted.

**Enforcement:** Agent self-check on all output + `sanitizer.py` pattern matching for common secret formats (API keys, tokens, passwords, private key headers).

**Failure behavior:** Abort the operation immediately. Warn the operator. If a secret was written, flag for immediate remediation.
