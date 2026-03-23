# Exceptions Schema

> **Version:** 1.0
> **Purpose:** Defines the typed structure for exceptions that suppress or defer specific findings.

---

## Exception ID Format

```
EXC-{NNNN}
```

Zero-padded sequential number. Example: `EXC-0012`.

---

## Required Fields

| Field | Type | Description | Example |
|---|---|---|---|
| `exception_id` | string | Unique exception identifier in `EXC-{NNNN}` format | `"EXC-0012"` |
| `finding_id` | string | The `NH-*` finding this exception suppresses | `"NH-AUDIT-HEADERS-0004"` |
| `reason` | string | **Required, non-empty.** Why this exception exists | `"Legacy app requires X-Frame-Options: ALLOW-FROM"` |
| `compensating_control` | string | **Required, non-empty.** What mitigates the risk while the exception is active | `"CSP frame-ancestors directive restricts to same-origin"` |
| `severity_tier` | enum | Determines review cadence and nag behavior | `"low"` |
| `owner` | string | Person or team responsible for this exception | `"platform-team"` |
| `scope` | enum | How broadly this exception applies | `"server-block"` |
| `linked_config_path` | string | Absolute path to the config file this exception covers | `"/etc/nginx/sites-enabled/legacy-app.conf"` |
| `approval_reference` | string | Ticket, PR, or document reference approving this exception | `"SEC-2026-0145"` |
| `created_at` | string | ISO 8601 date when the exception was created | `"2026-03-23"` |
| `last_reviewed_at` | string | ISO 8601 date of the most recent review | `"2026-03-23"` |
| `review_by` | string | ISO 8601 date by which the exception must be re-reviewed | `"2026-09-23"` |

### Enum Definitions

**severity_tier:**
- `"critical"` — Exception for a critical finding; reviewed every 30 days, nag after 7 days overdue
- `"high"` — Exception for a high finding; reviewed every 90 days, nag after 14 days overdue
- `"low"` — Exception for a low/medium/info finding; reviewed every 180 days, nag after 30 days overdue

**scope:**
- `"exact-directive"` — Applies to a single directive
- `"location"` — Applies to a single location block
- `"server-block"` — Applies to an entire server block
- `"include-file"` — Applies to a shared include file
- `"hostname"` — Applies to all server blocks for a hostname
- `"global"` — Applies globally (requires extra justification)

---

## Severity Tier Nag Behavior

| Tier | Review Cadence | Nag Starts | Escalation |
|---|---|---|---|
| `critical` | Every 30 days | 7 days after `review_by` | Blocks new deployments after 14 days overdue |
| `high` | Every 90 days | 14 days after `review_by` | Warning in every audit report after 21 days overdue |
| `low` | Every 180 days | 30 days after `review_by` | Info-level reminder in audit reports |

---

## Validation Rules

1. `reason` must be a non-empty string. Exceptions without a reason are rejected.
2. `compensating_control` must be a non-empty string. Exceptions without a compensating control are rejected.
3. `review_by` must be no more than 365 days after `created_at`. Exceptions requesting longer deferral are rejected.
4. `review_by` must be in the future at the time of creation.
5. `last_reviewed_at` must be on or after `created_at`.
6. `finding_id` must reference a valid `NH-*` finding ID.
7. **Invariant protection:** Exceptions **cannot** override invariants 1 through 11 as defined in `INVARIANTS.md`. Any exception targeting an invariant-protected finding is rejected at validation time.
8. `scope: "global"` exceptions require `severity_tier: "critical"` and an explicit approval reference.

---

## Markdown Frontmatter Example

```markdown
---
exception_id: "EXC-0012"
finding_id: "NH-AUDIT-HEADERS-0004"
reason: "Legacy application requires X-Frame-Options ALLOW-FROM for embedded iframe support in partner portal"
compensating_control: "CSP frame-ancestors directive restricts framing to same-origin and partner.example.com only"
severity_tier: "low"
owner: "platform-team"
scope: "server-block"
linked_config_path: "/etc/nginx/sites-enabled/legacy-app.conf"
approval_reference: "SEC-2026-0145"
created_at: "2026-03-23"
last_reviewed_at: "2026-03-23"
review_by: "2026-09-23"
---

## Context

The legacy partner portal embeds pages via iframe and requires `X-Frame-Options: ALLOW-FROM`.
This is scheduled for migration to CSP-only framing by Q3 2026.

## Review History

- **2026-03-23:** Initial exception created. Compensating control verified via CSP header audit.
```

---

## Lifecycle

1. **Created:** Exception is filed with all required fields. Validation runs immediately.
2. **Active:** Exception suppresses the linked finding in audit reports. Nag timer starts based on `review_by`.
3. **Review due:** Owner is notified per the severity tier nag schedule.
4. **Renewed or expired:** Owner either updates `last_reviewed_at` and `review_by` (renewal) or the exception expires and the finding resurfaces.
5. **Revoked:** Exception is manually deleted or the linked finding is resolved.
