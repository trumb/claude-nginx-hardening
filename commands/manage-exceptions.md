---
description: Manage security exceptions — create, review, renew, expire, and validate exception records
---

## Context

- Exception files: !`ls learnings/exceptions/*.md 2>/dev/null | wc -l` exceptions found
- Expired: !`python3 -c "
import os, datetime
from pathlib import Path
count = 0
for f in Path('learnings/exceptions').glob('*.md'):
    content = f.read_text()
    for line in content.split('\n'):
        if line.startswith('review_by:'):
            date_str = line.split(':',1)[1].strip()
            try:
                if datetime.date.fromisoformat(date_str) < datetime.date.today():
                    count += 1
            except: pass
print(count)
" 2>/dev/null || echo "0"` expired exceptions

## Operating Mode

**DEFAULT: R0 + R1**
With `--apply`: W1 (writes exception files)

## Subcommands

### `list`
Show all exceptions grouped by status:
- **Active** — within review_by date
- **Expiring Soon** — within 30 days of review_by (critical: 90 days)
- **Expired** — past review_by date

Display: exception_id, finding_id, severity_tier, owner, review_by, days remaining.

Color coding:
- Critical approaching expiry: prominent warning
- High approaching: warning
- Expired critical: BLOCKED indicator
- Expired high/low: warning indicator

### `create`
Interactive exception creation:

1. Show recent findings (from latest run outputs)
2. User selects finding to except
3. Prompt for **reason** (required, must be non-empty)
4. Prompt for **compensating control** (required, must be non-empty)
5. Auto-suggest **severity_tier** based on finding severity
6. Prompt for **owner** (required)
7. Prompt for **approval_reference** (ticket, PR, or doc reference)
8. Prompt for **review_by** date (suggest 90d/180d/365d options, max 365 days)
9. Run `python3 scripts/schema-validator.py --type exception --file <path>` to validate
10. On pass: write exception file to `learnings/exceptions/`
11. Add inline comment to linked config: `# nginx-hardening: excepted EXC-NNNN — see learnings/exceptions/`
12. Append to CHANGELOG.md

### `review <exception-id>`
Show full exception details. Prompt: renew, remove, or keep as-is.

### `renew <exception-id>`
Extend review_by date. Requires new reason documenting why still needed.
Validates new date is within 365 days. Updates last_reviewed_at.

### `expire`
List all expired exceptions. For each:
- Critical: mark as BLOCKING — deploy will be blocked until resolved
- High: prominent warning
- Low: flag

Prompt user to renew, remove, or acknowledge each.

### `validate`
Run schema-validator.py on ALL exception files.
Report: total, valid, invalid, expired, expiring soon.

## Invariant Reminders
- Invariant 12: Exceptions require reason + compensating control
- Invariant 13: Exceptions cannot override invariants 1-11
- Invariant 14: Max 365 days, tiered nag escalation
