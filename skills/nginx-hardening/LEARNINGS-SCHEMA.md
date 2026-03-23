# Learnings Schema

> **Version:** 1.0
> **Purpose:** Defines the typed structure for learnings discovered during analysis runs. Learnings capture reusable knowledge about attack patterns, scanner signatures, exceptions, infrastructure observations, and IOC responses.

---

## Required Frontmatter Fields

| Field | Type | Description | Example |
|---|---|---|---|
| `type` | enum | Category of learning | `"attack-pattern"` |
| `status` | enum | Lifecycle state | `"active"` |
| `discovered` | string | ISO 8601 date of discovery | `"2026-03-23"` |
| `source` | enum | How this learning was discovered | `"log-analysis"` |
| `run_id` | string | Identifier of the analysis run that created this learning | `"run-20260323-1900"` |
| `finding_ids` | array of strings | Linked `NH-*` finding IDs | `["NH-LOG-SCANNER-0018"]` |
| `hit_count` | integer | Number of times this pattern was observed | `142` |

### Enum Definitions

**type:**
- `"attack-pattern"` — A recurring attack pattern (e.g., path traversal variant, JNDI probe)
- `"scanner-signature"` — A newly identified scanner User-Agent or behavioral fingerprint
- `"exception"` — A learning derived from exception review (e.g., why a compensating control works)
- `"infrastructure"` — An observation about the nginx configuration or deployment topology
- `"ioc-response"` — A learning from responding to an indicator-of-compromise alert

**status:**
- `"draft"` — Newly discovered, not yet validated
- `"active"` — Validated and applied to current analysis
- `"promoted"` — Merged into upstream rules or hardening config

**source:**
- `"log-analysis"` — Discovered via automated log analysis pipeline
- `"manual"` — Discovered by human review
- `"upstream"` — Imported from an upstream threat feed or community source
- `"ioc-feed"` — Discovered via IOC feed integration

---

## Content Safety Rules

Learnings may reference attacker behavior but **must never contain raw attacker-controlled strings**. The following rules are mandatory:

1. **No raw attacker-controlled strings.** Paths, query strings, headers, and payloads must be normalized or categorized, never quoted verbatim.
2. **No secrets or shell fragments.** No API keys, passwords, tokens, or strings containing shell metacharacters.
3. **Hex-encoded examples only.** When a specific payload must be referenced, hex-encode it and prefix with the warning: `ATTACKER-CONTROLLED DATA (hex-encoded)`.
4. **Max 200 characters per `safe_notes` field.** Any human-readable summary must not exceed 200 characters.
5. **No executable content.** Learnings must not contain code blocks that could be executed (no shell commands, no nginx config that has not been reviewed).

---

## Lifecycle

```
draft  ──>  active  ──>  promoted
  │                         │
  └── (rejected/deleted) ◄──┘ (if superseded)
```

1. **draft:** Created automatically by an analysis run. Not yet used for decision-making. Requires human or agent review before promotion.
2. **active:** Validated and incorporated into the current analysis pipeline. Used to enrich findings and improve detection accuracy.
3. **promoted:** Merged into upstream hardening rules (e.g., `security-hardening.conf`) or shared to a community feed. The learning is archived but retained for provenance.

Transitions:
- `draft -> active`: Requires review confirming the pattern is valid and the content is safe.
- `active -> promoted`: Requires the learning to be encoded as a concrete rule or config change.
- Any state -> deleted: Manual removal if the learning is incorrect or superseded.

---

## Markdown Frontmatter Example

```markdown
---
type: "scanner-signature"
status: "active"
discovered: "2026-03-23"
source: "log-analysis"
run_id: "run-20260323-1900"
finding_ids:
  - "NH-LOG-SCANNER-0018"
  - "NH-LOG-SCANNER-0019"
hit_count: 142
---

## Summary

New scanner signature identified: requests with path class "spring-actuator" combined
with UA family "zgrab" showing a distinctive 3-request burst pattern (health, env, info
endpoints in sequence within 2 seconds).

## Pattern Details

- **Path class:** spring-actuator
- **UA family:** zgrab
- **Behavioral signature:** Sequential requests to /actuator/health, /actuator/env,
  /actuator/info within a 2-second window
- **Rate signal:** burst
- **First seen:** 2026-03-23T19:00Z
- **Confidence:** 0.91

## Recommended Action

Add zgrab spring-actuator burst pattern to scanner detection rules. Consider
rate-limiting the /actuator/ prefix for non-allowlisted sources.
```

---

## Validation Rules

1. All required frontmatter fields must be present.
2. `type`, `status`, and `source` must be valid enum values.
3. `discovered` must be a valid ISO 8601 date.
4. `finding_ids` must be an array of valid `NH-*` format strings.
5. `hit_count` must be a non-negative integer.
6. Content body must pass the content safety rules (no raw attacker strings, no secrets, no shell fragments).
7. `safe_notes` fields (if present) must not exceed 200 characters.
