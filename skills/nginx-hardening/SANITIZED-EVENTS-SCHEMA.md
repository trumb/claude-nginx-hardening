# Sanitized Events Schema

> **Schema Version:** 1.0
> **Boundary:** Layer 2 (sanitizer.py) -> Layer 3 (config-auditor agent)
> **Security Classification:** CRITICAL — no raw attacker data crosses this boundary.

---

## Purpose

This schema defines the typed contract for events emitted by the Layer 2 sanitizer and consumed by the Layer 3 config-auditor agent. Every field is either enumerated, bounded, or normalized. Raw attacker-controlled strings are **never** passed through this boundary.

---

## Required Fields

| Field | Type | Description | Example |
|---|---|---|---|
| `schema_version` | string | Schema version identifier | `"1.0"` |
| `event_id` | string | Unique identifier per event | `"evt-20260323-001"` |
| `source_type` | enum | Log source category | `"access_log"` |
| `log_source_path` | string | Absolute path to the originating log file | `"/var/log/nginx/access.log"` |
| `timestamp_bucket` | string | ISO 8601 hour bucket (truncated to hour) | `"2026-03-23T19:00Z"` |
| `remote_addr_class` | enum | Classified address type (never the actual IP) | `"public_ipv4"` |
| `method_class` | enum | HTTP method classification | `"GET"` |
| `path_class` | string | Normalized attack category from the 35-category taxonomy | `"dotfile"` |
| `status_bucket` | enum | HTTP status code bucket | `"4xx"` |
| `user_agent_family` | string | Normalized UA family name | `"browser"` |
| `rate_signal` | enum | Request rate classification for the source | `"normal"` |
| `scanner_family` | string or null | Identified scanner family, if any | `"nmap"` |
| `indicator_match_type` | enum or null | How the indicator was matched | `"exact_path"` |
| `candidate_mitigation_type` | enum or null | Suggested mitigation class | `"location_block"` |
| `confidence` | float | Confidence score, 0.0 to 1.0 | `0.92` |
| `provenance` | string | Identifier for the analysis pipeline that produced this event | `"log-analysis-layer2-v1.0"` |
| `ttl_recommendation` | string or null | Suggested time-to-live for any resulting rule | `"30d"` |
| `safe_notes` | string | Sanitized human-readable summary, max 200 characters | `"Repeated dotfile probes from public IPv4, nmap UA"` |
| `count` | integer | Aggregated hit count for this event bucket | `47` |

### Enum Definitions

**source_type:**
- `"access_log"` — Standard nginx access log
- `"error_log"` — Standard nginx error log
- `"honeypot_log"` — Honeypot capture log (e.g., claw.pwnship.com)

**remote_addr_class:**
- `"public_ipv4"` — Routable IPv4 address
- `"public_ipv6"` — Routable IPv6 address
- `"private"` — RFC 1918 / RFC 4193 private address
- `"loopback"` — 127.0.0.0/8 or ::1

**method_class:**
- `"GET"`, `"POST"`, `"PUT"`, `"DELETE"`, `"PATCH"`, `"OPTIONS"`, `"HEAD"` — Standard HTTP methods
- `"OTHER"` — Valid but uncommon methods (TRACE, CONNECT, etc.)
- `"INVALID"` — Malformed or non-HTTP method strings

**status_bucket:**
- `"2xx"`, `"3xx"`, `"4xx"`, `"5xx"` — HTTP status code ranges
- `"invalid"` — Non-numeric or missing status

**rate_signal:**
- `"normal"` — Baseline request rate
- `"elevated"` — Above baseline, not yet concerning
- `"burst"` — Short spike in requests
- `"flood"` — Sustained high-volume traffic

**indicator_match_type:**
- `"exact_path"` — Matched a known malicious exact path
- `"regex_path"` — Matched a path pattern/regex
- `"ua_match"` — Matched a known scanner User-Agent
- `"header_match"` — Matched a suspicious header pattern
- `null` — No indicator match

**candidate_mitigation_type:**
- `"location_block"` — Add/modify an nginx location block
- `"ua_block"` — Block by User-Agent pattern
- `"rate_limit"` — Apply rate limiting
- `"method_restrict"` — Restrict allowed HTTP methods
- `null` — No mitigation suggested

---

## Forbidden Fields

The following fields **MUST NEVER** appear in a sanitized event. Their presence indicates a sanitization failure and the event must be rejected.

| Forbidden Field | Reason |
|---|---|
| `raw_request_body` | May contain attacker payloads, injection strings, or exploit code |
| `raw_full_url` | Attacker-controlled path and query string may contain shell injection |
| `raw_query_string` | Direct attacker input; may contain SQL injection, XSS, or command injection |
| `unsanitized_headers` | Headers like X-Forwarded-For, Referer can carry arbitrary attacker data |
| `shell_fragments` | Any string containing shell metacharacters (`$`, `` ` ``, `|`, `;`, `&&`) |
| `raw_user_agent` | Unless normalized to an allowlisted family name; raw UA strings are attacker-controlled |

If any forbidden field is detected, the Layer 3 consumer **MUST** reject the entire event and log a sanitization boundary violation.

---

## JSON Example

```json
{
  "schema_version": "1.0",
  "event_id": "evt-20260323-001",
  "source_type": "access_log",
  "log_source_path": "/var/log/nginx/access.log",
  "timestamp_bucket": "2026-03-23T19:00Z",
  "remote_addr_class": "public_ipv4",
  "method_class": "GET",
  "path_class": "dotfile",
  "status_bucket": "4xx",
  "user_agent_family": "scanner",
  "rate_signal": "burst",
  "scanner_family": "nmap",
  "indicator_match_type": "exact_path",
  "candidate_mitigation_type": "location_block",
  "confidence": 0.95,
  "provenance": "log-analysis-layer2-v1.0",
  "ttl_recommendation": "permanent",
  "safe_notes": "Repeated dotfile probes (.env, .git/config) from public IPv4, nmap scanner signature",
  "count": 47
}
```

---

## Validation Rules

1. All required fields must be present; missing fields cause event rejection.
2. `schema_version` must equal `"1.0"` for this schema version.
3. `confidence` must be a float in the range `[0.0, 1.0]`.
4. `count` must be a positive integer.
5. `safe_notes` must not exceed 200 characters.
6. `timestamp_bucket` must be a valid ISO 8601 datetime truncated to the hour.
7. Enum fields must contain only the defined values; unknown values cause event rejection.
8. Forbidden fields trigger immediate rejection with a boundary violation log entry.
9. `event_id` must be unique within a single analysis run.
