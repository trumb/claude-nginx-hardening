# Findings Schema

> **Version:** 1.0
> **Purpose:** Defines the typed structure for every finding produced by the nginx hardening plugin.

---

## Finding ID Format

```
NH-{SOURCE}-{CATEGORY}-{NNNN}
```

- **SOURCE:** `AUDIT` (config audit), `LOG` (log analysis), `IOC` (indicator-of-compromise feed)
- **CATEGORY:** Short category tag (e.g., `HEADERS`, `SCANNER`, `CVE`, `DOTFILE`, `RATE`)
- **NNNN:** Zero-padded sequential number within the run

Examples:
- `NH-AUDIT-HEADERS-0004`
- `NH-LOG-SCANNER-0018`
- `NH-IOC-CVE-0007`

---

## Required Fields

| Field | Type | Description | Example |
|---|---|---|---|
| `finding_id` | string | Unique finding identifier in `NH-{SOURCE}-{CATEGORY}-{NNNN}` format | `"NH-AUDIT-HEADERS-0004"` |
| `category` | string | One of the 35 attack categories or a finding family name | `"dotfile"` |
| `severity` | enum | Impact severity level | `"high"` |
| `confidence` | float | Confidence score, 0.0 to 1.0 | `0.88` |
| `source_layers` | array of strings | Which pipeline layers contributed to this finding | `["layer1", "layer2"]` |
| `scope` | enum | How narrowly the finding is scoped | `"location"` |
| `blast_radius` | enum | How far a fix or misconfiguration could propagate | `"server-block"` |
| `recommended_action` | string | Human-readable description of the recommended remediation | `"Add X-Content-Type-Options: nosniff header"` |
| `rule_class` | enum | Rule classification for the recommended action | `"C"` |
| `requires_live_test` | boolean | Whether the fix requires live testing before deployment | `true` |
| `exception_eligible` | boolean | Whether this finding can be excepted via the exceptions schema | `true` |
| `linked_artifacts` | array of strings | File paths to related config files, logs, or generated rules | `["/etc/nginx/snippets/security-hardening.conf"]` |

### Enum Definitions

**severity:**
- `"critical"` — Actively exploitable, immediate action required
- `"high"` — Significant risk, should be addressed promptly
- `"medium"` — Moderate risk, schedule remediation
- `"low"` — Minor concern, address when convenient
- `"info"` — Informational finding, no action required

**source_layers:**
- `"layer1"` — Static config analysis
- `"layer2"` — Log analysis / sanitizer
- `"layer3"` — Config-auditor agent reasoning

**scope:**
- `"exact-directive"` — A single nginx directive
- `"location"` — A single location block
- `"server-block"` — An entire server block
- `"include-file"` — A shared include file
- `"hostname"` — All server blocks for a hostname
- `"global"` — The entire nginx configuration

**blast_radius:**
- `"exact-location"` — Change affects only one location block
- `"server-block"` — Change affects one server block
- `"include-file"` — Change propagates to all consumers of an include
- `"vhost-group"` — Change affects multiple related virtual hosts
- `"global-http"` — Change affects the http{} context globally
- `"unknown-shared"` — Blast radius cannot be determined (requires manual review)

**rule_class:**
- `"A"` — Containment Controls
- `"B"` — Request Handling Controls
- `"C"` — Baseline Hardening Controls
- `"D"` — Behavioral/Routing Controls

---

## Finding Families

The 35 attack categories map to 16 finding families for grouping and reporting:

| Finding Family | Description | Example Categories |
|---|---|---|
| `transport_security` | TLS, HSTS, certificate issues | ssl-protocol, hsts-missing |
| `headers` | Security header gaps | x-frame-options, csp, x-content-type |
| `request_filtering` | Malicious request blocking | dotfile, env-variants, source-maps |
| `path_exposure` | Sensitive path disclosure | php, wordpress, spring-actuator, swagger |
| `scanner_detection` | Automated scanner identification | scanner-ua, censys, shodan, nmap |
| `brute_force_detection` | Authentication brute force patterns | login-brute, auth-flood |
| `enumeration_behavior` | Resource/user enumeration | wp-user-enum, directory-listing |
| `ioc_matches` | Indicator-of-compromise hits | cve-probes, known-exploit-paths |
| `device_exploitation` | IoT/device exploit attempts | k8s, vite-webpack, exchange |
| `proxy_safety` | Proxy header and upstream safety | x-forwarded-for, proxy-pass |
| `logging_gaps` | Missing or insufficient logging | access-log-missing, error-log-level |
| `rate_control` | Rate limiting deficiencies | rate-limit-missing, burst-config |
| `include_hierarchy` | Include file organization issues | circular-include, missing-include |
| `location_precedence` | Location block ordering problems | regex-precedence, prefix-shadow |
| `stale_control_cleanup` | Outdated rules needing removal | expired-block, deprecated-directive |
| `exception_hygiene` | Exception review and expiry | overdue-review, missing-compensating |

---

## JSON Example

```json
{
  "finding_id": "NH-AUDIT-HEADERS-0004",
  "category": "headers",
  "severity": "medium",
  "confidence": 0.95,
  "source_layers": ["layer1"],
  "scope": "server-block",
  "blast_radius": "include-file",
  "recommended_action": "Add 'X-Content-Type-Options: nosniff' to security-hardening.conf or the server block. This header prevents MIME-type sniffing attacks.",
  "rule_class": "C",
  "requires_live_test": false,
  "exception_eligible": true,
  "linked_artifacts": [
    "/etc/nginx/snippets/security-hardening.conf",
    "/etc/nginx/sites-enabled/example.conf"
  ]
}
```

---

## Validation Rules

1. `finding_id` must match the pattern `NH-(AUDIT|LOG|IOC)-[A-Z0-9]+-\d{4}`.
2. `severity` must be one of the defined enum values.
3. `confidence` must be a float in `[0.0, 1.0]`.
4. `source_layers` must be a non-empty array containing only `"layer1"`, `"layer2"`, or `"layer3"`.
5. `scope` and `blast_radius` must be defined enum values.
6. `rule_class` must be one of `"A"`, `"B"`, `"C"`, `"D"`.
7. `linked_artifacts` must be an array (may be empty) of absolute file paths.
8. Findings with `blast_radius: "unknown-shared"` must have `requires_live_test: true`.
