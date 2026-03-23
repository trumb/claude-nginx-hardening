# Environment Profiles

> **Version:** 1.0
> **Purpose:** Defines 6 environment profiles that control which rule classes, analysis levels, and deployment behaviors are available.

---

## Profile Summary

| Profile | Description | Allowed Rule Classes | Default Analysis Level |
|---|---|---|---|
| `edge-public` | Internet-facing reverse proxy | A, B, C | L1 + L2 |
| `internal-only` | Private/internal deployment | B, C | L1 |
| `api-gateway` | Strict API protection | A, B, C | L1 + L2 |
| `static-site` | Static file serving, aggressive hardening | A, B, C | L1 |
| `reverse-proxy-app` | App-backed proxy, compatibility sensitive | B, C | L1 |
| `high-risk-lockdown` | Maximum containment posture | A, B, C | L1 + L2 + L3 |

**Analysis Levels:**
- **L1** — Static config analysis (Layer 1)
- **L2** — Log analysis via sanitizer pipeline (Layer 2)
- **L3** — Config-auditor agent reasoning (Layer 3)

> **Note:** Class D (Behavioral/Routing Controls) is never auto-applied in any profile. Class D recommendations may appear in findings for all profiles, but enforcement is always manual.

---

## edge-public

**Description:** Internet-facing reverse proxy serving one or more applications. Exposed to the full spectrum of automated scanning, brute force, and targeted attacks.

**Allowed rule classes:** A, B, C

**Default analysis level:** L1 + L2

**Required compatibility checks:**
- Verify TLS cipher suites against client base (mobile, older browsers if needed)
- Check CORS headers before applying method restrictions
- Validate upstream health before rate limiting changes

**Live test expectations:**
- All Class B rules must be tested against known-good request paths
- Header changes validated with security header scanner
- Rate limit thresholds validated with synthetic load

**Recommended recipes:**
- `daily-log-audit` — Analyze access/error logs daily
- `weekly-config-audit` — Full config audit weekly
- `ioc-check` — IOC feed check on schedule

**Emergency containment limits:**
- Class A rules with `exact-location` or `server-block` scope: auto-deploy allowed
- Class A rules with broader scope: require confirmation
- Max emergency duration: 24 hours

**Default staging paths:**
- Config staging: `outputs/staging/edge-public/`
- Findings output: `outputs/findings/edge-public/`
- Learnings output: `learnings/edge-public/`

---

## internal-only

**Description:** Private deployment accessible only from internal networks (RFC 1918). Not exposed to internet scanning but may face insider threats or lateral movement.

**Allowed rule classes:** B, C

**Default analysis level:** L1

**Required compatibility checks:**
- Verify internal service discovery compatibility
- Check mTLS requirements if applicable
- Validate internal DNS resolution for upstream blocks

**Live test expectations:**
- Minimal — internal services have controlled traffic patterns
- Method restrictions should be validated against internal API contracts

**Recommended recipes:**
- `weekly-config-audit` — Full config audit weekly
- `monthly-baseline-check` — Verify baseline hardening monthly

**Emergency containment limits:**
- Class A rules are not available for this profile
- Emergency mode is typically not applicable (no internet exposure)
- If lateral movement is detected, escalate to `high-risk-lockdown` profile

**Default staging paths:**
- Config staging: `outputs/staging/internal-only/`
- Findings output: `outputs/findings/internal-only/`
- Learnings output: `learnings/internal-only/`

---

## api-gateway

**Description:** Strict API protection layer. Handles structured API traffic (JSON/gRPC) with well-defined endpoints. Zero tolerance for unexpected paths or methods.

**Allowed rule classes:** A, B, C

**Default analysis level:** L1 + L2

**Required compatibility checks:**
- Validate allowed methods per endpoint against API specification
- Verify Content-Type restrictions do not block legitimate API clients
- Check rate limit thresholds against documented API SLAs
- Validate CORS preflight handling for browser-based API consumers

**Live test expectations:**
- All method restrictions must be tested against the API specification
- Rate limit thresholds validated with API load testing
- Path deny rules validated against API route inventory

**Recommended recipes:**
- `daily-log-audit` — Analyze access/error logs daily
- `api-endpoint-audit` — Verify all defined routes have hardened location blocks
- `ioc-check` — IOC feed check on schedule

**Emergency containment limits:**
- Class A rules with `exact-location` scope: auto-deploy allowed
- Rate limiting changes require confirmation (may affect API SLAs)
- Max emergency duration: 24 hours

**Default staging paths:**
- Config staging: `outputs/staging/api-gateway/`
- Findings output: `outputs/findings/api-gateway/`
- Learnings output: `learnings/api-gateway/`

---

## static-site

**Description:** Serves static files only (HTML, CSS, JS, images). No dynamic backend. Allows aggressive hardening because the request surface is minimal and predictable.

**Allowed rule classes:** A, B, C

**Default analysis level:** L1

**Required compatibility checks:**
- Verify allowed file extensions match deployed assets
- Check cache header compatibility
- Validate that deny rules do not block legitimate static asset paths

**Live test expectations:**
- Minimal — static sites have highly predictable traffic
- Verify all served file types are accessible after method restrictions
- Validate security headers do not break embedded resources (fonts, images)

**Recommended recipes:**
- `weekly-config-audit` — Full config audit weekly
- `static-asset-audit` — Verify only expected file types are served

**Emergency containment limits:**
- Class A rules: broadly permissive for static sites due to minimal legitimate path surface
- Can aggressively block any path not matching known static extensions
- Max emergency duration: 24 hours

**Default staging paths:**
- Config staging: `outputs/staging/static-site/`
- Findings output: `outputs/findings/static-site/`
- Learnings output: `learnings/static-site/`

---

## reverse-proxy-app

**Description:** Application-backed reverse proxy where nginx fronts a dynamic application (Node.js, Python, Go, etc.). Compatibility with the application is critical — overly aggressive hardening can break functionality.

**Allowed rule classes:** B, C

**Default analysis level:** L1

**Required compatibility checks:**
- **Critical:** Verify all location blocks against application route inventory
- Check that proxy headers (`X-Forwarded-For`, `X-Real-IP`, `Host`) are correctly passed
- Validate WebSocket support if applicable (`Upgrade`, `Connection` headers)
- Verify request body size limits against application requirements
- Check timeout values against application response times

**Live test expectations:**
- All Class B rules require live testing against the application
- Method restrictions must be validated per-route against application behavior
- Header changes must be tested for conflicts with application-set headers

**Recommended recipes:**
- `weekly-config-audit` — Full config audit weekly
- `proxy-health-check` — Verify upstream connectivity and header passthrough

**Emergency containment limits:**
- Class A rules are not available for this profile (risk of breaking app)
- Emergency response should focus on upstream application controls
- If active exploitation detected, escalate to `high-risk-lockdown` profile

**Default staging paths:**
- Config staging: `outputs/staging/reverse-proxy-app/`
- Findings output: `outputs/findings/reverse-proxy-app/`
- Learnings output: `learnings/reverse-proxy-app/`

---

## high-risk-lockdown

**Description:** Maximum containment posture for servers under active attack or handling extremely sensitive data. All three analysis layers are active. Aggressive rules are permitted with broader scope.

**Allowed rule classes:** A, B, C

**Default analysis level:** L1 + L2 + L3

**Required compatibility checks:**
- Verify allowlisted paths and sources before applying broad deny rules
- Check that critical application functionality is preserved
- Validate that monitoring/alerting endpoints remain accessible
- Confirm rollback procedures are in place

**Live test expectations:**
- Class A emergency rules: may skip live testing if blast radius is narrow
- Class B/C rules: require testing but on accelerated timeline
- All changes logged with full provenance for incident review

**Recommended recipes:**
- `continuous-log-audit` — Analyze logs every hour
- `emergency-containment` — Deploy Class A containment rules
- `ioc-check` — IOC feed check every 6 hours
- `incident-report` — Generate incident summary with all findings and actions

**Emergency containment limits:**
- Class A rules: broadest permissions of any profile
- Server-block and vhost-group scope allowed without confirmation
- Global-http scope still requires confirmation
- Max emergency duration: 48 hours (extended from default 24)
- All emergency rules are automatically reviewed after the emergency window

**Default staging paths:**
- Config staging: `outputs/staging/high-risk-lockdown/`
- Findings output: `outputs/findings/high-risk-lockdown/`
- Learnings output: `learnings/high-risk-lockdown/`

---

## Profile Selection Guide

| Scenario | Recommended Profile |
|---|---|
| Public website behind Cloudflare/CDN | `edge-public` |
| Internal microservice mesh | `internal-only` |
| REST/gRPC API with strict contracts | `api-gateway` |
| GitHub Pages-style static hosting | `static-site` |
| nginx fronting a Node.js/Django/Rails app | `reverse-proxy-app` |
| Server under active attack or incident response | `high-risk-lockdown` |

To change profiles mid-operation, update the `profile` field in the recipe frontmatter and re-run. Profile changes take effect on the next recipe execution.
