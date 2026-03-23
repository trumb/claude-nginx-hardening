# Rule Classes

> **Version:** 1.0
> **Purpose:** Defines the four rule classes (A, B, C, D) that categorize every nginx hardening rule by function, risk profile, and emergency eligibility.

---

## Overview

| Class | Name | Emergency Eligible | Auto-Generate | Blast Radius Constraint |
|---|---|---|---|---|
| **A** | Containment Controls | Yes (if narrow scope) | Yes | Prefer exact-location |
| **B** | Request Handling Controls | No (default) | Yes | Requires precedence checks |
| **C** | Baseline Hardening Controls | No | Yes | Requires compatibility checks |
| **D** | Behavioral/Routing Controls | No | Recommendation only | Blocked from emergency mode |

---

## Class A — Containment Controls

**Purpose:** Block known-malicious traffic as close to the edge as possible. These are reactive, targeted rules designed to stop active threats.

**Examples:**
- IP/CIDR deny rules for known-malicious sources
- `deny` directives for malicious path classes (e.g., `.env`, `.git/config`)
- Rate limiting for identified scanner sources
- User-Agent blocking for known scanner families (nmap, zgrab, censys, etc.)
- Geographic or ASN-based restrictions

**Emergency eligible:** Yes, provided the rule has narrow scope (exact-location or server-block blast radius). Rules with global-http or vhost-group blast radius require confirmation even in emergency mode.

**Auto-generate:** Yes. The plugin can generate Class A rules automatically from findings and sanitized events.

**Blast radius constraint:** Prefer `exact-location` scope. If a broader scope is necessary, the finding must document why and the rule must include a TTL recommendation.

**Deployment notes:**
- Class A rules are typically added to location blocks or included via `security-hardening.conf`.
- Expiry/TTL should be set for IP-based blocks (default 30 days unless marked permanent).
- Must not conflict with allowlisted paths or sources.

---

## Class B — Request Handling Controls

**Purpose:** Enforce correct HTTP request handling. These rules define what requests are acceptable and how they are processed.

**Examples:**
- HTTP method restrictions (e.g., only allow GET/HEAD/POST on static locations)
- Exact-path deny rules for known dangerous endpoints
- Hardened location blocks with explicit `internal` or `deny all` directives
- Request body size limits
- URI normalization and duplicate-slash handling

**Emergency eligible:** No (default). Class B rules change request handling semantics and can break legitimate functionality if deployed without testing.

**Auto-generate:** Yes. The plugin can generate Class B rules, but they require precedence checks before deployment.

**Requirements:**
- **Precedence checks:** Before deploying a Class B rule, the plugin must verify it does not shadow or conflict with existing location blocks. Nginx location matching priority (exact > prefix > regex) must be respected.
- **Live test recommended:** Class B rules that restrict methods or block paths should be validated against known-good traffic patterns.

**Deployment notes:**
- Class B rules are typically placed in specific location blocks.
- Method restrictions must account for CORS preflight (OPTIONS) if applicable.
- Exact-path denies should use `= /path` for precision.

---

## Class C — Baseline Hardening Controls

**Purpose:** Establish and maintain security baselines for headers, TLS configuration, timeouts, and logging. These are proactive, non-reactive controls.

**Examples:**
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, `Referrer-Policy`, `Permissions-Policy`
- TLS/protocol settings: `ssl_protocols`, `ssl_ciphers`, `ssl_prefer_server_ciphers`
- Timeout tuning: `client_body_timeout`, `client_header_timeout`, `keepalive_timeout`
- Logging configuration: access log format, error log level
- `server_tokens off`

**Emergency eligible:** No. Baseline changes are not appropriate for emergency response — they require careful testing and rollout.

**Auto-generate:** Yes. The plugin can generate Class C rules, but they require compatibility checks.

**Requirements:**
- **Compatibility checks:** Header additions must not conflict with application-set headers. TLS changes must be validated against client compatibility requirements.
- **Immutable header invariant:** The plugin must respect the immutable header list defined in `INVARIANTS.md`. Headers already set by the application layer must not be overridden without explicit exception.

**Deployment notes:**
- Class C rules are typically placed in `security-hardening.conf` (shared include) or the `http{}` block.
- Header changes should be tested with a security header scanner before production deployment.
- TLS changes should be validated against SSL Labs or equivalent.

---

## Class D — Behavioral/Routing Controls

**Purpose:** Modify application routing, authentication flows, or upstream behavior. These rules have the highest potential for unintended side effects.

**Examples:**
- Upstream routing changes (`proxy_pass` target modifications)
- Authentication flow changes (auth_request, auth_basic configuration)
- Broad rewrite rules (`rewrite` directives affecting multiple paths)
- Redirect chains
- Load balancer upstream modifications

**Emergency eligible:** No. **Class D rules are blocked from emergency mode entirely.** They affect application behavior in ways that require thorough testing and coordination with application teams.

**Auto-generate:** Recommendation only. The plugin may **recommend** Class D changes in findings but must **never** generate enforceable Class D rules. All Class D changes require manual implementation and review.

**Requirements:**
- **Manual review mandatory:** Class D recommendations must be clearly marked as "recommendation only — requires manual implementation."
- **Application team coordination:** Changes to upstream routing or auth flows must involve the application team.
- **Rollback plan:** Any Class D change must have a documented rollback procedure.

**Deployment notes:**
- Class D recommendations appear in findings with `rule_class: "D"` and `requires_live_test: true`.
- The plugin will never write Class D rules to config files.
- Class D items in audit reports are marked with a distinct visual indicator.

---

## Emergency Mode Summary

| Class | Emergency Mode | Conditions |
|---|---|---|
| A | Allowed | Narrow scope only (exact-location or server-block) |
| B | Not allowed | — |
| C | Not allowed | — |
| D | Blocked | Cannot be used in emergency mode under any circumstances |

Emergency mode is a time-limited state (max 24 hours) where Class A containment rules can be deployed with reduced confirmation requirements. After 24 hours, emergency rules must be reviewed and either promoted to permanent rules or removed.

---

## Rule Class Selection Guide

When a finding is produced, the rule class is determined by:

1. **Is the recommended action blocking/rate-limiting active threats?** -> Class A
2. **Is it restricting HTTP methods or blocking specific paths?** -> Class B
3. **Is it adding headers, TLS settings, or logging?** -> Class C
4. **Does it change routing, auth, or upstream behavior?** -> Class D

If ambiguous, prefer the lower class (A < B < C < D) to minimize blast radius.
