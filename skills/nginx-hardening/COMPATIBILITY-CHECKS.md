# Compatibility Checks Reference

> **Version:** 1.0
> **Purpose:** Reference document for all 9 compatibility checks performed by `scripts/compatibility-checker.py` before nginx config deployment.

---

## Overview

The compatibility checker runs after invariant validation and before deployment. It ensures that proposed hardening changes do not break legitimate functionality. Each check returns one of three severities:

- **Critical** — Deployment MUST be blocked. The proposed change will break essential functionality.
- **Warning** — User confirmation required. The change may cause issues depending on the environment.
- **Pass** — No compatibility issue detected.

Profile-specific severity overrides are documented per check below.

---

## Check 1: ACME / Let's Encrypt Challenge Paths

### What It Checks
Verifies that `/.well-known/acme-challenge/` paths remain accessible and are not blocked by deny rules, method restrictions, or aggressive location blocks in the proposed config.

### Why It Matters
Let's Encrypt and other ACME-based CAs require HTTP-01 challenges to validate domain ownership. If challenge paths are blocked, certificate renewal fails silently until expiry, causing outages.

### What Failure Means
- **Critical failure:** A deny rule, return 403/404, or restrictive location match covers `/.well-known/acme-challenge/`. Certificate renewal will fail.
- **Warning:** Challenge path is not explicitly allowed but may still work due to fallthrough — requires manual verification.

### Profile Severity
| Profile | Severity |
|---|---|
| `edge-public` | Critical |
| `api-gateway` | Critical |
| `static-site` | Critical |
| `reverse-proxy-app` | Critical |
| `internal-only` | Warning (may use internal CA) |
| `high-risk-lockdown` | Warning (may use DNS-01 challenge instead) |

---

## Check 2: Health and Readiness Endpoints

### What It Checks
Verifies that common health check endpoints remain accessible: `/health`, `/healthz`, `/ready`, `/readiness`, `/status`, `/ping`, and any custom health paths declared in the config or detected in upstream blocks.

### Why It Matters
Load balancers, Kubernetes probes, and monitoring systems rely on health endpoints. Blocking them causes cascading failures: the server is removed from rotation, traffic shifts, and alerts fire.

### What Failure Means
- **Critical failure:** A known health endpoint is explicitly denied or returns a non-2xx status due to the proposed changes.
- **Warning:** Health endpoint exists but is not explicitly preserved in the proposed config (relies on fallthrough behavior).

### Profile Severity
| Profile | Severity |
|---|---|
| `edge-public` | Critical |
| `api-gateway` | Critical |
| `reverse-proxy-app` | Critical |
| `internal-only` | Critical |
| `static-site` | Warning (typically no health checks) |
| `high-risk-lockdown` | Critical |

---

## Check 3: Reverse Proxy Headers

### What It Checks
Verifies that required proxy headers are preserved in all `proxy_pass` location blocks: `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `Host`, and any custom headers defined in the current config.

### Why It Matters
Backend applications depend on proxy headers for IP-based rate limiting, protocol detection (HTTP vs HTTPS), session affinity, and audit logging. Missing headers cause authentication failures, incorrect redirects, and broken IP logging.

### What Failure Means
- **Critical failure:** A `proxy_pass` block in the proposed config is missing `proxy_set_header` directives that exist in the current config.
- **Warning:** New `proxy_pass` blocks are added without the standard set of proxy headers.

### Profile Severity
| Profile | Severity |
|---|---|
| `reverse-proxy-app` | Critical |
| `edge-public` | Critical |
| `api-gateway` | Critical |
| `internal-only` | Warning |
| `static-site` | Pass (no proxy_pass expected) |
| `high-risk-lockdown` | Critical |

---

## Check 4: WebSocket Upgrade Handling

### What It Checks
Verifies that location blocks serving WebSocket connections preserve `proxy_set_header Upgrade $http_upgrade` and `proxy_set_header Connection "upgrade"` directives. Also checks that method restrictions do not block the initial GET request used for WebSocket handshake.

### Why It Matters
WebSocket connections start as an HTTP GET with an `Upgrade: websocket` header. If the upgrade headers are stripped or the GET method is restricted on that path, WebSocket connections fail, breaking real-time features (chat, live updates, etc.).

### What Failure Means
- **Critical failure:** A known WebSocket location block has its `Upgrade`/`Connection` headers removed or overwritten by the proposed changes.
- **Warning:** A `proxy_pass` block includes `proxy_http_version 1.1` (a WebSocket indicator) but lacks explicit upgrade headers.

### Profile Severity
| Profile | Severity |
|---|---|
| `reverse-proxy-app` | Critical |
| `api-gateway` | Critical (if WebSocket endpoints exist) |
| `edge-public` | Warning |
| `internal-only` | Warning |
| `static-site` | Pass (no WebSocket expected) |
| `high-risk-lockdown` | Warning (may intentionally disable WS) |

---

## Check 5: Include Graph Integrity

### What It Checks
Verifies that all `include` directives in the proposed config resolve to existing files, that no circular includes exist, and that the include graph does not reference files outside the expected config directories (`/etc/nginx/`, project `deploy/nginx/`).

### Why It Matters
A broken include causes `nginx -t` to fail, which blocks reload. Circular includes cause infinite loops. Includes pointing outside expected directories may pull in untrusted configuration.

### What Failure Means
- **Critical failure:** An `include` directive references a file that does not exist, or a circular dependency is detected.
- **Warning:** An `include` references a file outside standard config directories.

### Profile Severity
| Profile | Severity |
|---|---|
| All profiles | Critical |

This check is **always critical** regardless of profile. A broken include graph means nginx will not start.

---

## Check 6: Duplicate Directives

### What It Checks
Scans the proposed config (including all resolved includes) for duplicate directives in the same context. Detects cases where the same directive appears multiple times in the same `server`, `location`, or `http` block, which may cause unexpected behavior depending on the directive type.

### Why It Matters
Some nginx directives use last-wins semantics (e.g., `root`), while others are additive (e.g., `add_header`). Duplicate directives can silently override intended values, causing security headers to disappear or access controls to weaken.

### What Failure Means
- **Critical failure:** A security-critical directive (`add_header` for security headers, `deny`, `allow`, `ssl_protocols`) is duplicated with conflicting values.
- **Warning:** A non-security directive is duplicated (may be intentional for override patterns).

### Profile Severity
| Profile | Severity |
|---|---|
| `high-risk-lockdown` | Critical (all duplicates) |
| `edge-public` | Critical (security directives), Warning (others) |
| `api-gateway` | Critical (security directives), Warning (others) |
| `reverse-proxy-app` | Critical (security directives), Warning (others) |
| `static-site` | Critical (security directives), Warning (others) |
| `internal-only` | Warning (all duplicates) |

---

## Check 7: Header Inheritance Conflicts

### What It Checks
Detects cases where `add_header` directives in a child block (e.g., `location`) cause all parent-level `add_header` directives to be dropped. In nginx, if ANY `add_header` appears in a child context, ALL parent `add_header` directives are no longer inherited.

### Why It Matters
This is one of the most common nginx misconfiguration pitfalls. Adding a single `add_header` in a location block silently removes all security headers defined at the server level (CSP, HSTS, X-Frame-Options, etc.), creating a significant security regression.

### What Failure Means
- **Critical failure:** A proposed location block adds `add_header` directives without re-declaring all security headers from the parent `server` block.
- **Warning:** A location block inherits headers but the proposed changes add new `add_header` directives at the server level that existing location blocks will not inherit.

### Profile Severity
| Profile | Severity |
|---|---|
| All profiles | Critical |

This check is **always critical**. Header inheritance bugs silently remove security headers without any nginx error, making them extremely dangerous.

---

## Check 8: Location Precedence

### What It Checks
Analyzes the location block precedence order (exact `=`, prefix `^~`, regex `~`/`~*`, plain prefix) to detect cases where a proposed deny rule is shadowed by a higher-precedence allow rule, or where a new location block unintentionally captures traffic meant for another block.

### Why It Matters
Nginx location matching follows a specific precedence order. A new `location ~ \.php$` deny rule is useless if an existing `location = /index.php` allows the request first. Misunderstanding precedence is a leading cause of security bypass.

### What Failure Means
- **Critical failure:** A proposed security deny rule is completely shadowed by a higher-precedence location block that allows the request.
- **Warning:** A new location block changes the effective match for some request paths, potentially altering behavior.

### Profile Severity
| Profile | Severity |
|---|---|
| `edge-public` | Critical |
| `api-gateway` | Critical |
| `high-risk-lockdown` | Critical |
| `reverse-proxy-app` | Critical |
| `static-site` | Warning |
| `internal-only` | Warning |

---

## Check 9: Deny/Allow Interaction Analysis

### What It Checks
Analyzes the interaction between `deny` and `allow` directives across the proposed config to detect:
- `deny all` rules that are unreachable because a preceding `allow all` matches first
- `allow` rules that are negated by a subsequent `deny all` in the same block
- Mixed `deny`/`allow` patterns that do not achieve the intended access control
- Geo-block or IP-based restrictions that conflict with proposed changes

### Why It Matters
Nginx processes `deny` and `allow` directives in order within a block, stopping at the first match. Incorrect ordering can either lock out legitimate users or fail to block attackers, depending on which directive matches first.

### What Failure Means
- **Critical failure:** An `allow` directive for a critical IP range (health check source, internal network, ACME validator) is negated by a preceding `deny all`.
- **Warning:** The deny/allow ordering achieves the intended result but uses a non-standard pattern that may confuse future maintainers.

### Profile Severity
| Profile | Severity |
|---|---|
| `edge-public` | Critical |
| `api-gateway` | Critical |
| `high-risk-lockdown` | Critical |
| `reverse-proxy-app` | Critical |
| `internal-only` | Critical (deny/allow is primary access control) |
| `static-site` | Warning |

---

## Running the Checker

### Command Line
```bash
python3 scripts/compatibility-checker.py \
  --proposed <proposed-config-path> \
  --current <current-config-path> \
  --profile <profile-name>
```

### Output Format
```json
{
  "checks": [
    {
      "id": 1,
      "name": "acme_challenge_paths",
      "status": "pass|warning|critical",
      "details": "...",
      "affected_blocks": []
    }
  ],
  "summary": {
    "total": 9,
    "pass": 7,
    "warning": 1,
    "critical": 1
  },
  "deploy_allowed": false
}
```

`deploy_allowed` is `false` if any check returns `critical` status.

### Integration Points
- **deploy-nginx** — runs automatically before deployment (Step 2b)
- **harden-nginx full** — runs during the validate phase
- **audit-nginx** — can be invoked standalone for config review
