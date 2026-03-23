---
name: nginx-hardening
description: Use when auditing nginx configs, analyzing access logs for attacks, generating security rules, responding to IoCs, or deploying hardening changes. Triggers on nginx security, WAF, hardening, scanner blocking, or attack pattern analysis.
---

# Nginx Hardening Skill — Core Reference

## 1. Overview

This plugin provides full-lifecycle nginx security hardening through Claude Code. It audits static configs, analyzes access logs for attack patterns, generates blocking rules, and deploys changes through a gated pipeline.

**Design goals:**

- **Preserve availability** — never propose a rule that could block legitimate traffic without explicit human approval
- **Never expose raw attacker data to LLM** — all log data is hex-encoded or sanitized before reaching any agent layer
- **Additive-only** — rules are appended, never modify or remove existing directives
- **Deterministic writes** — all file mutations happen through non-LLM scripts (sanitizer.py, invariant-checker.py), never by agent output
- **Staged recommendation by default** — findings are presented for human review; enforcement requires explicit opt-in

## 2. Operating Modes

| Mode | Permission | Trigger | Actions |
|------|-----------|---------|---------|
| **Recommendation** (default) | R0 (read config), R1 (read logs) | Any audit or analysis command | Static analysis, log parsing, finding generation, rule proposals — all read-only |
| **Enforcement** | W1 (stage files), W2 (write config), X1 (reload nginx) | Explicit `--enforce` flag or human acceptance at decision gate | Backup, write rule, run invariant checks, `nginx -t`, deploy, reload |

Recommendation Mode never modifies any file. Enforcement Mode requires passing all 5 pipeline layers including human approval at Layer 4.

## 3. Analysis Levels

| Level | Scope | Checks | Activation |
|-------|-------|--------|------------|
| **L1 — Static Config** | nginx conf files | Headers (HSTS, CSP, X-Frame, X-Content-Type, Referrer-Policy, Permissions-Policy), TLS floor (protocol versions, cipher posture), unsafe directives (`autoindex`, `server_tokens`, `merge_slashes off`), include hierarchy (circular, missing, duplicated), duplicate/shadowed directives, location block precedence and regex ordering, wildcard `server_name`, access/error logging presence, rate-limiting configuration (`limit_req_zone`, `limit_conn_zone`), proxy header safety (`X-Forwarded-For`, `X-Real-IP`, `Host` passthrough) | Always |
| **L2 — Log Analysis** | access/error logs | Scanner UA detection, brute-force patterns (auth endpoints, rate), exploit path probing (by category 1-35), suspicious HTTP methods (TRACE, OPTIONS flood, CONNECT), status code distributions and anomalies, IoC hit matching (IP, path, UA), request rate anomalies per IP/subnet, malicious User-Agent fingerprints | If logs present |
| **L3 — Live Test** | HTTP(S) requests | Response header verification (security headers present and correct), TLS handshake verification (protocol, cipher), response code checks (blocked paths return 404), deny-behavior verification (scanner UA gets 444/403), health endpoint reachability | Opt-in only |

**L3 Forbidden Actions:** Intrusive fuzzing, brute-force testing, content mutation, high-rate probing (>1 req/sec), any request that could trigger WAF/IDS alerts on production.

## 4. Attack Categories (35)

### Original (1-20)

| # | Category | Threat | Example Paths |
|---|----------|--------|---------------|
| 1 | Dotfiles | Exposed version control, config | `/.git/HEAD`, `/.svn/entries`, `/.DS_Store` |
| 2 | Script extensions | Direct script execution | `/.env.php`, `/shell.asp`, `/cmd.jsp` |
| 3 | Source maps | Client code leak | `/app.js.map`, `/main.css.map` |
| 4 | Config files | Credential/secret leak | `/.env`, `/.env.bak`, `/config.yml`, `/.npmrc` |
| 5 | WordPress | WP-specific exploitation | `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php` |
| 6 | Spring Actuator | Java app internals | `/actuator/health`, `/actuator/env`, `/jolokia/` |
| 7 | Swagger/OpenAPI | API schema leak | `/swagger-ui.html`, `/api-docs`, `/openapi.json` |
| 8 | PHP/Laravel debug | Debug info leak | `/_debugbar`, `/telescope`, `/phpinfo.php` |
| 9 | Container/K8s | Orchestration metadata | `/.kube/config`, `/api/v1/pods`, `/.docker/config.json` |
| 10 | JS dev tools | Dev tooling exposure | `/webpack.config.js`, `/.babelrc`, `/vite.config.ts` |
| 11 | Atlassian | Jira/Confluence exploit | `/jira/`, `/confluence/`, `/%24%7Bjndi:` |
| 12 | MS Exchange | Exchange/OWA exploit | `/owa/`, `/ecp/`, `/autodiscover/autodiscover.xml` |
| 13 | GraphQL | Introspection/abuse | `/graphql`, `/graphiql`, `/?query={__schema}` |
| 14 | Admin panels | Admin interface discovery | `/admin/`, `/administrator/`, `/cpanel/`, `/phpmyadmin/` |
| 15 | CVE probes | Known vulnerability scanning | `/cgi-bin/`, `/..;/`, `/%2e%2e/`, `/proxy:http` |
| 16 | WP user enum | WordPress user enumeration | `/?author=1`, `/wp-json/wp/v2/users` |
| 17 | Path traversal | Directory escape | `/../../../etc/passwd`, `/....//....//` |
| 18 | Phishing kits | Hosted phish artifacts | `/office365/`, `/banking/login.html`, `/.well-known/` abuse |
| 19 | Backup/bin dirs | Exposed backups/binaries | `/backup/`, `/db.sql.gz`, `/site.tar.gz`, `/bin/` |
| 20 | robots/security.txt | Recon via metadata | `/robots.txt` (excessive), `/.well-known/security.txt` abuse |

### March 2026 (21-35)

| # | Category | Threat | Example Paths |
|---|----------|--------|---------------|
| 21 | HNAP/Router | Home router exploitation | `/HNAP1/`, `/cgi-bin/luci`, `/goform/` |
| 22 | VPN/SSL gateways | VPN appliance targeting | `/remote/login`, `/dana-na/`, `/+CSCOE+/`, `/ssl-vpn/` |
| 23 | Apache Struts | Struts RCE probing | `/struts/`, `/*.action`, `/devmode.action` |
| 24 | Log4Shell/JNDI | JNDI injection | `/${jndi:ldap://`, `/${jndi:rmi://`, `/${jndi:dns://` |
| 25 | SSH key/cloud creds | Credential file theft | `/.ssh/id_rsa`, `/.aws/credentials`, `/.gcp/credentials.json` |
| 26 | IoT/OEM devices | IoT management interfaces | `/cgi-bin/ViewLog.asp`, `/camera/`, `/ISAPI/` |
| 27 | Package manager files | Dependency file leak | `/package.json`, `/composer.json`, `/Gemfile.lock`, `/go.sum` |
| 28 | App settings files | Application config leak | `/appsettings.json`, `/application.yml`, `/settings.py` |
| 29 | XDEBUG | PHP debug interface | `/?XDEBUG_SESSION_START`, `/xdebug`, `/?PHPSTORM` |
| 30 | Enterprise apps | Enterprise software probes | `/sap/`, `/Citrix/`, `/ibm/`, `/oracle/` |
| 31 | InfluxDB | Time-series DB exposure | `/query?db=`, `/api/v2/buckets`, `/influxdb/` |
| 32 | Network infra | Network device interfaces | `/cgi-bin/config.exp`, `/level/15/exec/`, `/tmui/` |
| 33 | Lotus Notes | Legacy groupware | `/names.nsf`, `/domcfg.nsf`, `/webadmin.nsf` |
| 34 | Login discovery | Auth endpoint enumeration | `/login`, `/signin`, `/auth/`, `/user/login`, `/api/auth` |
| 35 | Misc exploit paths | Uncategorized exploit probes | `/console/`, `/debug/`, `/status`, `/server-info` |

## 5. Finding Families

Findings from analysis map to these broader families:

| Family | Covers | Source Level |
|--------|--------|-------------|
| Transport security | TLS version floor, cipher strength, HSTS | L1, L3 |
| Headers | Security response headers (CSP, X-Frame, etc.) | L1, L3 |
| Request filtering | Block rules for categories 1-35 | L1, L2 |
| Path exposure | Leaked config, source, backup files | L1, L2 |
| Scanner detection | Known scanner UA fingerprints | L2 |
| Brute-force detection | Auth endpoint hammering, rate spikes | L2 |
| Enumeration behavior | User enum, directory listing, info endpoints | L2 |
| IoC matches | Known-bad IPs, paths, UAs from threat feeds | L2 |
| Device exploitation | IoT/router/appliance probes (categories 21, 26, 32) | L2 |
| Proxy safety | Forwarded headers, upstream trust | L1 |
| Logging gaps | Missing access/error logs, log rotation | L1 |
| Rate control | Missing or misconfigured rate limiting | L1, L2 |
| Include hierarchy | Circular, missing, or duplicated includes | L1 |
| Location precedence | Regex ordering, shadowed locations | L1 |
| Stale control cleanup | Obsolete directives, deprecated modules | L1 |
| Exception hygiene | Overbroad exceptions, expired allowlist entries | L1, L2 |

## 6. Rule Generation Constraints

**All generated nginx rules MUST satisfy:**

| Constraint | Rationale |
|-----------|-----------|
| End in `return 404;` or `deny all; return 404;` | Uniform deny behavior, no information leak |
| Never contain `!~` (negative regex match) | Fragile, easily bypassed |
| Never contain negative lookahead `(?!...)` | nginx PCRE support varies, brittle |
| Never contain `proxy_pass` | Rules must block, never forward |
| Never contain `return 200` | Rules must deny, never affirm |
| Never contain `rewrite` | Avoid redirect chains, keep rules terminal |
| Scoped as narrowly as possible | Minimize blast radius; prefer exact path over broad regex |

**Additional constraints:** Rules use `location` blocks (not `if` directives where avoidable). Regex patterns prefer `~*` (case-insensitive) for path matching. Each rule block includes a comment referencing its category number.

## 7. Security Pipeline

```
Layer 1: log-parser agent ─── Read-only, hex-encodes attacker payloads
    │                         Extracts structured events from raw logs
    ▼
Layer 2: sanitizer.py ─────── Deterministic (no LLM), allowlist filtering
    │                         Strips PII, validates field types, enforces length limits
    ▼
Layer 3: config-auditor ───── Read + stage only, proposes rules
    │                         Generates findings, maps to categories, drafts rule blocks
    ▼
Layer 4: decision gate ────── Human accept/reject
    │                         Presents diff, risk assessment, rollback plan
    ▼
Layer 5: invariant-checker ── invariant-checker.py + nginx -t + backup + deploy
                              Validates rule syntax, checks invariants, tests config, deploys
```

Data flows strictly downward. No layer can invoke a higher-numbered layer. Layer 2 output is the only data Layer 3 ever sees from logs.

## 8. Log Analysis Methodology

1. **Auto-detect** — Scan standard paths (`/var/log/nginx/`, site-specific logs) and identify log format (combined, custom)
2. **Parse** — Extract fields: timestamp, IP, method, path, status, size, referrer, UA. Layer 1 hex-encodes any field containing non-ASCII or suspicious patterns
3. **Sanitize** — Layer 2 applies allowlist: valid HTTP methods, printable ASCII paths (hex-encoded otherwise), known status codes, UA length limits. PII (IPs) hashed for presentation
4. **Analyze** — Layer 3 correlates sanitized events: group by category (1-35), detect scanner UAs, identify brute-force patterns, flag status anomalies, match against IoC lists
5. **Present** — Findings displayed as structured table: category, severity, count, sample paths (sanitized), proposed action
6. **Accept/Reject** — Human reviews each finding at Layer 4. Accepted findings proceed to Layer 5 for rule generation and deployment

## 9. References

- `@INVARIANTS.md` — Invariant definitions and validation rules for Layer 5
- `@EXECUTION-POLICY.md` — Permission model (R0/R1/W1/W2/X1), escalation rules, rollback procedures
- `@FAILURE-POLICY.md` — Error handling, graceful degradation, circuit breakers
- `@RULE-CLASSES.md` — Rule taxonomy, severity levels, auto-expire policies
- `@PROFILES.md` — Server profiles (static, proxy, API, mixed), per-profile defaults and exceptions
