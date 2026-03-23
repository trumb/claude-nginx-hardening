# claude-nginx-hardening

Full-lifecycle nginx security hardening plugin for [Claude Code](https://claude.ai/claude-code).

## What It Does

A Claude Code plugin that audits nginx configs, analyzes access logs for attack patterns, generates blocking rules, responds to indicators of compromise, and deploys hardening changes through a gated pipeline. Covers 35 attack categories derived from live honeypot data. Implements a 5-layer security pipeline that never exposes raw attacker data to the LLM. Enforces 18 invariants on every operation. Includes IoC/threat intel with 10 built-in feeds, a recipe system with scheduling, canary deployment, rule aging, and environment profiles.

## Quick Start

```bash
# Install the plugin (from the Claude Code CLI)
claude plugin add trumb/claude-nginx-hardening

# First run — audit your nginx config
/harden-nginx audit

# Analyze access logs for attack patterns
/harden-nginx analyze-logs

# Full lifecycle: analyze + audit + review + stage + deploy
/harden-nginx full

# Check threat feeds for IoCs
/harden-nginx ioc --feed all

# Run a saved recipe
/harden-nginx recipe run weekly-scan
```

The plugin auto-detects nginx configs in `/etc/nginx/sites-enabled/` and logs in `/var/log/nginx/`. All operations default to **Recommendation Mode** (read-only) — no files are modified unless you explicitly opt in.

## Commands

| Command | Description | Default Mode |
|---|---|---|
| `/harden-nginx` | Main entry — NL routing, explicit subcommands, or interactive menu | R0+R1 |
| `/harden-nginx audit` | Config compliance audit (headers, TLS, blocking rules, 35 categories) | R0+R1 |
| `/harden-nginx analyze-logs` | Log analysis through sanitizer pipeline (scanner detection, attack patterns) | R0+R1 |
| `/harden-nginx deploy` | Staged deployment (backup, validate, write, nginx -t, reload) | W1 (explicit) |
| `/harden-nginx ioc` | IoC/threat intel response — local + feed-based indicator matching, 3 response modes | R0+R1 |
| `/harden-nginx recipe` | Recipe management — create, run, list, edit, install, export saved workflows | R0+R1 |
| `/harden-nginx aging` | Rule aging — scan for stale rules, report staleness, tag for review | R0+R1 |
| `/harden-nginx exceptions` | Exception management — review, create, renew security exceptions | R0+R1 |
| `/harden-nginx rollback` | Rollback — restore config from timestamped backups with safety checks | R0+R1 |
| `/harden-nginx learnings` | Learnings management — list, promote, compact, export | R0+R1 |

Append `--apply` for local writes or `--deploy` for full enforcement (writes + git push + remote execution).

All commands support `--json` for machine-readable output and `--profile <name>` for environment profile selection.

## Security Pipeline

```
Layer 1: log-parser agent      Read-only, hex-encodes attacker payloads
   |                           Extracts structured events from raw logs
   v
Layer 2: sanitizer.py          Deterministic (no LLM), allowlist filtering
   |                           Strips PII, validates fields, enforces length limits
   v
Layer 3: config-auditor        Read + stage only, proposes rules
   |                           Generates findings, maps to categories, drafts rule blocks
   v
Layer 4: decision gate         Human accept/reject
   |                           Presents diff, risk assessment, rollback plan
   v
Layer 5: invariant-checker     invariant-checker.py + nginx -t + backup + deploy
                               Validates rule syntax, checks invariants, tests config
```

Data flows strictly downward. No layer can invoke a higher-numbered layer. Layer 2 output is the only data Layer 3 ever sees from logs.

## Analysis Levels

| Level | Scope | Checks | Activation |
|---|---|---|---|
| **L1 -- Static Config** | nginx conf files | Headers, TLS floor, unsafe directives, include hierarchy, location precedence, rate limiting, proxy headers | Always |
| **L2 -- Log Analysis** | access/error logs | Scanner UAs, brute-force patterns, exploit path probing (categories 1-35), method anomalies, status distributions, IoC matching | If logs present |
| **L3 -- Live Verification** | HTTP(S) requests | Response header verification, TLS handshake, blocked path checks, deny behavior, health endpoint | Opt-in (`--live`) |

L3 forbidden actions: intrusive fuzzing, brute-force testing, content mutation, high-rate probing (>1 req/sec).

## 35 Attack Categories

### Original (1-20)

| # | Category | Threat | Examples |
|---|---|---|---|
| 1 | Dotfiles | Exposed VCS/config | `/.git/HEAD`, `/.svn/entries`, `/.DS_Store` |
| 2 | Script extensions | Direct script exec | `/.env.php`, `/shell.asp`, `/cmd.jsp` |
| 3 | Source maps | Client code leak | `/app.js.map`, `/main.css.map` |
| 4 | Config files | Credential/secret leak | `/.env`, `/.env.bak`, `/config.yml`, `/.npmrc` |
| 5 | WordPress | WP exploitation | `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php` |
| 6 | Spring Actuator | Java app internals | `/actuator/health`, `/actuator/env`, `/jolokia/` |
| 7 | Swagger/OpenAPI | API schema leak | `/swagger-ui.html`, `/api-docs`, `/openapi.json` |
| 8 | PHP/Laravel debug | Debug info leak | `/_debugbar`, `/telescope`, `/phpinfo.php` |
| 9 | Container/K8s | Orchestration metadata | `/.kube/config`, `/api/v1/pods`, `/.docker/config.json` |
| 10 | JS dev tools | Dev tooling exposure | `/webpack.config.js`, `/.babelrc`, `/vite.config.ts` |
| 11 | Atlassian | Jira/Confluence exploit | `/jira/`, `/confluence/`, `/%24%7Bjndi:` |
| 12 | MS Exchange | Exchange/OWA exploit | `/owa/`, `/ecp/`, `/autodiscover/autodiscover.xml` |
| 13 | GraphQL | Introspection/abuse | `/graphql`, `/graphiql`, `/?query={__schema}` |
| 14 | Admin panels | Admin discovery | `/admin/`, `/cpanel/`, `/phpmyadmin/` |
| 15 | CVE probes | Known vuln scanning | `/cgi-bin/`, `/..;/`, `/%2e%2e/`, `/proxy:http` |
| 16 | WP user enum | User enumeration | `/?author=1`, `/wp-json/wp/v2/users` |
| 17 | Path traversal | Directory escape | `/../../../etc/passwd`, `/....//....//` |
| 18 | Phishing kits | Hosted phish artifacts | `/office365/`, `/banking/login.html` |
| 19 | Backup/bin dirs | Exposed backups | `/backup/`, `/db.sql.gz`, `/site.tar.gz` |
| 20 | robots/security.txt | Recon via metadata | `/robots.txt` abuse, `/.well-known/security.txt` abuse |

### March 2026 (21-35)

| # | Category | Threat | Examples |
|---|---|---|---|
| 21 | HNAP/Router | Router exploitation | `/HNAP1/`, `/cgi-bin/luci`, `/goform/` |
| 22 | VPN/SSL gateways | VPN appliance targeting | `/remote/login`, `/dana-na/`, `/+CSCOE+/` |
| 23 | Apache Struts | Struts RCE probing | `/struts/`, `/*.action`, `/devmode.action` |
| 24 | Log4Shell/JNDI | JNDI injection | `/${jndi:ldap://`, `/${jndi:rmi://` |
| 25 | SSH key/cloud creds | Credential file theft | `/.ssh/id_rsa`, `/.aws/credentials` |
| 26 | IoT/OEM devices | IoT mgmt interfaces | `/cgi-bin/ViewLog.asp`, `/camera/`, `/ISAPI/` |
| 27 | Package manager files | Dependency leak | `/package.json`, `/composer.json`, `/Gemfile.lock` |
| 28 | App settings files | App config leak | `/appsettings.json`, `/application.yml`, `/settings.py` |
| 29 | XDEBUG | PHP debug interface | `/?XDEBUG_SESSION_START`, `/?PHPSTORM` |
| 30 | Enterprise apps | Enterprise probes | `/sap/`, `/Citrix/`, `/ibm/`, `/oracle/` |
| 31 | InfluxDB | Time-series DB exposure | `/query?db=`, `/api/v2/buckets` |
| 32 | Network infra | Network device UIs | `/cgi-bin/config.exp`, `/level/15/exec/`, `/tmui/` |
| 33 | Lotus Notes | Legacy groupware | `/names.nsf`, `/domcfg.nsf`, `/webadmin.nsf` |
| 34 | Login discovery | Auth endpoint enum | `/login`, `/signin`, `/auth/`, `/api/auth` |
| 35 | Misc exploit paths | Uncategorized probes | `/console/`, `/debug/`, `/status`, `/server-info` |

## Operating Modes

| Mode | Trigger | Actions | File Writes |
|---|---|---|---|
| **Recommendation** (default) | Any command without flags | Static analysis, log parsing, finding generation, rule proposals | None |
| **Enforcement** | `--apply` or `--deploy` flag, or human acceptance at decision gate | Backup, write rule, invariant checks, `nginx -t`, deploy, reload | Yes |

Recommendation Mode never modifies any file. Enforcement Mode requires passing all 5 pipeline layers including human approval at Layer 4.

## Action Classes

| Class | Name | Description |
|---|---|---|
| **R0** | Read-only | Read configs, logs (via sanitizer), recipes, learnings, exceptions, feeds |
| **R1** | Stage-only | Generate proposals, reports, JSON outputs, deployment plans to stdout/staging |
| **W1** | Local write | Write backups, reports, learnings, exceptions, configs, CHANGELOG entries |
| **W2** | Network write | Git push, feed polling state, remote API writes (Cloudflare, GitHub) |
| **X1** | Remote execution | SSH deploy, remote `nginx -t`, remote reload, cron/systemd job install |

Escalation: R0+R1 (default) -> W1 (`--apply`) -> W1+W2+X1 (`--deploy`). No auto-escalation.

## Rule Classes

| Class | Name | Emergency Eligible | Auto-Generate | Blast Radius |
|---|---|---|---|---|
| **A** | Containment Controls | Yes (narrow scope) | Yes | Prefer exact-location |
| **B** | Request Handling | No | Yes | Requires precedence checks |
| **C** | Baseline Hardening | No | Yes | Requires compatibility checks |
| **D** | Behavioral/Routing | Blocked | Recommendation only | Manual implementation only |

Emergency mode is time-limited (max 24h). Class A rules with narrow scope can deploy with reduced confirmation. Class D rules are never auto-generated.

## Environment Profiles

| Profile | Description | Rule Classes | Default Level |
|---|---|---|---|
| `edge-public` | Internet-facing reverse proxy | A, B, C | L1+L2 |
| `internal-only` | Private/internal deployment | B, C | L1 |
| `api-gateway` | Strict API protection | A, B, C | L1+L2 |
| `static-site` | Static file serving, aggressive hardening | A, B, C | L1 |
| `reverse-proxy-app` | App-backed proxy, compatibility sensitive | B, C | L1 |
| `high-risk-lockdown` | Maximum containment posture | A, B, C | L1+L2+L3 |

Profiles are selected with the `--profile` flag on `audit`, `analyze-logs`, and the main `/harden-nginx` command. Auto-detected from config when not specified.

## IoC / Threat Intel

Indicator-of-compromise response workflow with 3 response modes and support for multiple indicator sources.

### Response Modes

| Mode | Trigger | Behavior |
|---|---|---|
| **Advisory** (default) | No flags | Read-only matching and recommendations |
| **Stage** | `--apply` | Match + stage containment rules for review |
| **Emergency** | `--deploy --emergency` | Deploy Class A narrow-scope rules with reduced confirmation (24h TTL) |

### Supported Sources

- **YARA rules** — indicator extraction from strings and metadata
- **CVE IDs** — lookup via NVD feed, generate findings for matching paths
- **Text/CSV/JSON** — one indicator per line or structured indicator objects
- **STIX 2.x** — full indicator extraction (IPs, domains, URLs, hashes)
- **Built-in feeds** — 10 pre-configured threat intelligence feeds
- **Custom feeds** — user-defined via environment variables

### Built-in Threat Feeds

| Feed | Auth Required | Data Type |
|------|--------------|-----------|
| CISA KEV | No | CVEs |
| URLhaus | No | Malware URLs |
| ThreatFox | No | IoCs |
| OpenPhish | No | Phishing URLs |
| Blocklist.de | No | Attacker IPs |
| Feodo Tracker | No | C2 IPs |
| AlienVault OTX | Yes (`NH_OTX_TOKEN`) | Multi-type |
| Emerging Threats | Yes (`NH_ET_TOKEN`) | Suricata rules |
| PhishTank | Optional (`NH_PHISHTANK_TOKEN`) | Phishing URLs |
| NVD/CVE API | Optional (`NH_NVD_TOKEN`) | CVE details |

Feed unavailability degrades gracefully — results marked as partial, pipeline continues.

## Recipe System

Named, composable workflows that sequence plugin commands with configuration. Recipes support scheduling (cron/systemd/event-driven), environment profiles, privilege ceilings, confirmation checkpoints, and emergency mode eligibility. Remote deploy via SSH with host groups. Stored in `learnings/recipes/` with schema validation.

### Recipe Commands

| Subcommand | Description |
|---|---|
| `recipe create` | Interactive builder for new recipes |
| `recipe run <name>` | Execute a saved recipe |
| `recipe list` | List all available recipes |
| `recipe edit <name>` | Edit an existing recipe |
| `recipe install <name>` | Install recipe as cron job or systemd timer |
| `recipe export <name>` | Export recipe as portable YAML |

### Scheduling

- **Cron** — install as cron job with `recipe install <name> --cron`
- **Systemd timer** — generate `.service` and `.timer` units with `recipe install <name> --systemd`
- **Remote** — schedule on remote hosts via SSH with `recipe install <name> --remote`

### Organic Capture

After any manual analysis run, the plugin offers to save the session as a recipe for future reuse.

## Canary Deployment

Phased rollout for deploying hardening changes across multiple hosts.

### Pipeline

```
validate → sync → canary → verify → fanout
```

1. **Validate** — `invariant-checker.py` + `nginx -t` on proposed changes
2. **Sync** — push config to canary host(s) via SSH/sshpass
3. **Canary** — apply config on canary host, reload nginx
4. **Verify** — per-host health check and deny-path verification
5. **Fanout** — roll out to remaining hosts in the group

### Safety

- Per-host health and deny-path verification at each stage
- Automatic stop on first failure — no further hosts receive the change
- Full rollback of canary host on verification failure

## Rule Aging

Staleness detection for deployed blocking rules.

### Commands

| Subcommand | Description |
|---|---|
| `aging scan` | Scan deployed rules for staleness indicators |
| `aging report` | Generate a staleness report with hit counts and last-seen dates |
| `aging tag` | Tag stale rules for human review |

### Design

- Detects rules that have not matched any traffic in a configurable window
- Reports staleness with hit counts, last-seen dates, and age metrics
- Tags stale rules for human review with structured annotations
- **Never auto-removes rules** (Invariant 1 — additive-only)

## 18 Invariants

1. **Additive-only** -- Generated rules can only add or tighten blocking rules, never remove or weaken
2. **No regex negation** -- No `(?!...)`, `!~`, `proxy_pass`, `return 200`, or `rewrite` in generated rules
3. **Headers immutable** -- Cannot remove or weaken X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy
4. **TLS floor at 1.2** -- `ssl_protocols` must not include TLSv1.0 or TLSv1.1
5. **Raw logs never enter LLM** -- All log data passes through sanitizer.py before any agent sees it
6. **No attacker strings in shell** -- Log-derived data never interpolated into Bash commands
7. **No attacker strings in commits** -- Commit messages use category labels and counts only
8. **No attacker strings in learnings** -- Learning bodies contain sanitized summaries; raw payloads hex-encoded with warnings
9. **nginx -t before every reload** -- Config must pass syntax validation; on failure, restore from backup
10. **Backup before every write** -- Timestamped `.bak` copy created before any config modification
11. **No destructive git ops** -- `push --force`, `reset --hard`, `checkout .`, `clean -f` are forbidden
12. **Exceptions require reason + compensating control** -- Both fields mandatory, non-empty
13. **Exceptions cannot override invariants 1-11** -- Exceptions suppress findings, not invariants
14. **Exceptions expire (max 365 days)** -- Tiered nag schedule; critical exceptions block deploy after expiry
15. **Changelog append-only** -- CHANGELOG.md is never edited in-place or truncated
16. **Compaction preserves counts and dates** -- Merged hit counts must sum; first_seen must be earliest
17. **Narrow scope preferred** -- Exact-location > server-block > include-file > global; global requires confirmation
18. **Secrets never in output** -- No credentials, keys, or tokens in chat, learnings, changelog, recipes, commits, or artifacts

## Exception System

Exceptions suppress specific findings (not invariants). Dual persistence: markdown files in `learnings/exceptions/` and JSON validated by `schema-validator.py`. Tiered expiry based on severity -- critical exceptions nag at 90/60/30 days and block deploy after expiry; high/low exceptions warn only. Maximum lifetime: 365 days. Every exception requires a reason, compensating control, owner, and approval reference.

## Learnings System

The plugin auto-captures reusable knowledge during analysis runs: attack patterns, scanner signatures, infrastructure observations, exception rationale, and IoC responses. Learnings are indexed in `learnings/LEARNINGS.md` with changes tracked in `learnings/CHANGELOG.md`. Compaction merges related entries while preserving aggregate hit counts and earliest discovery dates (Invariant 16). Learnings promote through lifecycle states: draft -> active -> compacted.

## Scripts Inventory

11 Python scripts in `scripts/`:

| Script | Purpose |
|---|---|
| `sanitizer.py` | Layer 2 log sanitizer — allowlist filtering, PII stripping |
| `invariant-checker.py` | Validates all 18 invariants before deploy |
| `schema-validator.py` | JSON schema validation for learnings, exceptions, recipes |
| `compatibility-checker.py` | 9 pre-deployment safety checks |
| `blast-radius.py` | Impact analysis scoring for proposed changes |
| `finding-id.py` | Stable finding ID generation and tracking |
| `ioc-matcher.py` | Indicator matching against logs and config |
| `feed-poller.py` | Threat feed polling and state management |
| `recipe-runner.py` | Recipe execution engine |
| `canary-deployer.py` | Canary deployment pipeline |
| `rule-aging.py` | Rule staleness detection and reporting |

## New in Phase 2

- **`--json` flag** on all commands for machine-readable output (CI/CD integration, scripting)
- **Compatibility checker** — 9 pre-deployment safety checks (nginx version, directive support, module availability, upstream health, SSL cert validity, rate limit sanity, include path resolution, worker connection capacity, shared memory zones)
- **Blast-radius scoring** — impact analysis for every proposed change (scope, traffic exposure, reversibility, dependency count)
- **Rollback with safety backup** — `rollback` command lists, previews, and restores from timestamped backups with pre-restore `nginx -t` validation
- **Exception management with tiered expiry** — `exceptions` command for reviewing, creating, and renewing exceptions with severity-based nag schedules and deploy blocking for expired critical exceptions
- **Finding ID traceability** — every finding gets a stable ID (`FID-<category>-<hash>`) tracked across runs, enabling exception binding and trend analysis
- **Learnings management** — `learnings` command with subcommands: `list` (filter/search), `promote` (draft to active), `compact` (merge related entries preserving counts/dates per Invariant 16), `export` (JSON/markdown)

## New in Phase 3

- **IoC/threat intel** — 3 response modes (advisory, stage, emergency), 10 built-in feeds, YARA/CVE/STIX/text source support
- **Recipe system** — create, run, list, edit, install, export; scheduling via cron, systemd, and remote SSH
- **Canary deployment** — phased rollout with validate/sync/canary/verify/fanout pipeline, per-host health checks, automatic stop on failure
- **Rule aging** — staleness detection with scan/report/tag, never auto-removes (Invariant 1)
- **Environment profile activation** — `--profile` flag on audit, analyze-logs, and main commands
- **Remote deployment** — SSH/sshpass-based remote execution with host groups
- **Organic recipe capture** — save any manual run as a reusable recipe

## Roadmap

| Phase | Status | Scope |
|---|---|---|
| **Phase 1** | Done | Core pipeline (audit, analyze-logs, deploy), 5-layer security model, 18 invariants, 35 attack categories, 6 profiles, learnings system, exception system |
| **Phase 2** | Done | Compatibility checker, blast-radius scoring, rollback manager, finding ID traceability, machine-readable outputs (`--json`), exception management command, learnings management |
| **Phase 3** | Done | Canary deployment, IoC/threat intel (10 built-in feeds), recipe system with scheduling, remote deployment via SSH/sshpass, rule aging/decay, environment profile activation |

**v1.0.0 — All three phases complete.**

## Related Projects

- [trumb/nginx-hardening](https://github.com/trumb/nginx-hardening) -- The security configs (blocking rules, scanner UA lists, security headers) that this plugin audits and manages

## Contributing

1. Fork the repo
2. Create a feature branch
3. Ensure all invariants pass: `python3 scripts/invariant-checker.py`
4. Validate schemas: `python3 scripts/schema-validator.py`
5. Submit a PR with a description of what changed and why

Bug reports and feature requests via [GitHub Issues](https://github.com/trumb/claude-nginx-hardening/issues).

## License

[MIT](LICENSE)
