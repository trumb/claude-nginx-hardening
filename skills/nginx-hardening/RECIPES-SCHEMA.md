# Recipes Schema

> **Version:** 1.0
> **Purpose:** Defines the typed structure for recipes — composable, schedulable sequences of actions that perform analysis, auditing, deployment, and maintenance tasks.

---

## Required Frontmatter Fields

| Field | Type | Description | Example |
|---|---|---|---|
| `name` | string | Kebab-case recipe identifier | `"daily-log-audit"` |
| `description` | string | Human-readable description of what this recipe does | `"Analyze access logs and produce findings"` |
| `profile` | enum | Target environment profile | `"edge-public"` |
| `execution_class` | string | Privilege class expression | `"R0+R1"` |
| `requires_network` | boolean | Whether the recipe needs network access | `false` |
| `requires_remote_exec` | boolean | Whether the recipe executes commands on a remote host | `false` |
| `required_env_vars` | array of strings | Environment variables that must be set | `["NGINX_LOG_DIR"]` |
| `confirmation_checkpoints` | array of strings | Step names that require user confirmation before proceeding | `["deploy"]` |
| `allows_emergency_mode` | boolean | Whether this recipe can run in emergency mode | `false` |
| `max_privilege_level` | enum | Highest privilege level any step in this recipe requires | `"R1"` |
| `schedule_mode` | enum | How this recipe is intended to be triggered | `"cron"` |
| `steps` | array of step objects | Ordered list of actions to execute | *(see below)* |
| `outputs` | array of strings | Expected output artifacts (file paths or descriptions) | `["outputs/findings.json"]` |

### Enum Definitions

**profile:**
- `"edge-public"` — Internet-facing reverse proxy
- `"internal-only"` — Private/internal deployment
- `"api-gateway"` — Strict API protection
- `"static-site"` — Static file serving with aggressive hardening
- `"reverse-proxy-app"` — Application-backed reverse proxy
- `"high-risk-lockdown"` — Maximum containment posture

**max_privilege_level:**
- `"R0"` — Read-only, local files only
- `"R1"` — Read-only, includes network reads (IOC feeds, remote configs)
- `"W1"` — Write to output/staging directories only
- `"W2"` — Write to nginx config directories (requires confirmation)
- `"X1"` — Execute nginx reload/restart (requires confirmation)

**schedule_mode:**
- `"manual"` — Run on demand by the user
- `"cron"` — Scheduled via cron job
- `"systemd-timer"` — Scheduled via systemd timer unit

---

## Step Object

Each step in the `steps` array has the following fields:

| Field | Type | Description | Example |
|---|---|---|---|
| `action` | enum | The action this step performs | `"analyze-logs"` |
| `params` | object | Action-specific parameters | `{"log_dir": "/var/log/nginx"}` |

**action enum values:**
- `"analyze-logs"` — Parse and analyze nginx log files
- `"audit-config"` — Audit nginx configuration files for security issues
- `"check-ioc-feeds"` — Query IOC feeds for known-bad indicators
- `"deploy"` — Deploy generated rules to nginx configuration
- `"compact-learnings"` — Consolidate and deduplicate learnings
- `"sync-repos"` — Synchronize configuration or rule repositories

### Action-Specific Parameters

**analyze-logs:**
- `log_dir` (string) — Directory containing log files
- `source_type` (string) — Log type to analyze
- `lookback_hours` (integer) — How many hours of logs to analyze

**audit-config:**
- `config_paths` (array of strings) — Paths to audit
- `include_depth` (integer) — Max depth for following includes

**check-ioc-feeds:**
- `feed_urls` (array of strings) — IOC feed URLs
- `match_fields` (array of strings) — Fields to match against

**deploy:**
- `target_path` (string) — Where to write the generated config
- `backup` (boolean) — Whether to back up the existing config
- `reload_nginx` (boolean) — Whether to reload nginx after deployment

**compact-learnings:**
- `learnings_dir` (string) — Directory containing learning files
- `dedup_strategy` (string) — Deduplication approach ("merge", "newest", "highest-confidence")

**sync-repos:**
- `remote_url` (string) — Repository URL
- `branch` (string) — Branch to sync

---

## Deployment Targets

Recipes with `schedule_mode` of `"cron"` or `"systemd-timer"` can target one of three deployment modes:

| Target | Description | Requirements |
|---|---|---|
| `local` | Self-install cron job or systemd timer on the current host | Write access to user crontab or `~/.config/systemd/user/` |
| `remote` | Install schedule on a remote host via SSH | SSH key or `SSHPASS` env var; `requires_remote_exec: true` |
| `generate-only` | Output the cron/systemd config for the user to install manually | No special privileges; outputs to `outputs/` directory |

---

## Safety Rules

1. **First execution privilege summary:** The first time a recipe runs, it must display a summary of all privileges it will exercise (read paths, write paths, network access, remote execution) and require explicit confirmation.
2. **Cannot suppress invariants:** No recipe step may disable or bypass invariants 1-11 from `INVARIANTS.md`.
3. **Cannot embed secrets:** Recipe definitions must not contain secrets, API keys, passwords, or tokens. Use `required_env_vars` to reference secrets from the environment.
4. **Write-capable recipes require confirmation:** Any recipe with `max_privilege_level` of `"W1"` or higher must have at least one `confirmation_checkpoints` entry, unless the recipe is explicitly marked for non-interactive scheduled execution with `schedule_mode: "cron"` or `"systemd-timer"`.
5. **Emergency mode restrictions:** Only recipes with `allows_emergency_mode: true` can be invoked in emergency mode. Emergency-eligible recipes must contain only Class A rule actions with narrow blast radius.

---

## YAML Frontmatter Example

```yaml
---
name: "daily-log-audit"
description: "Analyze nginx access and error logs, produce findings and learnings"
profile: "edge-public"
execution_class: "R0+R1"
requires_network: true
requires_remote_exec: false
required_env_vars:
  - "NGINX_LOG_DIR"
confirmation_checkpoints: []
allows_emergency_mode: false
max_privilege_level: "R1"
schedule_mode: "cron"
steps:
  - action: "analyze-logs"
    params:
      log_dir: "${NGINX_LOG_DIR}"
      source_type: "access_log"
      lookback_hours: 24
  - action: "analyze-logs"
    params:
      log_dir: "${NGINX_LOG_DIR}"
      source_type: "error_log"
      lookback_hours: 24
  - action: "check-ioc-feeds"
    params:
      feed_urls:
        - "https://ioc.example.com/nginx-threats.json"
      match_fields:
        - "path_class"
        - "scanner_family"
  - action: "compact-learnings"
    params:
      learnings_dir: "learnings/"
      dedup_strategy: "highest-confidence"
outputs:
  - "outputs/findings.json"
  - "outputs/learnings/"
  - "outputs/sanitized-events.json"
---
```

---

## Validation Rules

1. `name` must be kebab-case (lowercase alphanumeric and hyphens only).
2. `profile` must be a valid profile enum value.
3. `max_privilege_level` must be consistent with the steps: no step may require privileges exceeding `max_privilege_level`.
4. `steps` must be a non-empty array.
5. Each step `action` must be a valid action enum value.
6. `required_env_vars` must not contain values — only variable names.
7. Write-capable recipes (`W1`+) must declare `confirmation_checkpoints` unless scheduled.
8. `outputs` must be a non-empty array describing expected artifacts.
9. Emergency-eligible recipes must only contain Class A actions.
