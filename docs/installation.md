# Installation Guide

## Marketplace Install (Recommended)

The plugin ships with a `marketplace.json` so it can be installed directly from the Claude Code CLI.

### Step 1: Add the marketplace

```bash
claude plugin marketplace add trumb/claude-nginx-hardening
```

This registers the GitHub repo as a plugin marketplace. You only need to do this once.

### Step 2: Install the plugin

```bash
claude plugin install claude-nginx-hardening
```

The plugin is now available in all future Claude Code sessions (user scope by default).

### Scope options

| Flag | Behavior |
|------|----------|
| `--scope user` (default) | Available in all projects for the current user |
| `--scope project` | Available only in the current project directory |

### Updating

```bash
claude plugin marketplace update claude-nginx-hardening
claude plugin install claude-nginx-hardening
```

### Uninstalling

```bash
claude plugin remove claude-nginx-hardening

# Optionally remove the marketplace entry
claude plugin marketplace remove claude-nginx-hardening
```

---

## Manual Install via --plugin-dir

For one-off sessions or testing without registering a marketplace:

```bash
git clone https://github.com/trumb/claude-nginx-hardening.git /path/to/local/clone

claude --plugin-dir /path/to/local/clone
```

The plugin is loaded for that session only.

---

## Prerequisites

| Requirement | Purpose |
|-------------|---------|
| Claude Code CLI | Plugin host |
| Python 3.8+ | Deterministic scripts (sanitizer, invariant-checker, schema-validator) |
| nginx | Target system for deployment features |
| Git | Version-controlled config management |

All Python scripts use stdlib only — no `pip install` required.

---

## Verify Installation

```
/harden-nginx
```

You should see the interactive menu with all available operations.

---

## Environment Variables (Optional)

| Variable | Purpose | Required For |
|----------|---------|-------------|
| `NGINX_LOG_DIR` | Custom log directory path | Log analysis with non-standard paths |
| `NH_SSH_HOST` | Remote deployment target | `--remote` deploys |
| `NH_SSH_USER` | SSH username | `--remote` deploys |
| `NH_SSH_KEY` | SSH key path | `--remote` deploys |
| `CF_API_TOKEN` | Cloudflare API token | Cloudflare integration |
| `NH_OTX_TOKEN` | AlienVault OTX API key | OTX threat feed |
| `NH_ET_TOKEN` | Emerging Threats API key | ET feed |
| `NH_PHISHTANK_TOKEN` | PhishTank API key | PhishTank feed |
| `NH_NVD_TOKEN` | NVD API key | NVD/CVE feed |

Secrets are referenced by environment variable name only — the plugin never prompts for credentials.
