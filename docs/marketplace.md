# Marketplace Architecture

## How it works

The plugin doubles as its own standalone marketplace. This is achieved via `.claude-plugin/marketplace.json`, which sits alongside the existing `.claude-plugin/plugin.json`.

### File layout

```
.claude-plugin/
  plugin.json          # Plugin metadata (name, version, description, author)
  marketplace.json     # Marketplace manifest — points to "./" (repo root) as the plugin source
```

### marketplace.json

```json
{
  "$schema": "https://anthropic.com/claude-code/marketplace.schema.json",
  "name": "claude-nginx-hardening",
  "description": "Full lifecycle nginx hardening...",
  "owner": { "name": "trumb" },
  "plugins": [
    {
      "name": "claude-nginx-hardening",
      "description": "...",
      "source": "./",
      "category": "development",
      "homepage": "https://github.com/trumb/claude-nginx-hardening"
    }
  ]
}
```

The key insight is `"source": "./"` — this tells Claude Code the plugin lives at the repository root, making the repo both the marketplace and the plugin.

---

## User install flow

```
claude plugin marketplace add trumb/claude-nginx-hardening
    └─ clones repo, reads .claude-plugin/marketplace.json
    └─ registers "claude-nginx-hardening" as a known marketplace

claude plugin install claude-nginx-hardening
    └─ finds the plugin in the marketplace
    └─ resolves source "./" to the repo root
    └─ installs into ~/.claude/plugins/cache/
```

---

## For other plugin authors

If you maintain a single-plugin repo and want marketplace support, you need:

1. A `.claude-plugin/plugin.json` with your plugin metadata
2. A `.claude-plugin/marketplace.json` with a single entry pointing `"source": "./"` to the repo root

That's it. Users can then `marketplace add` your repo and `plugin install` your plugin.
