# Threat Intelligence Feeds Reference

Reference document for the `feed-poller.py` threat intelligence feed system.

## Built-in Feeds

### 1. CISA KEV (Known Exploited Vulnerabilities)

| Field | Value |
|---|---|
| Feed ID | `cisa_kev` |
| URL | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| Format | JSON |
| Auth | None required |
| Data Type | CVE identifiers with exploitation metadata |
| Refresh Rate | Daily |
| Indicators | cveID, vendorProject, product, vulnerabilityName, knownRansomwareCampaignUse |

CISA's authoritative catalog of vulnerabilities known to be actively exploited in the wild. All entries are critical severity by definition. Includes ransomware campaign association data.

### 2. Abuse.ch URLhaus

| Field | Value |
|---|---|
| Feed ID | `urlhaus` |
| URL | `https://urlhaus-api.abuse.ch/v1/urls/recent/` |
| Format | JSON (POST with empty body) |
| Auth | None required |
| Data Type | Malicious URLs |
| Refresh Rate | Every 5 minutes |
| Indicators | url, url_status, threat, tags |

Community-driven malicious URL collection. URLs are tagged with threat type (malware distribution, C2, etc.) and status (online/offline). Higher confidence for "online" URLs.

### 3. Abuse.ch ThreatFox

| Field | Value |
|---|---|
| Feed ID | `threatfox` |
| URL | `https://threatfox-api.abuse.ch/api/v1/` |
| Format | JSON (POST `{"query": "get_iocs", "days": 1}`) |
| Auth | None required |
| Data Type | Mixed IOCs (IPs, domains, URLs, hashes) |
| Refresh Rate | Daily |
| Indicators | ioc_value, ioc_type, threat_type, malware |

Broad IOC sharing platform. Includes IP:port pairs, domains, URLs, and file hashes associated with specific malware families. Confidence levels provided per IOC.

### 4. OpenPhish

| Field | Value |
|---|---|
| Feed ID | `openphish` |
| URL | `https://openphish.com/feed.txt` |
| Format | Text (one URL per line) |
| Auth | None required |
| Data Type | Phishing URLs |
| Refresh Rate | Every 6 hours |
| Indicators | Phishing URLs |

Community phishing URL feed. Plain text format, one URL per line. Useful for blocking known phishing landing pages.

### 5. Blocklist.de

| Field | Value |
|---|---|
| Feed ID | `blocklist_de` |
| URL | `https://api.blocklist.de/getlast.php?time=86400` |
| Format | Text (one IP per line) |
| Auth | None required |
| Data Type | Attacking IP addresses |
| Refresh Rate | Daily |
| Indicators | IPv4 addresses |

IPs reported for attacks (SSH brute force, web attacks, mail spam, etc.) in the last 24 hours. Community-driven with honeypot validation.

### 6. Feodo Tracker

| Field | Value |
|---|---|
| Feed ID | `feodo_tracker` |
| URL | `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt` |
| Format | Text with comments (one IP per line, `#` comments) |
| Auth | None required |
| Data Type | Botnet C2 IP addresses |
| Refresh Rate | Every 5 minutes |
| Indicators | IPv4 addresses (C2 servers) |

Tracks botnet command-and-control servers (Dridex, Emotet, TrickBot, QakBot). The "recommended" blocklist contains only currently active C2s. Critical severity.

### 7. AlienVault OTX

| Field | Value |
|---|---|
| Feed ID | `otx` |
| URL | `https://otx.alienvault.com/api/v1/indicators/export` |
| Format | JSON |
| Auth | Required: `NH_OTX_TOKEN` |
| Data Type | Mixed (IPs, domains, URLs, hashes, CVEs) |
| Refresh Rate | Hourly |
| Indicators | Varies by pulse subscription |

Open Threat Exchange platform. Requires free API key. Returns indicators from subscribed "pulses" (threat reports). Broad coverage but variable quality.

### 8. Emerging Threats

| Field | Value |
|---|---|
| Feed ID | `emerging_threats` |
| URL | `https://rules.emergingthreats.net/open/suricata/rules/` |
| Format | Text (Suricata rule format) |
| Auth | Required: `NH_ET_TOKEN` (for pro rules; open rules are free) |
| Data Type | IDS/IPS rules |
| Refresh Rate | Daily |
| Indicators | Suricata rules with embedded indicators |

Network-level threat detection rules. The open ruleset is free; the pro ruleset requires a subscription. Rules contain embedded IPs, domains, and patterns.

### 9. PhishTank

| Field | Value |
|---|---|
| Feed ID | `phishtank` |
| URL | `https://data.phishtank.com/data/online-valid.json` |
| Format | JSON |
| Auth | Required: `NH_PHISHTANK_TOKEN` |
| Data Type | Verified phishing URLs |
| Refresh Rate | Hourly |
| Indicators | Phishing URLs with verification status |

Community-verified phishing URL database. URLs are submitted and verified by multiple community members. Higher confidence than unverified feeds.

### 10. NVD (National Vulnerability Database)

| Field | Value |
|---|---|
| Feed ID | `nvd` |
| URL | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| Format | JSON |
| Auth | Required: `NH_NVD_TOKEN` (for higher rate limits) |
| Data Type | CVE records with CVSS scores |
| Refresh Rate | Every 2 hours |
| Indicators | CVE IDs, CVSS scores, affected products (CPE) |

NIST's comprehensive CVE database. Free API key increases rate limits from 5 to 50 requests per 30-second window. Essential for vulnerability-to-product mapping.

## Authentication Setup

Set environment variables for feeds that require API keys:

```bash
# AlienVault OTX — free at https://otx.alienvault.com/
export NH_OTX_TOKEN="your-otx-api-key"

# Emerging Threats — pro rules require subscription
export NH_ET_TOKEN="your-et-oinkcode"

# PhishTank — free at https://www.phishtank.com/developer_info.php
export NH_PHISHTANK_TOKEN="your-phishtank-key"

# NVD — free at https://nvd.nist.gov/developers/request-an-api-key
export NH_NVD_TOKEN="your-nvd-api-key"
```

For persistent configuration, add these to a `.env` file (never committed to git) or your secrets manager.

## Custom Feed Configuration

Custom feeds are defined in a JSON config file:

```json
{
  "feeds": [
    {
      "id": "my_ip_blocklist",
      "url": "https://example.com/blocklist.txt",
      "indicator_type": "ip",
      "tags": ["custom", "internal"],
      "description": "Internal IP blocklist"
    },
    {
      "id": "my_url_feed",
      "url": "https://example.com/malicious-urls.txt",
      "indicator_type": "url",
      "tags": ["custom", "malware"],
      "description": "Internal malicious URL feed"
    }
  ]
}
```

Usage:

```bash
python3 scripts/feed-poller.py --feeds custom --config /path/to/feeds.json
```

Custom feeds are parsed as text (one indicator per line, `#` comments skipped).

## Polling Best Practices

1. **Schedule polling, don't run ad-hoc.** Use cron or systemd timers:
   ```
   # Poll all no-auth feeds every 6 hours
   0 */6 * * * python3 /path/to/feed-poller.py --feeds builtin --feed-name cisa_kev,urlhaus,threatfox,openphish,blocklist_de,feodo_tracker --timeout 30 > /var/lib/nginx-hardening/feeds-latest.json
   ```

2. **Store results, don't pipe directly.** Write to a dated file so you have history:
   ```bash
   python3 scripts/feed-poller.py --feeds builtin > feeds-$(date +%Y%m%d-%H%M).json
   ```

3. **Monitor for feed failures.** Check `feeds_skipped` in the output. A feed that starts failing may indicate an API change or rate limit.

4. **Cap indicator counts.** The poller limits to 500 indicators per feed by default to prevent memory issues. For large feeds (NVD, PhishTank), use API parameters to filter.

5. **Treat all data as untrusted.** Feed data is external input. The poller sanitizes values but downstream consumers should validate before acting.

## Rate Limiting Guidance

| Feed | Rate Limit | Recommendation |
|---|---|---|
| CISA KEV | None documented | Poll once per day |
| URLhaus | Generous | Poll every 5-15 minutes if needed |
| ThreatFox | Generous | Poll once per day |
| OpenPhish | Undocumented | Poll every 6 hours max |
| Blocklist.de | Generous | Poll once per day |
| Feodo Tracker | Generous | Poll every 5-15 minutes if needed |
| OTX | 1000 req/hr with key | Poll hourly |
| Emerging Threats | No API rate limit | Poll daily |
| PhishTank | 1 download/hr | Poll hourly at most |
| NVD | 5 req/30s (no key), 50 req/30s (with key) | Poll every 2 hours with key |

When in doubt, poll less frequently. Threat intelligence data has a half-life of hours to days — polling every minute provides negligible benefit over polling every few hours.
