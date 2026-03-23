#!/usr/bin/env python3
"""
Threat Intelligence Feed Poller — polls feeds and outputs normalized indicators.

Stdlib-only Python. Uses urllib.request for HTTP.

Built-in feeds (10):
  1. CISA KEV         — Known Exploited Vulnerabilities (no auth)
  2. Abuse.ch URLhaus — Recent malicious URLs (no auth)
  3. Abuse.ch ThreatFox — IOCs (no auth)
  4. OpenPhish        — Phishing URLs (no auth)
  5. Blocklist.de     — Attacking IPs (no auth)
  6. Feodo Tracker    — Botnet C2 IPs (no auth)
  7. AlienVault OTX   — Threat indicators (requires NH_OTX_TOKEN)
  8. Emerging Threats  — ET rules (requires NH_ET_TOKEN)
  9. PhishTank        — Phishing DB (requires NH_PHISHTANK_TOKEN)
  10. NVD             — CVE database (requires NH_NVD_TOKEN)

Safety:
  - HTTP timeout: 30 seconds (configurable)
  - Feed failure -> skip, don't abort
  - All indicator data treated as external/untrusted
  - No raw feed data in output — normalize to typed schema
  - Credentials from env vars only

Usage:
  python3 scripts/feed-poller.py --feeds builtin [--feed-name cisa_kev,urlhaus] [--timeout 30]
  python3 scripts/feed-poller.py --feeds custom --config PATH
  python3 scripts/feed-poller.py --list
"""

import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT = 30
MAX_INDICATORS_PER_FEED = 500  # Cap to prevent memory issues

# Sanitization: only allow safe characters in indicator values
SAFE_VALUE_RE = re.compile(r"[^a-zA-Z0-9.:/\-_?&=@%+~,;#\[\]() ]")


# ── Feed Registry ────────────────────────────────────────────────────────────

BUILTIN_FEEDS = {
    "cisa_kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "format": "json",
        "method": "GET",
        "auth_env": None,
        "data_type": "cve",
        "refresh_rate": "daily",
    },
    "urlhaus": {
        "name": "Abuse.ch URLhaus Recent URLs",
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "format": "json",
        "method": "POST",
        "post_body": b"",
        "auth_env": None,
        "data_type": "url",
        "refresh_rate": "5min",
    },
    "threatfox": {
        "name": "Abuse.ch ThreatFox IOCs",
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "format": "json",
        "method": "POST",
        "post_body": json.dumps({"query": "get_iocs", "days": 1}).encode(),
        "auth_env": None,
        "data_type": "ioc",
        "refresh_rate": "daily",
    },
    "openphish": {
        "name": "OpenPhish Community Feed",
        "url": "https://openphish.com/feed.txt",
        "format": "text_urls",
        "method": "GET",
        "auth_env": None,
        "data_type": "url",
        "refresh_rate": "6h",
    },
    "blocklist_de": {
        "name": "Blocklist.de Attacking IPs (24h)",
        "url": "https://api.blocklist.de/getlast.php?time=86400",
        "format": "text_ips",
        "method": "GET",
        "auth_env": None,
        "data_type": "ip",
        "refresh_rate": "daily",
    },
    "feodo_tracker": {
        "name": "Feodo Tracker Botnet C2 IPs",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "format": "text_ips_comments",
        "method": "GET",
        "auth_env": None,
        "data_type": "ip",
        "refresh_rate": "5min",
    },
    "otx": {
        "name": "AlienVault OTX Indicators",
        "url": "https://otx.alienvault.com/api/v1/indicators/export",
        "format": "json",
        "method": "GET",
        "auth_env": "NH_OTX_TOKEN",
        "data_type": "mixed",
        "refresh_rate": "hourly",
    },
    "emerging_threats": {
        "name": "Emerging Threats Ruleset",
        "url": "https://rules.emergingthreats.net/open/suricata/rules/",
        "format": "text",
        "method": "GET",
        "auth_env": "NH_ET_TOKEN",
        "data_type": "rule",
        "refresh_rate": "daily",
    },
    "phishtank": {
        "name": "PhishTank Verified Phishing URLs",
        "url": "https://data.phishtank.com/data/online-valid.json",
        "format": "json",
        "method": "GET",
        "auth_env": "NH_PHISHTANK_TOKEN",
        "data_type": "url",
        "refresh_rate": "hourly",
    },
    "nvd": {
        "name": "NVD CVE Database",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "format": "json",
        "method": "GET",
        "auth_env": "NH_NVD_TOKEN",
        "data_type": "cve",
        "refresh_rate": "2h",
    },
}


# ── Sanitization ─────────────────────────────────────────────────────────────

def sanitize_value(value: str) -> str:
    """Sanitize indicator values — remove anything suspicious."""
    if not isinstance(value, str):
        return str(value)
    # Truncate
    value = value[:500]
    # Strip control characters
    value = SAFE_VALUE_RE.sub("", value)
    return value.strip()


def sanitize_tags(tags: Any) -> List[str]:
    """Sanitize a list of tags."""
    if not tags:
        return []
    if isinstance(tags, str):
        tags = [tags]
    if not isinstance(tags, list):
        return []
    result = []
    for t in tags[:20]:  # Cap at 20 tags
        cleaned = sanitize_value(str(t))[:50]
        if cleaned:
            result.append(cleaned)
    return result


# ── HTTP Helper ──────────────────────────────────────────────────────────────

def http_fetch(
    url: str,
    method: str = "GET",
    post_body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> bytes:
    """Fetch URL using urllib. Returns response bytes."""
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "claude-nginx-hardening/1.0 feed-poller")
    req.add_header("Accept", "application/json, text/plain, */*")

    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    if method == "POST" and post_body is not None:
        req.data = post_body
        if not post_body:
            req.add_header("Content-Length", "0")

    # Create SSL context that works with most feeds
    ctx = ssl.create_default_context()

    response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
    return response.read()


# ── Feed Parsers ─────────────────────────────────────────────────────────────

def parse_cisa_kev(raw: bytes) -> List[Dict[str, Any]]:
    """Parse CISA KEV JSON feed."""
    data = json.loads(raw)
    vulnerabilities = data.get("vulnerabilities", [])
    indicators = []

    for vuln in vulnerabilities[:MAX_INDICATORS_PER_FEED]:
        cve_id = sanitize_value(vuln.get("cveID", ""))
        if not cve_id:
            continue

        tags = ["known_exploited"]
        vendor = sanitize_value(vuln.get("vendorProject", ""))
        product = sanitize_value(vuln.get("product", ""))
        if vendor:
            tags.append(vendor.lower().replace(" ", "_"))
        if product:
            tags.append(product.lower().replace(" ", "_"))

        ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
        if ransomware == "Known":
            tags.append("ransomware")

        severity = "critical"  # All KEV entries are critical by definition

        indicators.append({
            "type": "cve",
            "value": cve_id,
            "confidence": 1.0,
            "source": "cisa_kev",
            "severity": severity,
            "tags": tags,
            "first_seen": sanitize_value(vuln.get("dateAdded", "")),
            "description": sanitize_value(vuln.get("vulnerabilityName", "")),
        })

    return indicators


def parse_urlhaus(raw: bytes) -> List[Dict[str, Any]]:
    """Parse URLhaus recent URLs JSON."""
    data = json.loads(raw)
    urls = data.get("urls", [])
    indicators = []

    for entry in urls[:MAX_INDICATORS_PER_FEED]:
        url = sanitize_value(entry.get("url", ""))
        if not url:
            continue

        tags = sanitize_tags(entry.get("tags"))
        threat = sanitize_value(entry.get("threat", ""))
        if threat:
            tags.append(threat)

        status = entry.get("url_status", "unknown")
        confidence = 0.9 if status == "online" else 0.6

        indicators.append({
            "type": "url",
            "value": url,
            "confidence": confidence,
            "source": "urlhaus",
            "severity": "high",
            "tags": tags,
            "first_seen": sanitize_value(entry.get("date_added", "")),
        })

    return indicators


def parse_threatfox(raw: bytes) -> List[Dict[str, Any]]:
    """Parse ThreatFox IOC JSON."""
    data = json.loads(raw)
    query_status = data.get("query_status", "")
    if query_status != "ok":
        return []

    iocs = data.get("data", [])
    indicators = []

    for entry in iocs[:MAX_INDICATORS_PER_FEED]:
        ioc_value = sanitize_value(entry.get("ioc_value", ""))
        if not ioc_value:
            continue

        ioc_type_raw = entry.get("ioc_type", "unknown")
        # Map ThreatFox types to our types
        type_map = {
            "ip:port": "ip",
            "domain": "domain",
            "url": "url",
            "md5_hash": "hash",
            "sha256_hash": "hash",
        }
        ioc_type = type_map.get(ioc_type_raw, "unknown")

        malware = sanitize_value(entry.get("malware", ""))
        threat_type = sanitize_value(entry.get("threat_type", ""))
        tags = []
        if malware:
            tags.append(malware.lower().replace(" ", "_"))
        if threat_type:
            tags.append(threat_type)

        confidence_level = entry.get("confidence_level", 50)
        confidence = min(max(int(confidence_level) / 100.0, 0.0), 1.0)

        indicators.append({
            "type": ioc_type,
            "value": ioc_value,
            "confidence": confidence,
            "source": "threatfox",
            "severity": "high",
            "tags": tags,
            "first_seen": sanitize_value(entry.get("first_seen_utc", "")),
        })

    return indicators


def parse_openphish(raw: bytes) -> List[Dict[str, Any]]:
    """Parse OpenPhish text feed (one URL per line)."""
    indicators = []
    lines = raw.decode("utf-8", errors="replace").strip().splitlines()

    for line in lines[:MAX_INDICATORS_PER_FEED]:
        url = sanitize_value(line.strip())
        if not url or not url.startswith("http"):
            continue

        indicators.append({
            "type": "url",
            "value": url,
            "confidence": 0.85,
            "source": "openphish",
            "severity": "high",
            "tags": ["phishing"],
            "first_seen": "",
        })

    return indicators


def parse_blocklist_de(raw: bytes) -> List[Dict[str, Any]]:
    """Parse Blocklist.de text feed (one IP per line)."""
    indicators = []
    lines = raw.decode("utf-8", errors="replace").strip().splitlines()

    for line in lines[:MAX_INDICATORS_PER_FEED]:
        ip = line.strip()
        if not ip or not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            continue

        indicators.append({
            "type": "ip",
            "value": ip,
            "confidence": 0.8,
            "source": "blocklist_de",
            "severity": "medium",
            "tags": ["attacking_ip", "blocklist"],
            "first_seen": "",
        })

    return indicators


def parse_feodo_tracker(raw: bytes) -> List[Dict[str, Any]]:
    """Parse Feodo Tracker text feed (IPs with # comments)."""
    indicators = []
    lines = raw.decode("utf-8", errors="replace").strip().splitlines()

    for line in lines[:MAX_INDICATORS_PER_FEED]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        ip = line.split()[0] if line.split() else ""
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            continue

        indicators.append({
            "type": "ip",
            "value": ip,
            "confidence": 0.95,
            "source": "feodo_tracker",
            "severity": "critical",
            "tags": ["botnet", "c2", "feodo"],
            "first_seen": "",
        })

    return indicators


# ── Feed Dispatcher ──────────────────────────────────────────────────────────

FEED_PARSERS = {
    "cisa_kev": parse_cisa_kev,
    "urlhaus": parse_urlhaus,
    "threatfox": parse_threatfox,
    "openphish": parse_openphish,
    "blocklist_de": parse_blocklist_de,
    "feodo_tracker": parse_feodo_tracker,
}

# Feeds requiring API keys — stubs
STUB_FEEDS = {"otx", "emerging_threats", "phishtank", "nvd"}


def poll_feed(
    feed_id: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Poll a single feed and return normalized result."""
    feed_config = BUILTIN_FEEDS.get(feed_id)
    if not feed_config:
        return {
            "feed": feed_id,
            "status": "error",
            "reason": f"Unknown feed: {feed_id}",
        }

    # Check if this is a stub feed requiring an API key
    if feed_id in STUB_FEEDS:
        env_var = feed_config.get("auth_env", "")
        token = os.environ.get(env_var, "") if env_var else ""
        if not token:
            return {
                "feed": feed_id,
                "status": "skipped",
                "reason": f"API key not configured ({env_var})",
            }
        # If token is set, attempt the actual call
        # For now, stubs return a success with the token acknowledgement
        # Real implementations would make the API call here
        headers = {}
        if feed_id == "otx":
            headers["X-OTX-API-KEY"] = token
        elif feed_id == "nvd":
            headers["apiKey"] = token
        elif feed_id == "phishtank":
            # PhishTank uses token in URL
            pass
        elif feed_id == "emerging_threats":
            # ET uses token in URL
            pass

        try:
            raw = http_fetch(
                feed_config["url"],
                method=feed_config.get("method", "GET"),
                headers=headers,
                timeout=timeout,
            )
            # Generic JSON parse for stub feeds
            return {
                "feed": feed_id,
                "status": "success",
                "indicators_count": 0,
                "indicators": [],
                "note": f"Feed polled with {env_var} but parser not fully implemented",
            }
        except Exception as e:
            return {
                "feed": feed_id,
                "status": "error",
                "reason": f"HTTP error: {e}",
            }

    # Poll the feed
    parser = FEED_PARSERS.get(feed_id)
    if not parser:
        return {
            "feed": feed_id,
            "status": "error",
            "reason": f"No parser for feed: {feed_id}",
        }

    try:
        raw = http_fetch(
            feed_config["url"],
            method=feed_config.get("method", "GET"),
            post_body=feed_config.get("post_body"),
            timeout=timeout,
        )

        indicators = parser(raw)

        return {
            "feed": feed_id,
            "status": "success",
            "indicators_count": len(indicators),
            "indicators": indicators,
        }

    except urllib.error.HTTPError as e:
        return {
            "feed": feed_id,
            "status": "error",
            "reason": f"HTTP {e.code}: {e.reason}",
        }
    except urllib.error.URLError as e:
        return {
            "feed": feed_id,
            "status": "error",
            "reason": f"URL error: {e.reason}",
        }
    except json.JSONDecodeError as e:
        return {
            "feed": feed_id,
            "status": "error",
            "reason": f"JSON parse error: {e}",
        }
    except Exception as e:
        return {
            "feed": feed_id,
            "status": "error",
            "reason": f"Unexpected error: {e}",
        }


# ── CLI Commands ─────────────────────────────────────────────────────────────

def cmd_list() -> int:
    """List all available feeds with status."""
    print(json.dumps({
        "feeds": [
            {
                "id": feed_id,
                "name": config["name"],
                "url": config["url"],
                "auth_required": config["auth_env"] is not None,
                "auth_env": config.get("auth_env"),
                "configured": (
                    config["auth_env"] is None
                    or bool(os.environ.get(config["auth_env"], ""))
                ),
                "data_type": config["data_type"],
                "refresh_rate": config["refresh_rate"],
            }
            for feed_id, config in BUILTIN_FEEDS.items()
        ]
    }, indent=2))
    return 0


def cmd_poll_builtin(
    feed_names: Optional[List[str]] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> int:
    """Poll built-in feeds."""
    if feed_names:
        feeds_to_poll = feed_names
    else:
        feeds_to_poll = list(BUILTIN_FEEDS.keys())

    # Validate feed names
    for name in feeds_to_poll:
        if name not in BUILTIN_FEEDS:
            print(f"ERROR: Unknown feed: {name}", file=sys.stderr)
            print(f"Available: {', '.join(BUILTIN_FEEDS.keys())}", file=sys.stderr)
            return 1

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    results = []
    total_indicators = 0
    feeds_polled = 0
    feeds_skipped = 0

    for feed_id in feeds_to_poll:
        print(f"Polling {feed_id}...", file=sys.stderr)
        result = poll_feed(feed_id, timeout=timeout)
        results.append(result)

        if result["status"] == "success":
            feeds_polled += 1
            total_indicators += result.get("indicators_count", 0)
        else:
            feeds_skipped += 1
            print(f"  Skipped: {result.get('reason', 'unknown')}", file=sys.stderr)

    output = {
        "polled_at": now,
        "feeds_polled": feeds_polled,
        "feeds_skipped": feeds_skipped,
        "total_indicators": total_indicators,
        "results": results,
    }

    json.dump(output, sys.stdout, indent=2)
    print()  # trailing newline
    return 0


def cmd_poll_custom(config_path: str, timeout: int = DEFAULT_TIMEOUT) -> int:
    """Poll custom feeds from a config file."""
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"ERROR: Cannot read custom feed config: {e}", file=sys.stderr)
        return 1

    feeds = config.get("feeds", [])
    if not feeds:
        print("ERROR: No feeds defined in config", file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    results = []
    total_indicators = 0
    feeds_polled = 0
    feeds_skipped = 0

    for feed_def in feeds:
        feed_id = feed_def.get("id", "unknown")
        url = feed_def.get("url", "")
        if not url:
            results.append({
                "feed": feed_id,
                "status": "error",
                "reason": "No URL configured",
            })
            feeds_skipped += 1
            continue

        try:
            print(f"Polling custom feed {feed_id}...", file=sys.stderr)
            raw = http_fetch(url, timeout=timeout)
            # Custom feeds: return raw line count as indicators
            lines = raw.decode("utf-8", errors="replace").strip().splitlines()
            indicators = []
            for line in lines[:MAX_INDICATORS_PER_FEED]:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                indicators.append({
                    "type": feed_def.get("indicator_type", "unknown"),
                    "value": sanitize_value(line),
                    "confidence": 0.7,
                    "source": feed_id,
                    "severity": "medium",
                    "tags": sanitize_tags(feed_def.get("tags", [])),
                    "first_seen": "",
                })

            results.append({
                "feed": feed_id,
                "status": "success",
                "indicators_count": len(indicators),
                "indicators": indicators,
            })
            feeds_polled += 1
            total_indicators += len(indicators)

        except Exception as e:
            results.append({
                "feed": feed_id,
                "status": "error",
                "reason": str(e),
            })
            feeds_skipped += 1

    output = {
        "polled_at": now,
        "feeds_polled": feeds_polled,
        "feeds_skipped": feeds_skipped,
        "total_indicators": total_indicators,
        "results": results,
    }

    json.dump(output, sys.stdout, indent=2)
    print()
    return 0


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Feed Poller — polls feeds and outputs normalized indicators"
    )
    parser.add_argument("--feeds", choices=["builtin", "custom"],
                        help="Feed source: builtin or custom")
    parser.add_argument("--feed-name", type=str, default=None,
                        help="Comma-separated list of specific feed names to poll")
    parser.add_argument("--config", type=str, default=None,
                        help="Path to custom feed config (required for --feeds custom)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--list", action="store_true",
                        help="List all available feeds with status")

    args = parser.parse_args()

    if args.list:
        return cmd_list()

    if not args.feeds:
        parser.print_help()
        return 1

    if args.feeds == "custom":
        if not args.config:
            print("ERROR: --config is required for --feeds custom", file=sys.stderr)
            return 1
        return cmd_poll_custom(args.config, timeout=args.timeout)

    # builtin
    feed_names = None
    if args.feed_name:
        feed_names = [n.strip() for n in args.feed_name.split(",")]

    return cmd_poll_builtin(feed_names=feed_names, timeout=args.timeout)


if __name__ == "__main__":
    sys.exit(main())
