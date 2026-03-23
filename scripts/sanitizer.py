#!/usr/bin/env python3
"""
Layer 2 Deterministic Sanitizer — CRITICAL SECURITY BOUNDARY

This script ensures NO raw attacker-controlled data reaches LLM agents.
It is 100% deterministic: no LLM involvement, stdlib-only.

Reads structured JSON from Layer 1 (log-parser), applies:
  1. Hex decoding
  2. Character allowlist (printable ASCII URL chars only)
  3. Prompt injection pattern stripping
  4. Shell metacharacter removal
  5. Path truncation (200 chars)
  6. Path classification (35 attack categories)
  7. UA classification (scanner families)
  8. Deduplication
  9. Versioned sanitized-events schema output

Fail-closed: exits 1 on ANY error.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ── Constants ────────────────────────────────────────────────────────────────

SCHEMA_VERSION = "1.0"
PROVENANCE = "log-analysis-layer2-v1.0"
MAX_PATH_LEN = 200

# Character allowlist: printable ASCII URL chars
# a-zA-Z0-9 and / - _ . ~ : ? # [ ] @ ! $ & ' ( ) * + , ; = %
ALLOWED_CHARS_RE = re.compile(r"[^a-zA-Z0-9/\-_\.~:?#\[\]@!$&'()*+,;=% ]")

# Shell metacharacters to strip
SHELL_META_RE = re.compile(r"[;|&`$(){}<>\n\r\0]")

# ── Prompt injection patterns ────────────────────────────────────────────────

PROMPT_INJECTION_STRINGS = [
    "ignore previous",
    "ignore all",
    "you are now",
    "you are a",
    "system:",
    "assistant:",
    "user:",
    "human:",
]

PROMPT_INJECTION_TOKENS = [
    "</s>",
    "<s>",
    "<|im_end|>",
    "<|im_start|>",
    "<|endoftext|>",
    "[INST]",
    "[/INST]",
    "<system>",
    "</system>",
    "<tool>",
    "</tool>",
    "<function>",
    "</function>",
]

# Template injection: ${...} patterns — but preserve ${jndi: as attack indicator
TEMPLATE_INJECTION_RE = re.compile(r"\$\{(?!jndi:)[^}]*\}")
# Also strip ${jndi:...} but leave the text "jndi:" for classification
JNDI_TEMPLATE_RE = re.compile(r"\$\{(jndi:[^}]*)\}")

# Command substitution: $(...)
CMD_SUBSTITUTION_RE = re.compile(r"\$\([^)]*\)")

# Backtick sequences
BACKTICK_RE = re.compile(r"`[^`]*`")

# ── Path classification regexes (35 categories) ─────────────────────────────

PATH_CLASSIFIERS: List[Tuple[str, re.Pattern]] = [
    ("path_traversal", re.compile(r"(\.%2e|\.\.%2|%2f\.\.|%%32%65|/etc/(passwd|shadow))", re.I)),
    ("jndi", re.compile(r"jndi:", re.I)),
    ("cve_probe", re.compile(r"__cve_probe", re.I)),
    ("wordpress", re.compile(r"^/(wp-admin|wp-login|wordpress|wp-includes|wp-content|wp-json|xmlrpc)", re.I)),
    ("actuator", re.compile(r"/actuator/", re.I)),
    ("swagger", re.compile(r"(swagger|api-docs)", re.I)),
    ("php_debug", re.compile(r"(telescope|_ignition|_profiler|_wdt|__debug__)", re.I)),
    ("container", re.compile(r"(v2/_catalog|api/v1/namespaces)", re.I)),
    ("js_devtools", re.compile(r"(@vite|__webpack|_next)", re.I)),
    ("atlassian", re.compile(r"(META-INF|login\.action)", re.I)),
    ("exchange", re.compile(r"^/ecp/", re.I)),
    ("graphql", re.compile(r"(graphql|api/gql)", re.I)),
    ("admin_panel", re.compile(r"(phpmyadmin|adminer|solr|server-status|hudson|druid|jenkins)", re.I)),
    ("phishing", re.compile(r"(twint|lkk|support_parent)", re.I)),
    ("backup_dir", re.compile(r"^/(bins?|backup|dump|sql|db|logs)/", re.I)),
    ("hnap", re.compile(r"^/HNAP", re.I)),
    ("vpn_gateway", re.compile(r"(\+CSCOE\+|dana-na|remote/fgt_lang)", re.I)),
    ("struts", re.compile(r"^/(struts|struts2-)", re.I)),
    ("ssh_key", re.compile(r"^/(id_rsa|id_ed25519|id_dsa)", re.I)),
    ("iot_device", re.compile(r"(boaform|GponForm|EXCU_SHELL|evox|DevMgmt|hp/jetdirect|PRESENTATION|config/getuser|SDK/webLanguage)", re.I)),
    ("xdebug", re.compile(r"XDEBUG_SESSION", re.I)),
    ("influxdb", re.compile(r"^/query.*SHOW", re.I)),
    ("network_infra", re.compile(r"(portal/redlion|cgi-bin/luci|cgi-bin/authLogin)", re.I)),
    ("enterprise", re.compile(r"(developmentserver|PassTrixMain|isgw|apiclient)", re.I)),
    ("misc_exploit", re.compile(r"(functionRouter|partymgr|emsapi|auto_prepend_file|allow_url_include)", re.I)),
    ("package_file", re.compile(r"(composer\.json|yarn\.lock|package\.json|package-lock|requirements\.txt|Gemfile|pom\.xml|Pipfile|go\.sum)", re.I)),
    ("app_settings", re.compile(r"(appsettings\.json|settings\.(py|php)|parameters\.ya?ml|WEB-INF|\.nsf$)", re.I)),
    ("lotus", re.compile(r"\.nsf$", re.I)),
    ("config_file", re.compile(r"(docker-compose|Dockerfile|Makefile|credentials\.json|config\.env|config\.json|config\.js)", re.I)),
    ("source_map", re.compile(r"\.map$", re.I)),
    ("script_ext", re.compile(r"\.(php|asp|aspx|jsp|cgi)($|\?)", re.I)),
    ("dotfile", re.compile(r"/\.", re.I)),
    ("unknown", re.compile(r".*")),  # catch-all, always last
]

# ── UA classification ────────────────────────────────────────────────────────

SCANNER_FAMILIES: List[Tuple[str, re.Pattern]] = [
    ("nmap", re.compile(r"nmap", re.I)),
    ("censys", re.compile(r"censys", re.I)),
    ("leakix", re.compile(r"(leakix|l9scan|l9explore)", re.I)),
    ("paloalto", re.compile(r"paloalto", re.I)),
    ("bitsight", re.compile(r"bitsight", re.I)),
    ("modatscanner", re.compile(r"modatscanner", re.I)),
    ("freepbx", re.compile(r"freepbx", re.I)),
    ("genomecrawler", re.compile(r"genomecrawler", re.I)),
    ("odin", re.compile(r"odin", re.I)),
    ("mrtscan", re.compile(r"mrtscan", re.I)),
    ("visionheight", re.compile(r"visionheight", re.I)),
    ("zgrab", re.compile(r"zgrab", re.I)),
    ("nuclei", re.compile(r"nuclei", re.I)),
    ("nikto", re.compile(r"nikto", re.I)),
    ("sqlmap", re.compile(r"sqlmap", re.I)),
    ("masscan", re.compile(r"masscan", re.I)),
    ("shodan", re.compile(r"shodan", re.I)),
    ("go-http-client", re.compile(r"go-http-client", re.I)),
    ("python-requests", re.compile(r"python-requests", re.I)),
    ("python-httpx", re.compile(r"python-httpx", re.I)),
    ("fasthttp", re.compile(r"fasthttp", re.I)),
    ("curl", re.compile(r"^curl/", re.I)),
    ("wget", re.compile(r"^wget", re.I)),
    ("libredtail", re.compile(r"libredtail", re.I)),
    ("xfa1", re.compile(r"xfa1", re.I)),
    ("okhttp", re.compile(r"okhttp", re.I)),
    ("headless_chrome", re.compile(r"HeadlessChrome", re.I)),
]

# Bare Mozilla: exactly "Mozilla/5.0" with nothing meaningful after
BARE_MOZILLA_RE = re.compile(r"^Mozilla/5\.0$")

# Ancient Chrome: Chrome/20-79
ANCIENT_CHROME_RE = re.compile(r"Chrome/[2-7][0-9]\.")

# Truncated Chrome: has Chrome/ but missing KHTML
TRUNCATED_CHROME_RE = re.compile(r"Chrome/")
KHTML_RE = re.compile(r"KHTML")

# Legitimate browser heuristic: has Mozilla + AppleWebKit or Gecko + a modern version
BROWSER_RE = re.compile(r"Mozilla/5\.0.*?(AppleWebKit|Gecko).*?(Chrome/[89]\d|Chrome/1[0-9]\d|Firefox/[89]\d|Firefox/1[0-9]\d|Safari/[5-7]\d\d|Edg/)")


# ── Sanitization functions ───────────────────────────────────────────────────

def hex_decode(hex_str: str) -> str:
    """Decode a hex-encoded string. Returns empty string on failure."""
    try:
        return bytes.fromhex(hex_str).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def strip_prompt_injection(s: str) -> str:
    """Remove all prompt injection patterns from a string."""
    lower = s.lower()
    for pat in PROMPT_INJECTION_STRINGS:
        idx = lower.find(pat)
        while idx != -1:
            s = s[:idx] + s[idx + len(pat):]
            lower = s.lower()
            idx = lower.find(pat)

    for token in PROMPT_INJECTION_TOKENS:
        lower = s.lower()
        token_lower = token.lower()
        idx = lower.find(token_lower)
        while idx != -1:
            s = s[:idx] + s[idx + len(token):]
            lower = s.lower()
            idx = lower.find(token_lower)

    # Template injection: strip ${...} but keep jndi: content
    s = JNDI_TEMPLATE_RE.sub(r"\1", s)
    s = TEMPLATE_INJECTION_RE.sub("", s)

    # Command substitution
    s = CMD_SUBSTITUTION_RE.sub("", s)

    # Backticks
    s = BACKTICK_RE.sub("", s)

    return s


def apply_allowlist(s: str) -> str:
    """Keep only allowed URL characters."""
    return ALLOWED_CHARS_RE.sub("", s)


def strip_shell_meta(s: str) -> str:
    """Remove shell metacharacters."""
    return SHELL_META_RE.sub("", s)


def sanitize_field(hex_value: str) -> str:
    """Full sanitization pipeline for a hex-encoded field."""
    decoded = hex_decode(hex_value)
    decoded = strip_prompt_injection(decoded)
    decoded = apply_allowlist(decoded)
    decoded = strip_shell_meta(decoded)
    return decoded


def classify_path(path: str) -> str:
    """Classify a sanitized path into one of 35 attack categories."""
    for category, pattern in PATH_CLASSIFIERS:
        if category == "unknown":
            return "unknown"
        if pattern.search(path):
            return category
    return "unknown"


def classify_ua(ua: str) -> Tuple[str, Optional[str]]:
    """
    Classify a sanitized UA string.
    Returns (ua_family, scanner_family).
    scanner_family is None if not a scanner.
    """
    if not ua or ua == "-":
        return ("empty", None)

    # Check scanner families first
    for family, pattern in SCANNER_FAMILIES:
        if pattern.search(ua):
            return (family, family)

    # Bare Mozilla
    if BARE_MOZILLA_RE.match(ua):
        return ("bare_mozilla", None)

    # Ancient Chrome
    if ANCIENT_CHROME_RE.search(ua):
        return ("ancient_chrome", None)

    # Truncated Chrome (has Chrome/ but no KHTML)
    if TRUNCATED_CHROME_RE.search(ua) and not KHTML_RE.search(ua):
        return ("truncated_chrome", None)

    # Legitimate browser
    if BROWSER_RE.search(ua):
        return ("browser", None)

    return ("unknown", None)


def status_bucket(status: int) -> str:
    """Map HTTP status code to bucket."""
    if 200 <= status < 300:
        return "2xx"
    elif 300 <= status < 400:
        return "3xx"
    elif 400 <= status < 500:
        return "4xx"
    elif 500 <= status < 600:
        return "5xx"
    return "other"


def classify_ip(addr: str) -> str:
    """Classify IP address type."""
    if not addr:
        return "unknown"
    if addr.startswith("10.") or addr.startswith("192.168.") or addr.startswith("172."):
        return "private_ipv4"
    if addr == "127.0.0.1" or addr == "::1":
        return "loopback"
    if ":" in addr:
        return "public_ipv6"
    return "public_ipv4"


def rate_signal(count: int) -> str:
    """Classify request rate."""
    if count >= 100:
        return "high"
    elif count >= 10:
        return "elevated"
    return "normal"


def mitigation_type(path_class: str) -> str:
    """Suggest mitigation type based on path classification."""
    block_types = {
        "dotfile": "location_block",
        "script_ext": "location_block",
        "source_map": "location_block",
        "config_file": "location_block",
        "wordpress": "location_block",
        "actuator": "location_block",
        "swagger": "location_block",
        "php_debug": "location_block",
        "container": "location_block",
        "js_devtools": "location_block",
        "atlassian": "location_block",
        "exchange": "location_block",
        "graphql": "location_block",
        "admin_panel": "location_block",
        "cve_probe": "location_block",
        "path_traversal": "location_block",
        "phishing": "location_block",
        "backup_dir": "location_block",
        "hnap": "location_block",
        "vpn_gateway": "location_block",
        "struts": "location_block",
        "jndi": "location_block",
        "ssh_key": "location_block",
        "iot_device": "location_block",
        "package_file": "location_block",
        "app_settings": "location_block",
        "xdebug": "location_block",
        "enterprise": "location_block",
        "influxdb": "location_block",
        "network_infra": "location_block",
        "lotus": "location_block",
        "misc_exploit": "location_block",
        "unknown": "monitor",
    }
    return block_types.get(path_class, "location_block")


def confidence_for(path_class: str, scanner_family: Optional[str]) -> float:
    """Return confidence score based on classification."""
    if path_class == "unknown" and scanner_family is None:
        return 0.3
    if path_class == "unknown":
        return 0.6
    if scanner_family:
        return 0.98
    return 0.95


def safe_note(path_class: str, sanitized_path: str, count: int) -> str:
    """Generate a safe human-readable note."""
    note_templates = {
        "dotfile": "dotfile probe",
        "script_ext": "script extension probe",
        "source_map": "source map probe",
        "config_file": "config file probe",
        "wordpress": "WordPress probe",
        "actuator": "Spring Actuator probe",
        "swagger": "Swagger/API docs probe",
        "php_debug": "PHP debug tool probe",
        "container": "container/K8s probe",
        "js_devtools": "JS devtools probe",
        "atlassian": "Atlassian probe",
        "exchange": "Exchange probe",
        "graphql": "GraphQL probe",
        "admin_panel": "admin panel probe",
        "cve_probe": "CVE probe",
        "path_traversal": "path traversal attempt",
        "phishing": "phishing path probe",
        "backup_dir": "backup directory probe",
        "hnap": "HNAP probe",
        "vpn_gateway": "VPN gateway probe",
        "struts": "Struts probe",
        "jndi": "JNDI injection attempt",
        "ssh_key": "SSH key probe",
        "iot_device": "IoT device probe",
        "package_file": "package file probe",
        "app_settings": "app settings probe",
        "xdebug": "Xdebug probe",
        "enterprise": "enterprise software probe",
        "influxdb": "InfluxDB probe",
        "network_infra": "network infra probe",
        "lotus": "Lotus Notes probe",
        "misc_exploit": "misc exploit probe",
        "unknown": "unclassified request",
    }
    desc = note_templates.get(path_class, "unclassified request")
    # Truncate the path snippet for the note
    snippet = sanitized_path[:60]
    return f"{desc}: {snippet} ({count} hits)"


def timestamp_bucket(ts: str) -> str:
    """Truncate timestamp to hour bucket."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:00Z")
    except (ValueError, AttributeError):
        return "unknown"


def validate_method(method: str) -> str:
    """Validate and return HTTP method, or INVALID."""
    valid = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
    m = method.upper().strip()
    if m in valid:
        return m
    return "INVALID"


# ── Main pipeline ────────────────────────────────────────────────────────────

def process_events(
    raw_events: List[Dict[str, Any]],
    log_source: str,
    source_type: str,
) -> Dict[str, Any]:
    """Process raw Layer 1 events into sanitized-events schema."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    events = []
    seen = set()  # dedup key
    event_counter = 0

    for entry in raw_events:
        # Extract and sanitize fields
        remote_addr = str(entry.get("remote_addr", "")).strip()
        timestamp = str(entry.get("timestamp", "")).strip()
        method = str(entry.get("method", "")).strip()
        hex_path = str(entry.get("hex_path", "")).strip()
        status = int(entry.get("status", 0))
        raw_bytes = int(entry.get("bytes", 0))
        hex_referer = str(entry.get("hex_referer", "")).strip()
        hex_ua = str(entry.get("hex_user_agent", "")).strip()
        count = int(entry.get("count", 1))

        # Sanitize path and UA
        sanitized_path = sanitize_field(hex_path)
        sanitized_path = sanitized_path[:MAX_PATH_LEN]
        sanitized_ua = sanitize_field(hex_ua)
        sanitized_ua = sanitized_ua[:MAX_PATH_LEN]

        # Classify
        path_class = classify_path(sanitized_path)
        ua_family, scanner_family = classify_ua(sanitized_ua)
        method_class = validate_method(method)

        # Dedup key: path_class + ua_family + method + status_bucket + remote_addr
        dedup_key = (path_class, ua_family, method_class, status_bucket(status), remote_addr)
        if dedup_key in seen:
            # Find existing event and add count
            for evt in events:
                existing_key = (
                    evt["path_class"],
                    evt["user_agent_family"],
                    evt["method_class"],
                    evt["status_bucket"],
                    evt["remote_addr_class"],
                )
                # Match by the classified fields (remote_addr_class instead of raw)
                if (evt["path_class"] == path_class and
                    evt["user_agent_family"] == ua_family and
                    evt["method_class"] == method_class and
                    evt["status_bucket"] == status_bucket(status)):
                    evt["count"] += count
                    break
            continue
        seen.add(dedup_key)

        event_counter += 1
        ts_date = timestamp[:10] if len(timestamp) >= 10 else "unknown"
        event_id = f"evt-{ts_date.replace('-', '')}-{event_counter:04d}"

        events.append({
            "event_id": event_id,
            "source_type": source_type,
            "log_source_path": log_source,
            "timestamp_bucket": timestamp_bucket(timestamp),
            "remote_addr_class": classify_ip(remote_addr),
            "method_class": method_class,
            "path_class": path_class,
            "status_bucket": status_bucket(status),
            "user_agent_family": ua_family,
            "rate_signal": rate_signal(count),
            "scanner_family": scanner_family,
            "indicator_match_type": "regex_path" if path_class != "unknown" else "none",
            "candidate_mitigation_type": mitigation_type(path_class),
            "confidence": confidence_for(path_class, scanner_family),
            "provenance": PROVENANCE,
            "ttl_recommendation": "permanent" if path_class != "unknown" else "review",
            "safe_notes": safe_note(path_class, sanitized_path, count),
            "count": count,
        })

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now,
        "source_count": len(raw_events),
        "events": events,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Layer 2 Deterministic Sanitizer — sanitizes Layer 1 log-parser output"
    )
    parser.add_argument("--input", required=True, help="Path to Layer 1 JSON input")
    parser.add_argument("--output", required=True, help="Path to write sanitized JSON output")
    parser.add_argument("--log-source", default="/var/log/nginx/access.log",
                        help="Original log source path")
    parser.add_argument("--source-type", default="access_log",
                        choices=["access_log", "error_log", "honeypot_log"],
                        help="Type of log source")
    args = parser.parse_args()

    try:
        with open(args.input, "r") as f:
            raw_events = json.load(f)

        if not isinstance(raw_events, list):
            print("ERROR: Input must be a JSON array", file=sys.stderr)
            return 1

        result = process_events(raw_events, args.log_source, args.source_type)

        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)

        print(f"Sanitized {result['source_count']} events -> {len(result['events'])} unique events",
              file=sys.stderr)
        return 0

    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON input: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"ERROR: File not found: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
