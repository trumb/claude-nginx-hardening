#!/usr/bin/env python3
"""
Layer 5: Deterministic Compatibility Checker for nginx configs.

Checks proposed nginx config changes for compatibility issues BEFORE deployment.
Runs alongside invariant-checker.py as part of Layer 5.

9 checks: ACME paths, health endpoints, proxy headers, websocket upgrade,
include integrity, duplicate directives, header inheritance, location precedence,
deny/allow conflicts.

Stdlib-only Python, no LLM.

Usage:
    python3 scripts/compatibility-checker.py --config PATH \
        [--proposed-rules DIR] [--profile PROFILE]

Exit code: 0 = compatible, 1 = critical failure, 2 = warnings only
"""

import argparse
import glob as globmod
import json
import os
import re
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Profiles: which checks are critical vs warning per environment
# ---------------------------------------------------------------------------

PROFILES = {
    "edge-public": {
        "critical": [
            "acme_paths", "health_endpoints", "proxy_headers",
            "websocket_upgrade", "include_integrity",
            "header_inheritance", "location_precedence",
        ],
        "warn_only": ["duplicate_directives", "deny_allow_conflicts"],
    },
    "internal-only": {
        "critical": ["include_integrity", "proxy_headers"],
        "warn_only": [
            "acme_paths", "health_endpoints", "websocket_upgrade",
            "duplicate_directives", "header_inheritance",
            "location_precedence", "deny_allow_conflicts",
        ],
    },
    "api-gateway": {
        "critical": [
            "acme_paths", "health_endpoints", "proxy_headers",
            "websocket_upgrade", "include_integrity",
            "location_precedence",
        ],
        "warn_only": [
            "duplicate_directives", "header_inheritance",
            "deny_allow_conflicts",
        ],
    },
    "static-site": {
        "critical": [
            "acme_paths", "include_integrity", "header_inheritance",
        ],
        "warn_only": [
            "health_endpoints", "proxy_headers", "websocket_upgrade",
            "duplicate_directives", "location_precedence",
            "deny_allow_conflicts",
        ],
    },
    "reverse-proxy-app": {
        "critical": [
            "acme_paths", "health_endpoints", "proxy_headers",
            "websocket_upgrade", "include_integrity",
            "location_precedence",
        ],
        "warn_only": [
            "duplicate_directives", "header_inheritance",
            "deny_allow_conflicts",
        ],
    },
    "high-risk-lockdown": {
        "critical": [
            "acme_paths", "health_endpoints", "proxy_headers",
            "websocket_upgrade", "include_integrity",
            "duplicate_directives", "header_inheritance",
            "location_precedence", "deny_allow_conflicts",
        ],
        "warn_only": [],
    },
}

DEFAULT_PROFILE = "edge-public"


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def read_file(path):
    with open(path, "r") as f:
        return f.read()


def strip_comments(text):
    """Remove full-line and inline comments."""
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        # Remove inline comments (not inside quotes)
        cleaned = re.sub(r'\s+#.*$', '', line)
        lines.append(cleaned)
    return "\n".join(lines)


def extract_location_blocks(text, include_line_numbers=False):
    """Extract location blocks with their modifier, pattern, body, and line number."""
    blocks = []
    clean = strip_comments(text)
    pattern = re.compile(r'location\s+(.*?)\s*\{', re.DOTALL)

    for m in pattern.finditer(clean):
        loc_expr = m.group(1).strip()
        start = m.end()
        depth = 1
        pos = start
        while pos < len(clean) and depth > 0:
            if clean[pos] == '{':
                depth += 1
            elif clean[pos] == '}':
                depth -= 1
            pos += 1
        body = clean[start:pos - 1].strip()

        # Parse modifier and path
        modifier = ""
        path = loc_expr
        parts = loc_expr.split(None, 1)
        if len(parts) == 2 and parts[0] in ("=", "~", "~*", "^~"):
            modifier = parts[0]
            path = parts[1]
        elif len(parts) == 1:
            path = parts[0]

        line_num = 0
        if include_line_numbers:
            line_num = clean[:m.start()].count('\n') + 1

        blocks.append({
            "expr": loc_expr,
            "modifier": modifier,
            "path": path,
            "body": body,
            "line": line_num,
        })
    return blocks


def extract_server_blocks(text):
    """Extract server blocks with their content."""
    blocks = []
    clean = strip_comments(text)
    pattern = re.compile(r'\bserver\s*\{')

    for m in pattern.finditer(clean):
        start = m.end()
        depth = 1
        pos = start
        while pos < len(clean) and depth > 0:
            if clean[pos] == '{':
                depth += 1
            elif clean[pos] == '}':
                depth -= 1
            pos += 1
        body = clean[start:pos - 1].strip()
        line_num = clean[:m.start()].count('\n') + 1
        blocks.append({"body": body, "line": line_num})
    return blocks


def find_directives(text, directive_name):
    """Find all occurrences of a directive in text, returning (line_num, full_line)."""
    results = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.match(rf'\b{re.escape(directive_name)}\b', stripped):
            results.append((i, stripped))
    return results


def location_would_match(modifier, pattern_str, test_path):
    """Check if a location block would match a given path."""
    if modifier == "=":
        return pattern_str == test_path
    elif modifier == "~":
        try:
            return bool(re.search(pattern_str, test_path))
        except re.error:
            return False
    elif modifier == "~*":
        try:
            return bool(re.search(pattern_str, test_path, re.IGNORECASE))
        except re.error:
            return False
    elif modifier == "^~":
        return test_path.startswith(pattern_str)
    else:
        # Prefix match
        return test_path.startswith(pattern_str)


def block_is_deny(body):
    """Check if a location block denies access."""
    return bool(
        re.search(r'\breturn\s+(403|404|444)\b', body)
        or re.search(r'\bdeny\s+all\b', body)
    )


# ---------------------------------------------------------------------------
# Compatibility checks
# ---------------------------------------------------------------------------

HEALTH_PATHS = ["/health", "/ready", "/healthz", "/status", "/ping"]

REQUIRED_PROXY_HEADERS = [
    "Host",
    "X-Real-IP",
    "X-Forwarded-For",
    "X-Forwarded-Proto",
]


def check_acme_paths(text, blocks):
    """Verify /.well-known/acme-challenge/ is not blocked."""
    acme_path = "/.well-known/acme-challenge/test"

    # If this is a snippet/include file (no server block), skip — we cannot
    # determine full context (a ^~ ACME location in the parent config would
    # take precedence over regex blocks in the snippet).
    if not re.search(r'\bserver\s*\{', strip_comments(text)):
        return {
            "status": "skip",
            "details": "Snippet file — ACME path check requires full server context",
        }

    # Check if there is an explicit ACME allow (^~ or = match beats regex)
    has_acme_override = False
    for b in blocks:
        if b["modifier"] in ("=", "^~"):
            if location_would_match(b["modifier"], b["path"], acme_path):
                if not block_is_deny(b["body"]):
                    has_acme_override = True
                    break

    blocking = []
    for b in blocks:
        if location_would_match(b["modifier"], b["path"], acme_path):
            if block_is_deny(b["body"]):
                blocking.append(f"location {b['expr']} (line {b['line']})")

    if blocking and not has_acme_override:
        return {
            "status": "fail",
            "details": f"ACME challenge path blocked by: {'; '.join(blocking)}",
        }
    if blocking and has_acme_override:
        return {
            "status": "pass",
            "details": "ACME path matched by blocking rules but overridden by ^~/= location",
        }
    return {"status": "pass", "details": "ACME challenge path not blocked"}


def check_health_endpoints(text, blocks):
    """Verify health probe paths are not blocked."""
    blocked = []

    for hp in HEALTH_PATHS:
        for b in blocks:
            if location_would_match(b["modifier"], b["path"], hp):
                if block_is_deny(b["body"]):
                    blocked.append(f"{hp} blocked by location {b['expr']} (line {b['line']})")

    if blocked:
        return {
            "status": "fail",
            "details": "; ".join(blocked),
        }
    return {"status": "pass", "details": "No health endpoints blocked"}


def check_proxy_headers(text, blocks):
    """Verify proxy_pass locations have required headers."""
    issues = []

    for b in blocks:
        if not re.search(r'\bproxy_pass\b', b["body"]):
            continue

        for header in REQUIRED_PROXY_HEADERS:
            pattern = rf'proxy_set_header\s+{re.escape(header)}\b'
            if not re.search(pattern, b["body"]):
                issues.append(
                    f"location {b['expr']} (line {b['line']}) missing "
                    f"proxy_set_header {header}"
                )

    if issues:
        return {
            "status": "fail",
            "details": "; ".join(issues),
        }

    # Check if any proxy_pass locations exist
    has_proxy = any(re.search(r'\bproxy_pass\b', b["body"]) for b in blocks)
    if not has_proxy:
        return {"status": "skip", "details": "No proxy_pass locations found"}

    return {"status": "pass", "details": "All proxy locations have required headers"}


def check_websocket_upgrade(text, blocks):
    """Verify websocket locations have both Upgrade and Connection headers."""
    issues = []
    found_ws = False

    for b in blocks:
        body = b["body"]
        if not re.search(r'\bproxy_pass\b', body):
            continue

        has_upgrade = bool(re.search(
            r'proxy_set_header\s+Upgrade\b', body
        ))
        has_connection = bool(re.search(
            r'proxy_set_header\s+Connection\b', body
        ))

        if has_upgrade or has_connection:
            found_ws = True
            if has_upgrade and not has_connection:
                issues.append(
                    f"location {b['expr']} (line {b['line']}) has Upgrade "
                    f"header but missing Connection header"
                )
            elif has_connection and not has_upgrade:
                # Check if Connection is specifically for upgrade
                if re.search(r'proxy_set_header\s+Connection\s+"[Uu]pgrade"', body):
                    issues.append(
                        f"location {b['expr']} (line {b['line']}) has "
                        f"Connection \"upgrade\" but missing Upgrade header"
                    )

    if not found_ws:
        return {"status": "skip", "details": "No websocket locations found"}

    if issues:
        return {
            "status": "fail",
            "details": "; ".join(issues),
        }

    return {"status": "pass", "details": "All websocket locations have required headers"}


def check_include_integrity(text):
    """Verify all include directives reference existing files."""
    issues = []
    warnings = []

    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = re.match(r'include\s+([^;]+);', stripped)
        if not m:
            continue

        include_path = m.group(1).strip().strip("'\"")

        # Check for glob patterns
        if any(c in include_path for c in ['*', '?', '[']):
            matches = globmod.glob(include_path)
            if not matches:
                warnings.append(
                    f"include glob '{include_path}' (line {i}) matches no files"
                )
            continue

        if not os.path.exists(include_path):
            issues.append(
                f"include '{include_path}' (line {i}) not found on disk"
            )

    if issues:
        return {
            "status": "fail",
            "details": "; ".join(issues),
        }

    if warnings:
        return {
            "status": "warn",
            "details": "; ".join(warnings),
        }

    return {"status": "pass", "details": "All includes resolved"}


def check_duplicate_directives(text):
    """Warn if the same directive appears multiple times in the same context."""
    issues = []

    # Check at server block level
    server_blocks = extract_server_blocks(text)
    for sb in server_blocks:
        _check_dupes_in_context(sb["body"], f"server block (line {sb['line']})", issues)

    # Check at top level (outside server blocks) -- treat the whole file as a context
    # if no server blocks found
    if not server_blocks:
        _check_dupes_in_context(strip_comments(text), "top-level", issues)

    # Check within each location block
    blocks = extract_location_blocks(text, include_line_numbers=True)
    for b in blocks:
        _check_dupes_in_context(
            b["body"], f"location {b['expr']} (line {b['line']})", issues
        )

    if issues:
        return {
            "status": "warn",
            "details": "; ".join(issues),
        }

    return {"status": "pass", "details": "No duplicate directives found"}


def _strip_nested_blocks(body_text):
    """Remove nested block content, leaving only the current scope's directives."""
    result = []
    depth = 0
    for line in body_text.splitlines():
        stripped = line.strip()
        opens = stripped.count('{')
        closes = stripped.count('}')
        if depth == 0 and opens == 0:
            result.append(line)
        elif depth == 0 and opens > 0:
            # This line opens a nested block — skip it
            depth += opens - closes
        else:
            depth += opens - closes
            depth = max(0, depth)
    return "\n".join(result)


def _check_dupes_in_context(body_text, context_label, issues):
    """Find duplicate directives within a single context block."""
    # Strip nested blocks so we only count directives at this scope level
    scoped_text = _strip_nested_blocks(body_text)

    # Directives that are expected to repeat
    repeatable = {"add_header", "set", "proxy_set_header", "include",
                  "allow", "deny", "location", "if", "server"}

    directive_lines = {}
    for i, line in enumerate(scoped_text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped == "}":
            continue

        # Extract directive name (first word)
        m = re.match(r'(\w[\w_-]*)', stripped)
        if not m:
            continue
        directive = m.group(1)

        if directive in repeatable:
            continue

        if directive not in directive_lines:
            directive_lines[directive] = []
        directive_lines[directive].append(i)

    for directive, lines in directive_lines.items():
        if len(lines) > 1:
            issues.append(
                f"{directive} appears {len(lines)} times in {context_label}"
            )


def check_header_inheritance(text):
    """Warn if add_header in both server block and location block."""
    issues = []
    server_blocks = extract_server_blocks(text)

    for sb in server_blocks:
        # Check if server block has add_header
        server_has_headers = bool(
            re.search(r'\badd_header\b', sb["body"])
        )
        if not server_has_headers:
            continue

        # Check location blocks within this server block
        loc_blocks = extract_location_blocks(sb["body"], include_line_numbers=True)
        for lb in loc_blocks:
            if re.search(r'\badd_header\b', lb["body"]):
                issues.append(
                    f"add_header in both server block (line {sb['line']}) and "
                    f"location {lb['expr']} (line {lb['line'] + sb['line']}) "
                    f"— nginx will drop server-level headers in this location"
                )

    # Also check for non-server-block configs (include files)
    if not server_blocks:
        clean = strip_comments(text)
        top_level_headers = False
        for line in clean.splitlines():
            stripped = line.strip()
            if re.match(r'add_header\b', stripped):
                top_level_headers = True
                break

        if top_level_headers:
            loc_blocks = extract_location_blocks(text, include_line_numbers=True)
            for lb in loc_blocks:
                if re.search(r'\badd_header\b', lb["body"]):
                    issues.append(
                        f"add_header at top level AND in location {lb['expr']} "
                        f"(line {lb['line']}) — nginx will drop top-level "
                        f"headers in this location"
                    )

    if issues:
        return {
            "status": "warn",
            "details": "; ".join(issues),
        }

    return {"status": "pass", "details": "No inheritance conflicts"}


def check_location_precedence(text, proposed_rules_text=None):
    """Check for location blocks that shadow each other."""
    issues = []
    blocks = extract_location_blocks(text, include_line_numbers=True)

    if proposed_rules_text:
        proposed_blocks = extract_location_blocks(
            proposed_rules_text, include_line_numbers=True
        )
    else:
        proposed_blocks = []

    all_blocks = blocks + proposed_blocks

    # Check for exact matches that shadow prefix matches
    exact_paths = {b["path"] for b in all_blocks if b["modifier"] == "="}
    prefix_paths = {b["path"] for b in all_blocks if b["modifier"] in ("", "^~")}

    # Check for regex patterns that could match paths meant for prefix locations
    regex_blocks = [b for b in all_blocks if b["modifier"] in ("~", "~*")]
    prefix_blocks = [b for b in all_blocks if b["modifier"] in ("", "^~")]

    for rb in regex_blocks:
        for pb in prefix_blocks:
            try:
                flags = re.IGNORECASE if rb["modifier"] == "~*" else 0
                if re.search(rb["path"], pb["path"], flags):
                    # A regex could match the prefix path
                    # ^~ prefix beats regex, but plain prefix loses to regex
                    if pb["modifier"] != "^~":
                        issues.append(
                            f"regex location {rb['expr']} (line {rb['line']}) "
                            f"could shadow prefix location {pb['expr']} "
                            f"(line {pb['line']})"
                        )
            except re.error:
                continue

    # Check for duplicate location patterns
    seen = {}
    for b in all_blocks:
        key = (b["modifier"], b["path"])
        if key in seen:
            issues.append(
                f"duplicate location {b['expr']} at lines {seen[key]} and {b['line']}"
            )
        else:
            seen[key] = b["line"]

    if issues:
        return {
            "status": "warn",
            "details": "; ".join(issues),
        }

    return {"status": "pass", "details": "No shadowed locations"}


def check_deny_allow_conflicts(text):
    """Warn if deny rules conflict with allow directives."""
    issues = []
    blocks = extract_location_blocks(text, include_line_numbers=True)

    for b in blocks:
        body = b["body"]
        has_deny = bool(re.search(r'\bdeny\b', body))
        has_allow = bool(re.search(r'\ballow\b', body))

        if has_deny and has_allow:
            # Check ordering — in nginx, last matching rule wins
            deny_pos = None
            allow_pos = None
            for i, line in enumerate(body.splitlines()):
                stripped = line.strip()
                if re.match(r'\bdeny\b', stripped):
                    deny_pos = i
                if re.match(r'\ballow\b', stripped):
                    allow_pos = i

            if deny_pos is not None and allow_pos is not None:
                if deny_pos < allow_pos:
                    # deny before allow — the allow will override
                    issues.append(
                        f"location {b['expr']} (line {b['line']}): "
                        f"deny appears before allow — allow will override"
                    )

    # Also check for deny all at top level conflicting with allow in locations
    clean = strip_comments(text)
    top_deny = bool(re.search(r'^\s*deny\s+all\s*;', clean, re.MULTILINE))
    if top_deny:
        for b in blocks:
            if re.search(r'\ballow\b', b["body"]):
                issues.append(
                    f"top-level deny all conflicts with allow in "
                    f"location {b['expr']} (line {b['line']})"
                )

    if issues:
        return {
            "status": "warn",
            "details": "; ".join(issues),
        }

    return {"status": "pass", "details": "No conflicts found"}


# ---------------------------------------------------------------------------
# CLI and main
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Nginx compatibility checker (Layer 5)"
    )
    p.add_argument("--config", required=True,
                    help="Path to nginx config file to check")
    p.add_argument("--proposed-rules", default=None,
                    help="Directory of proposed rule files to check against config")
    p.add_argument("--profile", default=DEFAULT_PROFILE,
                    choices=list(PROFILES.keys()),
                    help=f"Environment profile (default: {DEFAULT_PROFILE})")
    return p.parse_args()


def main():
    args = parse_args()
    profile_name = args.profile
    profile = PROFILES[profile_name]

    config_text = read_file(args.config)
    blocks = extract_location_blocks(config_text, include_line_numbers=True)

    # Load proposed rules if provided
    proposed_text = None
    if args.proposed_rules and os.path.isdir(args.proposed_rules):
        parts = []
        for fname in sorted(os.listdir(args.proposed_rules)):
            fpath = os.path.join(args.proposed_rules, fname)
            if os.path.isfile(fpath) and fname.endswith(".conf"):
                parts.append(read_file(fpath))
        if parts:
            proposed_text = "\n".join(parts)

    # Run all checks
    checks = {}
    checks["acme_paths"] = check_acme_paths(config_text, blocks)
    checks["health_endpoints"] = check_health_endpoints(config_text, blocks)
    checks["proxy_headers"] = check_proxy_headers(config_text, blocks)
    checks["websocket_upgrade"] = check_websocket_upgrade(config_text, blocks)
    checks["include_integrity"] = check_include_integrity(config_text)
    checks["duplicate_directives"] = check_duplicate_directives(config_text)
    checks["header_inheritance"] = check_header_inheritance(config_text)
    checks["location_precedence"] = check_location_precedence(
        config_text, proposed_text
    )
    checks["deny_allow_conflicts"] = check_deny_allow_conflicts(config_text)

    # Classify results based on profile
    critical_failures = []
    warnings = []

    for check_name, result in checks.items():
        status = result["status"]
        if status == "skip" or status == "pass":
            continue

        if check_name in profile["critical"] and status == "fail":
            critical_failures.append(f"{check_name}: {result['details']}")
        elif status == "fail" and check_name in profile["warn_only"]:
            # Downgrade to warning for warn_only checks
            result["status"] = "warn"
            warnings.append(f"{check_name}: {result['details']}")
        elif status == "warn":
            warnings.append(f"{check_name}: {result['details']}")
        elif status == "fail":
            critical_failures.append(f"{check_name}: {result['details']}")

    compatible = len(critical_failures) == 0

    output = {
        "compatible": compatible,
        "profile": profile_name,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config_path": os.path.abspath(args.config),
        "checks": checks,
        "critical_failures": critical_failures,
        "warnings": warnings,
    }

    json.dump(output, sys.stdout, indent=2)
    print()

    if critical_failures:
        sys.exit(1)
    elif warnings:
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
