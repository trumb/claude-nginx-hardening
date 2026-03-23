#!/usr/bin/env python3
"""
Layer 5: Deterministic Invariant Checker for nginx configs.

Validates proposed nginx config changes against invariants 1-4, 9-11, 17.
Stdlib-only Python, no LLM.

Usage:
    python3 scripts/invariant-checker.py --proposed PATH [--backup PATH] \
        [--run-nginx-test] [--require-backup] [--check-git-command "CMD"]

Exit code: 0 = pass, 1 = fail
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone


def parse_args():
    p = argparse.ArgumentParser(description="Nginx invariant checker (Layer 5)")
    p.add_argument("--proposed", required=True, help="Path to proposed config")
    p.add_argument("--backup", default=None, help="Path to backup config")
    p.add_argument("--run-nginx-test", action="store_true",
                    help="Run nginx -t (requires sudo)")
    p.add_argument("--require-backup", action="store_true",
                    help="Fail if backup file does not exist")
    p.add_argument("--check-git-command", default=None,
                    help="Git command string to check for destructive ops")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def read_file(path):
    with open(path, "r") as f:
        return f.read()


def extract_location_blocks(text):
    """Extract location blocks with their pattern and body content."""
    blocks = []
    # Match location [modifier] pattern { ... }
    # We need to handle nested braces
    pattern = re.compile(
        r'location\s+(.*?)\s*\{', re.DOTALL
    )
    for m in pattern.finditer(text):
        loc_pattern = m.group(1).strip()
        start = m.end()
        depth = 1
        pos = start
        while pos < len(text) and depth > 0:
            if text[pos] == '{':
                depth += 1
            elif text[pos] == '}':
                depth -= 1
            pos += 1
        body = text[start:pos - 1].strip()
        blocks.append({"pattern": loc_pattern, "body": body})
    return blocks


def extract_headers(text):
    """Extract add_header directives as {name: value}."""
    headers = {}
    for m in re.finditer(
        r'add_header\s+(\S+)\s+"([^"]*)"', text
    ):
        headers[m.group(1)] = m.group(2)
    return headers


def extract_ssl_protocols(text):
    """Extract ssl_protocols values as a set."""
    # Search line by line to avoid matching across newlines or in comments
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        m = re.match(r'ssl_protocols\s+([^;]+);', stripped)
        if m:
            return set(m.group(1).split())
    return set()


def is_blocking_location(block):
    """Check if a location block is a blocking/deny rule."""
    body = block["body"]
    return bool(
        re.search(r'\breturn\s+404\b', body) or
        re.search(r'\bdeny\s+all\b', body)
    )


def normalize_location_key(block):
    """Create a comparable key for a location block."""
    return block["pattern"]


# ---------------------------------------------------------------------------
# Invariant checks
# ---------------------------------------------------------------------------

REQUIRED_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "Permissions-Policy",
]

DESTRUCTIVE_GIT_PATTERNS = [
    r'\bpush\s+--force\b',
    r'\bpush\s+-f\b',
    r'\breset\s+--hard\b',
    r'\bcheckout\s+\.\s*$',
    r'\bcheckout\s+--\s+\.\s*$',
    r'\bclean\s+-f\b',
    r'\bbranch\s+-D\b',
]


def check_invariant_1(proposed_text, backup_text):
    """Additive-only: no blocking rules removed or weakened."""
    if backup_text is None:
        return {"status": "skip", "details": "No backup provided"}

    backup_blocks = extract_location_blocks(backup_text)
    proposed_blocks = extract_location_blocks(proposed_text)

    backup_blocking = {
        normalize_location_key(b) for b in backup_blocks if is_blocking_location(b)
    }
    proposed_blocking = {
        normalize_location_key(b) for b in proposed_blocks if is_blocking_location(b)
    }

    removed = backup_blocking - proposed_blocking
    if removed:
        return {
            "status": "fail",
            "details": f"Blocking rules removed: {sorted(removed)}"
        }

    # Check for weakened rules (blocking in backup, non-blocking in proposed)
    proposed_map = {normalize_location_key(b): b for b in proposed_blocks}
    weakened = []
    for b in backup_blocks:
        key = normalize_location_key(b)
        if is_blocking_location(b) and key in proposed_map:
            if not is_blocking_location(proposed_map[key]):
                weakened.append(key)

    if weakened:
        return {
            "status": "fail",
            "details": f"Blocking rules weakened: {sorted(weakened)}"
        }

    return {"status": "pass", "details": "No rules removed"}


def check_invariant_2(proposed_text):
    """No regex negation in location blocks; blocking locations must be clean."""
    blocks = extract_location_blocks(proposed_text)
    violations = []

    for b in blocks:
        pat = b["pattern"]
        body = b["body"]

        # Check for negated regex modifiers
        if "!~" in pat or "!~*" in pat:
            violations.append(f"Negated regex in location: {pat}")

        # Check for negative lookahead in pattern
        if "(?!" in pat:
            violations.append(f"Negative lookahead in location: {pat}")

        # If it's a blocking location, check for forbidden directives
        if is_blocking_location(b):
            if re.search(r'\bproxy_pass\b', body):
                violations.append(
                    f"proxy_pass in blocking location: {pat}"
                )
            if re.search(r'\breturn\s+200\b', body):
                violations.append(
                    f"return 200 in blocking location: {pat}"
                )
            if re.search(r'\brewrite\b', body):
                violations.append(
                    f"rewrite in blocking location: {pat}"
                )

    count = len(violations)
    if count > 0:
        return {
            "status": "fail",
            "details": f"{count} violation(s) found: {violations}"
        }
    return {"status": "pass", "details": "0 violations found"}


def check_invariant_3(proposed_text, backup_text):
    """Security headers must be present and unchanged."""
    if backup_text is None:
        # No backup: just check presence
        proposed_headers = extract_headers(proposed_text)
        missing = [h for h in REQUIRED_HEADERS if h not in proposed_headers]
        if missing:
            return {
                "status": "fail",
                "details": f"Missing security headers: {missing}"
            }
        return {
            "status": "pass",
            "details": f"All {len(REQUIRED_HEADERS)} headers present"
        }

    backup_headers = extract_headers(backup_text)
    proposed_headers = extract_headers(proposed_text)

    missing = [h for h in REQUIRED_HEADERS if h not in proposed_headers]
    if missing:
        return {
            "status": "fail",
            "details": f"Missing security headers: {missing}"
        }

    changed = []
    for h in REQUIRED_HEADERS:
        if h in backup_headers and h in proposed_headers:
            if backup_headers[h] != proposed_headers[h]:
                changed.append(
                    f"{h}: '{backup_headers[h]}' -> '{proposed_headers[h]}'"
                )

    if changed:
        return {
            "status": "fail",
            "details": f"Headers changed: {changed}"
        }

    return {
        "status": "pass",
        "details": f"All {len(REQUIRED_HEADERS)} headers present and unchanged"
    }


def check_invariant_4(proposed_text):
    """TLS floor: no TLSv1 or TLSv1.1."""
    protocols = extract_ssl_protocols(proposed_text)
    if not protocols:
        return {"status": "pass", "details": "No ssl_protocols directive found"}

    bad = set()
    for p in protocols:
        # Match TLSv1 and TLSv1.1 but not TLSv1.2 or TLSv1.3
        if p == "TLSv1" or p == "TLSv1.1":
            bad.add(p)

    if bad:
        return {
            "status": "fail",
            "details": f"Insecure TLS protocols found: {sorted(bad)}"
        }

    return {
        "status": "pass",
        "details": f"{' '.join(sorted(protocols))} only"
    }


def check_invariant_9(proposed_path, run_test):
    """nginx -t readiness check."""
    if not run_test:
        return {"status": "skip", "details": "Not requested"}

    try:
        result = subprocess.run(
            ["sudo", "nginx", "-t", "-c", os.path.abspath(proposed_path)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return {"status": "pass", "details": "nginx -t passed"}
        else:
            err = (result.stderr or result.stdout or "").strip()
            return {"status": "fail", "details": f"nginx -t failed: {err}"}
    except FileNotFoundError:
        return {"status": "fail", "details": "nginx binary not found"}
    except subprocess.TimeoutExpired:
        return {"status": "fail", "details": "nginx -t timed out"}
    except Exception as e:
        return {"status": "fail", "details": f"nginx -t error: {e}"}


def check_invariant_10(backup_path, require_backup):
    """Backup existence verification."""
    if not require_backup:
        return {"status": "skip", "details": "Not required"}

    if backup_path is None:
        return {"status": "fail", "details": "No backup path provided"}

    if os.path.isfile(backup_path):
        return {"status": "pass", "details": f"Backup exists: {backup_path}"}
    else:
        return {
            "status": "fail",
            "details": f"Backup not found: {backup_path}"
        }


def check_invariant_11(git_command):
    """No destructive git commands."""
    if git_command is None:
        return {"status": "skip", "details": "No command checked"}

    for pat in DESTRUCTIVE_GIT_PATTERNS:
        if re.search(pat, git_command):
            return {
                "status": "fail",
                "details": f"Destructive git command detected: {git_command}"
            }

    return {
        "status": "pass",
        "details": f"Command is safe: {git_command}"
    }


# Scope levels ordered from narrowest to broadest
SCOPE_LEVELS = [
    "exact-location",
    "server-block",
    "include-file",
    "vhost-group",
    "global-http",
    "unknown-shared",
]


def check_invariant_17(proposed_text, backup_text):
    """Scope / blast radius analysis."""
    if backup_text is None:
        # No backup to diff against; analyze proposed config scope
        blast = analyze_scope(proposed_text)
        result = {
            "status": "pass",
            "details": f"Blast radius: {blast}",
            "blast_radius": blast,
        }
        if SCOPE_LEVELS.index(blast) > SCOPE_LEVELS.index("server-block"):
            result["status"] = "warn"
            result["details"] = (
                f"Blast radius '{blast}' is broader than server-block"
            )
        return result

    # Compare proposed vs backup
    if proposed_text == backup_text:
        return {
            "status": "pass",
            "details": "Blast radius: exact-location",
            "blast_radius": "exact-location",
        }

    blast = determine_change_scope(proposed_text, backup_text)
    result = {
        "status": "pass",
        "details": f"Blast radius: {blast}",
        "blast_radius": blast,
    }
    if SCOPE_LEVELS.index(blast) > SCOPE_LEVELS.index("server-block"):
        result["status"] = "warn"
        result["details"] = (
            f"Blast radius '{blast}' is broader than server-block"
        )
    return result


def analyze_scope(text):
    """Determine scope of a config file."""
    # If it contains 'http {' it's global
    if re.search(r'\bhttp\s*\{', text):
        return "global-http"
    # If it contains 'server {' it's server-block level
    if re.search(r'\bserver\s*\{', text):
        return "server-block"
    # If it only has location blocks or directives, it's an include file
    if re.search(r'\blocation\b', text):
        return "include-file"
    # Bare directives
    return "include-file"


def determine_change_scope(proposed, backup):
    """Determine the scope of changes between proposed and backup."""
    proposed_lines = set(proposed.strip().splitlines())
    backup_lines = set(backup.strip().splitlines())

    added = proposed_lines - backup_lines
    removed = backup_lines - proposed_lines

    if not added and not removed:
        return "exact-location"

    all_changes = "\n".join(added | removed)

    # Check if changes are within a single location block
    loc_changes = re.findall(r'\blocation\b', all_changes)
    header_changes = re.findall(r'\badd_header\b', all_changes)
    ssl_changes = re.findall(r'\bssl_', all_changes)

    # If changes touch ssl or global directives, it's broader
    if ssl_changes:
        return "server-block"

    # If only location blocks changed
    if loc_changes and not header_changes and not ssl_changes:
        return "exact-location"

    # If headers changed, it's at least include-file scope
    if header_changes:
        return "include-file"

    return "include-file"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    proposed_text = read_file(args.proposed)
    backup_text = None
    if args.backup:
        try:
            backup_text = read_file(args.backup)
        except FileNotFoundError:
            if args.require_backup:
                pass  # Will be caught by invariant 10
            backup_text = None

    results = {}
    warnings = []
    errors = []

    # Invariant 1: Additive-only
    results["1_additive_only"] = check_invariant_1(proposed_text, backup_text)

    # Invariant 2: No regex negation
    results["2_no_regex_negation"] = check_invariant_2(proposed_text)

    # Invariant 3: Security headers immutable
    results["3_headers_immutable"] = check_invariant_3(
        proposed_text, backup_text
    )

    # Invariant 4: TLS floor
    results["4_tls_floor"] = check_invariant_4(proposed_text)

    # Invariant 9: nginx -t
    results["9_nginx_test"] = check_invariant_9(
        args.proposed, args.run_nginx_test
    )

    # Invariant 10: Backup exists
    results["10_backup_exists"] = check_invariant_10(
        args.backup, args.require_backup
    )

    # Invariant 11: No destructive git
    results["11_no_destructive_git"] = check_invariant_11(
        args.check_git_command
    )

    # Invariant 17: Scope check
    results["17_scope_check"] = check_invariant_17(
        proposed_text, backup_text
    )

    # Collect warnings and errors
    for key, val in results.items():
        if val["status"] == "fail":
            errors.append(f"Invariant {key}: {val['details']}")
        elif val["status"] == "warn":
            warnings.append(f"Invariant {key}: {val['details']}")

    # Determine overall status
    if errors:
        overall = "fail"
    elif warnings:
        overall = "warn"
    else:
        overall = "pass"

    output = {
        "overall": overall,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "proposed_path": os.path.abspath(args.proposed),
        "backup_path": os.path.abspath(args.backup) if args.backup else None,
        "invariants": results,
        "warnings": warnings,
        "errors": errors,
    }

    json.dump(output, sys.stdout, indent=2)
    print()  # trailing newline

    sys.exit(0 if overall == "pass" else 1)


if __name__ == "__main__":
    main()
