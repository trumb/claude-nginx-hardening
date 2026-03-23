#!/usr/bin/env python3
"""
Rule Aging Analyzer — staleness detection for nginx blocking rules.

Stdlib-only Python. Identifies blocking rules that haven't matched any
traffic recently, helping operators review and maintain their rulesets.

INVARIANT 1: This tool NEVER recommends "remove". Only "keep", "review",
or "monitor". Removal is always a human decision.

Usage:
  python3 scripts/rule-aging.py scan   --config PATH --log-data PATH [--stale-days 90]
  python3 scripts/rule-aging.py report --config PATH --log-data PATH [--stale-days 90]
  python3 scripts/rule-aging.py tag    --config PATH --log-data PATH
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ── Constants ────────────────────────────────────────────────────────────────

# Categories commonly targeted — even with 0 hits, recommend "review" not removal
COMMONLY_ATTACKED_CATEGORIES = {
    "dotfile", "wordpress", "php", "env_variants", "actuator",
    "swagger", "admin_panel", "source_map", "debug_tools",
    "script_ext", "path_traversal", "jndi", "exchange",
}

# Map config comment categories to log data path_class values
# The config uses comment-based category names; log data uses path_class
CATEGORY_TO_PATH_CLASS = {
    "dotfile": {"dotfile"},
    "env_variants": {"dotfile"},  # .env is classified as dotfile in sanitizer
    "source_map": {"source_map"},
    "php": {"script_ext"},
    "wordpress": {"wordpress"},
    "actuator": {"actuator"},
    "swagger": {"swagger"},
    "debug_tools": {"php_debug", "admin_panel"},
    "admin_panel": {"admin_panel"},
}


# ── Config Parser ────────────────────────────────────────────────────────────

def parse_config_rules(config_path: str) -> List[Dict[str, Any]]:
    """
    Parse nginx config for location blocks with 'return 404' or 'deny all'.
    Returns a list of rule dicts with category, pattern, line_number, action.
    """
    rules = []
    with open(config_path, "r") as f:
        lines = f.readlines()

    current_comment = None
    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Track comment lines as category hints
        if line.startswith("#"):
            # Extract category from comments like "# Block dotfiles"
            m = re.match(r"#\s*(?:aging:.*|Block\s+(.+)|(.+))$", line)
            if m:
                cat = m.group(1) or m.group(2)
                if cat:
                    current_comment = cat.strip().lower()
            i += 1
            continue

        # Match location blocks
        loc_match = re.match(r"location\s+(~\*?|=|)\s*(.+?)\s*\{", line)
        if loc_match:
            modifier = loc_match.group(1)
            pattern = loc_match.group(2)
            loc_line = i + 1  # 1-indexed

            # Look ahead for the action (return 404 or deny all)
            action = None
            j = i + 1
            while j < len(lines) and "}" not in lines[j]:
                action_line = lines[j].strip()
                if "return 404" in action_line or "return 403" in action_line:
                    action = "return_404"
                    break
                if "deny all" in action_line:
                    action = "deny_all"
                    break
                j += 1

            if action:
                category = _infer_category(current_comment, pattern)
                rules.append({
                    "category": category,
                    "pattern": pattern,
                    "line_number": loc_line,
                    "action": action,
                    "modifier": modifier,
                    "comment": current_comment,
                })

            current_comment = None
        else:
            # Reset comment if we hit a non-comment, non-location line
            if line and not line.startswith("#"):
                current_comment = None

        i += 1

    return rules


def _infer_category(comment: Optional[str], pattern: str) -> str:
    """Infer a rule category from comment text and pattern."""
    if comment:
        comment_lower = comment.lower()
        # Direct mapping from comment
        category_keywords = {
            "dotfile": "dotfile",
            "env": "env_variants",
            "source map": "source_map",
            "php": "php",
            "wordpress": "wordpress",
            "wp-": "wordpress",
            "actuator": "actuator",
            "spring": "actuator",
            "swagger": "swagger",
            "api-docs": "swagger",
            "debug": "debug_tools",
            "admin": "admin_panel",
            "lotus": "lotus",
            "atlassian": "atlassian",
            "exchange": "exchange",
            "graphql": "graphql",
            "container": "container",
            "k8s": "container",
            "vite": "js_devtools",
            "webpack": "js_devtools",
            "cve": "cve_probe",
        }
        for keyword, cat in category_keywords.items():
            if keyword in comment_lower:
                return cat

    # Fallback: infer from pattern
    pattern_lower = pattern.lower()
    if r"\." in pattern and "env" in pattern_lower:
        return "env_variants"
    if "/\\." in pattern or r"/\." in pattern:
        return "dotfile"
    if ".map$" in pattern:
        return "source_map"
    if ".php" in pattern_lower:
        return "php"
    if "wp-" in pattern_lower:
        return "wordpress"
    if "actuator" in pattern_lower:
        return "actuator"
    if "swagger" in pattern_lower or "api-docs" in pattern_lower:
        return "swagger"
    if "debug" in pattern_lower or "trace" in pattern_lower:
        return "debug_tools"
    if "admin" in pattern_lower or "phpmyadmin" in pattern_lower:
        return "admin_panel"

    return "uncategorized"


# ── Log Data Parser ──────────────────────────────────────────────────────────

def parse_log_data(log_data_path: str) -> Dict[str, int]:
    """
    Parse sanitized log data (Layer 2 output) and aggregate hits by path_class.
    Returns {path_class: total_hit_count}.
    """
    with open(log_data_path, "r") as f:
        data = json.load(f)

    hits: Dict[str, int] = {}

    # Handle both raw event lists and schema-wrapped output
    events = data if isinstance(data, list) else data.get("events", [])

    for event in events:
        path_class = event.get("path_class", "unknown")
        count = int(event.get("count", 1))
        hits[path_class] = hits.get(path_class, 0) + count

    return hits


# ── Cross-reference Engine ───────────────────────────────────────────────────

def cross_reference(
    rules: List[Dict[str, Any]],
    log_hits: Dict[str, int],
    stale_days: int,
) -> List[Dict[str, Any]]:
    """
    Cross-reference config rules with log hit data.
    Assigns recommendations based on hit counts.

    INVARIANT 1: Never recommends "remove". Only "keep", "review", or "monitor".
    """
    results = []

    for rule in rules:
        category = rule["category"]

        # Find matching path_class(es) for this config category
        path_classes = CATEGORY_TO_PATH_CLASS.get(category, {category})
        total_hits = sum(log_hits.get(pc, 0) for pc in path_classes)

        # Determine recommendation — NEVER "remove"
        if total_hits > 3:
            recommendation = "keep"
            reason = f"Active: {total_hits} hits in period"
        elif total_hits > 0:
            recommendation = "monitor"
            reason = f"Low activity: {total_hits} hits in period — may be declining"
        elif category in COMMONLY_ATTACKED_CATEGORIES:
            recommendation = "review"
            reason = "No hits in analysis period (commonly-attacked category)"
        else:
            recommendation = "review"
            reason = "No hits in analysis period"

        results.append({
            "category": category,
            "pattern": rule["pattern"],
            "line_number": rule["line_number"],
            "hits_in_period": total_hits,
            "recommendation": recommendation,
            "reason": reason,
        })

    return results


# ── Subcommands ──────────────────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> int:
    """Find stale rules and print summary."""
    rules = parse_config_rules(args.config)
    log_hits = parse_log_data(args.log_data)
    results = cross_reference(rules, log_hits, args.stale_days)

    stale = [r for r in results if r["recommendation"] == "review"]
    monitor = [r for r in results if r["recommendation"] == "monitor"]
    active = [r for r in results if r["recommendation"] == "keep"]

    print(f"Scanned {len(rules)} rules against log data", file=sys.stderr)
    print(f"  Active (keep):  {len(active)}", file=sys.stderr)
    print(f"  Low (monitor):  {len(monitor)}", file=sys.stderr)
    print(f"  Stale (review): {len(stale)}", file=sys.stderr)

    if stale:
        print("\nStale rules (0 hits):", file=sys.stderr)
        for r in stale:
            print(f"  Line {r['line_number']}: [{r['category']}] {r['pattern']}", file=sys.stderr)

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate JSON staleness report."""
    rules = parse_config_rules(args.config)
    log_hits = parse_log_data(args.log_data)
    results = cross_reference(rules, log_hits, args.stale_days)

    active = len([r for r in results if r["recommendation"] == "keep"])
    stale = len([r for r in results if r["recommendation"] == "review"])
    monitor = len([r for r in results if r["recommendation"] == "monitor"])

    report = {
        "total_rules": len(results),
        "active_rules": active,
        "stale_rules": stale,
        "monitor_rules": monitor,
        "unknown_rules": 0,
        "stale_threshold_days": args.stale_days,
        "analyzed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rules": results,
    }

    json.dump(report, sys.stdout, indent=2)
    print()  # trailing newline
    return 0


def cmd_tag(args: argparse.Namespace) -> int:
    """Add aging metadata as comments above each rule in the config file."""
    rules = parse_config_rules(args.config)
    log_hits = parse_log_data(args.log_data)
    results = cross_reference(rules, log_hits, args.stale_days)

    # Build a map of line_number -> aging info
    aging_map: Dict[int, Dict[str, Any]] = {}
    for r in results:
        aging_map[r["line_number"]] = r

    with open(args.config, "r") as f:
        lines = f.readlines()

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    output_lines = []
    i = 0

    while i < len(lines):
        line = lines[i]
        line_num = i + 1  # 1-indexed

        # Check if this line is a location block with aging data
        if line_num in aging_map:
            info = aging_map[line_num]
            aging_comment = f"# aging: hits={info['hits_in_period']}, last-analyzed={today}\n"

            # Check if previous line is already an aging comment — replace it
            if output_lines and output_lines[-1].strip().startswith("# aging:"):
                output_lines[-1] = aging_comment
            else:
                output_lines.append(aging_comment)

        output_lines.append(line)
        i += 1

    with open(args.config, "w") as f:
        f.writelines(output_lines)

    tagged = len(aging_map)
    print(f"Tagged {tagged} rules with aging metadata in {args.config}", file=sys.stderr)
    return 0


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rule Aging Analyzer — staleness detection for nginx blocking rules"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Common arguments
    def add_common_args(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--config", required=True, help="Path to nginx config file")
        sp.add_argument("--log-data", required=True, help="Path to sanitized log data (Layer 2 JSON)")
        sp.add_argument("--stale-days", type=int, default=90,
                        help="Days without hits before a rule is considered stale (default: 90)")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Find stale rules")
    add_common_args(scan_parser)

    # report
    report_parser = subparsers.add_parser("report", help="Generate JSON staleness report")
    add_common_args(report_parser)

    # tag
    tag_parser = subparsers.add_parser("tag", help="Add aging metadata as comments")
    add_common_args(tag_parser)

    args = parser.parse_args()

    try:
        if args.command == "scan":
            return cmd_scan(args)
        elif args.command == "report":
            return cmd_report(args)
        elif args.command == "tag":
            return cmd_tag(args)
        else:
            parser.print_help()
            return 1
    except FileNotFoundError as e:
        print(f"ERROR: File not found: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
