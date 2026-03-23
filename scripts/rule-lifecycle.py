#!/usr/bin/env python3
"""
Rule Lifecycle Manager — Finding ID generation, tracing, and status tracking.

Stdlib-only Python. Manages the full lifecycle of nginx hardening findings:
  discovered → staged → deployed → promoted

Usage:
  python3 scripts/rule-lifecycle.py generate-id --source AUDIT --category HEADERS [--base-dir .]
  python3 scripts/rule-lifecycle.py trace       --id NH-AUDIT-HEADERS-0001 [--base-dir .]
  python3 scripts/rule-lifecycle.py status      --id NH-AUDIT-HEADERS-0001 [--base-dir .]
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

VALID_SOURCES = {"AUDIT", "LOG", "IOC"}

VALID_CATEGORIES = {
    "HEADERS", "TLS", "DOTFILE", "WORDPRESS", "ACTUATOR", "SWAGGER",
    "PHP_DEBUG", "CONTAINER", "JS_DEVTOOLS", "ATLASSIAN", "EXCHANGE",
    "GRAPHQL", "ADMIN_PANEL", "CVE_PROBE", "WP_USER_ENUM", "PATH_TRAVERSAL",
    "PHISHING", "BACKUP_DIR", "HNAP", "VPN_GATEWAY", "STRUTS", "JNDI",
    "SSH_KEY", "IOT_DEVICE", "PACKAGE_FILE", "APP_SETTINGS", "XDEBUG",
    "ENTERPRISE", "INFLUXDB", "NETWORK_INFRA", "LOTUS", "LOGIN_DISCOVERY",
    "MISC_EXPLOIT", "SCANNER", "RATE_CONTROL",
}

FINDING_ID_PATTERN = re.compile(r"NH-([A-Z]+)-([A-Z_]+)-(\d{4})")

SEARCH_EXTENSIONS = {".md", ".json"}

# Lifecycle stage keywords detected in file content
LIFECYCLE_KEYWORDS = {
    "discovered": [
        "finding_id:", "discovered", "identified", "detected", "found",
    ],
    "staged": [
        "staged", "staging", "proposed", "draft rule", "rule draft",
        "proposed-rules", "proposed_rules",
    ],
    "deployed": [
        "deployed", "applied", "activated", "live", "production",
        "deploy", "deployment",
    ],
    "promoted": [
        "promoted", "permanent", "baseline", "canonical",
        "security-hardening.conf",
    ],
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def scan_for_ids(base_dir: str, source: str, category: str) -> list:
    """Scan outputs/ and learnings/ for existing finding IDs matching source+category."""
    prefix = f"NH-{source}-{category}-"
    found_ids = []
    search_dirs = [
        os.path.join(base_dir, "outputs"),
        os.path.join(base_dir, "learnings"),
        os.path.join(base_dir, "tests"),
    ]
    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            continue
        for root, _dirs, files in os.walk(search_dir):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in SEARCH_EXTENSIONS:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="replace") as f:
                        content = f.read()
                except OSError:
                    continue
                for m in FINDING_ID_PATTERN.finditer(content):
                    if m.group(1) == source and m.group(2) == category:
                        found_ids.append(int(m.group(3)))
    return found_ids


def search_references(base_dir: str, finding_id: str) -> list:
    """Search outputs/, learnings/, and CHANGELOG.md for references to a finding ID."""
    refs = []
    search_dirs = [
        os.path.join(base_dir, "outputs"),
        os.path.join(base_dir, "learnings"),
    ]
    # Also search CHANGELOG.md at root
    changelog = os.path.join(base_dir, "CHANGELOG.md")
    if os.path.isfile(changelog):
        search_dirs.append(changelog)
    # Also search learnings/CHANGELOG.md
    learnings_changelog = os.path.join(base_dir, "learnings", "CHANGELOG.md")
    # Already covered by learnings/ walk

    for search_target in search_dirs:
        if os.path.isfile(search_target):
            _search_file(search_target, finding_id, base_dir, refs)
        elif os.path.isdir(search_target):
            for root, _dirs, files in os.walk(search_target):
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in SEARCH_EXTENSIONS:
                        continue
                    fpath = os.path.join(root, fname)
                    _search_file(fpath, finding_id, base_dir, refs)
    return refs


def _search_file(fpath: str, finding_id: str, base_dir: str, refs: list):
    """Search a single file for finding_id references."""
    try:
        with open(fpath, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return
    for i, line in enumerate(lines, 1):
        if finding_id in line:
            # Use path relative to base_dir if possible
            try:
                rel = os.path.relpath(fpath, base_dir)
            except ValueError:
                rel = fpath
            refs.append({
                "file": rel,
                "line": i,
                "context": line.strip()[:200],
            })


def determine_lifecycle(base_dir: str, finding_id: str, references: list) -> dict:
    """Determine lifecycle stage from references and their content."""
    stages = {
        "discovered": None,
        "staged": None,
        "deployed": None,
        "promoted": None,
    }

    # Collect all content lines that reference this finding
    all_contexts = []
    for ref in references:
        all_contexts.append(ref.get("context", "").lower())
        # Also read surrounding content from file for better detection
        fpath = os.path.join(base_dir, ref["file"])
        if os.path.isfile(fpath):
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read().lower()
                all_contexts.append(content)
            except OSError:
                pass

    combined = " ".join(all_contexts)

    # Check stages in order — finding existence implies discovered
    if references:
        stages["discovered"] = _extract_date_from_refs(references)

    for stage in ["staged", "deployed", "promoted"]:
        for keyword in LIFECYCLE_KEYWORDS[stage]:
            if keyword.lower() in combined:
                stages[stage] = _extract_date_from_refs(references)
                break

    # Determine current lifecycle stage
    lifecycle = "unknown"
    for stage in ["promoted", "deployed", "staged", "discovered"]:
        if stages[stage] is not None:
            lifecycle = stage
            break

    return {
        "finding_id": finding_id,
        "lifecycle": lifecycle,
        "discovered": stages["discovered"],
        "staged": stages["staged"],
        "deployed": stages["deployed"],
        "promoted": stages["promoted"],
    }


def _extract_date_from_refs(references: list) -> str:
    """Extract a date from references (best effort from context or file paths)."""
    for ref in references:
        # Try to find a date in the file path
        m = re.search(r"(\d{4}-\d{2}-\d{2})", ref.get("file", ""))
        if m:
            return m.group(1)
        # Try context
        m = re.search(r"(\d{4}-\d{2}-\d{2})", ref.get("context", ""))
        if m:
            return m.group(1)
    return "unknown"


# ── Subcommands ──────────────────────────────────────────────────────────────

def cmd_generate_id(args):
    """Generate the next collision-free finding ID."""
    source = args.source.upper()
    category = args.category.upper()

    if source not in VALID_SOURCES:
        print(f"Error: invalid source '{source}'. Must be one of: {', '.join(sorted(VALID_SOURCES))}",
              file=sys.stderr)
        sys.exit(1)
    if category not in VALID_CATEGORIES:
        print(f"Error: invalid category '{category}'. Must be one of: {', '.join(sorted(VALID_CATEGORIES))}",
              file=sys.stderr)
        sys.exit(1)

    base_dir = os.path.abspath(args.base_dir)
    existing = scan_for_ids(base_dir, source, category)
    next_num = max(existing, default=0) + 1
    finding_id = f"NH-{source}-{category}-{next_num:04d}"
    print(finding_id)


def cmd_trace(args):
    """Find all references to a finding ID."""
    finding_id = args.id.upper()
    if not FINDING_ID_PATTERN.fullmatch(finding_id):
        print(f"Error: invalid finding ID format '{finding_id}'. Expected NH-SOURCE-CATEGORY-NNNN",
              file=sys.stderr)
        sys.exit(1)

    base_dir = os.path.abspath(args.base_dir)
    refs = search_references(base_dir, finding_id)

    result = {
        "finding_id": finding_id,
        "references": refs,
        "total_references": len(refs),
    }
    print(json.dumps(result, indent=2))


def cmd_status(args):
    """Show lifecycle status for a finding ID."""
    finding_id = args.id.upper()
    if not FINDING_ID_PATTERN.fullmatch(finding_id):
        print(f"Error: invalid finding ID format '{finding_id}'. Expected NH-SOURCE-CATEGORY-NNNN",
              file=sys.stderr)
        sys.exit(1)

    base_dir = os.path.abspath(args.base_dir)
    refs = search_references(base_dir, finding_id)
    status = determine_lifecycle(base_dir, finding_id, refs)
    print(json.dumps(status, indent=2))


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Rule Lifecycle Manager — finding ID generation, tracing, status"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # generate-id
    p_gen = sub.add_parser("generate-id", help="Generate next finding ID")
    p_gen.add_argument("--source", required=True, help="Source: AUDIT, LOG, IOC")
    p_gen.add_argument("--category", required=True, help="Category (e.g., HEADERS, TLS)")
    p_gen.add_argument("--base-dir", default=".", help="Base directory of the project")

    # trace
    p_trace = sub.add_parser("trace", help="Find all references to a finding ID")
    p_trace.add_argument("--id", required=True, help="Finding ID (e.g., NH-AUDIT-HEADERS-0001)")
    p_trace.add_argument("--base-dir", default=".", help="Base directory of the project")

    # status
    p_status = sub.add_parser("status", help="Show lifecycle status of a finding")
    p_status.add_argument("--id", required=True, help="Finding ID (e.g., NH-AUDIT-HEADERS-0001)")
    p_status.add_argument("--base-dir", default=".", help="Base directory of the project")

    args = parser.parse_args()

    dispatch = {
        "generate-id": cmd_generate_id,
        "trace": cmd_trace,
        "status": cmd_status,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
