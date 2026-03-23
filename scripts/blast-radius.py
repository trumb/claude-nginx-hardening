#!/usr/bin/env python3
"""
Blast-Radius Analyzer — Deterministic Change Impact Scoring

Analyzes proposed nginx config changes and labels each with a blast-radius
scope so operators understand how broadly a change affects infrastructure.

Labels:
  exact-location   — Affects one location block only
  server-block     — Affects one virtual host
  include-file     — Affects all servers that include this file
  vhost-group      — Affects multiple related vhosts
  global-http      — http-level directive
  unknown-shared   — Cannot determine scope

Stdlib only. No LLM involvement. Deterministic.
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


# ── Constants ────────────────────────────────────────────────────────────────

BLAST_RADIUS_ORDER = [
    "exact-location",
    "server-block",
    "include-file",
    "vhost-group",
    "global-http",
    "unknown-shared",
]

# Patterns for detecting nginx directive types in proposed rules
LOCATION_BLOCK_RE = re.compile(
    r"^\s*location\s+[^{]*\{", re.MULTILINE
)
SERVER_BLOCK_RE = re.compile(
    r"^\s*server\s*\{", re.MULTILINE
)
HTTP_BLOCK_RE = re.compile(
    r"^\s*http\s*\{", re.MULTILINE
)
UPSTREAM_BLOCK_RE = re.compile(
    r"^\s*upstream\s+\S+\s*\{", re.MULTILINE
)

# Directives that are server-level (not inside location)
SERVER_LEVEL_DIRECTIVES = {
    "listen", "server_name", "root", "index", "ssl_certificate",
    "ssl_certificate_key", "ssl_protocols", "ssl_ciphers",
    "ssl_prefer_server_ciphers", "ssl_session_cache",
    "ssl_session_timeout", "ssl_stapling", "ssl_stapling_verify",
    "client_max_body_size", "access_log", "error_log",
    "add_header", "proxy_set_header", "resolver",
}

# Directives that are http-level
HTTP_LEVEL_DIRECTIVES = {
    "sendfile", "tcp_nopush", "tcp_nodelay", "keepalive_timeout",
    "types_hash_max_size", "server_tokens", "gzip", "gzip_types",
    "gzip_vary", "gzip_proxied", "gzip_comp_level",
    "client_max_body_size", "log_format", "include",
    "proxy_cache_path", "proxy_temp_path",
}

INCLUDE_RE = re.compile(r"^\s*include\s+([^;]+);", re.MULTILINE)


# ── Parsing ──────────────────────────────────────────────────────────────────

def classify_change(content: str) -> str:
    """Classify the type of change based on content structure."""
    stripped = strip_comments(content)

    if LOCATION_BLOCK_RE.search(stripped):
        return "add_location_block"
    if SERVER_BLOCK_RE.search(stripped):
        return "add_server_block"
    if HTTP_BLOCK_RE.search(stripped):
        return "modify_http_block"
    if UPSTREAM_BLOCK_RE.search(stripped):
        return "add_upstream_block"

    # Check for bare directives (server-level or http-level)
    lines = [l.strip() for l in stripped.splitlines() if l.strip()]
    for line in lines:
        directive = line.split()[0] if line.split() else ""
        directive = directive.rstrip(";")
        if directive in HTTP_LEVEL_DIRECTIVES:
            return "modify_http_directive"
        if directive in SERVER_LEVEL_DIRECTIVES:
            return "modify_server_directive"

    # If it has any content, treat as add_location_block (most common case
    # for security rules like "location ~* ... { return 404; }")
    if lines:
        return "add_location_block"

    return "unknown"


def strip_comments(content: str) -> str:
    """Remove nginx comments from content."""
    lines = []
    for line in content.splitlines():
        # Remove inline comments (but not inside quoted strings — simplified)
        idx = line.find("#")
        if idx >= 0:
            lines.append(line[:idx])
        else:
            lines.append(line)
    return "\n".join(lines)


def extract_rule_summary(content: str) -> str:
    """Extract a short summary of the rule for display."""
    stripped = strip_comments(content).strip()
    # Collapse whitespace
    summary = re.sub(r"\s+", " ", stripped)
    if len(summary) > 120:
        summary = summary[:117] + "..."
    return summary


def resolve_target_file(target_file: Optional[str], proposed_content: str,
                        nginx_config_dir: str) -> Optional[str]:
    """Resolve the target file path. If not specified, try to infer."""
    if target_file:
        return os.path.abspath(target_file)
    # Cannot infer without explicit target
    return None


# ── Include Scanning ─────────────────────────────────────────────────────────

def scan_includes(nginx_config_dir: str) -> Dict[str, List[str]]:
    """
    Scan all nginx configs and build a map of:
      included_file -> [list of files that include it]
    """
    include_map: Dict[str, List[str]] = {}
    config_dir = os.path.abspath(nginx_config_dir)

    for dirpath, _dirnames, filenames in os.walk(config_dir):
        for fname in filenames:
            if not fname.endswith(".conf") and fname != "nginx.conf":
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "r") as f:
                    content = f.read()
            except (IOError, OSError):
                continue

            for match in INCLUDE_RE.finditer(content):
                include_path = match.group(1).strip().strip("'\"")
                # Resolve relative includes against config dir
                if not os.path.isabs(include_path):
                    include_path = os.path.join(config_dir, include_path)
                # Expand globs manually (stdlib only)
                resolved = _expand_include_path(include_path)
                for rpath in resolved:
                    rpath = os.path.abspath(rpath)
                    if rpath not in include_map:
                        include_map[rpath] = []
                    if fpath not in include_map[rpath]:
                        include_map[rpath].append(fpath)

    return include_map


def _expand_include_path(path: str) -> List[str]:
    """Expand an include path, handling wildcards with glob."""
    import glob as globmod
    if "*" in path or "?" in path:
        return globmod.glob(path)
    return [path]


def count_server_blocks_in_file(fpath: str) -> int:
    """Count the number of server { } blocks in a file."""
    try:
        with open(fpath, "r") as f:
            content = f.read()
    except (IOError, OSError):
        return 0

    count = 0
    depth = 0
    in_server = False
    stripped = strip_comments(content)

    i = 0
    while i < len(stripped):
        # Check for 'server' keyword followed by '{'
        if stripped[i:i+6] == "server" and not in_server:
            rest = stripped[i+6:].lstrip()
            if rest.startswith("{"):
                count += 1
                in_server = True
                depth = 0
                i += 6
                continue
        if stripped[i] == "{":
            depth += 1
        elif stripped[i] == "}":
            depth -= 1
            if in_server and depth <= 0:
                in_server = False
        i += 1

    return max(count, 0)


def is_inside_location_block(content: str) -> bool:
    """Check if the proposed content is a location block (not bare directives)."""
    stripped = strip_comments(content).strip()
    return bool(LOCATION_BLOCK_RE.search(stripped))


def is_inside_server_block(content: str) -> bool:
    """Check if the proposed content is a server block."""
    stripped = strip_comments(content).strip()
    return bool(SERVER_BLOCK_RE.search(stripped))


def is_http_level(content: str) -> bool:
    """Check if the proposed content contains http-level directives."""
    stripped = strip_comments(content).strip()
    if HTTP_BLOCK_RE.search(stripped):
        return True
    lines = [l.strip() for l in stripped.splitlines() if l.strip()]
    for line in lines:
        directive = line.split()[0].rstrip(";") if line.split() else ""
        if directive in HTTP_LEVEL_DIRECTIVES and directive != "include":
            return True
    return False


# ── Blast Radius Determination ───────────────────────────────────────────────

def determine_blast_radius(
    content: str,
    target_file: Optional[str],
    include_map: Dict[str, List[str]],
    change_type: str,
) -> Tuple[str, int, List[str], str]:
    """
    Determine the blast radius of a proposed change.

    Returns: (blast_radius, affected_server_blocks, affected_files, details)
    """
    # If no target file, we can't determine scope
    if not target_file:
        return ("unknown-shared", 0, [], "No target file specified; cannot determine scope")

    target_abs = os.path.abspath(target_file)

    # Check if target is an http-level config (e.g., nginx.conf)
    target_basename = os.path.basename(target_abs)
    if target_basename == "nginx.conf" or is_http_level(content):
        return (
            "global-http",
            0,
            [target_abs],
            "Change targets http-level configuration (affects all virtual hosts)",
        )

    # Check if target file is included by other files
    includers = include_map.get(target_abs, [])

    # Filter out top-level includes (nginx.conf including sites-enabled/*).
    # Being included by nginx.conf means the file IS a site config, not a
    # shared snippet. Only count includers that are themselves site configs
    # (i.e., files that contain server blocks or include other snippets).
    site_includers = [
        f for f in includers
        if os.path.basename(f) != "nginx.conf"
    ]

    if change_type == "add_upstream_block":
        # Upstream blocks can affect multiple vhosts
        if len(site_includers) > 1:
            total_server_blocks = sum(
                count_server_blocks_in_file(f) for f in site_includers
            )
            return (
                "vhost-group",
                total_server_blocks,
                site_includers,
                f"Upstream block in shared file included by {len(site_includers)} configs "
                f"({total_server_blocks} server blocks)",
            )
        elif len(site_includers) == 1:
            sb = count_server_blocks_in_file(site_includers[0])
            return (
                "server-block",
                sb,
                site_includers,
                f"Upstream block in file included by 1 config ({sb} server blocks)",
            )

    if site_includers:
        # File is included by site configs — it's a shared include
        total_server_blocks = sum(
            count_server_blocks_in_file(f) for f in site_includers
        )
        affected_files = sorted(set(site_includers))

        if is_inside_location_block(content):
            # Location block in a shared include
            return (
                "include-file",
                total_server_blocks,
                affected_files,
                f"Shared snippet included by {total_server_blocks} server blocks "
                f"across {len(affected_files)} site configs",
            )
        else:
            # Server-level directive in a shared include
            return (
                "include-file",
                total_server_blocks,
                affected_files,
                f"Shared snippet included by {total_server_blocks} server blocks "
                f"across {len(affected_files)} site configs",
            )
    else:
        # File is not included by others — it's a standalone config
        server_blocks = count_server_blocks_in_file(target_abs)

        if is_inside_location_block(content):
            return (
                "exact-location",
                max(server_blocks, 1),
                [target_abs],
                f"Location block in site-specific config ({max(server_blocks, 1)} server block(s))",
            )
        elif is_inside_server_block(content):
            return (
                "server-block",
                max(server_blocks, 1),
                [target_abs],
                f"Server block change in site-specific config",
            )
        else:
            # Bare directive in a standalone file
            return (
                "server-block",
                max(server_blocks, 1),
                [target_abs],
                f"Directive in site-specific config ({max(server_blocks, 1)} server block(s))",
            )


def radius_exceeds_server_block(radius: str) -> bool:
    """Check if a blast radius is broader than server-block."""
    broader = {"include-file", "vhost-group", "global-http", "unknown-shared"}
    return radius in broader


def max_radius(radii: List[str]) -> str:
    """Return the broadest blast radius from a list."""
    if not radii:
        return "unknown-shared"
    best_idx = -1
    for r in radii:
        if r in BLAST_RADIUS_ORDER:
            idx = BLAST_RADIUS_ORDER.index(r)
            if idx > best_idx:
                best_idx = idx
        else:
            return "unknown-shared"
    if best_idx < 0:
        return "unknown-shared"
    return BLAST_RADIUS_ORDER[best_idx]


# ── Main ─────────────────────────────────────────────────────────────────────

def analyze_file(
    proposed_path: str,
    nginx_config_dir: str,
    target_file: Optional[str],
    include_map: Dict[str, List[str]],
) -> Dict[str, Any]:
    """Analyze a single proposed rule file."""
    try:
        with open(proposed_path, "r") as f:
            content = f.read()
    except (IOError, OSError) as e:
        return {
            "rule": f"<error reading {proposed_path}>",
            "target_file": target_file or "unknown",
            "change_type": "unknown",
            "blast_radius": "unknown-shared",
            "affected_server_blocks": 0,
            "affected_files": [],
            "details": f"Error reading proposed rule: {e}",
        }

    resolved_target = resolve_target_file(target_file, content, nginx_config_dir)
    change_type = classify_change(content)
    rule_summary = extract_rule_summary(content)

    blast_radius, affected_sb, affected_files, details = determine_blast_radius(
        content, resolved_target, include_map, change_type
    )

    return {
        "rule": rule_summary,
        "target_file": resolved_target or "unknown",
        "change_type": change_type,
        "blast_radius": blast_radius,
        "affected_server_blocks": affected_sb,
        "affected_files": affected_files,
        "details": details,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Blast-radius analyzer for nginx config changes"
    )
    parser.add_argument(
        "--proposed-rule",
        required=True,
        help="Path to file (or directory of .conf files) containing proposed nginx rule(s)",
    )
    parser.add_argument(
        "--nginx-config-dir",
        default="/etc/nginx/",
        help="Directory to scan for include references (default: /etc/nginx/)",
    )
    parser.add_argument(
        "--target-file",
        default=None,
        help="The file where the rule would be inserted",
    )
    args = parser.parse_args()

    proposed = args.proposed_rule
    config_dir = args.nginx_config_dir

    # Validate inputs
    if not os.path.exists(proposed):
        print(json.dumps({"error": f"Proposed rule path not found: {proposed}"}),
              file=sys.stderr)
        return 1

    if not os.path.exists(config_dir):
        print(json.dumps({"error": f"Nginx config dir not found: {config_dir}"}),
              file=sys.stderr)
        return 1

    # Build include map
    include_map = scan_includes(config_dir)

    # Collect proposed files
    proposed_files: List[str] = []
    if os.path.isdir(proposed):
        for fname in sorted(os.listdir(proposed)):
            if fname.endswith(".conf"):
                proposed_files.append(os.path.join(proposed, fname))
    else:
        proposed_files.append(proposed)

    if not proposed_files:
        print(json.dumps({"error": "No .conf files found in proposed directory"}),
              file=sys.stderr)
        return 1

    # Analyze each file
    changes: List[Dict[str, Any]] = []
    for pf in proposed_files:
        result = analyze_file(pf, config_dir, args.target_file, include_map)
        changes.append(result)

    # Compute summary
    radii = [c["blast_radius"] for c in changes]
    overall_max = max_radius(radii)
    elevated = radius_exceeds_server_block(overall_max)
    total_sb = max(c["affected_server_blocks"] for c in changes) if changes else 0

    output = {
        "changes": changes,
        "max_blast_radius": overall_max,
        "requires_elevated_warning": elevated,
        "summary": (
            f"{len(changes)} change(s), max blast radius: {overall_max}"
            + (f" ({total_sb} server blocks affected)" if total_sb > 0 else "")
        ),
    }

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
