#!/usr/bin/env python3
"""
Rollback Manager — Backup, list, preview, and restore nginx configs.

Stdlib-only Python. Manages timestamped backups with JSON metadata sidecars.
Restore always creates a safety backup first (reversible).

Usage:
  python3 scripts/rollback-manager.py backup  --file /path/to/config.conf [--run-id RUN_ID]
  python3 scripts/rollback-manager.py list    --file /path/to/config.conf
  python3 scripts/rollback-manager.py preview --file /path/to/config.conf --backup-id YYYYMMDD-HHMMSS
  python3 scripts/rollback-manager.py restore --file /path/to/config.conf --backup-id YYYYMMDD-HHMMSS
"""

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


# ── Helpers ──────────────────────────────────────────────────────────────────

BACKUP_PATTERN = re.compile(r"\.bak\.(\d{8}-\d{6}(?:-\d{3})?)$")


def sha256_file(path: str) -> str:
    """Return hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def timestamp_now() -> str:
    """Return current UTC timestamp as YYYYMMDD-HHMMSS."""
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def unique_timestamp(filepath: str) -> str:
    """Return a timestamp that doesn't collide with existing backups for this file."""
    ts = timestamp_now()
    candidate = f"{filepath}.bak.{ts}"
    if not os.path.exists(candidate):
        return ts
    # Append incrementing suffix to avoid collision
    for i in range(1, 1000):
        ts_suffixed = f"{ts}-{i:03d}"
        candidate = f"{filepath}.bak.{ts_suffixed}"
        if not os.path.exists(candidate):
            return ts_suffixed
    raise RuntimeError("Could not generate unique backup timestamp")


def iso_from_backup_id(backup_id: str) -> str:
    """Convert backup ID (YYYYMMDD-HHMMSS or YYYYMMDD-HHMMSS-NNN) to ISO 8601 UTC string."""
    # Strip optional collision suffix
    base_id = backup_id[:15]  # YYYYMMDD-HHMMSS
    dt = datetime.strptime(base_id, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def find_backups(filepath: str) -> list:
    """Find all backup files for a given config file, sorted newest first."""
    parent = os.path.dirname(os.path.abspath(filepath))
    base = os.path.basename(filepath)
    backups = []
    if not os.path.isdir(parent):
        return backups
    for entry in os.listdir(parent):
        if entry.startswith(base + ".bak."):
            m = BACKUP_PATTERN.search(entry)
            if m and not entry.endswith(".meta.json"):
                backup_id = m.group(1)
                full_path = os.path.join(parent, entry)
                meta_path = full_path + ".meta.json"
                run_id = None
                if os.path.exists(meta_path):
                    try:
                        with open(meta_path, "r") as mf:
                            meta = json.load(mf)
                            run_id = meta.get("run_id")
                    except (json.JSONDecodeError, OSError):
                        pass
                backups.append({
                    "backup_id": backup_id,
                    "timestamp": iso_from_backup_id(backup_id),
                    "size_bytes": os.path.getsize(full_path),
                    "run_id": run_id,
                    "path": full_path,
                })
    backups.sort(key=lambda b: b["backup_id"], reverse=True)
    return backups


# ── Subcommands ──────────────────────────────────────────────────────────────

def cmd_backup(args):
    """Create a timestamped backup with JSON metadata sidecar."""
    filepath = os.path.abspath(args.file)
    if not os.path.isfile(filepath):
        print(json.dumps({"error": f"File not found: {filepath}"}), file=sys.stderr)
        sys.exit(1)

    ts = unique_timestamp(filepath)
    run_id = args.run_id if args.run_id else f"run-{ts}"
    backup_path = f"{filepath}.bak.{ts}"
    meta_path = f"{backup_path}.meta.json"

    shutil.copy2(filepath, backup_path)

    meta = {
        "original_file": filepath,
        "backup_file": backup_path,
        "timestamp": iso_from_backup_id(ts),
        "run_id": run_id,
        "size_bytes": os.path.getsize(backup_path),
        "sha256": sha256_file(backup_path),
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")

    print(json.dumps(meta, indent=2))


def cmd_list(args):
    """List available backups for a config file, newest first."""
    filepath = os.path.abspath(args.file)
    backups = find_backups(filepath)
    # Strip internal 'path' key from output
    output = []
    for b in backups:
        output.append({
            "backup_id": b["backup_id"],
            "timestamp": b["timestamp"],
            "size_bytes": b["size_bytes"],
            "run_id": b["run_id"],
        })
    print(json.dumps(output, indent=2))


def cmd_preview(args):
    """Show unified diff between current config and a backup."""
    filepath = os.path.abspath(args.file)
    backup_id = args.backup_id
    backup_path = f"{filepath}.bak.{backup_id}"

    if not os.path.isfile(filepath):
        print(json.dumps({"error": f"File not found: {filepath}"}), file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(backup_path):
        print(json.dumps({"error": f"Backup not found: {backup_path}"}), file=sys.stderr)
        sys.exit(1)

    with open(backup_path, "r") as f:
        backup_lines = f.readlines()
    with open(filepath, "r") as f:
        current_lines = f.readlines()

    diff = list(difflib.unified_diff(
        current_lines,
        backup_lines,
        fromfile=f"current: {filepath}",
        tofile=f"backup: {backup_path}",
        lineterm="",
    ))

    lines_added = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
    lines_removed = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))

    # Count section headers changed (lines starting with @@ in diff)
    sections_changed = sum(1 for line in diff if line.startswith("@@"))

    diff_text = "\n".join(diff)

    result = {
        "diff": diff_text,
        "lines_added": lines_added,
        "lines_removed": lines_removed,
        "sections_changed": sections_changed,
    }
    print(json.dumps(result, indent=2))


def cmd_restore(args):
    """Restore a config file from a backup. Creates safety backup first."""
    filepath = os.path.abspath(args.file)
    backup_id = args.backup_id
    backup_path = f"{filepath}.bak.{backup_id}"

    if not os.path.isfile(filepath):
        print(json.dumps({"error": f"File not found: {filepath}"}), file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(backup_path):
        print(json.dumps({"error": f"Backup not found: {backup_path}"}), file=sys.stderr)
        sys.exit(1)

    # Safety backup of current file before restoring
    safety_ts = unique_timestamp(filepath)
    safety_path = f"{filepath}.bak.{safety_ts}"
    safety_meta_path = f"{safety_path}.meta.json"
    shutil.copy2(filepath, safety_path)
    safety_meta = {
        "original_file": filepath,
        "backup_file": safety_path,
        "timestamp": iso_from_backup_id(safety_ts),
        "run_id": f"pre-restore-{safety_ts}",
        "size_bytes": os.path.getsize(safety_path),
        "sha256": sha256_file(safety_path),
    }
    with open(safety_meta_path, "w") as f:
        json.dump(safety_meta, f, indent=2)
        f.write("\n")

    # Restore from backup
    shutil.copy2(backup_path, filepath)

    result = {
        "restored_from": backup_path,
        "restored_to": filepath,
        "safety_backup": safety_path,
        "sha256_restored": sha256_file(filepath),
        "timestamp": iso_from_backup_id(safety_ts),
    }
    print(json.dumps(result, indent=2))


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Rollback Manager — backup, list, preview, restore nginx configs"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # backup
    p_backup = sub.add_parser("backup", help="Create timestamped backup")
    p_backup.add_argument("--file", required=True, help="Path to config file")
    p_backup.add_argument("--run-id", default=None, help="Run ID for metadata")

    # list
    p_list = sub.add_parser("list", help="List available backups")
    p_list.add_argument("--file", required=True, help="Path to config file")

    # preview
    p_preview = sub.add_parser("preview", help="Show diff between current and backup")
    p_preview.add_argument("--file", required=True, help="Path to config file")
    p_preview.add_argument("--backup-id", required=True, help="Backup ID (YYYYMMDD-HHMMSS)")

    # restore
    p_restore = sub.add_parser("restore", help="Restore from backup")
    p_restore.add_argument("--file", required=True, help="Path to config file")
    p_restore.add_argument("--backup-id", required=True, help="Backup ID (YYYYMMDD-HHMMSS)")

    args = parser.parse_args()

    dispatch = {
        "backup": cmd_backup,
        "list": cmd_list,
        "preview": cmd_preview,
        "restore": cmd_restore,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
