#!/usr/bin/env python3
"""
Tests for rollback-manager.py — full backup/list/preview/restore cycle.

Creates a temp config file, exercises every subcommand, and verifies
the restored content matches the original.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "scripts", "rollback-manager.py")
FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "rollback", "sample-nginx.conf")

PASS = 0
FAIL = 0


def run_cmd(args: list) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, SCRIPT] + args,
        capture_output=True, text=True,
    )


def check(name: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS: {name}")
    else:
        FAIL += 1
        print(f"  FAIL: {name} — {detail}")


def main():
    global PASS, FAIL

    # Set up temp directory with a copy of the fixture
    tmpdir = tempfile.mkdtemp(prefix="rollback-test-")
    config_path = os.path.join(tmpdir, "test.conf")
    shutil.copy2(FIXTURE, config_path)

    with open(config_path, "r") as f:
        original_content = f.read()

    print("=== Rollback Manager Tests ===\n")

    # ── 1. Backup ────────────────────────────────────────────────────────
    print("1. Create backup")
    result = run_cmd(["backup", "--file", config_path, "--run-id", "test-run-001"])
    check("backup exits 0", result.returncode == 0, result.stderr)
    meta = json.loads(result.stdout)
    check("backup has sha256", "sha256" in meta and len(meta["sha256"]) == 64)
    check("backup has run_id", meta.get("run_id") == "test-run-001")
    check("backup file exists", os.path.isfile(meta["backup_file"]))
    backup_id = os.path.basename(meta["backup_file"]).split(".bak.")[1]
    print()

    # ── 2. Modify config ─────────────────────────────────────────────────
    print("2. Modify config")
    with open(config_path, "a") as f:
        f.write("\n    # Added new location\n    location /api { proxy_pass http://127.0.0.1:9090; }\n")
    with open(config_path, "r") as f:
        modified_content = f.read()
    check("config was modified", modified_content != original_content)
    print()

    # ── 3. List backups ──────────────────────────────────────────────────
    print("3. List backups")
    result = run_cmd(["list", "--file", config_path])
    check("list exits 0", result.returncode == 0, result.stderr)
    backups = json.loads(result.stdout)
    check("list shows 1 backup", len(backups) == 1, f"got {len(backups)}")
    check("list has correct run_id", backups[0].get("run_id") == "test-run-001")
    check("list has correct backup_id", backups[0].get("backup_id") == backup_id)
    print()

    # ── 4. Preview ───────────────────────────────────────────────────────
    print("4. Preview diff")
    result = run_cmd(["preview", "--file", config_path, "--backup-id", backup_id])
    check("preview exits 0", result.returncode == 0, result.stderr)
    preview = json.loads(result.stdout)
    check("preview has diff", len(preview.get("diff", "")) > 0)
    check("preview shows lines_removed > 0", preview.get("lines_removed", 0) > 0,
          f"got {preview.get('lines_removed')}")
    check("preview shows sections_changed > 0", preview.get("sections_changed", 0) > 0)
    print()

    # ── 5. Restore ───────────────────────────────────────────────────────
    print("5. Restore from backup")
    result = run_cmd(["restore", "--file", config_path, "--backup-id", backup_id])
    check("restore exits 0", result.returncode == 0, result.stderr)
    restore_info = json.loads(result.stdout)
    check("restore created safety backup", os.path.isfile(restore_info.get("safety_backup", "")))
    print()

    # ── 6. Verify restored content ───────────────────────────────────────
    print("6. Verify restored content matches original")
    with open(config_path, "r") as f:
        restored_content = f.read()
    check("restored content matches original", restored_content == original_content,
          f"lengths: original={len(original_content)} restored={len(restored_content)}")
    print()

    # ── 7. List should now show 2 backups (original + safety) ────────────
    print("7. Verify safety backup appears in list")
    result = run_cmd(["list", "--file", config_path])
    backups = json.loads(result.stdout)
    check("list shows 2 backups after restore", len(backups) == 2, f"got {len(backups)}")
    print()

    # ── Cleanup ──────────────────────────────────────────────────────────
    shutil.rmtree(tmpdir)

    print(f"\n{'=' * 40}")
    print(f"Results: {PASS} passed, {FAIL} failed")
    if FAIL > 0:
        sys.exit(1)
    print("All tests passed!")


if __name__ == "__main__":
    main()
