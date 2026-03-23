#!/usr/bin/env python3
"""
Tests for rule-lifecycle.py — generate-id, trace, and status.

Uses fixture data in tests/fixtures/findings/ to verify:
  - ID generation produces correct format and auto-increments
  - Trace finds references across multiple directories
  - Status correctly identifies lifecycle stage
"""

import json
import os
import subprocess
import sys

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "scripts", "rule-lifecycle.py")
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "findings")

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
    base_dir = os.path.abspath(FIXTURES_DIR)

    print("=== Rule Lifecycle Tests ===\n")

    # ── 1. Generate ID — existing IDs ────────────────────────────────────
    print("1. Generate ID (should increment past existing NH-AUDIT-HEADERS-0001)")
    result = run_cmd(["generate-id", "--source", "AUDIT", "--category", "HEADERS",
                       "--base-dir", base_dir])
    check("generate-id exits 0", result.returncode == 0, result.stderr)
    generated_id = result.stdout.strip()
    check("generated ID is NH-AUDIT-HEADERS-0002", generated_id == "NH-AUDIT-HEADERS-0002",
          f"got '{generated_id}'")
    print()

    # ── 2. Generate ID — fresh category ──────────────────────────────────
    print("2. Generate ID for new category (no existing IDs)")
    result = run_cmd(["generate-id", "--source", "IOC", "--category", "TLS",
                       "--base-dir", base_dir])
    check("fresh generate-id exits 0", result.returncode == 0, result.stderr)
    generated_id = result.stdout.strip()
    check("fresh ID is NH-IOC-TLS-0001", generated_id == "NH-IOC-TLS-0001",
          f"got '{generated_id}'")
    print()

    # ── 3. Generate ID — invalid source ──────────────────────────────────
    print("3. Generate ID with invalid source (should fail)")
    result = run_cmd(["generate-id", "--source", "INVALID", "--category", "HEADERS",
                       "--base-dir", base_dir])
    check("invalid source exits non-zero", result.returncode != 0)
    print()

    # ── 4. Trace — find references ───────────────────────────────────────
    print("4. Trace NH-AUDIT-HEADERS-0001")
    result = run_cmd(["trace", "--id", "NH-AUDIT-HEADERS-0001", "--base-dir", base_dir])
    check("trace exits 0", result.returncode == 0, result.stderr)
    trace = json.loads(result.stdout)
    check("trace finding_id correct", trace["finding_id"] == "NH-AUDIT-HEADERS-0001")
    check("trace found references", trace["total_references"] >= 3,
          f"got {trace['total_references']}")

    # Check it found references in expected locations
    ref_files = [r["file"] for r in trace["references"]]
    ref_files_str = " ".join(ref_files)
    check("trace includes findings.json",
          any("findings.json" in f for f in ref_files), str(ref_files))
    check("trace includes attack-patterns markdown",
          any("headers.md" in f for f in ref_files), str(ref_files))
    check("trace includes CHANGELOG.md",
          any("CHANGELOG.md" in f for f in ref_files), str(ref_files))
    print()

    # ── 5. Trace — nonexistent ID ────────────────────────────────────────
    print("5. Trace nonexistent ID")
    result = run_cmd(["trace", "--id", "NH-AUDIT-HEADERS-9999", "--base-dir", base_dir])
    check("nonexistent trace exits 0", result.returncode == 0)
    trace = json.loads(result.stdout)
    check("nonexistent trace has 0 references", trace["total_references"] == 0)
    print()

    # ── 6. Status — existing finding ─────────────────────────────────────
    print("6. Status for NH-AUDIT-HEADERS-0001")
    result = run_cmd(["status", "--id", "NH-AUDIT-HEADERS-0001", "--base-dir", base_dir])
    check("status exits 0", result.returncode == 0, result.stderr)
    status = json.loads(result.stdout)
    check("status finding_id correct", status["finding_id"] == "NH-AUDIT-HEADERS-0001")
    check("status discovered is set", status["discovered"] is not None)
    check("status lifecycle is staged",
          status["lifecycle"] == "staged",
          f"got '{status['lifecycle']}'")
    print()

    # ── 7. Invalid ID format ─────────────────────────────────────────────
    print("7. Invalid ID format")
    result = run_cmd(["trace", "--id", "INVALID-ID", "--base-dir", base_dir])
    check("invalid ID exits non-zero", result.returncode != 0)
    print()

    print(f"\n{'=' * 40}")
    print(f"Results: {PASS} passed, {FAIL} failed")
    if FAIL > 0:
        sys.exit(1)
    print("All tests passed!")


if __name__ == "__main__":
    main()
