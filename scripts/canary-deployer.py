#!/usr/bin/env python3
"""
P3-1: Canary Deployer — phased remote deployment with canary verification via SSH.

Manages phased remote deployment of nginx security configs with:
- SCP/SSH-based config sync
- Canary host reload + verification before fanout
- Health checks with retries
- Deny path verification (expect 404)
- Per-host status tracking and rollback guidance
- Dry-run mode for safe previewing

Stdlib-only Python, no LLM.

Usage:
    python3 scripts/canary-deployer.py \\
      --config-file PATH \\
      --hosts host1,host2,host3 \\
      --ssh-user USER \\
      --ssh-key PATH | --ssh-pass-env ENV_VAR \\
      --remote-config-path /etc/nginx/snippets/security-hardening.conf \\
      --health-endpoint /health \\
      --verify-deny-paths "/.env,/wp-admin,/actuator/env" \\
      [--canary-host host1] \\
      [--dry-run]

Exit codes: 0 = all pass, 1 = any failure, 2 = dry-run completed.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

HEALTH_RETRIES = 3
HEALTH_TIMEOUT = 10  # seconds per attempt

# Collects dry-run commands for inclusion in the report
_dry_run_log = []


def parse_args():
    p = argparse.ArgumentParser(description="Canary deployer for nginx configs")
    p.add_argument("--config-file", required=True,
                    help="Local path to nginx config file to deploy")
    p.add_argument("--hosts", required=True,
                    help="Comma-separated list of target hosts")
    p.add_argument("--ssh-user", required=True,
                    help="SSH username for remote connections")
    auth = p.add_mutually_exclusive_group(required=True)
    auth.add_argument("--ssh-key", default=None,
                      help="Path to SSH private key file")
    auth.add_argument("--ssh-pass-env", default=None,
                      help="Name of env var containing SSH password (used with sshpass)")
    p.add_argument("--remote-config-path", required=True,
                    help="Remote destination path for the config file")
    p.add_argument("--health-endpoint", default="/health",
                    help="HTTP path for health check (default: /health)")
    p.add_argument("--verify-deny-paths", default="/.env,/wp-admin,/actuator/env",
                    help="Comma-separated paths that should return 404")
    p.add_argument("--canary-host", default=None,
                    help="Host to use as canary (default: first host)")
    p.add_argument("--dry-run", action="store_true",
                    help="Print commands without executing")
    return p.parse_args()


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def build_ssh_base(args):
    """Return the base SSH command prefix and env overrides."""
    env = dict(os.environ)
    opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15"]

    if args.ssh_key:
        prefix = ["ssh"] + opts + ["-i", args.ssh_key]
        scp_prefix = ["scp"] + opts + ["-i", args.ssh_key]
    else:
        # sshpass mode: read password from the named env var
        pass_env_name = args.ssh_pass_env
        password = os.environ.get(pass_env_name, "")
        env["SSHPASS"] = password
        prefix = ["sshpass", "-e", "ssh"] + opts
        scp_prefix = ["sshpass", "-e", "scp"] + opts

    return prefix, scp_prefix, env


def _log_dry(label, cmd_parts):
    """Record a dry-run command."""
    _dry_run_log.append(f"[{label}] {' '.join(cmd_parts)}")


def ssh_run(prefix, env, user, host, remote_cmd, dry_run=False, label="ssh"):
    """Execute a remote SSH command. Returns (success, stdout, stderr)."""
    cmd = prefix + [f"{user}@{host}", remote_cmd]
    if dry_run:
        _log_dry(label, cmd)
        return True, "", ""

    try:
        result = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "SSH command timed out"
    except FileNotFoundError as e:
        return False, "", f"Command not found: {e}"


def scp_upload(scp_prefix, env, user, host, local_path, remote_path, dry_run=False):
    """Upload a file via SCP. Returns (success, stderr)."""
    cmd = scp_prefix + [local_path, f"{user}@{host}:{remote_path}"]
    if dry_run:
        _log_dry("scp", cmd)
        return True, ""

    try:
        result = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=60
        )
        return result.returncode == 0, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "SCP timed out"
    except FileNotFoundError as e:
        return False, f"Command not found: {e}"


# ---------------------------------------------------------------------------
# Deployment phases
# ---------------------------------------------------------------------------

def phase_validate(args):
    """Phase 1: Local validation."""
    errors = []
    if not os.path.isfile(args.config_file):
        errors.append(f"Config file not found: {args.config_file}")
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    if not hosts:
        errors.append("No valid hosts provided")
    if args.canary_host and args.canary_host not in hosts:
        errors.append(f"Canary host '{args.canary_host}' not in hosts list")
    return hosts, errors


def phase_sync(scp_prefix, env, args, hosts, dry_run=False):
    """Phase 2: Sync config to all hosts without reload."""
    results = {}
    for host in hosts:
        # First create a backup of the existing config on remote
        backup_cmd = (
            f"sudo cp {args.remote_config_path} "
            f"{args.remote_config_path}.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null; true"
        )
        ssh_prefix, _, ssh_env = build_ssh_base(args)
        ssh_run(ssh_prefix, ssh_env, args.ssh_user, host, backup_cmd,
                dry_run=dry_run, label="backup")

        ok, err = scp_upload(scp_prefix, env, args.ssh_user, host,
                             args.config_file, args.remote_config_path,
                             dry_run=dry_run)
        results[host] = "pass" if ok else f"fail: {err}"
    return results


def phase_nginx_test(ssh_prefix, env, args, host, dry_run=False):
    """Run nginx -t on a remote host."""
    ok, out, err = ssh_run(
        ssh_prefix, env, args.ssh_user, host,
        "sudo nginx -t",
        dry_run=dry_run, label="nginx_test"
    )
    return ok, err


def phase_reload(ssh_prefix, env, args, host, dry_run=False):
    """Reload nginx on a remote host (after nginx -t passes)."""
    ok, out, err = ssh_run(
        ssh_prefix, env, args.ssh_user, host,
        "sudo systemctl reload nginx",
        dry_run=dry_run, label="reload"
    )
    return ok, err


def phase_health_check(ssh_prefix, env, args, host, dry_run=False):
    """Health check with retries."""
    curl_cmd = (
        f"curl -s -o /dev/null -w '%{{http_code}}' "
        f"http://localhost{args.health_endpoint}"
    )
    if dry_run:
        _log_dry(f"health_check ({HEALTH_RETRIES} retries)",
                 ["ssh", f"{args.ssh_user}@{host}", curl_cmd])
        return True, "200"

    for attempt in range(1, HEALTH_RETRIES + 1):
        ok, out, err = ssh_run(
            ssh_prefix, env, args.ssh_user, host, curl_cmd,
            dry_run=False, label=f"health_check (attempt {attempt})"
        )
        if ok and out == "200":
            return True, out
        if attempt < HEALTH_RETRIES:
            time.sleep(2)

    return False, out if out else err


def phase_deny_checks(ssh_prefix, env, args, host, deny_paths, dry_run=False):
    """Verify deny paths return 404."""
    results = {}
    for path in deny_paths:
        curl_cmd = (
            f"curl -s -o /dev/null -w '%{{http_code}}' "
            f"http://localhost{path}"
        )
        if dry_run:
            _log_dry(f"deny_check {path}",
                     ["ssh", f"{args.ssh_user}@{host}", curl_cmd])
            results[path] = 404
            continue

        ok, out, err = ssh_run(
            ssh_prefix, env, args.ssh_user, host, curl_cmd,
            dry_run=False, label=f"deny_check {path}"
        )
        try:
            results[path] = int(out)
        except (ValueError, TypeError):
            results[path] = 0
    return results


def verify_host(ssh_prefix, env, args, host, deny_paths, dry_run=False):
    """Run nginx_test + reload + health_check + deny_checks on a host.
    Returns a dict of results and whether the host passed."""
    result = {}

    # nginx -t
    ok, err = phase_nginx_test(ssh_prefix, env, args, host, dry_run)
    result["nginx_test"] = "pass" if ok else "fail"
    if not ok and not dry_run:
        return result, False, "nginx_test", err

    # reload
    ok, err = phase_reload(ssh_prefix, env, args, host, dry_run)
    result["reload"] = "pass" if ok else "fail"
    if not ok and not dry_run:
        return result, False, "reload", err

    # health check
    ok, code = phase_health_check(ssh_prefix, env, args, host, dry_run)
    result["health_check"] = "pass" if ok else f"fail (code={code})"
    if not ok and not dry_run:
        return result, False, "health_check", f"Health returned {code}"

    # deny path checks
    deny_results = phase_deny_checks(ssh_prefix, env, args, host, deny_paths, dry_run)
    result["deny_checks"] = deny_results
    for path, code in deny_results.items():
        if code != 404 and not dry_run:
            return result, False, "deny_check", f"{path} returned {code}, expected 404"

    return result, True, None, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    dry_run = args.dry_run

    # Phase 1: local validation
    hosts, errors = phase_validate(args)
    if errors:
        report = {
            "error": "validation_failed",
            "errors": errors,
        }
        print(json.dumps(report, indent=2))
        sys.exit(1)

    canary_host = args.canary_host or hosts[0]
    follower_hosts = [h for h in hosts if h != canary_host]
    deny_paths = [p.strip() for p in args.verify_deny_paths.split(",") if p.strip()]

    ssh_prefix, scp_prefix, env = build_ssh_base(args)

    # Initialize report
    report = {
        "dry_run": dry_run,
        "config_file": os.path.abspath(args.config_file),
        "remote_config_path": args.remote_config_path,
        "total_hosts": len(hosts),
        "canary_host": canary_host,
        "canary_result": {},
        "hosts": {},
        "summary": {"passed": 0, "failed": 0, "skipped": 0},
        "stopped_at": None,
        "rollback_needed": [],
    }

    # Phase 2: sync config to all hosts
    sync_results = phase_sync(scp_prefix, env, args, hosts, dry_run)
    for host, status in sync_results.items():
        if status != "pass" and not dry_run:
            report["hosts"][host] = {
                "status": "fail",
                "role": "canary" if host == canary_host else "follower",
                "error": status,
                "phase": "sync",
            }
            report["summary"]["failed"] += 1
            report["stopped_at"] = host
            # Remaining hosts skipped
            for h in hosts:
                if h not in report["hosts"]:
                    report["hosts"][h] = {
                        "status": "skipped",
                        "role": "canary" if h == canary_host else "follower",
                    }
                    report["summary"]["skipped"] += 1
            print(json.dumps(report, indent=2))
            sys.exit(1)

    report["canary_result"]["sync"] = "pass"

    # Phase 3-4: canary reload + verify
    canary_detail, canary_ok, fail_phase, fail_err = verify_host(
        ssh_prefix, env, args, canary_host, deny_paths, dry_run
    )
    report["canary_result"].update(canary_detail)

    if canary_ok or dry_run:
        report["hosts"][canary_host] = {"status": "pass", "role": "canary"}
        report["summary"]["passed"] += 1
    else:
        report["hosts"][canary_host] = {
            "status": "fail", "role": "canary",
            "error": fail_err, "phase": fail_phase,
        }
        report["summary"]["failed"] += 1
        report["stopped_at"] = canary_host
        report["rollback_needed"].append(canary_host)
        # Skip all followers
        for h in follower_hosts:
            report["hosts"][h] = {"status": "skipped", "role": "follower"}
            report["summary"]["skipped"] += 1
        print(json.dumps(report, indent=2))
        sys.exit(1)

    # Phase 5-6: fanout to followers
    for host in follower_hosts:
        detail, ok, fail_phase, fail_err = verify_host(
            ssh_prefix, env, args, host, deny_paths, dry_run
        )
        if ok or dry_run:
            report["hosts"][host] = {"status": "pass", "role": "follower"}
            report["summary"]["passed"] += 1
        else:
            report["hosts"][host] = {
                "status": "fail", "role": "follower",
                "error": fail_err, "phase": fail_phase,
            }
            report["summary"]["failed"] += 1
            report["stopped_at"] = host
            report["rollback_needed"].append(host)
            # Skip remaining
            remaining = follower_hosts[follower_hosts.index(host) + 1:]
            for h in remaining:
                report["hosts"][h] = {"status": "skipped", "role": "follower"}
                report["summary"]["skipped"] += 1
            break

    # Include dry-run command log in report
    if dry_run and _dry_run_log:
        report["dry_run_commands"] = _dry_run_log

    # Output
    print(json.dumps(report, indent=2))

    if dry_run:
        sys.exit(2)
    elif report["summary"]["failed"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
