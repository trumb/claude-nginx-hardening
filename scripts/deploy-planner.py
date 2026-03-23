#!/usr/bin/env python3
"""
P3-2: Deploy Planner — generates deployment plans for remote nginx config rollouts.

Produces a structured JSON deployment plan with:
- Ordered phases (validate, sync, canary, fanout)
- Per-host rollback commands
- Estimated duration

Stdlib-only Python, no LLM.

Usage:
    python3 scripts/deploy-planner.py \\
      --hosts host1,host2,host3 \\
      --config-file PATH \\
      --remote-config-path PATH \\
      [--canary-host HOST]

Exit code: 0 always (plan generation is read-only).
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


# Estimated seconds per host for each phase
EST_VALIDATE_SECS = 5
EST_SYNC_PER_HOST = 10
EST_RELOAD_SECS = 5
EST_VERIFY_SECS = 15


def parse_args():
    p = argparse.ArgumentParser(description="Deployment plan generator for nginx configs")
    p.add_argument("--hosts", required=True,
                    help="Comma-separated list of target hosts")
    p.add_argument("--config-file", required=True,
                    help="Local path to nginx config file to deploy")
    p.add_argument("--remote-config-path", required=True,
                    help="Remote destination path for the config file")
    p.add_argument("--canary-host", default=None,
                    help="Host to use as canary (default: first host)")
    return p.parse_args()


def generate_plan(hosts, config_file, remote_config_path, canary_host):
    """Generate the deployment plan JSON structure."""
    now = datetime.now(timezone.utc)
    deployment_id = f"deploy-{now.strftime('%Y%m%d-%H%M%S')}"

    canary = canary_host or hosts[0]
    followers = [h for h in hosts if h != canary]

    phases = [
        {
            "phase": 1,
            "action": "local_validate",
            "description": "Validate config file locally with invariant checker",
            "commands": [
                f"python3 scripts/invariant-checker.py --proposed {config_file}"
            ],
        },
        {
            "phase": 2,
            "action": "sync_all",
            "description": "SCP config to all hosts (no reload yet)",
            "hosts": hosts,
            "commands": [
                f"scp {config_file} USER@HOST:{remote_config_path}"
                for _ in hosts
            ],
        },
        {
            "phase": 3,
            "action": "canary_reload",
            "description": "Test and reload nginx on canary host",
            "host": canary,
            "commands": [
                f"ssh {canary} 'sudo nginx -t && sudo systemctl reload nginx'"
            ],
        },
        {
            "phase": 4,
            "action": "canary_verify",
            "description": "Verify canary host health and deny paths",
            "host": canary,
            "checks": ["nginx_test", "health", "deny_paths"],
        },
        {
            "phase": 5,
            "action": "fanout_reload",
            "description": "Test and reload nginx on remaining hosts, stop on first failure",
            "hosts": followers,
            "stop_on_failure": True,
        },
        {
            "phase": 6,
            "action": "fanout_verify",
            "description": "Verify health and deny paths on remaining hosts",
            "hosts": followers,
        },
    ]

    # Rollback plan: restore from timestamped backup
    rollback_plan = {}
    for host in hosts:
        rollback_plan[host] = (
            f"ssh {host} 'sudo cp {remote_config_path}.bak.* "
            f"{remote_config_path} && sudo nginx -t && "
            f"sudo systemctl reload nginx'"
        )

    # Estimate duration
    est = (
        EST_VALIDATE_SECS
        + EST_SYNC_PER_HOST * len(hosts)
        + EST_RELOAD_SECS  # canary reload
        + EST_VERIFY_SECS  # canary verify
        + (EST_RELOAD_SECS + EST_VERIFY_SECS) * len(followers)  # fanout
    )

    return {
        "deployment_id": deployment_id,
        "total_hosts": len(hosts),
        "canary_host": canary,
        "config_file": os.path.abspath(config_file),
        "remote_config_path": remote_config_path,
        "phases": phases,
        "rollback_plan": rollback_plan,
        "estimated_duration_seconds": est,
    }


def main():
    args = parse_args()

    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    if not hosts:
        print(json.dumps({"error": "No valid hosts provided"}), file=sys.stderr)
        sys.exit(1)

    if args.canary_host and args.canary_host not in hosts:
        print(json.dumps({
            "error": f"Canary host '{args.canary_host}' not in hosts list"
        }), file=sys.stderr)
        sys.exit(1)

    plan = generate_plan(hosts, args.config_file, args.remote_config_path,
                         args.canary_host)
    print(json.dumps(plan, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()
