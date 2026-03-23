#!/usr/bin/env python3
"""Schema validator for markdown files with YAML frontmatter.

Validates learnings, exceptions, recipes, and findings against their
defined schemas. Stdlib-only Python.

Usage:
    python3 scripts/schema-validator.py --type exception --file PATH
"""

import argparse
import json
import re
import sys
from datetime import date, timedelta


def parse_frontmatter(text):
    """Extract YAML frontmatter from markdown text.

    Returns (dict, errors). Uses a simple stdlib parser since we
    cannot depend on PyYAML.
    """
    text = text.strip()
    if not text.startswith("---"):
        return None, ["File does not start with YAML frontmatter delimiter '---'"]

    end = text.find("\n---", 3)
    if end == -1:
        return None, ["No closing YAML frontmatter delimiter '---' found"]

    yaml_block = text[3:end].strip()
    return parse_yaml(yaml_block)


def parse_yaml(block):
    """Minimal YAML parser for flat and simple-list structures."""
    data = {}
    errors = []
    lines = block.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # Key-value line
        m = re.match(r"^([a-z_][a-z0-9_]*):\s*(.*)", line)
        if not m:
            errors.append(f"Unparseable YAML line: {line!r}")
            i += 1
            continue

        key = m.group(1)
        value_str = m.group(2).strip()

        # Check if this is a list (value empty and next lines are "- item")
        if value_str == "" or value_str == "[]":
            # Peek ahead for list items
            items = []
            j = i + 1
            while j < len(lines) and lines[j].startswith("  - "):
                item = lines[j].strip().lstrip("- ").strip()
                items.append(_coerce_scalar(item))
                j += 1
            if j > i + 1:
                data[key] = items
                i = j
                continue
            elif value_str == "[]":
                data[key] = []
                i += 1
                continue
            else:
                # Empty string value
                data[key] = ""
                i += 1
                continue

        # Inline list: [item1, item2]
        if value_str.startswith("[") and value_str.endswith("]"):
            inner = value_str[1:-1].strip()
            if inner == "":
                data[key] = []
            else:
                data[key] = [_coerce_scalar(v.strip().strip('"').strip("'")) for v in inner.split(",")]
            i += 1
            continue

        data[key] = _coerce_scalar(value_str)
        i += 1

    return data, errors


def _coerce_scalar(val):
    """Coerce a YAML scalar string to a Python type."""
    if val in ("true", "True"):
        return True
    if val in ("false", "False"):
        return False
    # Try int
    try:
        return int(val)
    except (ValueError, TypeError):
        pass
    # Try float
    try:
        return float(val)
    except (ValueError, TypeError):
        pass
    # Strip quotes
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        return val[1:-1]
    return val


def parse_iso_date(val):
    """Parse an ISO 8601 date string (YYYY-MM-DD). Returns date or None."""
    if not isinstance(val, str):
        # Could be a date-like object from int coercion; try string conversion
        val = str(val)
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", val)
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Schema definitions
# ---------------------------------------------------------------------------

def validate_exception(data):
    errors = []
    warnings = []

    required = [
        "exception_id", "finding_id", "reason", "compensating_control",
        "severity_tier", "owner", "scope", "linked_config_path",
        "approval_reference", "created_at", "last_reviewed_at", "review_by",
    ]
    for field in required:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    # exception_id format
    if "exception_id" in data:
        if not re.match(r"^EXC-\d{4}$", str(data["exception_id"])):
            errors.append(f"exception_id must match EXC-NNNN pattern, got: {data['exception_id']}")

    # finding_id format
    if "finding_id" in data:
        if not str(data["finding_id"]).startswith("NH-"):
            errors.append(f"finding_id must start with 'NH-', got: {data['finding_id']}")

    # Non-empty strings
    for field in ("reason", "compensating_control"):
        if field in data and (not isinstance(data[field], str) or not data[field].strip()):
            errors.append(f"{field} must be a non-empty string")

    # severity_tier enum
    if "severity_tier" in data:
        allowed = ("critical", "high", "low")
        if data["severity_tier"] not in allowed:
            errors.append(f"severity_tier must be one of {allowed}, got: {data['severity_tier']}")

    # scope enum
    if "scope" in data:
        allowed = ("exact-directive", "location", "server-block", "include-file", "hostname", "global")
        if data["scope"] not in allowed:
            errors.append(f"scope must be one of {allowed}, got: {data['scope']}")

    # Date validations
    created = None
    if "created_at" in data:
        created = parse_iso_date(str(data["created_at"]))
        if created is None:
            errors.append(f"created_at must be a valid ISO 8601 date, got: {data['created_at']}")

    if "last_reviewed_at" in data:
        if parse_iso_date(str(data["last_reviewed_at"])) is None:
            errors.append(f"last_reviewed_at must be a valid ISO 8601 date, got: {data['last_reviewed_at']}")

    review_by = None
    if "review_by" in data:
        review_by = parse_iso_date(str(data["review_by"]))
        if review_by is None:
            errors.append(f"review_by must be a valid ISO 8601 date, got: {data['review_by']}")

    # 365-day rule
    if created and review_by:
        max_review = created + timedelta(days=365)
        if review_by > max_review:
            errors.append(
                f"review_by ({review_by.isoformat()}) exceeds 365-day maximum "
                f"from created_at ({created.isoformat()})"
            )

    return errors, warnings


def validate_learning(data):
    errors = []
    warnings = []

    required = [
        "type", "status", "discovered", "source", "run_id",
        "finding_ids", "hit_count",
    ]
    for field in required:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    # type enum
    if "type" in data:
        allowed = ("attack-pattern", "scanner-signature", "exception", "infrastructure", "ioc-response")
        if data["type"] not in allowed:
            errors.append(f"type must be one of {allowed}, got: {data['type']}")

    # status enum
    if "status" in data:
        allowed = ("draft", "active", "promoted")
        if data["status"] not in allowed:
            errors.append(f"status must be one of {allowed}, got: {data['status']}")

    # source enum
    if "source" in data:
        allowed = ("log-analysis", "manual", "upstream", "ioc-feed")
        if data["source"] not in allowed:
            errors.append(f"source must be one of {allowed}, got: {data['source']}")

    # discovered date
    if "discovered" in data:
        if parse_iso_date(str(data["discovered"])) is None:
            errors.append(f"discovered must be a valid ISO 8601 date, got: {data['discovered']}")

    # finding_ids must be a list
    if "finding_ids" in data:
        if not isinstance(data["finding_ids"], list):
            errors.append("finding_ids must be a list of strings")

    # hit_count must be integer >= 0
    if "hit_count" in data:
        if not isinstance(data["hit_count"], int) or data["hit_count"] < 0:
            errors.append(f"hit_count must be an integer >= 0, got: {data['hit_count']}")

    return errors, warnings


def validate_recipe(data):
    errors = []
    warnings = []

    required = [
        "name", "description", "profile", "execution_class",
        "requires_network", "requires_remote_exec", "required_env_vars",
        "confirmation_checkpoints", "allows_emergency_mode",
        "max_privilege_level", "schedule_mode", "steps", "outputs",
    ]
    for field in required:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    # name: kebab-case
    if "name" in data:
        if not re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", str(data["name"])):
            errors.append(f"name must be kebab-case, got: {data['name']}")

    # description non-empty
    if "description" in data:
        if not isinstance(data["description"], str) or not data["description"].strip():
            errors.append("description must be a non-empty string")

    # profile enum
    if "profile" in data:
        allowed = ("edge-public", "internal-only", "api-gateway", "static-site", "reverse-proxy-app", "high-risk-lockdown")
        if data["profile"] not in allowed:
            errors.append(f"profile must be one of {allowed}, got: {data['profile']}")

    # execution_class pattern
    if "execution_class" in data:
        if not re.match(r"^[RWX]\d(\+[RWX]\d)*$", str(data["execution_class"])):
            errors.append(f"execution_class must match pattern like 'R0', 'R0+R1', 'W1+W2+X1', got: {data['execution_class']}")

    # booleans
    for field in ("requires_network", "requires_remote_exec", "allows_emergency_mode"):
        if field in data and not isinstance(data[field], bool):
            errors.append(f"{field} must be a boolean, got: {data[field]}")

    # lists
    for field in ("required_env_vars", "confirmation_checkpoints", "outputs"):
        if field in data and not isinstance(data[field], list):
            errors.append(f"{field} must be a list, got: {data[field]}")

    # steps: non-empty list
    if "steps" in data:
        if not isinstance(data["steps"], list):
            errors.append("steps must be a list")
        elif len(data["steps"]) == 0:
            errors.append("steps must be non-empty")

    # max_privilege_level enum
    if "max_privilege_level" in data:
        allowed = ("R0", "R1", "W1", "W2", "X1")
        if data["max_privilege_level"] not in allowed:
            errors.append(f"max_privilege_level must be one of {allowed}, got: {data['max_privilege_level']}")

    # schedule_mode enum
    if "schedule_mode" in data:
        allowed = ("manual", "cron", "systemd-timer")
        if data["schedule_mode"] not in allowed:
            errors.append(f"schedule_mode must be one of {allowed}, got: {data['schedule_mode']}")

    return errors, warnings


def validate_finding(data):
    errors = []
    warnings = []

    required = [
        "finding_id", "category", "severity", "confidence",
        "source_layers", "scope", "blast_radius", "recommended_action",
        "rule_class", "requires_live_test", "exception_eligible",
        "linked_artifacts",
    ]
    for field in required:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    # finding_id format: NH-{SOURCE}-{CATEGORY}-{NNNN}
    if "finding_id" in data:
        if not re.match(r"^NH-(AUDIT|LOG|IOC)-[A-Z]+-\d{4}$", str(data["finding_id"])):
            errors.append(
                f"finding_id must match NH-{{AUDIT|LOG|IOC}}-{{CATEGORY}}-{{NNNN}}, "
                f"got: {data['finding_id']}"
            )

    # category non-empty
    if "category" in data:
        if not isinstance(data["category"], str) or not data["category"].strip():
            errors.append("category must be a non-empty string")

    # severity enum
    if "severity" in data:
        allowed = ("critical", "high", "medium", "low", "info")
        if data["severity"] not in allowed:
            errors.append(f"severity must be one of {allowed}, got: {data['severity']}")

    # confidence float 0.0-1.0
    if "confidence" in data:
        val = data["confidence"]
        if not isinstance(val, (int, float)) or val < 0.0 or val > 1.0:
            errors.append(f"confidence must be a float between 0.0 and 1.0, got: {val}")

    # source_layers list
    if "source_layers" in data:
        if not isinstance(data["source_layers"], list):
            errors.append("source_layers must be a list of strings")

    # scope enum
    if "scope" in data:
        allowed = ("exact-directive", "location", "server-block", "include-file", "hostname", "global")
        if data["scope"] not in allowed:
            errors.append(f"scope must be one of {allowed}, got: {data['scope']}")

    # blast_radius enum
    if "blast_radius" in data:
        allowed = ("exact-location", "server-block", "include-file", "vhost-group", "global-http", "unknown-shared")
        if data["blast_radius"] not in allowed:
            errors.append(f"blast_radius must be one of {allowed}, got: {data['blast_radius']}")

    # recommended_action non-empty
    if "recommended_action" in data:
        if not isinstance(data["recommended_action"], str) or not data["recommended_action"].strip():
            errors.append("recommended_action must be a non-empty string")

    # rule_class enum
    if "rule_class" in data:
        allowed = ("A", "B", "C", "D")
        if data["rule_class"] not in allowed:
            errors.append(f"rule_class must be one of {allowed}, got: {data['rule_class']}")

    # booleans
    for field in ("requires_live_test", "exception_eligible"):
        if field in data and not isinstance(data[field], bool):
            errors.append(f"{field} must be a boolean, got: {data[field]}")

    # linked_artifacts list
    if "linked_artifacts" in data:
        if not isinstance(data["linked_artifacts"], list):
            errors.append("linked_artifacts must be a list of strings")

    return errors, warnings


VALIDATORS = {
    "exception": validate_exception,
    "learning": validate_learning,
    "recipe": validate_recipe,
    "finding": validate_finding,
}


def main():
    parser = argparse.ArgumentParser(description="Validate markdown YAML frontmatter against schema")
    parser.add_argument("--type", required=True, choices=VALIDATORS.keys(), help="Schema type")
    parser.add_argument("--file", required=True, help="Path to markdown file")
    args = parser.parse_args()

    try:
        with open(args.file, "r") as f:
            content = f.read()
    except FileNotFoundError:
        result = {
            "valid": False,
            "type": args.type,
            "file": args.file,
            "errors": [f"File not found: {args.file}"],
            "warnings": [],
        }
        print(json.dumps(result, indent=2))
        sys.exit(1)

    data, parse_errors = parse_frontmatter(content)
    if data is None:
        result = {
            "valid": False,
            "type": args.type,
            "file": args.file,
            "errors": parse_errors,
            "warnings": [],
        }
        print(json.dumps(result, indent=2))
        sys.exit(1)

    errors, warnings = VALIDATORS[args.type](data)
    errors = parse_errors + errors
    valid = len(errors) == 0

    result = {
        "valid": valid,
        "type": args.type,
        "file": args.file,
        "errors": errors,
        "warnings": warnings,
    }
    print(json.dumps(result, indent=2))
    sys.exit(0 if valid else 1)


if __name__ == "__main__":
    main()
