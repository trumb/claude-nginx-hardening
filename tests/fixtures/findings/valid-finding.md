---
finding_id: NH-AUDIT-HEADERS-0001
category: missing-security-headers
severity: high
confidence: 0.95
source_layers:
  - config-audit
  - response-check
scope: server-block
blast_radius: vhost-group
recommended_action: Add security-hardening.conf include to server block
rule_class: A
requires_live_test: true
exception_eligible: true
linked_artifacts:
  - /etc/nginx/sites-enabled/example.conf
---

Server block for example.com is missing the security-hardening.conf include,
leaving it without standard security headers.
