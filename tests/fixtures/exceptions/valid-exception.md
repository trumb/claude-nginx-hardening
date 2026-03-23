---
exception_id: EXC-0001
finding_id: NH-AUDIT-HEADERS-0004
reason: Legacy PHP application requires pass-through for specific endpoint
compensating_control: WAF rule on upstream load balancer blocks malicious PHP payloads
severity_tier: high
owner: platform-team
scope: location
linked_config_path: /etc/nginx/sites-enabled/legacy-app
approval_reference: SEC-2026-0142
created_at: 2026-03-23
last_reviewed_at: 2026-03-23
review_by: 2026-09-23
---

Legacy PHP application at /api/legacy requires PHP pass-through.
