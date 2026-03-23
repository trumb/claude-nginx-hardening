---
name: rotate-tls-certs
description: Rotate TLS certificates for all nginx vhosts
profile: edge-public
execution_class: W1+X1
requires_network: true
requires_remote_exec: false
required_env_vars:
  - CERT_PATH
  - KEY_PATH
confirmation_checkpoints:
  - Verify new certificate validity
  - Confirm nginx config test passes
allows_emergency_mode: true
max_privilege_level: W1
schedule_mode: cron
steps:
  - Backup current certificates
  - Deploy new certificates
  - Reload nginx
outputs:
  - /var/log/cert-rotation.log
---

Recipe for rotating TLS certificates across edge-public nginx instances.
