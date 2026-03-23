---
type: attack-pattern
status: active
discovered: 2026-03-20
source: log-analysis
run_id: run-20260320-001
finding_ids:
  - NH-LOG-SCAN-0001
  - NH-LOG-SCAN-0002
hit_count: 47
---

Observed repeated path traversal attempts targeting /etc/passwd via
double-encoded URL sequences. Pattern matches known scanner signature.
