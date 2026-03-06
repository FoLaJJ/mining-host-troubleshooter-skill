# Root Cause Matrix

This matrix is for performance diagnosis only. Do not use it as the default incident-triage path for suspected compromise.

Use this table to move from symptom to evidence-backed diagnosis.

| Symptom | Likely Cause | Evidence to Confirm | Typical Remediation (Approval-Gated if Mutating) |
| --- | --- | --- | --- |
| Sudden hashrate drop on GPU rig | Thermal throttle | `nvidia-smi` temp/power + lower clocks | Improve cooling, tune power/fan profile |
| High reject/stale share ratio | Pool path instability | ping loss, traceroute jitter, miner reject logs | Route/DNS fix, pool endpoint switch |
| Frequent miner restarts | Miner crash loop or OOM | process restarts + kernel/syslog errors | Config fix, memory adjustment, version pinning |
| One GPU underperforming | PCIe lane/bus error or bad riser | dmesg PCIe errors + per-GPU utilization gap | Reseat/swap riser, slot remap |
| All GPUs low utilization | Driver fault or power cap issue | driver errors + low clocks at normal temps | Driver rollback/pin, power policy correction |
| CPU miner unstable | Thermal or thread config issue | high CPU temp + throttling + affinity mismatch | Cooling, thread/affinity tuning, hugepages |
| Offline worker after reboot | Service/unit startup issue | systemd unit status and logs | unit fix, dependency ordering correction |
| Intermittent pool disconnect | DNS or firewall policy drift | DNS mismatch + firewall logs | DNS standardization, policy correction |

## Confidence Scoring

- High: 3+ independent signals align in time and magnitude.
- Medium: 2 signals align; one gap remains.
- Low: weak or indirect signal only.

Always state confidence explicitly in the final report.
