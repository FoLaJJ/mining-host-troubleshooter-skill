# Legitimate High-Compute Review

Use this review whenever high CPU, high GPU utilization, or long-running compute-heavy workloads are observed.

Do not label high utilization as mining solely because it is sustained or resource-intensive.

## Objective

Separate legitimate workloads from mining-like abuse using evidence, not intuition.

## Required Questions

1. What business workload is expected on this host right now?
2. Is the workload declared by the operator or documented in change / deployment records?
3. Does the process name, binary path, parent process, service unit, container image, and network behavior match that declared workload?
4. Does the same workload appear in prior known-clean baseline cases from the same host?
5. Are outbound endpoints expected for that workload?

## Benign Signals

Examples of signals that can support a benign explanation:

- expected renderer, scientific compute, ML training, video encode, CI build, compression, or load test job
- parent process or service matches known deployment tooling
- binary path is in trusted application directories
- container image or package matches approved software inventory
- baseline history shows the same process tree and same outbound destinations during known-clean periods

## Suspicious Signals

Examples of signals that raise suspicion even under high utilization:

- process name masquerades as system service or kernel worker
- binary launches from `/tmp`, `/var/tmp`, `/dev/shm`, user cache, or hidden path
- parent process is shell history, curl/wget pipe, ad hoc Python, or suspicious service unit
- outbound traffic matches stratum, pool, wallet, or repeated short-interval reconnect behavior
- workload was not declared but resource usage is sustained
- service file, cron, PAM, preload, sudoers, or key material changed around the same time

## Decision Rule

Use the following outcomes:

- `[CONFIRMED: legitimate high-compute workload]` only when workload intent and runtime evidence agree.
- `[INCONCLUSIVE: high-compute workload observed, legitimacy not established]` when utilization is high but miner evidence is absent.
- `[CONFIRMED: suspicious mining-like behavior]` only when runtime evidence, persistence, or network IOC evidence supports it.

## Report Requirement

If a legitimate workload is declared, record it in the case as `expected_workload` and mention whether runtime evidence matched it.
