# Case Learnings from Local PDF Records

Source set:

1. `12月16日顽固木马排查.pdf`
2. `<internal-host-A>主机排查.pdf`
3. `<internal-host-B>主机排查.pdf`

Sensitive credentials present in source records were intentionally not copied here.

## Case Pattern A: Core Utility Tampering + Immutable/Append Flags

Observed signals:

1. Multiple system binaries diverged from package baseline (`dpkg -V` mismatch).
2. `rm` failed with `Operation not permitted`.
3. `lsattr` output indicated immutable/append flags (`i`, `a`) on suspicious binaries.
4. `chattr` itself appeared tampered and unusable in one record.

Operational implications:

1. Command trust checks must happen before relying on tool output.
2. `lsattr/chattr/systemctl/netstat/uptime/w` require provenance verification.
3. Recovery may require package integrity restore and forensic-safe flag handling.

## Case Pattern B: Service Masquerading for Mining Workload

Observed signals:

1. Suspicious service name masquerading as normal component (`<service-name>.service`).
2. Service command line included proxy and mining arguments.
3. Journal timeline provided earliest/latest active windows.

Operational implications:

1. Always inspect unit file content and not only unit name.
2. Build timeline from journal events to bound compromise window.
3. Mark service findings as confirmed only if unit content and runtime evidence align.

## Case Pattern C: Multi-Layer Persistence and Hidden Process Chain

Observed signals:

1. Loader chain with scripts and binaries (`x`, `a`, `run`, `upd`, `h32/h64`, `-zsh`).
2. Frequent cron execution (`* * * * *`) used as watchdog.
3. PID spoofing behavior via `bios.pid`.

Operational implications:

1. Check service + cron + user startup files as a combined persistence set.
2. Verify process identity via `/proc/<pid>/exe` and command lineage.
3. Avoid attributing process identity by process name alone.

## Case Pattern D: Lateral Movement and Traceability Gaps

Observed signals:

1. Pivot host used for internal SSH probing and connections.
2. History/log tampering attempts were present in records.
3. Some external source IPs were documented as no longer attributable.

Operational implications:

1. IP tracking needs explicit status: `traced`, `untraceable`, `unknown`.
2. For untraceable IPs, report reason and stop attribution there.
3. Use surviving evidence (`journalctl`, saved keys, command traces) for bounded claims.

## IOC Fragments (from records; validate before action)

1. Service path pattern: `/etc/systemd/system/<masqueraded-service>.service`
2. Hidden process argument: `-zsh`
3. Persistence file names: `bios.pid`, `cron.d`, `upd`, `run`
4. Suspicious local proxy listener pattern on a non-business forwarding port
5. Mentioned external endpoint examples in records (treat as historical context, not active IOC): `<redacted-ip-1>:10400`, `<redacted-ip-2>`, `<redacted-ip-3>:12345`

## Usage Rule

Treat all case learnings as hypotheses until reproduced on the current host with current evidence.
