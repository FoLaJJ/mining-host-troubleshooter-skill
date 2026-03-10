# Manual Shell Fallback

Use this when Python is unavailable, script execution is blocked, file writes are forbidden, or the session only allows basic shell commands.

## When To Switch

Switch to shell fallback and state `mode=shell_fallback` when any of these are true:

1. The host does not have a usable Python runtime.
2. Bundled scripts cannot be copied or executed.
3. The agent cannot write a case bundle locally.
4. The connection only allows a narrow shell.

## Required Session Markers

At the start of a shell-fallback run, emit:

1. `[MODE: SHELL_FALLBACK]`
2. `[PRIVILEGE: restricted|user|sudo|root]`
3. `[CHECKPOINT: scope_confirmed]`

After each major phase, emit another checkpoint.

## Four-Quadrant Decision Matrix

Choose the branch that matches the current host reality.

| Quadrant | sudo/root | systemd+journald | Priority | Recommended focus |
| --- | --- | --- | --- | --- |
| Q1 | yes | yes | Full read-only coverage | `journalctl`, `systemctl`, `/proc`, auth logs, services, cron, sockets, startup items, hashes |
| Q2 | yes | no | Root without systemd | `/var/log/*`, init scripts, cron, `/proc`, sockets, rc/local startup, hashes |
| Q3 | no | yes | User with systemd visibility | readable `journalctl`, readable unit files, current-user scope, sockets, home startup, histories |
| Q4 | no | no | Minimal shell | current-user processes, readable `/proc`, home persistence, readable logs, sockets if visible |

### Q1: sudo/root + systemd

Use the full workflow where possible. Prioritize `journalctl`, `systemctl`, service `ExecStart`, auth logs, cron, sockets, and artifact hashing.

### Q2: sudo/root + no systemd

Pivot away from `systemctl` and `journalctl`. Prioritize:

```bash
ps aux --sort=-%cpu | head -n 40
ss -antup 2>/dev/null || netstat -antup 2>/dev/null
ls -l /etc/init.d /etc/rc*.d 2>/dev/null
find /etc/cron* -maxdepth 3 -type f -printf '%TY-%Tm-%Td %TH:%TM %p
' 2>/dev/null | sort
sha256sum /bin/ps /usr/bin/ss 2>/dev/null || true
```

### Q3: no sudo/root + systemd readable

Use readable `journalctl` and unit metadata, but say coverage is partial:

```bash
journalctl -u ssh --no-pager | tail -n 200
systemctl list-units --type=service --all --no-pager 2>/dev/null
systemctl cat <service-name> 2>/dev/null
ps -fu "$USER"
```

### Q4: no sudo/root + no systemd

Restrict claims to user scope and readable data only:

```bash
ps -fu "$USER"
ls -la ~ ~/.config ~/.config/autostart ~/.ssh 2>/dev/null
crontab -l 2>/dev/null || true
grep -RniE 'miner|xmrig|stratum|autossh|clash' ~ 2>/dev/null | head -n 80
```

## Minimal Read-Only Flow

1. Scope and privilege self-check

```bash
date -u
whoami; id
sudo -n true >/dev/null 2>&1 && echo sudo_nopasswd=yes || echo sudo_nopasswd=no
hostnamectl 2>/dev/null || hostname
```

2. Command trust and environment

```bash
echo "$PATH"
for c in ps ss netstat ip systemctl journalctl lsattr sha256sum; do type -a "$c" 2>/dev/null || true; done
for c in ps ss netstat ip systemctl journalctl lsattr; do p=$(command -v "$c" 2>/dev/null || true); [ -n "$p" ] && sha256sum "$p"; done
```

3. Process, network, auth, persistence

```bash
ps aux --sort=-%cpu | head -n 40
ps aux | grep -Ei 'miner|xmrig|lolminer|trex|gminer|nbminer|clash|autossh|h32|h64|stratum' | grep -v grep
ss -antup 2>/dev/null || netstat -antup 2>/dev/null
journalctl -u ssh --no-pager | tail -n 200
grep -E 'Failed password|Accepted password|Invalid user|authentication failure' /var/log/auth.log /var/log/secure 2>/dev/null | tail -n 200
systemctl list-units --type=service --all --no-pager 2>/dev/null | grep -Ei 'miner|xmrig|lolminer|trex|gminer|nbminer|clash|autossh|proxy|python\.service|stratum'
find /etc/cron* -maxdepth 3 -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort
```

If the primary command is missing, pivot immediately instead of retrying the same tool:

```bash
ss -antup 2>/dev/null || netstat -antup 2>/dev/null || lsof -nPi 2>/dev/null || { head -n 30 /proc/net/tcp; head -n 30 /proc/net/udp; }
ip a 2>/dev/null || ifconfig -a 2>/dev/null || cat /proc/net/route
ps aux 2>/dev/null || for pid in $(ls /proc | grep -E '^[0-9]+$' | head -n 40); do tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null; done
journalctl -u ssh --no-pager 2>/dev/null || grep -E 'Failed password|Accepted password|Invalid user|authentication failure' /var/log/auth.log /var/log/secure 2>/dev/null
systemctl list-units --type=service --all --no-pager 2>/dev/null || service --status-all 2>/dev/null || ls -l /etc/init.d 2>/dev/null
```

4. Deleted logs or weak trust

```bash
last -Faiwx | head -n 80
lastb -Faiwx | head -n 80
lastlog | head -n 80
find /etc/systemd/system /lib/systemd/system -maxdepth 2 -type f -name '*.service' -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort
ps -ef 2>/dev/null | grep -E 'rsyslogd|syslog-ng|systemd-journald' | grep -v grep
grep -RniE '(Storage=|ForwardToSyslog=|SystemMaxUse=|RuntimeMaxUse=)' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null
find /root /home -xdev -maxdepth 3 \( -name '.bash_history' -o -name '.zsh_history' -o -name '.wget-hsts' -o -name '.lesshst' -o -name '.viminfo' \) -printf '%TY-%Tm-%Td %TH:%TM %u %s %p\n' 2>/dev/null | sort
```

5. GPU / CPU branch

```bash
nvidia-smi -L 2>/dev/null || true
nvidia-smi --query-gpu=index,name,utilization.gpu,temperature.gpu,power.draw --format=csv,noheader 2>/dev/null || true
lscpu
```

## Evidence Rules

1. If you cannot store artifacts or hashes, say so explicitly.
2. If a command output is partial because of privilege limits, record that as a gap.
3. If miner identity is not provable, output `[INCONCLUSIVE: process anomaly observed, miner signature not confirmed]`.
