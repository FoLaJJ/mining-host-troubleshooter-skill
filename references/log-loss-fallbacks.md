# Log Loss and Tampering Fallbacks

Use this when `auth.log`, `secure`, `syslog`, or journal data is missing/tampered.

## 1) Detect Integrity First

```bash
python scripts/check_log_integrity.py
```

Treat as high-risk if:

1. log path missing unexpectedly
2. log file symlinked to `/dev/null`
3. primary auth log is empty with suspicious timeline

## 2) Alternative Evidence Sources (Read-Only)

Authentication and session traces:

1. `last -Faiwx`
2. `lastb -Faiwx`
3. `lastlog`
4. `journalctl --list-boots --no-pager`
5. `journalctl -u ssh --no-pager`

Persistence and startup traces:

1. `find /etc/systemd/system /lib/systemd/system -name '*.service' -printf '%TY-%Tm-%Td %TH:%TM %p\n'`
2. `find /etc/cron* -maxdepth 3 -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n'`
3. `crontab -l`
4. `crontab -u <user> -l`

Runtime and lateral movement traces:

1. `ss -antup`
2. `lsof -nPi`
3. `/proc/<pid>/exe` linkage for suspicious processes
4. shell history files if present (read-only)
5. `/proc/net/{tcp,udp,unix}` when socket tools are unavailable

Logging pipeline traces:

1. `ps -ef | grep -E 'rsyslogd|syslog-ng|systemd-journald' | grep -v grep`
2. `grep -RniE '(Storage=|ForwardToSyslog=|SystemMaxUse=|RuntimeMaxUse=)' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf /etc/rsyslog.conf /etc/rsyslog.d/*.conf`
3. `find /var/log -maxdepth 2 -type l -printf '%p -> %l\n'`

Residual user and package traces:

1. `find /root /home -xdev -maxdepth 3 \( -name '.bash_history' -o -name '.zsh_history' -o -name '.wget-hsts' -o -name '.lesshst' -o -name '.viminfo' \) -printf '%TY-%Tm-%Td %TH:%TM %u %s %p\n'`
2. `grep -HniE '(xmrig|miner|stratum|curl .*[|] *sh|wget .*[|] *sh|/tmp/|/var/tmp/|/dev/shm/)' /root/.*history /home/*/.*history /root/.wget-hsts /home/*/.wget-hsts /root/.lesshst /home/*/.lesshst /root/.viminfo /home/*/.viminfo`
3. `grep -HniE '(install|upgrade|remove|xmrig|miner|cuda|nvidia|rocm|docker|containerd|kubelet)' /var/log/apt/history.log /var/log/dpkg.log /var/log/dnf.log /var/log/yum.log /var/log/pacman.log /var/log/zypper.log`

Startup and scheduler traces:

1. `systemctl list-timers --all --no-pager`
2. `find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' \) -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`
3. `find /etc/cron* -maxdepth 3 -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort`
4. `find /root/.ssh /home/*/.ssh -maxdepth 2 -type f -name 'authorized_keys' -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n' | sort`

## 3) Confidence Downgrade Rules

1. If core auth logs are missing and no strong side evidence exists, mark attribution as `inconclusive`.
2. If IP linkage is incomplete, mark `untraceable` or `unknown`.
3. Explicitly list missing artifacts in final report.

## 4) Prohibited Actions in This Stage

1. deleting or truncating logs/history
2. forcing log rotation/cleanup
3. mutation commands without user approval
