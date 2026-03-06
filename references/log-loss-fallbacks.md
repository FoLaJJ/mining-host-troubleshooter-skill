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

## 3) Confidence Downgrade Rules

1. If core auth logs are missing and no strong side evidence exists, mark attribution as `inconclusive`.
2. If IP linkage is incomplete, mark `untraceable` or `unknown`.
3. Explicitly list missing artifacts in final report.

## 4) Prohibited Actions in This Stage

1. deleting or truncating logs/history
2. forcing log rotation/cleanup
3. mutation commands without user approval
