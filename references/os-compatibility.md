# OS Compatibility and Command Fallbacks

Use this file when command sets differ across Ubuntu, Debian, Arch, RHEL-family, or minimal images.

## 1) Detect Distribution First

Run:

```bash
cat /etc/os-release
uname -a
```

Or run:

```bash
python scripts/preflight_environment.py
```

## 2) Package Manager Mapping

| Family | Install Command |
| --- | --- |
| Ubuntu/Debian | `apt-get install <pkg>` |
| RHEL/CentOS/Rocky/Fedora | `dnf install <pkg>` or `yum install <pkg>` |
| Arch | `pacman -S <pkg>` |
| SUSE | `zypper install <pkg>` |

## 3) Command Availability Fallbacks

| Capability | Preferred | Fallback |
| --- | --- | --- |
| Socket inspection | `ss -tulpn` | `netstat -tulpn` |
| Route table | `ip route` | `route -n` |
| Process overview | `ps aux` | `top -b -n 1` |
| System logs | `journalctl` | `/var/log/syslog` or `/var/log/messages` |
| GPU NVIDIA | `nvidia-smi` | miner log + driver log |
| GPU AMD | `rocm-smi` | `dmesg` + miner log |
| CPU temperature | `sensors` | `cat /sys/class/thermal/thermal_zone*/temp` |
| File attrs | `lsattr` | `stat` + package verification of `lsattr` binary |

## 4) If a Command Is Missing

1. Try fallback command first.
2. Keep investigation read-only.
3. If installation is required, request approval before package install.
4. Re-run baseline collection after installing tooling.

## 5) Cross-Platform Note

On Windows hosts, use PowerShell equivalents for process/network/event checks.
