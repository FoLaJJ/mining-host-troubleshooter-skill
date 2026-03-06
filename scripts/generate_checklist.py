#!/usr/bin/env python3
"""Generate read-only diagnostic checklists for mining host incidents."""

from __future__ import annotations

import argparse


SHELL_FALLBACK_GUARDRAILS = [
    "If Python scripts are unavailable, switch to manual shell fallback and state [MODE: SHELL_FALLBACK].",
    "At session start, record [PRIVILEGE: restricted|user|sudo|root] based on the actual shell.",
    "After each phase, record [CHECKPOINT: <stage>].",
    "When evidence is partial, use [INCONCLUSIVE: ...] instead of speculative explanations.",
]

COMMON_LINUX = [
    "date; timedatectl",
    "uptime; who -b",
    "hostnamectl || hostname",
    "free -h; vmstat 1 5",
    "df -hT; lsblk",
    "ip a; ip route; ss -tulpn",
    "journalctl -p err -n 200 --no-pager",
    "dmesg -T | tail -n 200",
    "ps aux --sort=-%cpu | head -n 30",
]

LOG_FALLBACK_LINUX = [
    "python scripts/check_log_integrity.py",
    "ls -l /var/log/auth.log* /var/log/secure /var/log/messages /var/log/syslog 2>/dev/null",
    "stat /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null",
    "last -Faiwx | head -n 60",
    "lastb -Faiwx | head -n 60",
    "lastlog | head -n 80",
    "journalctl --list-boots --no-pager",
    "journalctl -u ssh --no-pager | tail -n 200",
    "find /etc/systemd/system /lib/systemd/system -maxdepth 2 -type f -name '*.service' -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort",
    "find /etc/cron* -maxdepth 3 -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort",
]

COMMON_WINDOWS = [
    "Get-Date; w32tm /query /status",
    "Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime",
    "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber",
    "Get-Process | Sort-Object CPU -Descending | Select-Object -First 30",
    "Get-NetIPAddress; Get-NetRoute",
    "Get-WinEvent -LogName System -MaxEvents 200",
]

GPU_LINUX = [
    "nvidia-smi -L",
    "nvidia-smi --query-gpu=index,name,utilization.gpu,temperature.gpu,power.draw,power.limit,clocks.sm,clocks.mem --format=csv,noheader",
    "rocm-smi --showproductname --showuse --showtemp --showpower --showclocks",
    "lspci | grep -Ei 'vga|3d|nvidia|amd'",
]

CPU_LINUX = [
    "lscpu",
    "cat /proc/cpuinfo | head -n 80",
    "sensors",
    "grep -i huge /proc/meminfo",
    "numactl --hardware",
]

MINER_GENERIC = [
    "ps aux | grep -Ei 'miner|xmrig|lolminer|trex|gminer|nbminer' | grep -v grep",
    "tail -n 200 /var/log/syslog",
    "tail -n 200 <miner-log-path>",
]

ENTERPRISE_GOVERNANCE = [
    "Define incident scope: target host, expected miner role, affected business service, and observation window.",
    "Freeze non-essential changes on the target until read-only collection completes.",
    "Start with command-trust and log-integrity checks before deep collection.",
    "Collect volatile and high-value evidence into reports/<case>/ instead of ad-hoc folders.",
    "Keep conclusions evidence-bound; downgrade confidence immediately when trust or logs are weak.",
    "Treat performance tuning or pool-path checks as a separate, non-default workflow.",
]

ENTERPRISE_DELIVERY = [
    "Run python scripts/validate_case_bundle.py --case-dir reports/<case> --input reports/<case>/evidence/evidence.reviewed.auto.json --strict",
    "Export only redacted report artifacts unless raw evidence transfer is explicitly required.",
    "Retain meta/artifact_hashes.json and meta/case_manifest.json with the case bundle.",
    "If a prior case exists for the same host, run compare_case_bundles.py before closing the incident.",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a read-only incident checklist.")
    parser.add_argument("--os", choices=["linux", "windows"], default="linux")
    parser.add_argument("--mode", choices=["local", "remote"], default="remote")
    parser.add_argument("--type", choices=["auto", "gpu", "cpu", "mixed"], default="auto")
    parser.add_argument(
        "--profile",
        choices=["standard", "enterprise-self-audit"],
        default="standard",
        help="Checklist profile. enterprise-self-audit adds enterprise-style Linux incident checking controls.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    lines: list[str] = []

    lines.append(f"# Checklist ({args.os}, {args.mode}, target={args.type}, profile={args.profile})")
    lines.append("")

    if args.profile == "enterprise-self-audit":
        lines.append("## -1) Enterprise Governance")
        lines.extend(ENTERPRISE_GOVERNANCE)
        lines.append("")

    lines.append("## Guardrails")
    lines.extend(SHELL_FALLBACK_GUARDRAILS)
    lines.append("")

    lines.append("## 0) Environment Preflight (Read-Only)")
    lines.append("python scripts/preflight_environment.py")
    lines.append("If suspicious command trust flags appear, switch to absolute paths and escalate.")
    lines.append("If Python or file-write capability is unavailable, continue with manual shell commands instead of stopping the investigation.")
    lines.append("")

    lines.append("## 1) Common Baseline (Read-Only)")
    lines.extend(COMMON_LINUX if args.os == "linux" else COMMON_WINDOWS)
    lines.append("")

    lines.append("## 2) Miner and Process Signals (Read-Only)")
    lines.extend(MINER_GENERIC)

    if args.os == "linux":
        if args.type in {"auto", "gpu", "mixed"}:
            lines.append("")
            lines.append("## 3) GPU Branch (Read-Only)")
            lines.extend(GPU_LINUX)
        if args.type in {"auto", "cpu", "mixed"}:
            lines.append("")
            lines.append("## 4) CPU Branch (Read-Only)")
            lines.extend(CPU_LINUX)

    lines.append("")
    lines.append("## 5) Safety")
    lines.append("Use scripts/command_guard.py before any non-read-only command.")
    lines.append("Use scripts/redact_output.py before sharing output externally.")
    lines.append("Write all collected artifacts into reports/<case>/ rather than ad-hoc folders.")

    if args.os == "linux":
        lines.append("")
        lines.append("## 6) If Logs Are Missing/Tampered (Read-Only Fallback)")
        lines.extend(LOG_FALLBACK_LINUX)

    if args.profile == "enterprise-self-audit":
        lines.append("")
        lines.append("## 7) Enterprise Delivery")
        lines.extend(ENTERPRISE_DELIVERY)

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
