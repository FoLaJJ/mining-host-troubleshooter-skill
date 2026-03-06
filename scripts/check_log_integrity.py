#!/usr/bin/env python3
"""Assess whether key forensic logs appear missing or tampered."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/auth.log.1",
    "/var/log/secure",
    "/var/log/messages",
    "/var/log/syslog",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
]


def run(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(microsecond=0).isoformat()


def classify_log(path: str) -> dict[str, Any]:
    p = Path(path)
    entry: dict[str, Any] = {
        "path": path,
        "exists": p.exists() or p.is_symlink(),
        "status": "ok",
        "notes": [],
    }
    if not entry["exists"]:
        entry["status"] = "missing"
        entry["notes"].append("file_missing")
        return entry

    try:
        lst = os.lstat(path)
    except OSError as exc:
        entry["status"] = "unknown"
        entry["notes"].append(f"stat_error:{exc}")
        return entry

    entry["mode_octal"] = oct(stat.S_IMODE(lst.st_mode))
    entry["mtime_utc"] = iso(lst.st_mtime)
    entry["size_bytes"] = lst.st_size

    if stat.S_ISLNK(lst.st_mode):
        entry["is_symlink"] = True
        target = os.readlink(path)
        entry["symlink_target"] = target
        if target == "/dev/null":
            entry["status"] = "tampered"
            entry["notes"].append("symlink_to_dev_null")
        return entry

    entry["is_symlink"] = False
    if lst.st_size == 0 and any(k in path for k in ["auth.log", "secure", "messages", "syslog"]):
        entry["status"] = "suspicious"
        entry["notes"].append("empty_primary_log")
    return entry


def journald_status() -> dict[str, Any]:
    info: dict[str, Any] = {}
    persistent_dir = Path("/var/log/journal")
    info["persistent_dir_exists"] = persistent_dir.exists()

    if shutil.which("journalctl"):
        code, out, err = run(["journalctl", "--disk-usage"])
        info["journalctl_available"] = True
        info["disk_usage"] = out if code == 0 else "unknown"
        info["disk_usage_error"] = "" if code == 0 else err

        code2, out2, _ = run(["journalctl", "--list-boots", "--no-pager"])
        info["boot_history_available"] = code2 == 0 and bool(out2.strip())
        info["boot_history_lines"] = len(out2.splitlines()) if out2 else 0
    else:
        info["journalctl_available"] = False
        info["disk_usage"] = "journalctl_missing"
        info["boot_history_available"] = False
        info["boot_history_lines"] = 0
    return info


def fallback_sources() -> list[str]:
    sources = [
        "last -Faiwx",
        "lastb -Faiwx",
        "lastlog",
        "journalctl --list-boots --no-pager",
        "journalctl -u ssh --no-pager",
        "stat /etc/systemd/system/*.service",
        "find /etc/cron* -maxdepth 3 -type f -ls",
        "crontab -l",
        "crontab -u <user> -l",
        "stat /var/log/wtmp /var/log/btmp /var/log/lastlog",
        "lsof -nPi",
        "ss -antup",
    ]
    return sources


def overall_status(logs: list[dict[str, Any]]) -> str:
    levels = {"ok": 1, "suspicious": 2, "missing": 3, "tampered": 4, "unknown": 3}
    top = 1
    top_name = "ok"
    for item in logs:
        lvl = levels.get(str(item.get("status")), 3)
        if lvl > top:
            top = lvl
            top_name = str(item.get("status"))
    return top_name


def main() -> int:
    parser = argparse.ArgumentParser(description="Check log integrity and fallback evidence sources.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    args = parser.parse_args()

    system = platform.system().lower()
    if system != "linux":
        payload = {
            "overall_status": "unsupported_os",
            "os_family": system,
            "note": "check_log_integrity.py currently targets Linux log paths.",
            "fallback_sources": [],
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=True, indent=2))
            return 0
        print(f"overall_status: {payload['overall_status']}")
        print(f"os_family: {system}")
        print(payload["note"])
        return 0

    logs = [classify_log(path) for path in LOG_PATHS]
    journal = journald_status()
    overall = overall_status(logs)
    payload = {
        "overall_status": overall,
        "logs": logs,
        "journald": journal,
        "fallback_sources": fallback_sources(),
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 0

    print(f"overall_status: {overall}")
    for entry in logs:
        note = ",".join(entry.get("notes", []))
        print(f"- {entry['path']}: {entry['status']} notes={note or 'none'}")
    print("journald:")
    print(f"  persistent_dir_exists: {journal.get('persistent_dir_exists')}")
    print(f"  journalctl_available: {journal.get('journalctl_available')}")
    print(f"  disk_usage: {journal.get('disk_usage')}")
    print(f"  boot_history_lines: {journal.get('boot_history_lines')}")
    print("fallback_sources:")
    for cmd in payload["fallback_sources"]:
        print(f"  - {cmd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
