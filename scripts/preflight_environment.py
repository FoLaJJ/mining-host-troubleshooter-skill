#!/usr/bin/env python3
"""Preflight environment and command integrity checks for mining diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any


TRUSTED_PREFIXES = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/local/bin/")
TRUSTED_COMMAND_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin")

CRITICAL_COMMANDS: dict[str, list[str]] = {
    "shell_introspection": ["type", "command", "alias"],
    "service_control": ["systemctl", "service"],
    "process": ["ps", "top"],
    "network_sockets": ["ss", "netstat", "lsof"],
    "route": ["ip", "route", "ifconfig"],
    "logs": ["journalctl", "dmesg", "last", "lastlog"],
    "gpu_nvidia": ["nvidia-smi"],
    "gpu_amd": ["rocm-smi"],
    "cpu_temp": ["sensors"],
    "attrs": ["lsattr", "chattr"],
    "core_tools": ["uptime", "w"],
    "file_metadata": ["stat", "readlink"],
    "hashing": ["sha256sum", "shasum", "openssl", "python3"],
    "downloads": ["curl", "wget"],
}

FALLBACK_CHAINS: dict[str, list[str]] = {
    "shell_introspection": ["type", "command -v", "whereis"],
    "service_control": ["systemctl", "service", "/etc/init.d", "rc scripts"],
    "process": ["ps", "top", "/proc/<pid>/{cmdline,exe,status}"],
    "network_sockets": ["ss", "netstat", "lsof", "/proc/net/{tcp,udp,unix}"],
    "route": ["ip", "route", "ifconfig", "/proc/net/route"],
    "logs": ["journalctl", "/var/log/{auth.log,secure,syslog,messages}", "last", "lastlog"],
    "gpu_nvidia": ["nvidia-smi", "/proc/driver/nvidia", "lspci"],
    "gpu_amd": ["rocm-smi", "lspci"],
    "cpu_temp": ["sensors", "/sys/class/thermal", "lscpu"],
    "attrs": ["lsattr", "stat", "package metadata"],
    "core_tools": ["uptime", "w", "/proc/uptime"],
    "file_metadata": ["stat", "readlink", "ls -l"],
    "hashing": ["sha256sum", "shasum -a 256", "openssl dgst -sha256", "python hashlib"],
    "downloads": ["curl", "wget", "shell traces", "package manager history"],
}


def run(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def resolve_command_path(command: str) -> tuple[str, str]:
    path = shutil.which(command)
    if path:
        return path, "PATH"
    for base in TRUSTED_COMMAND_DIRS:
        candidate = os.path.join(base, command)
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate, "trusted_scan"
    return "", "missing"


def detect_linux_release() -> dict[str, str]:
    os_release = Path("/etc/os-release")
    data: dict[str, str] = {}
    if not os_release.exists():
        return data
    for line in os_release.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"')
    return data


def detect_package_manager() -> str:
    for pm in ("apt-get", "dnf", "yum", "pacman", "zypper"):
        if shutil.which(pm):
            return pm
    return "unknown"


def package_owner(path: str, package_manager: str) -> str:
    if package_manager == "apt-get":
        code, out, _ = run(["dpkg", "-S", path])
        return out if code == 0 else "unknown"
    if package_manager in {"dnf", "yum"}:
        code, out, _ = run(["rpm", "-qf", path])
        return out if code == 0 else "unknown"
    if package_manager == "pacman":
        code, out, _ = run(["pacman", "-Qo", path])
        return out if code == 0 else "unknown"
    if package_manager == "zypper":
        code, out, _ = run(["rpm", "-qf", path])
        return out if code == 0 else "unknown"
    return "unknown"


def sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "hash_failed"


def probe_shell() -> str:
    return shutil.which("bash") or shutil.which("sh") or ""


def check_alias_and_type(command: str) -> dict[str, Any]:
    result: dict[str, Any] = {"alias": "unknown", "type": "unknown"}
    shell = probe_shell()
    if not shell:
        result["alias"] = "shell_unavailable"
        result["type"] = "shell_unavailable"
        return result

    code_alias, out_alias, err_alias = run([shell, "-lc", f"alias {command}"])
    if code_alias == 0 and out_alias:
        result["alias"] = out_alias
    elif code_alias != 0:
        result["alias"] = "not_aliased"
    else:
        result["alias"] = err_alias or "not_aliased"

    code_type, out_type, err_type = run([shell, "-lc", f"type -a {command}"])
    result["type"] = out_type if code_type == 0 else (err_type or "not_found")
    return result


def command_record(command: str, package_manager: str) -> dict[str, Any]:
    path, path_source = resolve_command_path(command)
    record: dict[str, Any] = {
        "command": command,
        "available": bool(path),
        "path": path or "missing",
        "path_source": path_source,
    }

    alias_type = check_alias_and_type(command)
    record.update(alias_type)

    if not path:
        record["trust"] = "missing"
        return record

    real = os.path.realpath(path)
    record["realpath"] = real
    record["trusted_prefix"] = any(real.startswith(prefix) for prefix in TRUSTED_PREFIXES)

    try:
        st = os.stat(real)
        mode = stat.S_IMODE(st.st_mode)
        record["mode_octal"] = oct(mode)
        record["group_writable"] = bool(mode & stat.S_IWGRP)
        record["world_writable"] = bool(mode & stat.S_IWOTH)
    except OSError as exc:
        record["mode_error"] = str(exc)

    record["sha256"] = sha256(real)
    record["package_owner"] = package_owner(real, package_manager)

    suspicious = []
    if not record.get("trusted_prefix", False):
        suspicious.append("binary_outside_trusted_paths")
    if path_source != "PATH":
        suspicious.append("command_not_found_via_path")
    if record.get("group_writable"):
        suspicious.append("group_writable_binary")
    if record.get("world_writable"):
        suspicious.append("world_writable_binary")
    alias_text = str(record.get("alias", ""))
    if alias_text not in {"not_aliased", "unknown", "bash_unavailable"}:
        suspicious.append("command_is_aliased")
    type_text = str(record.get("type", ""))
    if " is a function" in type_text:
        suspicious.append("command_is_shell_function")

    record["suspicious_flags"] = suspicious
    record["trust"] = "suspicious" if suspicious else "ok"
    return record


def resolve_fallbacks(package_manager: str) -> dict[str, Any]:
    resolved: dict[str, Any] = {}
    for capability, candidates in CRITICAL_COMMANDS.items():
        picked = "missing"
        for cmd in candidates:
            if resolve_command_path(cmd)[0]:
                picked = cmd
                break
        resolved[capability] = {
            "selected": picked,
            "candidates": FALLBACK_CHAINS.get(capability, candidates),
        }

    if package_manager == "apt-get":
        resolved["pkg_install"] = "apt-get install"
    elif package_manager in {"dnf", "yum"}:
        resolved["pkg_install"] = f"{package_manager} install"
    elif package_manager == "pacman":
        resolved["pkg_install"] = "pacman -S"
    elif package_manager == "zypper":
        resolved["pkg_install"] = "zypper install"
    else:
        resolved["pkg_install"] = "manual"
    return resolved


def gather_report() -> dict[str, Any]:
    system = platform.system().lower()
    report: dict[str, Any] = {
        "os_family": system,
        "hostname": platform.node(),
        "python": platform.python_version(),
    }

    if system == "linux":
        report["os_release"] = detect_linux_release()
        package_manager = detect_package_manager()
        report["package_manager"] = package_manager
        report["fallbacks"] = resolve_fallbacks(package_manager)

        checks = []
        seen: set[str] = set()
        for candidates in CRITICAL_COMMANDS.values():
            for cmd in candidates:
                if cmd in seen:
                    continue
                seen.add(cmd)
                checks.append(command_record(cmd, package_manager))
        report["command_checks"] = checks
    else:
        report["note"] = "Detailed command integrity checks currently target Linux hosts."

    return report


def print_human(report: dict[str, Any]) -> None:
    print(f"os_family: {report.get('os_family')}")
    if report.get("os_release"):
        os_rel = report["os_release"]
        print(f"distro: {os_rel.get('ID', 'unknown')} {os_rel.get('VERSION_ID', '')}".strip())
    if report.get("package_manager"):
        print(f"package_manager: {report['package_manager']}")

    fallbacks = report.get("fallbacks", {})
    if fallbacks:
        print("fallbacks:")
        for key, value in fallbacks.items():
            if isinstance(value, dict):
                selected = value.get("selected", "missing")
                chain = " -> ".join(value.get("candidates", []))
                print(f"  {key}: {selected} | chain: {chain}")
            else:
                print(f"  {key}: {value}")

    checks = report.get("command_checks", [])
    if checks:
        print("command_checks:")
        for item in checks:
            print(f"- {item['command']}: {item['trust']} ({item['path']})")
            if item.get("suspicious_flags"):
                print(f"  suspicious_flags: {', '.join(item['suspicious_flags'])}")
            alias = item.get("alias", "")
            if alias not in {"not_aliased", "unknown", "bash_unavailable"}:
                print(f"  alias: {alias}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Preflight distro detection, command availability, and trust checks."
    )
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    args = parser.parse_args()

    report = gather_report()
    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
