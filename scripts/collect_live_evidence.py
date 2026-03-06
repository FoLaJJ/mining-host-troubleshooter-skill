#!/usr/bin/env python3
"""Collect read-only live evidence and generate report-ready evidence JSON."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import paramiko
except Exception:  # pragma: no cover - optional runtime dependency
    paramiko = None


@dataclass(frozen=True)
class Probe:
    source: str
    command: str


COLLECTOR_VERSION = "2026.03.06.3"


def command_hash(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest()


BASE_PROBES = [
    Probe("system", "date -Is; timedatectl show -p Timezone -p LocalRTC -p NTPSynchronized -p NTP 2>/dev/null || true; uname -a; cat /etc/os-release 2>/dev/null"),
    Probe("system", "uptime; who -b"),
    Probe("system", "free -h; df -hT"),
    Probe("privilege", "id; whoami; sudo -n -l 2>/dev/null | head -n 80 || true"),
    Probe(
        "trust",
        "echo \"PATH=$PATH\"; "
        "for c in lsattr chattr systemctl ss netstat ip route journalctl ps last lastlog crontab find grep awk sed; do "
        "echo \"## $c\"; type -a \"$c\" 2>/dev/null || echo \"$c: not_found\"; "
        "done",
    ),
    Probe(
        "trust",
        "for c in lsattr chattr systemctl ss ip journalctl ps; do "
        "p=$(command -v \"$c\" 2>/dev/null || true); "
        "if [ -n \"$p\" ]; then ls -l \"$p\"; fi; "
        "done",
    ),
    Probe(
        "trust",
        "if command -v sha256sum >/dev/null 2>&1; then "
        "for c in lsattr chattr systemctl ss ip journalctl ps; do "
        "p=$(command -v \"$c\" 2>/dev/null || true); "
        "if [ -n \"$p\" ]; then sha256sum \"$p\"; fi; "
        "done; "
        "else echo 'sha256sum unavailable'; fi",
    ),
    Probe("network", "ip a; ip route"),
    Probe("network", "ss -antup || netstat -antup"),
    Probe("process", "ps aux --sort=-%cpu | head -n 80"),
    Probe("process", "ps aux | grep -Ei 'miner|xmrig|lolminer|trex|gminer|nbminer|clash|autossh|h32|h64|\\-zsh' | grep -v grep"),
    Probe("auth", "journalctl -u ssh --no-pager | tail -n 300"),
    Probe("auth", "grep -E 'Failed password|Accepted password|Invalid user|authentication failure' /var/log/auth.log /var/log/secure 2>/dev/null | tail -n 300 || true"),
    Probe("auth", "journalctl -u ssh --no-pager | grep -Ei 'Failed password|Invalid user|authentication failure|Connection closed by authenticating user' | tail -n 300 || true"),
    Probe("auth", "last -Faiwx | head -n 120"),
    Probe("auth", "lastb -Faiwx | head -n 120"),
    Probe("auth", "lastlog | head -n 120"),
    Probe("persistence", "find /etc/systemd/system /lib/systemd/system -maxdepth 2 -type f -name '*.service' -printf '%TY-%Tm-%Td %TH:%TM %p\\n' 2>/dev/null | sort"),
    Probe("persistence", "systemctl list-unit-files --type=service 2>/dev/null | grep -Ei 'miner|xmrig|gminer|lolminer|trex|nbminer|python\\.service|clash|autossh|frp|ngrok|proxy|kawpow|stratum' || true"),
    Probe("persistence", "systemctl list-units --type=service --all 2>/dev/null | grep -Ei 'miner|xmrig|gminer|lolminer|trex|nbminer|python\\.service|clash|autossh|frp|ngrok|proxy|kawpow|stratum' || true"),
    Probe("persistence", "grep -RniE '(kawpow|xmrig|gminer|lolminer|trex|nbminer|stratum|51\\.195\\.|196\\.251\\.|7890|python2 --proxy|clash|autossh)' /etc/systemd/system /lib/systemd/system 2>/dev/null | head -n 120 || true"),
    Probe("persistence", "find /etc/cron* -maxdepth 3 -type f -printf '%TY-%Tm-%Td %TH:%TM %p\\n' 2>/dev/null | sort"),
    Probe("persistence", "grep -RniE '(kawpow|xmrig|gminer|lolminer|trex|nbminer|stratum|51\\.195\\.|196\\.251\\.|7890|clash|autossh|h32|h64|\\-zsh)' /etc/cron* 2>/dev/null | head -n 120 || true"),
    Probe("persistence", "crontab -l 2>/dev/null || true"),
    Probe("container", "docker ps --format '{{.ID}}\\t{{.Image}}\\t{{.Names}}\\t{{.Status}}' 2>/dev/null || true"),
    Probe(
        "container",
        "docker ps --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null | head -n 5 | while read -r id name image; do "
        "[ -n \"$id\" ] || continue; echo \"## $id $name $image\"; "
        "docker inspect \"$id\" --format 'Image={{.Config.Image}}; Path={{.Path}}; Args={{json .Args}}; Restart={{.HostConfig.RestartPolicy.Name}}; Mounts={{range .Mounts}}{{.Source}}:{{.Destination}};{{end}}' 2>/dev/null || true; "
        "done",
    ),
    Probe("gpu", "nvidia-smi -L 2>/dev/null || true"),
    Probe("gpu", "nvidia-smi --query-gpu=index,name,utilization.gpu,temperature.gpu,power.draw,power.limit --format=csv,noheader 2>/dev/null || true"),
    Probe("gpu", "rocm-smi --showproductname --showuse --showtemp --showpower 2>/dev/null || true"),
    Probe(
        "log_integrity",
        "for f in /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/syslog /var/log/messages /var/log/wtmp /var/log/btmp /var/log/lastlog; do "
        "if [ -L \"$f\" ]; then echo \"$f|symlink|$(readlink \"$f\")\"; "
        "elif [ -e \"$f\" ]; then sz=$(stat -c %s \"$f\" 2>/dev/null || echo -1); echo \"$f|file|$sz\"; "
        "else echo \"$f|missing|\"; fi; done",
    ),
]

DEEP_READONLY_PROBES = [
    Probe("system", "cat /proc/cmdline 2>/dev/null || true"),
    Probe(
        "trust",
        "echo '## aliases'; alias 2>/dev/null || true; "
        "echo '## functions'; declare -F 2>/dev/null || true; "
        "for c in lsattr chattr systemctl ss netstat ip journalctl ps find grep awk sed last lastlog crontab docker; do "
        "echo \"## $c\"; type \"$c\" 2>/dev/null || true; "
        "for p in /usr/bin/$c /bin/$c /usr/sbin/$c /sbin/$c /usr/local/bin/$c; do "
        "[ -e \"$p\" ] && ls -l \"$p\"; "
        "done; "
        "done",
    ),
    Probe(
        "trust",
        "for c in lsattr chattr systemctl ss ip journalctl ps docker; do "
        "p=$(command -v \"$c\" 2>/dev/null || true); "
        "[ -n \"$p\" ] || continue; "
        "echo \"## $c $p\"; "
        "if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -S \"$p\" 2>/dev/null || echo 'pkg=unknown'; "
        "elif command -v rpm >/dev/null 2>&1; then rpm -qf \"$p\" 2>/dev/null || echo 'pkg=unknown'; "
        "elif command -v pacman >/dev/null 2>&1; then pacman -Qo \"$p\" 2>/dev/null || echo 'pkg=unknown'; "
        "else echo 'package_manager=unavailable'; fi; "
        "done",
    ),
    Probe("process", "ps -eo pid,ppid,user,lstart,etimes,%cpu,%mem,comm,args --sort=-%cpu | head -n 120"),
    Probe(
        "process",
        "for pid in $(ps -eo pid= --sort=-%cpu | head -n 30); do "
        "exe=$(readlink -f /proc/$pid/exe 2>/dev/null || echo '[exe_unreadable]'); "
        "cmd=$(tr '\\0' ' ' < /proc/$pid/cmdline 2>/dev/null || echo '[cmdline_unreadable]'); "
        "[ -n \"$cmd\" ] && echo \"$pid|$exe|$cmd\"; "
        "done",
    ),
    Probe("process", "ls -l /proc/*/exe 2>/dev/null | grep ' (deleted)$' || true"),
    Probe(
        "service",
        "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -n 200 || true",
    ),
    Probe(
        "service",
        "systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | head -n 40 | "
        "while read -r unit; do "
        "[ -n \"$unit\" ] || continue; "
        "echo \"## $unit\"; "
        "systemctl show \"$unit\" -p Id -p LoadState -p ActiveState -p SubState -p FragmentPath -p ExecStart -p ExecMainPID -p User 2>/dev/null; "
        "done || true",
    ),
    Probe(
        "service",
        "systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | head -n 40 | "
        "while read -r unit; do "
        "[ -n \"$unit\" ] || continue; "
        "systemctl show \"$unit\" -p FragmentPath -p ExecStart 2>/dev/null; "
        "done | grep -Ei 'ExecStart=.*(/tmp/|/var/tmp/|/dev/shm/|curl|wget|base64 -d|python -c|bash -c|sh -c|nohup|setsid|screen -dm|tmux (new|new-session)|xmrig|miner|stratum|clash|autossh|frp|ngrok)|FragmentPath=.*/(tmp|var/tmp|dev/shm)/' || true",
    ),
    Probe(
        "persistence",
        "find /root /home -xdev -maxdepth 4 "
        "\\( -path '*/.config/autostart/*' -o -name '.bashrc' -o -name '.profile' -o -name '.bash_profile' -o -name '.zshrc' "
        "-o -name '.zprofile' -o -name '.xprofile' -o -name 'authorized_keys' -o -name 'rc.local' \\) "
        "-printf '%TY-%Tm-%Td %TH:%TM %u %m %p\\n' 2>/dev/null | sort",
    ),
    Probe(
        "persistence",
        "grep -RniE '(xmrig|miner|stratum|clash|autossh|frp|ngrok|curl .*[|] *sh|wget .*[|] *sh|base64 -d|/tmp/|/var/tmp/|/dev/shm/|nohup|setsid|screen -dm|tmux (new|new-session)|systemctl enable|crontab )' "
        "/root/.bash* /root/.profile /root/.config/autostart /home/*/.bash* /home/*/.profile /home/*/.config/autostart /etc/rc.local 2>/dev/null | head -n 200 || true",
    ),
    Probe(
        "auth",
        "find /root /home -xdev -maxdepth 3 "
        "\\( -name '.bash_history' -o -name '.zsh_history' -o -name '.python_history' -o -name '.mysql_history' \\) "
        "-printf '%TY-%Tm-%Td %TH:%TM %u %s %p\\n' 2>/dev/null | sort",
    ),
    Probe(
        "auth",
        "grep -HniE '(xmrig|miner|stratum|clash|autossh|frp|ngrok|curl .*[|] *sh|wget .*[|] *sh|base64 -d|chmod \\+x .*(/tmp/|/var/tmp/|/dev/shm/)|/tmp/|/var/tmp/|/dev/shm/|nohup|setsid|screen -dm|tmux (new|new-session)|systemctl enable|crontab |docker run .*--(privileged|pid=host|net=host)|kubectl exec)' "
        "/root/.*history /home/*/.*history 2>/dev/null | head -n 200 || true",
    ),
    Probe(
        "binary_drop",
        "find /tmp /var/tmp /dev/shm /run /root/.cache /root/.local /root/bin /home/*/.cache /home/*/.local /home/*/bin -maxdepth 4 -type f "
        "\\( -perm /111 -o -name '*.sh' -o -name '*.py' -o -name '*.bin' -o -name '*.run' \\) "
        "-printf '%TY-%Tm-%Td %TH:%TM %u %m %s %p\\n' 2>/dev/null | sort | tail -n 400",
    ),
    Probe(
        "binary_drop",
        "find /tmp /var/tmp /dev/shm /run /root/.cache /root/.local /root/bin /home/*/.cache /home/*/.local /home/*/bin -maxdepth 4 -type f "
        "2>/dev/null | grep -Ei '(miner|xmrig|stratum|clash|autossh|frp|ngrok|sysupdate|sysguard|dbus-|kworker|kswap|bioset)' "
        "| head -n 200 || true",
    ),
    Probe(
        "container",
        "docker ps --format '{{.ID}} {{.Names}}' 2>/dev/null | head -n 5 | while read -r id name; do "
        "[ -n \"$id\" ] || continue; "
        "echo \"## $id $name\"; docker port \"$id\" 2>/dev/null || true; "
        "done",
    ),
    Probe(
        "container",
        "docker ps --format '{{.ID}}' 2>/dev/null | head -n 5 | while read -r id; do "
        "[ -n \"$id\" ] || continue; "
        "echo \"## $id\"; docker top \"$id\" -eo pid,ppid,user,etime,pcpu,pmem,args 2>/dev/null || docker top \"$id\" 2>/dev/null || true; "
        "done",
    ),
    Probe(
        "log_integrity",
        "find /var/log/journal /run/log/journal -maxdepth 3 -printf '%TY-%Tm-%Td %TH:%TM %u %m %s %p\\n' 2>/dev/null | sort || true",
    ),
    Probe(
        "persistence",
        "test -f /etc/ld.so.preload && (ls -l /etc/ld.so.preload; cat /etc/ld.so.preload) || true",
    ),
    Probe(
        "persistence",
        "ls -l /etc/rc.local /etc/rc.d/rc.local 2>/dev/null || true",
    ),
    Probe(
        "auth",
        "find /root/.ssh /home/*/.ssh -maxdepth 2 -type f -name 'authorized_keys' -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n' 2>/dev/null | sort",
    ),
    Probe(
        "auth",
        "for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f \"$f\" ] || continue; echo \"## $f\"; (command -v ssh-keygen >/dev/null 2>&1 && ssh-keygen -lf \"$f\" 2>/dev/null) || awk '{print NR \":\" $1 \" \" substr($2,1,24) \"...\"}' \"$f\" 2>/dev/null; done | head -n 200",
    ),
    Probe(
        "persistence",
        "grep -RniE '(PermitRootLogin|PasswordAuthentication|AuthorizedKeysFile|PubkeyAuthentication)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true",
    ),
    Probe(
        "persistence",
        r"ls -l /etc/pam.d /etc/sudoers /etc/sudoers.d 2>/dev/null; grep -RniE '(pam_exec|pam_script|pam_permit|NOPASSWD|!authenticate|ALL=\(ALL\))' /etc/pam.d /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 200 || true",
    ),
    Probe(
        "persistence",
        "lsmod 2>/dev/null | head -n 200 || true",
    ),
    Probe(
        "persistence",
        "command -v bpftool >/dev/null 2>&1 && bpftool prog show 2>/dev/null || true",
    ),
    Probe(
        "persistence",
        "command -v bpftool >/dev/null 2>&1 && bpftool map show 2>/dev/null || true",
    ),
    Probe(
        "persistence",
        "sysctl kernel.modules_disabled 2>/dev/null || true; dmesg -T 2>/dev/null | grep -Ei '(module|bpf|ebpf|taint|hook)' | tail -n 120 || true",
    ),
    Probe(
        "cloud",
        "ls -l /var/log/cloud-init* /var/lib/cloud/instance 2>/dev/null || true",
    ),
    Probe(
        "cloud",
        r"grep -RniE '(169\.254\.169\.254|metadata\.google\.internal|security-credentials|api/token|Azure Instance Metadata Service)' /root/.bash* /home/*/.bash* /var/log/* /etc/systemd/system /lib/systemd/system 2>/dev/null | head -n 200 || true",
    ),
    Probe(
        "container",
        "docker images --format '{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}' 2>/dev/null | head -n 120 || true",
    ),
    Probe(
        "container",
        "command -v crictl >/dev/null 2>&1 && crictl ps -a 2>/dev/null || true",
    ),
    Probe(
        "container",
        "find /etc/kubernetes /var/lib/kubelet /etc/cni /opt/cni -maxdepth 3 -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n' 2>/dev/null | sort | head -n 300 || true",
    ),
    Probe(
        "container",
        "command -v kubectl >/dev/null 2>&1 && kubectl get pods,daemonsets,cronjobs -A -o wide --request-timeout=10s 2>/dev/null || true",
    ),
    Probe(
        "network_ioc",
        r"grep -RniE '(stratum\+tcp|stratum\+ssl|xmr|monero|nicehash|minexmr|supportxmr|2miners|f2pool|wallet|pass=|tls-fingerprint|kind:[[:space:]]*(DaemonSet|CronJob))' /etc/systemd/system /lib/systemd/system /etc/cron* /root/.bash* /home/*/.bash* /root/.config /home/*/.config 2>/dev/null | head -n 200 || true",
    ),
]

BASE_PROBES = BASE_PROBES + DEEP_READONLY_PROBES


def default_case_root() -> str:
    return str((Path.cwd() / "reports").resolve())


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def compact_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def sanitize_name(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", raw.strip())[:80] or "host"


def target_label(args: argparse.Namespace) -> str:
    if args.host_ip:
        return sanitize_name(args.host_ip)
    if args.remote:
        return sanitize_name(args.remote.split("@")[-1])
    if args.host_name:
        return sanitize_name(args.host_name)
    return sanitize_name(platform.node() or "local-host")


def build_case_layout(args: argparse.Namespace) -> dict[str, Path]:
    if args.case_dir:
        case_dir = Path(args.case_dir).resolve()
    else:
        tag = args.case_tag or f"{target_label(args)}-{compact_utc()}"
        case_root = Path(args.case_root).resolve() if args.case_root else (Path.cwd() / "reports").resolve()
        case_dir = case_root / sanitize_name(tag)

    evidence_dir = case_dir / "evidence"
    artifacts_dir = case_dir / "artifacts"
    reports_dir = case_dir / "reports"
    meta_dir = case_dir / "meta"
    for d in (case_dir, evidence_dir, artifacts_dir, reports_dir, meta_dir):
        d.mkdir(parents=True, exist_ok=True)

    output = Path(args.output).resolve() if args.output else (evidence_dir / "evidence.raw.json")
    return {
        "case_dir": case_dir,
        "evidence_dir": evidence_dir,
        "artifacts_dir": artifacts_dir,
        "reports_dir": reports_dir,
        "meta_dir": meta_dir,
        "output_json": output,
        "manifest": meta_dir / "case_manifest.json",
        "artifact_hashes": meta_dir / "artifact_hashes.json",
        "readme": meta_dir / "README.txt",
    }


def timeout_result(timeout: int) -> tuple[int, str, str]:
    return 124, "", f"probe_timeout_after_{timeout}s"


def run_local(cmd: str, timeout: int) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["bash", "-lc", cmd],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or ""), (exc.stderr or f"probe_timeout_after_{timeout}s")
    return proc.returncode, proc.stdout, proc.stderr


def normalize_fingerprint(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    if text.upper().startswith("SHA256:"):
        return "SHA256:" + text.split(":", 1)[1]
    return "SHA256:" + text


def key_sha256_fingerprint(key: Any) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def known_host_tokens(host: str, port: int) -> list[str]:
    tokens = [host]
    if port != 22:
        tokens.insert(0, f"[{host}]:{port}")
    return tokens


def resolve_known_hosts_files(args: argparse.Namespace) -> list[str]:
    files: list[str] = []
    if getattr(args, "known_hosts", ""):
        candidates = [str(Path(args.known_hosts).expanduser())]
    else:
        candidates = [
            str(Path("~/.ssh/known_hosts").expanduser()),
            "/etc/ssh/ssh_known_hosts",
        ]
    seen: set[str] = set()
    for item in candidates:
        if not item or item in seen:
            continue
        seen.add(item)
        if Path(item).exists():
            files.append(item)
    return files


def lookup_known_host_entry(host: str, port: int, known_hosts_files: list[str]) -> dict[str, str]:
    if paramiko is None:
        return {}
    tokens = known_host_tokens(host, port)
    for known_hosts_path in known_hosts_files:
        host_keys = paramiko.HostKeys()
        try:
            host_keys.load(known_hosts_path)
        except OSError:
            continue
        for token in tokens:
            match = host_keys.lookup(token)
            if not match:
                continue
            key_type = next(iter(match.keys()))
            key = match[key_type]
            return {
                "known_hosts_path": known_hosts_path,
                "host_token": token,
                "key_type": key_type,
                "host_key_fingerprint": key_sha256_fingerprint(key),
            }
    return {}


def fetch_remote_server_key(host: str, port: int, timeout: int) -> Any:
    if paramiko is None:
        raise SystemExit("paramiko is required for remote host-key verification.")
    sock = socket.create_connection((host, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        transport.banner_timeout = timeout
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    finally:
        transport.close()
        sock.close()


def write_known_hosts_entry(path: Path, host: str, port: int, key: Any) -> None:
    token = host if port == 22 else f"[{host}]:{port}"
    line = f"{token} {key.get_name()} {key.get_base64()}\n"
    path.write_text(line, encoding="utf-8")


def bootstrap_remote_trust(args: argparse.Namespace) -> dict[str, Any]:
    if not args.remote:
        args.trust_known_hosts_files = []
        args.runtime_known_hosts = ""
        return {
            "mode": "local",
            "status": "not_applicable",
            "verification_source": "local_shell",
        }

    if "@" not in args.remote:
        raise SystemExit("--remote must be in user@host format.")
    _username, host = args.remote.split("@", 1)
    port = args.port or 22

    if args.host_key_fingerprint:
        expected = normalize_fingerprint(args.host_key_fingerprint)
        server_key = fetch_remote_server_key(host, port, args.timeout)
        observed = key_sha256_fingerprint(server_key)
        if observed != expected:
            raise SystemExit(
                f"Remote trust bootstrap failed: host key fingerprint mismatch for {host}:{port}. expected={expected} observed={observed}"
            )
        pinned_path = Path(args.case_meta_dir) / "pinned_known_hosts"
        write_known_hosts_entry(pinned_path, host, port, server_key)
        args.runtime_known_hosts = str(pinned_path)
        args.trust_known_hosts_files = [str(pinned_path)]
        return {
            "mode": "pinned_fingerprint",
            "status": "verified",
            "verification_source": "explicit_host_key_fingerprint",
            "host": host,
            "port": port,
            "host_key_fingerprint": observed,
            "known_hosts_path": str(pinned_path),
        }

    known_hosts_files = resolve_known_hosts_files(args)
    match = lookup_known_host_entry(host, port, known_hosts_files)
    if not match:
        raise SystemExit(
            "Remote trust bootstrap failed: no trusted host-key source found. "
            "Provide --host-key-fingerprint or --known-hosts, or pre-populate known_hosts before collection."
        )
    args.trust_known_hosts_files = known_hosts_files
    args.runtime_known_hosts = str(Path(args.known_hosts).expanduser()) if getattr(args, "known_hosts", "") else ""
    return {
        "mode": "known_hosts",
        "status": "verified",
        "verification_source": "existing_known_hosts",
        "host": host,
        "port": port,
        "host_key_fingerprint": match["host_key_fingerprint"],
        "known_hosts_path": match["known_hosts_path"],
        "host_token": match["host_token"],
    }


def build_ssh_prefix(args: argparse.Namespace) -> list[str]:
    prefix = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"ConnectTimeout={args.timeout}",
        "-o", "ConnectionAttempts=1",
    ]
    if getattr(args, "runtime_known_hosts", ""):
        prefix.extend(["-o", f"UserKnownHostsFile={args.runtime_known_hosts}"])
    if args.port:
        prefix.extend(["-p", str(args.port)])
    if args.identity:
        prefix.extend(["-i", args.identity])
    if args.jump:
        prefix.extend(["-J", args.jump])
    prefix.append(args.remote)
    return prefix


def run_remote(prefix: list[str], cmd: str, timeout: int) -> tuple[int, str, str]:
    wrapped = f"bash -lc {shlex.quote(cmd)}"
    try:
        proc = subprocess.run(
            prefix + [wrapped],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or ""), (exc.stderr or f"probe_timeout_after_{timeout}s")
    return proc.returncode, proc.stdout, proc.stderr


def run_remote_paramiko(
    host: str,
    username: str,
    password: str,
    port: int,
    cmd: str,
    timeout: int = 30,
    known_hosts_files: list[str] | None = None,
) -> tuple[int, str, str]:
    if paramiko is None:
        return 1, "", "paramiko_not_available"

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    for path in known_hosts_files or []:
        try:
            client.load_host_keys(path)
        except OSError:
            continue
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        wrapped = f"bash -lc {shlex.quote(cmd)}"
        stdin, stdout, stderr = client.exec_command(wrapped, timeout=timeout)
        stdout.channel.settimeout(timeout)
        stderr.channel.settimeout(timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err
    except (socket.timeout, TimeoutError):
        return timeout_result(timeout)
    except Exception as exc:
        return 1, "", f"paramiko_error: {exc}"
    finally:
        client.close()


def parse_log_integrity(text: str, evidence_id: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 3:
            continue
        path, kind, value = parts[0], parts[1], parts[2]
        status = "ok"
        reason = "Present and appears regular."
        if kind == "missing":
            status = "missing"
            reason = "Log artifact not found at collection time."
        elif kind == "symlink":
            if value == "/dev/null":
                status = "tampered"
                reason = "Symlink points to /dev/null."
            else:
                status = "suspicious"
                reason = f"Symlink target is {value}."
        elif kind == "file":
            try:
                size = int(value)
            except ValueError:
                size = -1
            if size == 0 and any(x in path for x in ["auth.log", "secure", "syslog", "messages"]):
                status = "suspicious"
                reason = "Primary log file is zero bytes."
            elif size < 0:
                status = "unknown"
                reason = "Could not read file size."
            else:
                reason = f"File exists, size={size}."
        entries.append(
            {
                "artifact": path,
                "status": status,
                "reason": reason,
                "evidence_ids": [evidence_id],
            }
        )
    return entries


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_artifact_hashes(artifacts_dir: Path) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for p in sorted(artifacts_dir.glob("E-*.txt")):
        st = p.stat()
        items.append(
            {
                "artifact": str(p),
                "size_bytes": st.st_size,
                "mtime_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                .replace(microsecond=0)
                .isoformat(),
                "sha256": sha256_file(p),
            }
        )
    return {
        "generated_at_utc": now_utc(),
        "algorithm": "sha256",
        "count": len(items),
        "items": items,
    }


def collect(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    evidence: list[dict[str, Any]] = []
    log_integrity: list[dict[str, Any]] = []
    unknowns: list[str] = []

    incident_id = args.incident_id or f"INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    artifacts_dir = Path(args.artifacts_dir).resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    trust_info = bootstrap_remote_trust(args)
    remote_prefix = build_ssh_prefix(args) if args.remote else []
    if args.remote and args.password:
        if "@" not in args.remote:
            raise SystemExit("--remote must be in user@host format when using --password.")
        username, host = args.remote.split("@", 1)
        run_fn = lambda command: run_remote_paramiko(
            host=host,
            username=username,
            password=args.password,
            port=args.port or 22,
            cmd=command,
            timeout=args.timeout,
            known_hosts_files=list(getattr(args, "trust_known_hosts_files", [])),
        )
    elif args.remote:
        run_fn = lambda command: run_remote(remote_prefix, command, args.timeout)
    else:
        run_fn = lambda command: run_local(command, args.timeout)

    for idx, probe in enumerate(BASE_PROBES, 1):
        evidence_id = f"E-{idx:03d}"
        start = now_utc()
        if args.dry_run:
            code, out, err = 0, "", ""
        else:
            code, out, err = run_fn(probe.command)
        end = now_utc()

        artifact = artifacts_dir / f"{evidence_id}.txt"
        timed_out = code == 124 or "probe_timeout_after_" in err
        artifact.write_text(
            f"# source={probe.source}\n# command={probe.command}\n# started={start}\n# ended={end}\n# exit_code={code}\n# timed_out={str(timed_out).lower()}\n\n[STDOUT]\n{out}\n\n[STDERR]\n{err}\n",
            encoding="utf-8",
            errors="replace",
        )

        evidence.append(
            {
                "id": evidence_id,
                "source": probe.source,
                "observed_at": end,
                "command": probe.command,
                "command_hash": command_hash(probe.command),
                "artifact": str(artifact),
                "artifact_hash": sha256_file(artifact),
                "artifact_size_bytes": artifact.stat().st_size,
                "timed_out": timed_out,
            }
        )

        if probe.source == "log_integrity":
            log_integrity.extend(parse_log_integrity(out, evidence_id))

        if timed_out:
            unknowns.append(f"{evidence_id} timed out after {args.timeout}s; evidence may be partial.")
        if code != 0 and probe.source in {"auth", "log_integrity"}:
            unknowns.append(
                f"{evidence_id} failed for {probe.source}; log-based attribution may be incomplete."
            )

    host_name = args.host_name or (args.remote.split("@")[-1] if args.remote else platform.node() or "local-host")
    host_ip = args.host_ip or ("unknown-remote" if args.remote else "127.0.0.1")
    summary = (
        "Auto-collected read-only evidence snapshot. Analyst review required. "
        "No findings are asserted without explicit evidence linkage."
    )

    payload: dict[str, Any] = {
        "case_id": incident_id,
        "host_id": sanitize_name(host_ip if host_ip not in {"unknown-remote", "127.0.0.1"} else host_name),
        "collector_version": COLLECTOR_VERSION,
        "report_timezone_basis": "UTC",
        "timezone": "UTC",
        "timezone_semantics": "Report normalization basis only; not the host local timezone.",
        "expected_workload": (args.expected_workload or "").strip(),
        "remote_trust": trust_info,
        "incident": {
            "id": incident_id,
            "title": args.title or "Mining Host Investigation",
        },
        "generated_at": now_utc(),
        "analyst": args.analyst,
        "host": {
            "name": host_name,
            "ip": host_ip,
            "os": args.os_hint or "unknown",
            "mining_mode": args.mining_mode,
        },
        "summary": summary,
        "evidence": evidence,
        "findings": [],
        "timeline": [],
        "ip_traces": [],
        "log_integrity": log_integrity,
        "actions": [],
        "unknowns": sorted(set(unknowns + [
            "No analyst findings yet. Add only evidence-backed findings.",
            "Mark untraceable/unknown IPs explicitly; do not infer attribution without evidence.",
        ])),
    }
    return payload, [str(artifacts_dir)]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect read-only live evidence into report schema JSON.")
    parser.add_argument("--output", help="Output evidence JSON file. Defaults to case_dir/evidence/evidence.raw.json.")
    parser.add_argument("--case-root", default=default_case_root(), help="Root directory for case bundles. Defaults to <current working directory>/reports.")
    parser.add_argument("--case-dir", help="Explicit case directory path.")
    parser.add_argument("--case-tag", help="Case folder tag, e.g. host-20260306-120000.")
    parser.add_argument("--incident-id", help="Incident ID. Auto-generated if omitted.")
    parser.add_argument("--title", help="Incident title.")
    parser.add_argument("--analyst", default="unknown", help="Analyst/team name.")
    parser.add_argument("--host-name", help="Host display name override.")
    parser.add_argument("--host-ip", help="Host IP override.")
    parser.add_argument("--os-hint", help="OS hint (e.g., Ubuntu 22.04).")
    parser.add_argument("--mining-mode", choices=["auto", "gpu", "cpu", "mixed"], default="auto")
    parser.add_argument("--expected-workload", help="Declared legitimate high-compute workload for false-positive control.")
    parser.add_argument("--remote", help="Remote target in user@host format. If omitted, collect locally.")
    parser.add_argument("--port", type=int, help="SSH port.")
    parser.add_argument("--identity", help="SSH private key path.")
    parser.add_argument("--jump", help="SSH jump host user@host.")
    parser.add_argument("--known-hosts", help="Known-hosts file containing the pinned server key.")
    parser.add_argument("--host-key-fingerprint", help="Pinned remote host key fingerprint in SHA256:<base64> form.")
    parser.add_argument("--password", help="Deprecated insecure SSH password input. Disabled unless --allow-insecure-cli-password is set.")
    parser.add_argument("--password-env", help="Read SSH password from environment variable name.")
    parser.add_argument("--prompt-password", action="store_true", help="Prompt securely for the SSH password instead of using command-line plaintext.")
    parser.add_argument("--allow-insecure-cli-password", action="store_true", help="Allow deprecated plaintext --password usage. Avoid unless no safer path exists.")
    parser.add_argument("--timeout", type=int, default=30, help="Per-command timeout seconds for local and remote probe execution.")
    parser.add_argument("--dry-run", action="store_true", help="Generate structure without executing commands.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.timeout <= 0:
        raise SystemExit("--timeout must be greater than 0.")
    if args.password and not args.allow_insecure_cli_password:
        raise SystemExit("Plaintext --password is disabled by default. Use --password-env or --prompt-password instead.")
    if sum(bool(x) for x in [args.password, args.password_env, args.prompt_password]) > 1:
        raise SystemExit("Use only one of --password, --password-env, or --prompt-password.")
    if args.password_env and not args.password:
        args.password = os.getenv(args.password_env, "")
        if not args.password:
            raise SystemExit(f"Environment variable {args.password_env} is empty or not set.")
    if args.prompt_password:
        if not args.remote:
            raise SystemExit("--prompt-password requires --remote.")
        args.password = getpass.getpass("SSH password: ")
    if args.password and args.identity:
        raise SystemExit("Use either password-based auth or --identity, not both.")
    if args.password and args.jump:
        raise SystemExit("--jump is not supported with password auth in this script.")

    if not args.remote:
        system = platform.system().lower()
        if system != "linux":
            raise SystemExit("Local mode currently supports Linux only. Use --remote for Linux targets.")
        if shutil.which("bash") is None:
            raise SystemExit("bash is required in local mode.")

    layout = build_case_layout(args)
    args.artifacts_dir = str(layout["artifacts_dir"])
    args.case_meta_dir = str(layout["meta_dir"])

    payload, artifact_dirs = collect(args)
    out = layout["output_json"]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    artifact_hashes = build_artifact_hashes(layout["artifacts_dir"])
    layout["artifact_hashes"].write_text(
        json.dumps(artifact_hashes, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    manifest = {
        "case_dir": str(layout["case_dir"]),
        "created_at_utc": now_utc(),
        "incident_id": payload["incident"]["id"],
        "target": {
            "remote": args.remote or "local",
            "host_name": payload["host"]["name"],
            "host_ip": payload["host"]["ip"],
            "auth_method": (
                "password_env" if args.password_env else
                "password_prompt" if args.prompt_password else
                "password_cli_deprecated" if args.password else
                "ssh_key_file" if args.identity else
                "ssh_agent_or_default_key" if args.remote else
                "local_shell"
            ),
        },
        "paths": {
            "evidence_json": str(out),
            "artifacts_dir": str(layout["artifacts_dir"]),
            "reports_dir": str(layout["reports_dir"]),
            "artifact_hashes": str(layout["artifact_hashes"]),
        },
        "remote_trust": payload.get("remote_trust", {}),
        "notes": [
            "All commands are read-only probes.",
            "Add analyst-reviewed findings before final report export.",
            "Verify artifact integrity with meta/artifact_hashes.json before external transfer.",
        ],
    }
    layout["manifest"].write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    layout["readme"].write_text(
        "\n".join(
            [
                "Case Bundle Layout",
                f"Case: {layout['case_dir']}",
                f"Evidence JSON: {out}",
                f"Artifacts: {layout['artifacts_dir']}",
                f"Reports: {layout['reports_dir']}",
                f"Artifact hashes: {layout['artifact_hashes']}",
                "",
                "Recommended next steps:",
                "1) Review evidence JSON and add evidence-backed findings.",
                "2) Run case validation gate before final export.",
                f"3) Export report to: {layout['reports_dir'] / 'report.md'}",
                "4) Keep no-fabrication and redaction constraints enabled.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"Evidence JSON written: {out}")
    for p in artifact_dirs:
        print(f"Artifacts dir: {p}")
    print(f"Case dir: {layout['case_dir']}")
    print(f"Reports dir: {layout['reports_dir']}")
    print(f"Case manifest: {layout['manifest']}")
    print(f"Artifact hashes: {layout['artifact_hashes']}")
    print("Next step: review JSON, add evidence-backed findings, then run export_investigation_report.py --strict")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
