#!/usr/bin/env python3
"""Natural-language controller for mining-host read-only workflow."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_HOST_RE = re.compile(r"\b([A-Za-z0-9_.-]+)@((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9.-]+)\b")
PORT_RE = re.compile(r"(?:\bport\b|端口)\s*[:：]?\s*(\d{1,5})", re.I)
USER_RE = re.compile(r"(?:\busername\b|\buser\b|账号|用户名|用户)\s*[:：]?\s*([A-Za-z0-9_.-]+)", re.I)
PASS_RE = re.compile(r"(?:\bpassword\b|\bpasswd\b|密码)\s*[:：]?\s*([^\s,，;；]+)", re.I)
FINGERPRINT_RE = re.compile(r"\bSHA256:[A-Za-z0-9+/=]+\b")
KEY_RE = re.compile(r"(?:\bidentity\b|\bkey\b|私钥|密钥)\s*[:：]?\s*([^\s,，;；]+)", re.I)


def parse_request(text: str) -> dict[str, Any]:
    req = " ".join((text or "").split())
    out: dict[str, Any] = {
        "remote_user": "",
        "remote_ip": "",
        "port": 22,
        "password": "",
        "identity": "",
        "host_key_fingerprint": "",
        "mining_mode": "auto",
        "redact": False,
    }
    m = USER_HOST_RE.search(req)
    if m:
        out["remote_user"] = m.group(1)
        out["remote_ip"] = m.group(2)
    user = USER_RE.search(req)
    if user:
        out["remote_user"] = user.group(1)
    ips = IP_RE.findall(req)
    if ips and not out["remote_ip"]:
        out["remote_ip"] = ips[0]
    port = PORT_RE.search(req)
    if port:
        out["port"] = int(port.group(1))
    pwd = PASS_RE.search(req)
    if pwd:
        out["password"] = pwd.group(1)
    fp = FINGERPRINT_RE.search(req)
    if fp:
        out["host_key_fingerprint"] = fp.group(0)
    key = KEY_RE.search(req)
    if key:
        out["identity"] = key.group(1)

    lower = req.lower()
    if "mixed" in lower or ("gpu" in lower and "cpu" in lower):
        out["mining_mode"] = "mixed"
    elif "gpu" in lower:
        out["mining_mode"] = "gpu"
    elif "cpu" in lower:
        out["mining_mode"] = "cpu"
    if "脱敏" in req or "redact" in lower:
        out["redact"] = True
    return out


def build_command(parsed: dict[str, Any], analyst: str, case_root: str) -> tuple[list[str], dict[str, str]]:
    script = Path(__file__).resolve().parent / "run_readonly_workflow.py"
    cmd = [
        sys.executable,
        str(script),
        "--analyst",
        analyst,
        "--profile",
        "enterprise-self-audit",
        "--strict-report",
        "--case-root",
        case_root,
        "--mining-mode",
        str(parsed.get("mining_mode", "auto")),
    ]
    if parsed.get("redact"):
        cmd.append("--redact")

    env = os.environ.copy()
    remote_user = str(parsed.get("remote_user", "")).strip()
    remote_ip = str(parsed.get("remote_ip", "")).strip()
    if remote_user and remote_ip:
        cmd.extend(["--remote-user", remote_user, "--remote-ip", remote_ip, "--host-ip", remote_ip])
        port = int(parsed.get("port", 22) or 22)
        if port != 22:
            cmd.extend(["--port", str(port)])
        fingerprint = str(parsed.get("host_key_fingerprint", "")).strip()
        if fingerprint:
            cmd.extend(["--host-key-fingerprint", fingerprint])
        else:
            cmd.append("--trust-on-first-use")
        identity = str(parsed.get("identity", "")).strip()
        password = str(parsed.get("password", "")).strip()
        if identity:
            cmd.extend(["--identity", identity])
        elif password:
            env["MHT_NL_REMOTE_PASSWORD"] = password
            cmd.extend(["--password-env", "MHT_NL_REMOTE_PASSWORD"])
    return cmd, env


def sanitize_parsed_for_log(parsed: dict[str, Any]) -> dict[str, Any]:
    safe = dict(parsed)
    if safe.get("password"):
        safe["password"] = "[REDACTED]"
    return safe


def main() -> int:
    parser = argparse.ArgumentParser(description="Natural-language wrapper for run_readonly_workflow.py")
    parser.add_argument("--request", required=True, help="Natural-language request from user.")
    parser.add_argument("--analyst", default="unknown", help="Analyst name.")
    parser.add_argument("--case-root", default=str((Path.cwd() / "reports").resolve()), help="Case root path.")
    args = parser.parse_args()

    parsed = parse_request(args.request)
    cmd, env = build_command(parsed, args.analyst, args.case_root)
    print("[NL_PARSE]")
    print(json.dumps(sanitize_parsed_for_log(parsed), ensure_ascii=False, indent=2))
    print("[RUN]")
    print(" ".join(cmd))
    proc = subprocess.run(cmd, env=env, check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
