#!/usr/bin/env python3
"""Enrich evidence JSON with evidence-bound timeline, findings, and IP trace hints."""

from __future__ import annotations

import argparse
import json
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AUTH_ACCEPT_RE = re.compile(
    r"(?:^|[\s:])Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
)
AUTH_FAIL_RE = re.compile(
    r"(?:^|[\s:])Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
)
AUTH_INVALID_RE = re.compile(
    r"(?:^|[\s:])Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
)
AUTH_CLOSE_RE = re.compile(
    r"(?:^|[\s:])Connection closed by authenticating user (?P<user>\S+) (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
)
LISTEN_PORT_RE = re.compile(r"\b(?:LISTEN|UNCONN)\b.*?(\d{1,3}(?:\.\d{1,3}){3}|::|0\.0\.0\.0|\*)[:.](\d{1,5})\b")
GPU_QUERY_LINE_RE = re.compile(
    r"^\s*(?P<index>\d+)\s*,\s*(?P<name>[^,]+)\s*,\s*(?P<util>[^,]+)\s*,\s*(?P<temp>[^,]+)\s*,\s*(?P<power>[^,]+)\s*,\s*(?P<limit>[^,]+)\s*,\s*(?P<mem_used>[^,]+)\s*,\s*(?P<mem_total>[^,]+)\s*$"
)
GPU_COMPUTE_APP_RE = re.compile(
    r"^\s*(?P<pid>\d+)\s*,\s*(?P<process>[^,]+)\s*,\s*(?P<gpu_uuid>[^,]+)\s*,\s*(?P<mem>[^,]+)\s*$"
)
MINER_KEYWORD_RE = re.compile(r"(miner|xmrig|gminer|lolminer|trex|nbminer|stratum|kawpow)", re.I)
FALLBACK_MARKER_RE = re.compile(
    r"(?:\b\w+_missing\b|\b\w+_unavailable\b|tools_missing|sha256sum unavailable|journalctl_missing|ps_missing)",
    re.I,
)
PS_AUX_RE = re.compile(
    r"^\s*(?P<user>\S+)\s+(?P<pid>\d+)\s+(?P<cpu>-?\d+(?:\.\d+)?)\s+(?P<mem>-?\d+(?:\.\d+)?)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<cmd>.+)$"
)
PS_EXTENDED_RE = re.compile(
    r"^\s*(?P<pid>[0-9]+)\s+(?P<ppid>[0-9]+)\s+(?P<user>\S+)\s+\w{3}\s+\w{3}\s+[0-9]+\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\s+[0-9]{4}\s+\S+\s+(?P<cpu>-?[0-9]+(?:\.[0-9]+)?)\s+(?P<mem>-?[0-9]+(?:\.[0-9]+)?)\s+\S+\s+(?P<args>.+)$"
)
PROC_EXE_MAP_RE = re.compile(r"^\s*(?P<pid>\d+)\|(?P<exe>[^|]+)\|(?P<cmd>.*)$")
PROC_FALLBACK_RE = re.compile(r"^\s*(?P<pid>\d+)\|(?P<state>[A-Za-z])\|(?P<cmd>.+)$")
GREP_CTX_RE = re.compile(r"^(?P<path>[^:\n]+):(?P<line>\d+):(?P<body>.*)$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
RUNTIME_HINT_RE = re.compile(
    r"(?:\bxmrig\b|\bgminer\b|\blolminer\b|\btrex\b|\bnbminer\b|\bsrb\b|\bstratum(?:\+|://)?\b|"
    r"--algorithm\b|--algo\b|\bkawpow\b|\brandomx\b|\bethash\b|\betchash\b|"
    r"--pool\b|--wallet\b|--proxy\b|--cpu-threads\b|--threads\b|\bcpu-threads\b)",
    re.I,
)
CRON_AT_RE = re.compile(r"^@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)$", re.I)
CRON_FIELD_RE = re.compile(r"^[\d*/,\-A-Za-z]+$")


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON ({path}): {exc}")
    if not isinstance(data, dict):
        raise SystemExit("Input JSON must be an object.")
    return data


def split_artifact_sections(text: str) -> tuple[str, str]:
    stdout = ""
    stderr = ""
    marker = "\n[STDOUT]\n"
    marker2 = "\n\n[STDERR]\n"
    if marker not in text:
        return stdout, stderr
    after = text.split(marker, 1)[1]
    if marker2 in after:
        stdout, stderr = after.split(marker2, 1)
    else:
        stdout = after
    return stdout, stderr


def parse_exit_code(text: str) -> int | None:
    for line in text.splitlines():
        if line.startswith("# exit_code="):
            try:
                return int(line.split("=", 1)[1].strip())
            except ValueError:
                return None
    return None


def normalize_time_utc(value: str) -> str:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return "unknown"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def parse_int_from_text(value: str) -> int | None:
    m = re.search(r"(-?\d+)", value or "")
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def compact_space(value: str) -> str:
    return " ".join((value or "").split()).strip()


def safe_shlex_split(value: str) -> list[str]:
    text = (value or "").strip()
    if not text:
        return []
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def parse_endpoint(value: str) -> tuple[str, str, str]:
    text = (value or "").strip().strip("'\"").rstrip(",;")
    if not text:
        return "", "", ""
    if "://" in text:
        text = text.split("://", 1)[1]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    text = text.split("/", 1)[0]
    host = text
    port = ""
    if text.startswith("[") and "]" in text:
        host = text[1 : text.index("]")]
        rest = text[text.index("]") + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            port = rest[1:]
    elif text.count(":") == 1 and text.rsplit(":", 1)[1].isdigit():
        host, port = text.rsplit(":", 1)
    ip = host if IPV4_RE.fullmatch(host) else ""
    return text, host, port if port else ""


def parse_grep_context_line(line: str) -> tuple[str, str, str]:
    m = GREP_CTX_RE.match(line.strip())
    if not m:
        return "", "", line.strip()
    return m.group("path").strip(), m.group("line").strip(), m.group("body").strip()


def normalize_execstart_command(line_body: str) -> str:
    text = compact_space(line_body)
    if "ExecStart=" in text:
        text = text.split("ExecStart=", 1)[1].strip()
    argv_match = re.search(r"argv\[\]=([^;]+)", text)
    if argv_match:
        text = argv_match.group(1).strip()
    return text.lstrip("-@").strip()


def parse_cron_command(body: str) -> tuple[str, str]:
    tokens = safe_shlex_split(body)
    if not tokens:
        return "", body
    if CRON_AT_RE.match(tokens[0]):
        schedule = tokens[0]
        command = " ".join(tokens[2:]) if len(tokens) >= 3 else " ".join(tokens[1:])
        return schedule, command.strip()
    if len(tokens) >= 6 and all(CRON_FIELD_RE.match(tok) for tok in tokens[:5]):
        if len(tokens) >= 7:
            return " ".join(tokens[:5]), " ".join(tokens[6:]).strip()
        return " ".join(tokens[:5]), " ".join(tokens[5:]).strip()
    return "", body.strip()


def parse_option_values(tokens: list[str]) -> dict[str, list[str]]:
    opts: dict[str, list[str]] = {}

    def token_can_be_value(tok: str) -> bool:
        if not tok:
            return False
        if not tok.startswith("-"):
            return True
        return bool(re.fullmatch(r"-?\d+(?:\.\d+)?", tok) or re.fullmatch(r"-?0x[0-9a-fA-F]+", tok))

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("--"):
            if "=" in tok:
                key, value = tok.split("=", 1)
                opts.setdefault(key, []).append(value)
            else:
                value = ""
                if i + 1 < len(tokens) and token_can_be_value(tokens[i + 1]):
                    value = tokens[i + 1]
                    i += 1
                opts.setdefault(tok, []).append(value)
        elif tok in {"-a", "-o", "-u", "-p", "-t", "-x"}:
            value = ""
            if i + 1 < len(tokens) and token_can_be_value(tokens[i + 1]):
                value = tokens[i + 1]
                i += 1
            opts.setdefault(tok, []).append(value)
        i += 1
    return opts


def first_option_value(options: dict[str, list[str]], keys: list[str]) -> str:
    for key in keys:
        values = options.get(key) or []
        for value in values:
            if str(value).strip():
                return str(value).strip()
    return ""


def parse_runtime_profile_from_line(line: str, source: str, evidence_id: str) -> dict[str, Any] | None:
    raw = line.strip()
    if not raw:
        return None

    origin_path, origin_line, body = parse_grep_context_line(raw)
    command_text = normalize_execstart_command(body or raw)
    schedule = ""
    if origin_path and "/cron" in origin_path:
        schedule, command_text = parse_cron_command(command_text)
    if " crontab " in command_text:
        schedule = schedule or "dynamic_crontab"
    if not RUNTIME_HINT_RE.search(command_text):
        return None

    tokens = safe_shlex_split(command_text)
    if not tokens:
        return None
    options = parse_option_values(tokens)

    executable = tokens[0] if tokens and not tokens[0].startswith("-") else ""
    algorithm = first_option_value(options, ["--algorithm", "--algo", "-a"])
    if not algorithm:
        kw = re.search(r"\b(kawpow|randomx|ethash|etchash|rx/0|cn/\w+)\b", command_text, re.I)
        algorithm = kw.group(1) if kw else ""
    proxy_raw = first_option_value(options, ["--proxy", "--proxy-url"])
    pool_raw = first_option_value(options, ["--pool", "--url", "-o"])
    wallet = first_option_value(options, ["--wallet", "--user", "--username", "-u"])
    password = first_option_value(options, ["--password", "--pass", "-p"])
    cpu_threads = first_option_value(options, ["--cpu-threads", "--threads", "-t"])
    cpu_affinity = first_option_value(options, ["--cpu-affinity", "--cpu-bind", "-x"])

    if not pool_raw:
        stratum = re.search(r"(stratum\+[A-Za-z0-9]+://[^\s'\";]+)", command_text, re.I)
        pool_raw = stratum.group(1) if stratum else ""

    pool_endpoint, pool_host, pool_port = parse_endpoint(pool_raw)
    proxy_endpoint, proxy_host, proxy_port = parse_endpoint(proxy_raw)

    if not any([algorithm, pool_endpoint, proxy_endpoint, wallet, password, cpu_threads, cpu_affinity]):
        return None

    wallet_base = wallet.split(".", 1)[0] if wallet else ""
    worker_name = wallet.split(".", 1)[1] if wallet and "." in wallet else ""
    return {
        "source": source,
        "evidence_id": evidence_id,
        "origin_path": origin_path,
        "origin_line": origin_line,
        "schedule": schedule,
        "command": compact_space(command_text),
        "executable": executable,
        "algorithm": algorithm.lower() if algorithm else "",
        "proxy": proxy_endpoint,
        "proxy_host": proxy_host,
        "proxy_port": proxy_port,
        "pool": pool_endpoint,
        "pool_host": pool_host,
        "pool_port": pool_port,
        "wallet": wallet,
        "wallet_base": wallet_base,
        "worker_name": worker_name,
        "password": password,
        "cpu_threads": cpu_threads,
        "cpu_affinity": cpu_affinity,
    }


def dedupe_runtime_profiles(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        key = (
            str(item.get("executable", "")),
            str(item.get("algorithm", "")),
            str(item.get("proxy", "")),
            str(item.get("pool", "")),
            str(item.get("wallet", "")),
            str(item.get("password", "")),
            str(item.get("cpu_threads", "")),
            str(item.get("origin_path", "")),
            str(item.get("origin_line", "")),
            str(item.get("schedule", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def parse_top_process_line(line: str) -> dict[str, Any] | None:
    raw = line.strip()
    if not raw:
        return None
    m = PS_EXTENDED_RE.match(raw)
    if m:
        return {
            "pid": m.group("pid"),
            "ppid": m.group("ppid"),
            "user": m.group("user"),
            "cpu_percent": m.group("cpu"),
            "mem_percent": m.group("mem"),
            "command": compact_space(m.group("args")),
        }
    m = PS_AUX_RE.match(raw)
    if m:
        return {
            "pid": m.group("pid"),
            "ppid": "",
            "user": m.group("user"),
            "cpu_percent": m.group("cpu"),
            "mem_percent": m.group("mem"),
            "command": compact_space(m.group("cmd")),
        }
    m = PROC_FALLBACK_RE.match(raw)
    if m:
        return {
            "pid": m.group("pid"),
            "ppid": "",
            "user": "",
            "cpu_percent": "unknown",
            "mem_percent": "unknown",
            "command": compact_space(m.group("cmd")),
        }
    return None


def finding_shape(
    finding_id: str,
    statement: str,
    confidence: str,
    evidence_ids: list[str],
    claim_type: str,
    hypothesis_id: str,
    confidence_reason: str,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "statement": statement,
        "confidence": confidence,
        "claim_type": claim_type,
        "hypothesis_id": hypothesis_id,
        "confidence_reason": confidence_reason,
        "evidence_ids": evidence_ids,
    }


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in findings:
        statement = str(item.get("statement", "")).strip()
        confidence = str(item.get("confidence", "unknown")).strip()
        key = (statement, confidence)
        if not statement or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def dedupe_timeline(timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in timeline:
        key = (
            str(item.get("time", "")).strip(),
            str(item.get("event", "")).strip(),
            ",".join(str(x) for x in as_list(item.get("evidence_ids"))),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def merge_ip_traces(existing: list[dict[str, Any]], new_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    idx: dict[tuple[str, str], dict[str, Any]] = {}
    for item in existing:
        ip = str(item.get("ip", "")).strip()
        role = str(item.get("role", "unknown")).strip()
        if ip:
            idx[(ip, role)] = item

    for item in new_items:
        ip = str(item.get("ip", "")).strip()
        role = str(item.get("role", "unknown")).strip()
        if not ip:
            continue
        key = (ip, role)
        if key not in idx:
            idx[key] = item
            continue
        cur = idx[key]
        cur_ids = set(str(x) for x in as_list(cur.get("evidence_ids")))
        new_ids = set(str(x) for x in as_list(item.get("evidence_ids")))
        cur["evidence_ids"] = sorted(cur_ids | new_ids)
        if not str(cur.get("reason", "")).strip():
            cur["reason"] = item.get("reason", "")
    return list(idx.values())


def enrich(data: dict[str, Any]) -> dict[str, Any]:
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    existing_findings = [as_dict(x) for x in as_list(data.get("findings"))]
    existing_timeline = [as_dict(x) for x in as_list(data.get("timeline"))]
    existing_ip_traces = [as_dict(x) for x in as_list(data.get("ip_traces"))]
    unknowns = [str(x) for x in as_list(data.get("unknowns"))]

    timeline_add: list[dict[str, Any]] = []
    finding_add: list[dict[str, Any]] = []
    ip_trace_add: list[dict[str, Any]] = []
    auth_source_map: dict[str, set[str]] = {}
    accepted_source_map: dict[str, set[str]] = {}
    failed_source_map: dict[str, set[str]] = {}
    invalid_source_map: dict[str, set[str]] = {}
    closed_source_map: dict[str, set[str]] = {}
    listen_ports: set[str] = set()
    trust_flags: set[str] = set()
    ioc_process_lines: list[str] = []
    top_cpu_processes: list[dict[str, Any]] = []
    process_exe_by_pid: dict[str, str] = {}
    process_cmd_by_pid: dict[str, str] = {}
    runtime_profiles: list[dict[str, Any]] = []
    fallback_markers: list[str] = []
    fallback_marker_ids: set[str] = set()
    cron_runtime_candidates: list[dict[str, Any]] = []
    initial_access_review_hits: list[str] = []
    container_cloud_review_hits: list[str] = []
    network_ioc_hits: list[str] = []
    kernel_review_hits: list[str] = []
    gpu_probe_ids: set[str] = set()
    gpu_vendor_hints: set[str] = set()
    gpu_adapter_lines: list[str] = []
    gpu_utilization_samples: list[dict[str, Any]] = []
    gpu_compute_processes: list[dict[str, str]] = []
    gpu_suspicious_processes: list[dict[str, str]] = []
    host_reported_timezone = "unknown"
    host_ntp_synchronized = "unknown"
    privilege_user = "unknown"
    privilege_uid = "unknown"
    privilege_has_passwordless_sudo = False
    auth_timeline_seen: set[tuple[str, str, str]] = set()
    accepted_count = 0
    failed_count = 0
    invalid_count = 0

    def add_timeline(observed_at: str, event: str, source: str, evid_id: str) -> None:
        timeline_add.append(
            {
                "time": observed_at or "unknown",
                "normalized_time_utc": normalize_time_utc(observed_at) if observed_at else "unknown",
                "event": event,
                "source": source,
                "evidence_ids": [evid_id],
            }
        )

    def add_auth_timeline_once(observed_at: str, event_type: str, user: str, ip: str, evid_id: str) -> None:
        key = (event_type, user, ip)
        if key in auth_timeline_seen:
            return
        auth_timeline_seen.add(key)
        if event_type == "failed":
            event = f"Failed password login observed for user {user} from {ip}."
        elif event_type == "invalid":
            event = f"Invalid user attempt observed for {user} from {ip}."
        else:
            event = f"Authentication connection closed for user {user} from {ip}."
        add_timeline(observed_at, event, "auth", evid_id)

    for item in evidence_items:
        evid_id = str(item.get("id", "")).strip()
        source = str(item.get("source", "")).strip()
        observed_at = str(item.get("observed_at", "")).strip()
        command = str(item.get("command", "")).strip()
        artifact_path = Path(str(item.get("artifact", "")).strip())
        if not evid_id or not artifact_path.exists():
            continue

        text = artifact_path.read_text(encoding="utf-8", errors="replace")
        stdout, _ = split_artifact_sections(text)
        exit_code = parse_exit_code(text)

        for line in stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if FALLBACK_MARKER_RE.search(stripped) and len(fallback_markers) < 80:
                fallback_markers.append(stripped)
                fallback_marker_ids.add(evid_id)

        if source == "auth":
            for line in stdout.splitlines():
                m = AUTH_ACCEPT_RE.search(line)
                if m:
                    accepted_count += 1
                    ip = m.group("ip")
                    user = m.group("user")
                    auth_source_map.setdefault(ip, set()).add(evid_id)
                    accepted_source_map.setdefault(ip, set()).add(evid_id)
                m = AUTH_FAIL_RE.search(line)
                if m:
                    failed_count += 1
                    ip = m.group("ip")
                    user = m.group("user")
                    auth_source_map.setdefault(ip, set()).add(evid_id)
                    failed_source_map.setdefault(ip, set()).add(evid_id)
                    add_auth_timeline_once(observed_at, "failed", user, ip, evid_id)
                m = AUTH_INVALID_RE.search(line)
                if m:
                    invalid_count += 1
                    ip = m.group("ip")
                    user = m.group("user")
                    auth_source_map.setdefault(ip, set()).add(evid_id)
                    invalid_source_map.setdefault(ip, set()).add(evid_id)
                    add_auth_timeline_once(observed_at, "invalid", user, ip, evid_id)
                m = AUTH_CLOSE_RE.search(line)
                if m:
                    ip = m.group("ip")
                    user = m.group("user")
                    auth_source_map.setdefault(ip, set()).add(evid_id)
                    closed_source_map.setdefault(ip, set()).add(evid_id)
                    add_auth_timeline_once(observed_at, "closed", user, ip, evid_id)

        if source == "network" and ("ss -antup" in command or "netstat -antup" in command):
            for line in stdout.splitlines():
                m = LISTEN_PORT_RE.search(line)
                if not m:
                    continue
                port = m.group(2)
                if port:
                    listen_ports.add(port)

        if source == "trust":
            for line in stdout.splitlines():
                if " is aliased to " in line:
                    trust_flags.add("command_is_aliased")
                if " is a function" in line:
                    trust_flags.add("command_is_shell_function")
                if line.strip().endswith(": not_found"):
                    trust_flags.add("critical_command_missing")

        if source == "process" and "grep -Ei 'miner|xmrig|lolminer|trex|gminer|nbminer|clash|autossh|h32|h64|\\-zsh'" in command:
            if exit_code == 0 and stdout.strip():
                for ln in stdout.splitlines():
                    if ln.strip():
                        ioc_process_lines.append(ln.strip())

        if source == "process":
            for line in stdout.splitlines():
                entry = parse_top_process_line(line)
                if entry and len(top_cpu_processes) < 40:
                    top_cpu_processes.append(entry)
                m = PROC_EXE_MAP_RE.match(line.strip())
                if m:
                    pid = m.group("pid").strip()
                    exe = m.group("exe").strip()
                    cmdline = compact_space(m.group("cmd"))
                    if pid:
                        process_exe_by_pid[pid] = exe
                        if cmdline:
                            process_cmd_by_pid[pid] = cmdline

        if source == "gpu":
            gpu_probe_ids.add(evid_id)
            if stdout.strip():
                for line in stdout.splitlines():
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if len(gpu_adapter_lines) < 24 and (
                        stripped.lower().startswith("gpu ")
                        or "nvidia" in stripped.lower()
                        or "amd" in stripped.lower()
                        or "radeon" in stripped.lower()
                    ):
                        gpu_adapter_lines.append(stripped)
                    lower = stripped.lower()
                    if "nvidia" in lower:
                        gpu_vendor_hints.add("nvidia")
                    if "amd" in lower or "radeon" in lower:
                        gpu_vendor_hints.add("amd")

                    mq = GPU_QUERY_LINE_RE.match(stripped)
                    if mq:
                        util = parse_int_from_text(mq.group("util"))
                        entry = {
                            "index": mq.group("index").strip(),
                            "name": mq.group("name").strip(),
                            "utilization": str(util if util is not None else "unknown"),
                            "memory_used": mq.group("mem_used").strip(),
                            "memory_total": mq.group("mem_total").strip(),
                        }
                        if len(gpu_utilization_samples) < 16:
                            gpu_utilization_samples.append(entry)
                        continue

                    mc = GPU_COMPUTE_APP_RE.match(stripped)
                    if mc:
                        proc_entry = {
                            "pid": mc.group("pid").strip(),
                            "process": mc.group("process").strip(),
                            "gpu_uuid": mc.group("gpu_uuid").strip(),
                            "memory": mc.group("mem").strip(),
                        }
                        if len(gpu_compute_processes) < 32:
                            gpu_compute_processes.append(proc_entry)

        if source == "system" and "timedatectl show" in command:
            for line in stdout.splitlines():
                if line.startswith("Timezone="):
                    host_reported_timezone = line.split("=", 1)[1].strip() or "unknown"
                if line.startswith("NTPSynchronized="):
                    host_ntp_synchronized = line.split("=", 1)[1].strip() or "unknown"

        if source in {"persistence", "auth"} and any(token in command for token in ["authorized_keys", "sshd_config", "/etc/pam.d", "/etc/sudoers", "/etc/ld.so.preload", "/etc/rc.local"]):
            for line in stdout.splitlines():
                if line.strip() and len(initial_access_review_hits) < 20:
                    initial_access_review_hits.append(line.strip())

        if source in {"container", "cloud"} and stdout.strip():
            for line in stdout.splitlines():
                if line.strip() and len(container_cloud_review_hits) < 20:
                    container_cloud_review_hits.append(line.strip())

        if source == "network_ioc" and stdout.strip():
            for line in stdout.splitlines():
                if line.strip() and len(network_ioc_hits) < 20:
                    network_ioc_hits.append(line.strip())

        if source in {"process", "service", "persistence", "network_ioc", "binary_drop", "container", "cloud"}:
            for line in stdout.splitlines():
                profile = parse_runtime_profile_from_line(line, source, evid_id)
                if not profile:
                    continue
                if len(runtime_profiles) < 120:
                    runtime_profiles.append(profile)
                if profile.get("schedule") and len(cron_runtime_candidates) < 40:
                    cron_runtime_candidates.append(profile)

        if source == "privilege" and stdout.strip():
            for line in stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("uid=") and privilege_uid == "unknown":
                    privilege_uid = stripped.split()[0].split("=", 1)[1].split("(", 1)[0]
                elif stripped and privilege_user == "unknown":
                    privilege_user = stripped
                if "(ALL" in stripped or "NOPASSWD" in stripped:
                    privilege_has_passwordless_sudo = True

        if source == "persistence" and stdout.strip() and ("bpftool" in command or "kernel.modules_disabled" in command or "dmesg -T" in command):
            for line in stdout.splitlines():
                if line.strip() and len(kernel_review_hits) < 20:
                    kernel_review_hits.append(line.strip())

    runtime_profiles = dedupe_runtime_profiles(runtime_profiles)
    for item in top_cpu_processes:
        pid = str(item.get("pid", "")).strip()
        if pid and pid in process_exe_by_pid:
            item["executable"] = process_exe_by_pid[pid]
        if pid and not item.get("command") and pid in process_cmd_by_pid:
            item["command"] = process_cmd_by_pid[pid]
        cmd_blob = f"{item.get('command', '')} {item.get('executable', '')}".strip()
        item["miner_keyword_hit"] = bool(MINER_KEYWORD_RE.search(cmd_blob))
    dedup_top: list[dict[str, Any]] = []
    seen_top: set[str] = set()
    for item in top_cpu_processes:
        pid = str(item.get("pid", "")).strip()
        if pid and pid in seen_top:
            continue
        if pid:
            seen_top.add(pid)
        dedup_top.append(item)
        if len(dedup_top) >= 20:
            break
    top_cpu_processes = dedup_top

    ioc_blob = "\n".join(ioc_process_lines).lower()
    for item in gpu_compute_processes:
        pname = str(item.get("process", "")).strip()
        pid = str(item.get("pid", "")).strip()
        pid_correlated = bool(pid and re.search(rf"(^|\\D){re.escape(pid)}(\\D|$)", ioc_blob))
        if MINER_KEYWORD_RE.search(pname) or pid_correlated:
            gpu_suspicious_processes.append(item)

    runtime_algorithms = sorted({str(x.get("algorithm", "")).strip() for x in runtime_profiles if str(x.get("algorithm", "")).strip()})
    runtime_pools = sorted({str(x.get("pool", "")).strip() for x in runtime_profiles if str(x.get("pool", "")).strip()})
    runtime_proxies = sorted({str(x.get("proxy", "")).strip() for x in runtime_profiles if str(x.get("proxy", "")).strip()})
    runtime_wallets = sorted({str(x.get("wallet", "")).strip() for x in runtime_profiles if str(x.get("wallet", "")).strip()})
    runtime_passwords = sorted({str(x.get("password", "")).strip() for x in runtime_profiles if str(x.get("password", "")).strip()})
    runtime_threads = sorted(
        {
            str(x.get("cpu_threads", "")).strip()
            for x in runtime_profiles
            if str(x.get("cpu_threads", "")).strip()
        }
    )
    runtime_exec_paths = sorted({str(x.get("executable", "")).strip() for x in runtime_profiles if str(x.get("executable", "")).strip()})
    runtime_pool_ips = sorted({str(x.get("pool_host", "")).strip() for x in runtime_profiles if IPV4_RE.fullmatch(str(x.get("pool_host", "")).strip())})
    runtime_proxy_ips = sorted({str(x.get("proxy_host", "")).strip() for x in runtime_profiles if IPV4_RE.fullmatch(str(x.get("proxy_host", "")).strip())})
    runtime_signal_count = sum(
        1
        for x in runtime_profiles
        if any(
            [
                str(x.get("algorithm", "")).strip(),
                str(x.get("pool", "")).strip(),
                str(x.get("proxy", "")).strip(),
                str(x.get("wallet", "")).strip(),
                str(x.get("password", "")).strip(),
                str(x.get("cpu_threads", "")).strip(),
            ]
        )
    )
    top_cpu_keyword_hits = sum(1 for x in top_cpu_processes if x.get("miner_keyword_hit"))

    fidx = len(existing_findings)

    if failed_count > 0 or invalid_count > 0:
        fidx += 1
        ids = sorted({eid for ip in auth_source_map for eid in auth_source_map[ip]})
        fail_related_ips = sorted(set(failed_source_map) | set(invalid_source_map))
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement=(
                    f"Authentication evidence includes {failed_count} failed password event(s) and {invalid_count} invalid-user event(s) "
                    f"across {len(fail_related_ips)} source IP(s)."
                ),
                confidence="medium",
                evidence_ids=ids,
                claim_type="observed_fact",
                hypothesis_id="H-AUTO-AUTH-001",
                confidence_reason="Direct authentication artifacts are present, but upstream intrusion path is not yet confirmed.",
            )
        )

    if trust_flags:
        fidx += 1
        trust_ids = [str(x.get("id", "")) for x in evidence_items if str(x.get("source", "")) == "trust"]
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement="Command trust probe indicates alias/function behavior on one or more critical commands.",
                confidence="medium",
                evidence_ids=sorted(set(trust_ids)),
                claim_type="observed_fact",
                hypothesis_id="H-AUTO-TRUST-001",
                confidence_reason="The trust probe directly observed alias/function output, but intent and impact still require analyst review.",
            )
        )

    if listen_ports:
        fidx += 1
        net_ids = [str(x.get("id", "")) for x in evidence_items if str(x.get("source", "")) == "network"]
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement=f"Listening socket evidence includes ports: {', '.join(sorted(listen_ports)[:12])}.",
                confidence="high",
                evidence_ids=sorted(set(net_ids)),
                claim_type="observed_fact",
                hypothesis_id="H-AUTO-NET-001",
                confidence_reason="The listening-port list comes directly from socket inspection output.",
            )
        )

    if gpu_probe_ids and (gpu_adapter_lines or gpu_utilization_samples or gpu_compute_processes):
        fidx += 1
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement=(
                    f"GPU evidence reports {len(gpu_adapter_lines) or len(gpu_utilization_samples)} adapter/utilization line(s), "
                    f"{len(gpu_compute_processes)} active compute process record(s), and {len(gpu_suspicious_processes)} suspicious GPU process correlation(s)."
                ),
                confidence="medium" if gpu_suspicious_processes else "low",
                evidence_ids=sorted(gpu_probe_ids),
                claim_type="observed_fact" if gpu_suspicious_processes else "inference",
                hypothesis_id="H-AUTO-GPU-001",
                confidence_reason=(
                    "GPU process lines include miner-like keyword or PID correlation with process IOC output."
                    if gpu_suspicious_processes
                    else "GPU runtime visibility is present, but no direct miner-linked GPU process is confirmed yet."
                ),
            )
        )

    if ioc_process_lines:
        fidx += 1
        proc_ids = [str(x.get("id", "")) for x in evidence_items if str(x.get("source", "")) == "process"]
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement=f"Process IOC keyword probe returned {len(ioc_process_lines)} matching line(s).",
                confidence="medium",
                evidence_ids=sorted(set(proc_ids)),
                claim_type="inference",
                hypothesis_id="H-AUTO-PROC-001",
                confidence_reason="Keyword-based IOC hits are suggestive, but do not independently prove malicious mining intent.",
            )
        )

    if top_cpu_processes:
        fidx += 1
        proc_ids = [str(x.get("id", "")) for x in evidence_items if str(x.get("source", "")) == "process"]
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement=(
                    f"Top-CPU process mapping captured {len(top_cpu_processes)} process-to-command record(s), "
                    f"with {top_cpu_keyword_hits} miner-keyword hit(s) in command or executable fields."
                ),
                confidence="medium" if top_cpu_keyword_hits else "low",
                evidence_ids=sorted(set(proc_ids)),
                claim_type="observed_fact",
                hypothesis_id="H-AUTO-PROC-TOP-001",
                confidence_reason="Process ranking and executable mapping come directly from live process inspection outputs.",
            )
        )

    if runtime_profiles:
        fidx += 1
        runtime_ids = sorted({str(x.get("evidence_id", "")).strip() for x in runtime_profiles if str(x.get("evidence_id", "")).strip()})
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement=(
                    f"Runtime parameter extraction recovered {len(runtime_profiles)} miner-like command profile(s) "
                    f"with explicit algorithm/pool/proxy/wallet/password/thread fields."
                ),
                confidence="high" if runtime_signal_count >= 1 and (runtime_pools or runtime_wallets) else "medium",
                evidence_ids=runtime_ids,
                claim_type="observed_fact",
                hypothesis_id="H-AUTO-RUNTIME-001",
                confidence_reason="Fields were parsed directly from process, service, or scheduled-command artifacts.",
            )
        )

    if fallback_markers:
        fidx += 1
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement=f"Command fallback markers were observed {len(fallback_markers)} time(s), indicating missing or unavailable primary tooling on at least one probe path.",
                confidence="low",
                evidence_ids=sorted(fallback_marker_ids),
                claim_type="observed_fact",
                hypothesis_id="H-AUTO-FALLBACK-001",
                confidence_reason="Fallback markers are emitted by executed probes when preferred commands are unavailable.",
            )
        )

    if initial_access_review_hits:
        fidx += 1
        access_ids = [str(x.get("id", "")) for x in evidence_items if str(x.get("source", "")) in {"auth", "persistence"}]
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement=f"Initial-access and privileged-access review surfaces returned {len(initial_access_review_hits)} noteworthy line(s) for analyst review.",
                confidence="low",
                evidence_ids=sorted(set(access_ids)),
                claim_type="inference",
                hypothesis_id="H-AUTO-ACCESS-001",
                confidence_reason="The lines indicate review surfaces such as authorized_keys, sshd, PAM, sudoers, or preload entries, but maliciousness is not established automatically.",
            )
        )

    if container_cloud_review_hits:
        fidx += 1
        cc_ids = [str(x.get("id", "")) for x in evidence_items if str(x.get("source", "")) in {"container", "cloud"}]
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement=f"Container or cloud review surfaces returned {len(container_cloud_review_hits)} line(s) that may require analyst triage.",
                confidence="low",
                evidence_ids=sorted(set(cc_ids)),
                claim_type="inference",
                hypothesis_id="H-AUTO-CLOUD-001",
                confidence_reason="Container, kube, or cloud-related lines can indicate exposure paths, but they are not sufficient for attribution by themselves.",
            )
        )

    if network_ioc_hits:
        fidx += 1
        ioc_ids = [str(x.get("id", "")) for x in evidence_items if str(x.get("source", "")) == "network_ioc"]
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement=f"Network IOC review found {len(network_ioc_hits)} line(s) containing pool, wallet, or deployment keywords.",
                confidence="low",
                evidence_ids=sorted(set(ioc_ids)),
                claim_type="inference",
                hypothesis_id="H-AUTO-NETIOC-001",
                confidence_reason="Keyword matches can be useful leads, but require analyst verification to rule out benign configuration text.",
            )
        )

    if kernel_review_hits:
        fidx += 1
        kernel_ids = [
            str(x.get("id", ""))
            for x in evidence_items
            if str(x.get("source", "")) == "persistence"
            and ("bpftool" in str(x.get("command", "")) or "kernel.modules_disabled" in str(x.get("command", "")) or "dmesg -T" in str(x.get("command", "")))
        ]
        finding_add.append(
            finding_shape(
                finding_id=f"F-AUTO-{fidx:03d}",
                statement=f"Kernel or eBPF review surfaces returned {len(kernel_review_hits)} line(s) that may require deeper rootkit-oriented triage.",
                confidence="low",
                evidence_ids=sorted(set(kernel_ids)),
                claim_type="inference",
                hypothesis_id="H-AUTO-KERNEL-001",
                confidence_reason="Kernel module, eBPF, or taint-related output can indicate deeper persistence or may reflect benign platform state; dedicated forensic tooling is required for confirmation.",
            )
        )

    for ip, ids in auth_source_map.items():
        ip_trace_add.append(
            {
                "ip": ip,
                "role": "auth_source",
                "trace_status": "unknown",
                "reason": "Observed in authentication evidence only; upstream attribution path is not established in this case.",
                "evidence_ids": sorted(ids),
            }
        )

    gpu_utils = [safe for safe in [parse_int_from_text(str(x.get("utilization", ""))) for x in gpu_utilization_samples] if safe is not None]
    gpu_peak_util = max(gpu_utils) if gpu_utils else 0
    has_network_ioc = bool(network_ioc_hits)
    has_process_ioc = bool(ioc_process_lines)
    has_runtime_profile = bool(runtime_profiles)
    has_auth_pressure = failed_count > 0 or invalid_count > 0
    has_persistence_surface = bool(initial_access_review_hits or kernel_review_hits)
    has_log_risk = any(str(item.get("status", "")).lower() in {"missing", "tampered", "suspicious"} for item in as_list(data.get("log_integrity")))

    def matrix_item(
        hypothesis_id: str,
        title: str,
        status: str,
        confidence: str,
        support_ids: list[str],
        counter_ids: list[str],
        summary: str,
    ) -> dict[str, Any]:
        return {
            "hypothesis_id": hypothesis_id,
            "title": title,
            "status": status,
            "confidence": confidence,
            "supporting_evidence_ids": sorted({x for x in support_ids if x}),
            "counter_evidence_ids": sorted({x for x in counter_ids if x}),
            "summary": summary,
        }

    src_ids = {}
    for item in evidence_items:
        src = str(item.get("source", "")).strip()
        evid = str(item.get("id", "")).strip()
        if src and evid:
            src_ids.setdefault(src, []).append(evid)

    hypothesis_matrix: list[dict[str, Any]] = []
    hypothesis_matrix.append(
        matrix_item(
            "H-MATRIX-CPU-001",
            "CPU runtime miner hypothesis",
            "supported" if has_process_ioc else "inconclusive",
            "medium" if has_process_ioc else "low",
            src_ids.get("process", []),
            [],
            "Process IOC keyword matches exist." if has_process_ioc else "No direct miner-like process keyword match was observed in this pass.",
        )
    )
    if gpu_probe_ids:
        gpu_status = "supported" if gpu_suspicious_processes else ("inconclusive" if gpu_compute_processes or gpu_peak_util > 0 else "not_observed")
        hypothesis_matrix.append(
            matrix_item(
                "H-MATRIX-GPU-001",
                "GPU runtime miner hypothesis",
                gpu_status,
                "medium" if gpu_suspicious_processes else "low",
                sorted(gpu_probe_ids),
                src_ids.get("process", []) if not gpu_suspicious_processes else [],
                (
                    f"GPU suspicious process correlations={len(gpu_suspicious_processes)}, peak utilization={gpu_peak_util}%."
                    if gpu_suspicious_processes
                    else f"GPU activity observed (peak utilization={gpu_peak_util}%), but no direct miner-linked GPU process was confirmed."
                ),
            )
        )
    hypothesis_matrix.append(
        matrix_item(
            "H-MATRIX-ACCESS-001",
            "Credential or initial-access abuse hypothesis",
            "supported" if has_auth_pressure else ("inconclusive" if initial_access_review_hits else "not_observed"),
            "medium" if has_auth_pressure else "low",
            src_ids.get("auth", []) + src_ids.get("persistence", []),
            [],
            (
                f"Authentication pressure observed (failed={failed_count}, invalid={invalid_count})."
                if has_auth_pressure
                else "Only review-surface signals are present; direct credential abuse evidence is limited."
            ),
        )
    )
    hypothesis_matrix.append(
        matrix_item(
            "H-MATRIX-PERSIST-001",
            "Persistence foothold hypothesis",
            "supported" if has_persistence_surface else "inconclusive",
            "low",
            src_ids.get("persistence", []) + src_ids.get("service", []),
            [],
            "Persistence review surfaces contain suspicious lines and require analyst confirmation."
            if has_persistence_surface
            else "No persistence surface hit was observed in this pass.",
        )
    )
    hypothesis_matrix.append(
        matrix_item(
            "H-MATRIX-RUNTIME-001",
            "Parsed miner runtime profile hypothesis",
            "supported" if has_runtime_profile else "inconclusive",
            "high" if has_runtime_profile else "low",
            sorted({str(x.get("evidence_id", "")).strip() for x in runtime_profiles if str(x.get("evidence_id", "")).strip()}),
            [],
            (
                f"Parsed {len(runtime_profiles)} runtime profile(s): algorithms={len(runtime_algorithms)}, pools={len(runtime_pools)}, proxies={len(runtime_proxies)}, wallets={len(runtime_wallets)}."
                if has_runtime_profile
                else "No command line with parseable miner runtime fields was observed in this pass."
            ),
        )
    )
    hypothesis_matrix.append(
        matrix_item(
            "H-MATRIX-NET-001",
            "Network IOC and outbound control hypothesis",
            "supported" if has_network_ioc else "inconclusive",
            "low",
            src_ids.get("network_ioc", []) + src_ids.get("network", []),
            [],
            "Pool/wallet/deployment keyword matches are present in network IOC review." if has_network_ioc else "No direct pool/wallet keyword hit in this pass.",
        )
    )
    if has_log_risk:
        hypothesis_matrix.append(
            matrix_item(
                "H-MATRIX-LOG-001",
                "Log tampering hypothesis",
                "supported",
                "medium",
                src_ids.get("log_integrity", []),
                [],
                "Primary log artifacts show missing/tampered/suspicious state.",
            )
        )

    merged_findings = dedupe_findings(existing_findings + finding_add)
    merged_timeline = dedupe_timeline(existing_timeline + timeline_add)
    merged_ip_traces = merge_ip_traces(existing_ip_traces, ip_trace_add)

    scene_reconstruction = {
        "generated_at_utc": now_utc(),
        "collector_version": str(data.get("collector_version", "unknown")),
        "time_normalization": {
            "report_timezone": str(data.get("report_timezone_basis", data.get("timezone", "UTC"))),
            "host_reported_timezone": host_reported_timezone,
            "host_ntp_synchronized": host_ntp_synchronized,
            "event_time_field": "normalized_time_utc",
            "log_time_source_priority": ["explicit log timestamp", "collector observed_at", "artifact mtime"],
            "clock_offset_assessment": "not_measured",
        },
        "auth_event_counts": {
            "accepted": accepted_count,
            "failed": failed_count,
            "invalid": invalid_count,
        },
        "auth_source_ips": sorted(auth_source_map),
        "auth_source_breakdown": {
            "accepted": sorted(accepted_source_map),
            "failed": sorted(failed_source_map),
            "invalid": sorted(invalid_source_map),
            "closed": sorted(closed_source_map),
        },
        "listening_ports": sorted(listen_ports),
        "trust_anomalies": sorted(trust_flags),
        "privilege_scope": {
            "user": privilege_user,
            "uid": privilege_uid,
            "passwordless_sudo_visible": privilege_has_passwordless_sudo,
        },
        "process_ioc_match_count": len(ioc_process_lines),
        "process_ioc_samples": sorted(ioc_process_lines)[:10],
        "top_cpu_process_count": len(top_cpu_processes),
        "top_cpu_process_keyword_hit_count": top_cpu_keyword_hits,
        "top_cpu_processes": top_cpu_processes[:10],
        "initial_access_review_hit_count": len(initial_access_review_hits),
        "initial_access_review_samples": initial_access_review_hits[:10],
        "container_cloud_review_hit_count": len(container_cloud_review_hits),
        "container_cloud_review_samples": container_cloud_review_hits[:10],
        "network_ioc_hit_count": len(network_ioc_hits),
        "network_ioc_samples": network_ioc_hits[:10],
        "kernel_review_hit_count": len(kernel_review_hits),
        "kernel_review_samples": kernel_review_hits[:10],
        "gpu_vendor_hints": sorted(gpu_vendor_hints),
        "gpu_adapter_line_count": len(gpu_adapter_lines),
        "gpu_adapter_samples": gpu_adapter_lines[:10],
        "gpu_utilization_samples": gpu_utilization_samples[:10],
        "gpu_peak_utilization_percent": gpu_peak_util,
        "gpu_compute_process_count": len(gpu_compute_processes),
        "gpu_compute_process_samples": gpu_compute_processes[:10],
        "gpu_suspicious_process_count": len(gpu_suspicious_processes),
        "gpu_suspicious_process_samples": gpu_suspicious_processes[:10],
        "gpu_probe_ids": sorted(gpu_probe_ids),
        "command_fallback_marker_count": len(fallback_markers),
        "command_fallback_markers": fallback_markers[:20],
        "runtime_profile_count": len(runtime_profiles),
        "runtime_profile_signal_count": runtime_signal_count,
        "runtime_profiles": runtime_profiles[:20],
        "runtime_algorithms": runtime_algorithms[:12],
        "runtime_pools": runtime_pools[:12],
        "runtime_pool_ips": runtime_pool_ips[:12],
        "runtime_proxies": runtime_proxies[:12],
        "runtime_proxy_ips": runtime_proxy_ips[:12],
        "runtime_wallets": runtime_wallets[:12],
        "runtime_passwords": runtime_passwords[:12],
        "runtime_cpu_threads": runtime_threads[:12],
        "runtime_exec_paths": runtime_exec_paths[:12],
        "cron_runtime_candidate_count": len(cron_runtime_candidates),
        "cron_runtime_candidates": cron_runtime_candidates[:20],
        "timeline_count": len(merged_timeline),
        "finding_count": len(merged_findings),
        "ip_trace_count": len(merged_ip_traces),
        "hypothesis_matrix_count": len(hypothesis_matrix),
    }

    note = (
        "Auto-enrichment added evidence-bound timeline/findings/ip-trace hints. "
        "Analyst confirmation is required for final attribution."
    )
    if note not in unknowns:
        unknowns.append(note)

    data["findings"] = merged_findings
    data["timeline"] = merged_timeline
    data["ip_traces"] = merged_ip_traces
    data["hypothesis_matrix"] = hypothesis_matrix
    data["unknowns"] = unknowns
    data["scene_reconstruction"] = scene_reconstruction
    data["enrichment"] = {
        "script": "enrich_case_evidence.py",
        "generated_at_utc": now_utc(),
        "added_findings": len(finding_add),
        "added_timeline": len(timeline_add),
        "added_ip_traces": len(ip_trace_add),
    }
    return data


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enrich evidence JSON with timeline and traceability hints (no fabrication)."
    )
    parser.add_argument("--input", required=True, help="Input evidence JSON.")
    parser.add_argument("--output", help="Output JSON path. Defaults to sibling evidence.reviewed.auto.json.")
    parser.add_argument("--in-place", action="store_true", help="Write enrichment back to input file.")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    if args.in_place:
        output_path = input_path
    else:
        output_path = Path(args.output).resolve() if args.output else (input_path.parent / "evidence.reviewed.auto.json")

    data = load_json(input_path)
    enriched = enrich(data)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(enriched, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Enriched evidence written: {output_path}")
    print(
        f"Counts: findings={len(as_list(enriched.get('findings')))} "
        f"timeline={len(as_list(enriched.get('timeline')))} "
        f"ip_traces={len(as_list(enriched.get('ip_traces')))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
