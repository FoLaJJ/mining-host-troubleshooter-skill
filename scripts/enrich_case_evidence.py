#!/usr/bin/env python3
"""Enrich evidence JSON with evidence-bound timeline, findings, and IP trace hints."""

from __future__ import annotations

import argparse
import json
import re
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
    initial_access_review_hits: list[str] = []
    container_cloud_review_hits: list[str] = []
    network_ioc_hits: list[str] = []
    kernel_review_hits: list[str] = []
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

        if source == "process" and "grep -Ei 'miner|xmrig|lolminer|trex|gminer|nbminer|clash|autossh|h32|h64|\\-zsh'" in command:
            if exit_code == 0 and stdout.strip():
                for ln in stdout.splitlines():
                    if ln.strip():
                        ioc_process_lines.append(ln.strip())

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
        "initial_access_review_hit_count": len(initial_access_review_hits),
        "initial_access_review_samples": initial_access_review_hits[:10],
        "container_cloud_review_hit_count": len(container_cloud_review_hits),
        "container_cloud_review_samples": container_cloud_review_hits[:10],
        "network_ioc_hit_count": len(network_ioc_hits),
        "network_ioc_samples": network_ioc_hits[:10],
        "kernel_review_hit_count": len(kernel_review_hits),
        "kernel_review_samples": kernel_review_hits[:10],
        "timeline_count": len(merged_timeline),
        "finding_count": len(merged_findings),
        "ip_trace_count": len(merged_ip_traces),
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
