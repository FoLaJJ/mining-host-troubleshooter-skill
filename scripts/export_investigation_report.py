#!/usr/bin/env python3
"""Export a fact-constrained investigation report from structured evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any


TRACE_STATUSES = {"traced", "untraceable", "unknown"}


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON: {exc}")
    if not isinstance(data, dict):
        raise SystemExit("Input JSON must be an object.")
    return data


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def mask_ip(ip: str) -> str:
    m = re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", ip.strip())
    if not m:
        return ip
    parts = ip.split(".")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return ip
    if any(n < 0 or n > 255 for n in nums):
        return ip
    return f"{parts[0]}.{parts[1]}.x.x"


def redact_secrets(text: str) -> str:
    redacted = text
    redacted = re.sub(r"\b0x[a-fA-F0-9]{40}\b", "[REDACTED_ETH_ADDRESS]", redacted)
    redacted = re.sub(
        r"\b(bc1[a-z0-9]{20,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
        "[REDACTED_BTC_ADDRESS]",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\b(password|passwd|token|secret|api[_-]?key)\b\s*[:=]\s*([^\s,;]+)",
        r"\1=[REDACTED_SECRET]",
        redacted,
    )
    redacted = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]", redacted, flags=re.S)
    return redacted


def redact_text(text: str) -> str:
    redacted = redact_secrets(text)
    redacted = re.sub(
        r"\b(\d{1,3}\.){3}\d{1,3}\b",
        lambda m: mask_ip(m.group(0)),
        redacted,
    )
    return redacted


def sanitize_report_text(text: str, redact: bool) -> str:
    base = redact_secrets(text)
    return redact_text(base) if redact else base


def md_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", "<br>")


def evidence_index(evidence_items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = {}
    for item in evidence_items:
        evid = str(item.get("id", "")).strip()
        if evid:
            idx[evid] = item
    return idx


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


def artifact_excerpt(item: dict[str, Any], max_lines: int = 3, max_chars: int = 220) -> list[str]:
    artifact_path = str(item.get("artifact", "")).strip()
    if not artifact_path:
        return []
    path = Path(artifact_path)
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    stdout, stderr = split_artifact_sections(text)
    chosen = stdout or stderr
    lines: list[str] = []
    for raw in chosen.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(compact_text(stripped, max_len=max_chars))
        if len(lines) >= max_lines:
            break
    return lines


def render_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(md_escape(cell) for cell in row) + " |")
    return "\n".join(lines)


def normalize_trace_status(value: str) -> str:
    v = (value or "").strip().lower()
    return v if v in TRACE_STATUSES else "unknown"


def evidence_time_window(evidence_items: list[dict[str, Any]]) -> tuple[str, str]:
    times = [
        str(item.get("observed_at", "")).strip()
        for item in evidence_items
        if str(item.get("observed_at", "")).strip()
    ]
    if not times:
        return "unknown", "unknown"
    return min(times), max(times)


def finding_status_counts(
    findings: list[dict[str, Any]], evid_idx: dict[str, dict[str, Any]]
) -> tuple[int, int]:
    confirmed = 0
    inconclusive = 0
    for item in findings:
        ids = [str(x) for x in as_list(item.get("evidence_ids"))]
        missing = [x for x in ids if x not in evid_idx]
        if ids and not missing:
            confirmed += 1
        else:
            inconclusive += 1
    return confirmed, inconclusive


def top_judgments(
    findings: list[dict[str, Any]], evid_idx: dict[str, dict[str, Any]], limit: int = 6
) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in findings:
        ids = [str(x) for x in as_list(item.get("evidence_ids"))]
        missing = [x for x in ids if x not in evid_idx]
        status = "confirmed" if ids and not missing else "inconclusive"
        out.append(
            {
                "id": str(item.get("id", "unknown")),
                "statement": str(item.get("statement", "")).strip(),
                "confidence": str(item.get("confidence", "unknown")),
                "status": status,
                "claim_type": normalize_claim_type(str(item.get("claim_type", ""))),
                "hypothesis_id": str(item.get("hypothesis_id", "-")).strip() or "-",
                "confidence_reason": str(item.get("confidence_reason", "")).strip() or "-",
                "evidence_ids": ", ".join(ids) if ids else "none",
            }
        )
    return out[:limit]


def load_optional_case_json(case_dir: str | None, relative_path: str) -> dict[str, Any]:
    if not case_dir:
        return {}
    path = Path(case_dir) / relative_path
    if not path.exists():
        return {}
    return as_dict(load_json(path))


def shorten_list(items: list[Any], limit: int = 6) -> str:
    rendered = [str(item) for item in items[:limit]]
    if len(items) > limit:
        rendered.append(f"... (+{len(items) - limit} more)")
    return ", ".join(rendered) if rendered else "-"


def short_hash(value: str, size: int = 12) -> str:
    text = value.strip()
    if not text:
        return "-"
    return text if len(text) <= size else f"{text[:size]}..."


def count_by(items: list[dict[str, Any]], key: str, default: str = "unknown") -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key, default)).strip() or default
        counts[value] = counts.get(value, 0) + 1
    return counts


def safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def normalize_claim_type(value: str) -> str:
    text = value.strip().lower()
    if text in {"observed_fact", "fact", "observation"}:
        return "observed_fact"
    if text in {"attribution", "attributed"}:
        return "attribution"
    return "inference"


def claim_type_label(value: str) -> str:
    return {
        "observed_fact": "Observed Fact",
        "inference": "Inference",
        "attribution": "Attribution",
    }.get(normalize_claim_type(value), "Inference")


def localize_auto_text_zh_cn(text: str) -> str:
    value = str(text or "").strip()
    if not value:
        return value

    exact_map = {
        "Auto-collected read-only evidence snapshot. Analyst review required.": "自动采集的只读证据快照，仍需分析人员复核。",
        "Auto-collected read-only evidence snapshot. Analyst review required. No findings are asserted without explicit evidence linkage.": "自动采集的只读证据快照，仍需分析人员复核；任何结论都必须显式关联证据后才可成立。",
        "Report normalization basis only; not the host local timezone.": "这里只表示报告统一归一化所使用的时区，不代表主机本地时区。",
        "Mark untraceable/unknown IPs explicitly; do not infer attribution without evidence.": "请明确标记未溯源或状态未知的 IP；在缺乏证据时不要推导攻击者归因。",
        "No analyst findings yet. Add only evidence-backed findings.": "当前尚无人工确认的结论；新增结论时仅允许写入有证据支撑的内容。",
        "Auto-enrichment added evidence-bound timeline/findings/ip-trace hints. Analyst confirmation is required for final attribution.": "自动补充流程已生成受证据约束的时间线、研判和 IP 溯源提示；最终归因仍需人工确认。",
        "Direct authentication artifacts are present, but upstream intrusion path is not yet confirmed.": "已观察到直接的认证类证据，但上游入侵路径尚未确认。",
        "The listening-port list comes directly from socket inspection output.": "监听端口列表直接来自套接字检查结果。",
        "The lines indicate review surfaces such as authorized_keys, sshd, PAM, sudoers, or preload entries, but maliciousness is not established automatically.": "这些命中行涉及 authorized_keys、sshd、PAM、sudoers 或 preload 等复核面，但不能自动判定其为恶意行为。",
        "Container, kube, or cloud-related lines can indicate exposure paths, but they are not sufficient for attribution by themselves.": "容器、Kubernetes 或云侧相关命中可能提示暴露面，但单凭这些内容不足以完成归因。",
        "Kernel module, eBPF, or taint-related output can indicate deeper persistence or may reflect benign platform state; dedicated forensic tooling is required for confirmation.": "内核模块、eBPF 或 taint 相关输出可能指向更深层的持久化，也可能只是平台正常状态；需要更专门的取证工具进一步确认。",
        "Keyword-based IOC hits are suggestive, but do not independently prove malicious mining intent.": "基于关键字的 IOC 命中只具提示意义，不能单独证明存在恶意挖矿意图。",
        "Observed in authentication evidence only; upstream attribution path is not established in this case.": "该 IP 目前仅在认证类证据中出现，本案尚未建立其上游归因路径。",
        "No direct miner-like process keyword match was observed in this pass.": "本轮未观察到直接的矿工类进程关键字命中。",
        "GPU runtime visibility is present, but no direct miner-linked GPU process is confirmed yet.": "已获取 GPU 运行时可见性，但暂未确认与矿工直接关联的 GPU 进程。",
        "Persistence review surfaces contain suspicious lines and require analyst confirmation.": "持久化复核面存在可疑线索，需分析人员进一步确认。",
        "No direct pool/wallet keyword hit in this pass.": "本轮未命中直接矿池或钱包关键字。",
        "Primary log artifacts show missing/tampered/suspicious state.": "关键日志产物存在缺失、篡改或可疑状态。",
        "No direct host-side lateral-movement indicator was observed in current visibility.": "当前可见性范围内，未直接观察到主机侧横向移动指标。",
        "Transfer or remote-shell tool strings were observed and require deeper pivot review.": "已观察到传输工具或远程壳相关字符串，需要继续做横向支点复核。",
        "No listening-port list was recovered in this pass.": "本轮未恢复出监听端口列表。",
        "No direct miner IOC was observed in this collection. Current results are limited to review surfaces that still require analyst confirmation.": "本次采集中未观察到直接的挖矿 IOC，当前结果主要是需要人工复核的访问面与环境侧线索。",
        "This does not clear the host. The present output supports review-driven triage, not a confirmed mining-compromise conclusion.": "这并不能证明主机安全无虞。当前输出仅支持复核驱动的分诊，不足以下结论为已确认的挖矿入侵。",
        "Absence of indicators in this pass is not proof of absence; visibility, timing, and privilege may still be incomplete.": "本轮未见指标并不等于不存在问题；当前可见性、采集时机和权限范围仍可能不完整。",
        "Prioritize runtime lineage, parent-child process review, wallet/pool traces, and persistence pivots.": "优先复核运行链路、父子进程关系、钱包或矿池痕迹，以及持久化支点。",
        "Prioritize surviving access traces, service startup context, container/cloud exposure, and deleted-log fallback artifacts.": "优先复核现存访问痕迹、服务启动上下文、容器或云侧暴露面，以及日志缺失后的替代证据。",
        "Expand time window, privilege visibility, and external telemetry correlation before closing the case.": "在结案前应继续扩展时间窗口、权限可见性，并补做外部遥测关联。",
        "yes": "是",
        "no": "否",
        "True": "是",
        "False": "否",
        "unknown": "未知",
    }
    if value in exact_map:
        return exact_map[value]

    pattern_rules: list[tuple[re.Pattern[str], Any]] = [
        (
            re.compile(
                r"^Authentication evidence includes (\d+) failed password event\(s\) and (\d+) invalid-user event\(s\) across (\d+) source IP\(s\)\.$"
            ),
            lambda m: f"认证类证据显示：共出现 {m.group(1)} 次失败密码事件、{m.group(2)} 次无效用户事件，涉及 {m.group(3)} 个来源 IP。",
        ),
        (
            re.compile(r"^Listening socket evidence includes ports: (.+)\.$"),
            lambda m: f"监听套接字证据显示，当前涉及的端口包括：{m.group(1).replace(', ', '、')}。",
        ),
        (
            re.compile(r"^Process IOC keyword probe returned (\d+) matching line\(s\)\.$"),
            lambda m: f"进程 IOC 关键字探测返回了 {m.group(1)} 条命中记录。",
        ),
        (
            re.compile(
                r"^Initial-access and privileged-access review surfaces returned (\d+) noteworthy line\(s\) for analyst review\.$"
            ),
            lambda m: f"初始访问与高权限访问复核面共返回 {m.group(1)} 条值得分析人员复核的记录。",
        ),
        (
            re.compile(r"^Container or cloud review surfaces returned (\d+) line\(s\) that may require analyst triage\.$"),
            lambda m: f"容器或云侧复核面共返回 {m.group(1)} 条可能需要进一步分诊的记录。",
        ),
        (
            re.compile(r"^Network IOC review found (\d+) line\(s\) containing pool, wallet, or deployment keywords\.$"),
            lambda m: f"网络 IOC 复核发现了 {m.group(1)} 条包含矿池、钱包或投放关键字的记录。",
        ),
        (
            re.compile(r"^Kernel or eBPF review surfaces returned (\d+) line\(s\) that may require deeper rootkit-oriented triage\.$"),
            lambda m: f"内核或 eBPF 复核面共返回 {m.group(1)} 条可能需要更深入 rootkit 向分诊的记录。",
        ),
        (
            re.compile(
                r"^GPU evidence reports (\d+) adapter/utilization line\(s\), (\d+) active compute process record\(s\), and (\d+) suspicious GPU process correlation\(s\)\.$"
            ),
            lambda m: f"GPU 证据显示：适配器/利用率记录 {m.group(1)} 条，计算进程记录 {m.group(2)} 条，可疑 GPU 进程关联 {m.group(3)} 条。",
        ),
        (
            re.compile(r"^GPU activity observed \(peak utilization=(\d+)%\), but no direct miner-linked GPU process was confirmed\.$"),
            lambda m: f"已观察到 GPU 活动（峰值利用率 {m.group(1)}%），但未确认直接与矿工关联的 GPU 进程。",
        ),
        (
            re.compile(r"^Authentication pressure observed \(failed=(\d+), invalid=(\d+)\)\.$"),
            lambda m: f"认证压力已观察到（失败密码 {m.group(1)} 次，无效用户 {m.group(2)} 次）。",
        ),
        (
            re.compile(
                r"^Top-CPU process mapping captured (\d+) process-to-command record\(s\), with (\d+) miner-keyword hit\(s\) in command or executable fields\.$"
            ),
            lambda m: f"高 CPU 进程映射共捕获 {m.group(1)} 条进程-命令记录，其中 {m.group(2)} 条在命令或可执行路径中命中矿工关键字。",
        ),
        (
            re.compile(
                r"^Runtime parameter extraction recovered (\d+) miner-like command profile\(s\) with explicit algorithm/pool/proxy/wallet/password/thread fields\.$"
            ),
            lambda m: f"运行参数解析共恢复 {m.group(1)} 条矿工类命令画像，已提取算法、矿池、代理、钱包、密码和线程等字段。",
        ),
        (
            re.compile(
                r"^Command fallback markers were observed (\d+) time\(s\), indicating missing or unavailable primary tooling on at least one probe path\.$"
            ),
            lambda m: f"命令降级标记共出现 {m.group(1)} 次，表示至少一条探测路径存在主工具缺失或不可用。",
        ),
        (
            re.compile(
                r"^File correlation recovered (\d+) suspicious executable path/hash candidate\(s\) from runtime or drop-path evidence\.$"
            ),
            lambda m: f"文件关联共恢复 {m.group(1)} 条可疑可执行文件路径/哈希候选，来源于运行时或落地路径证据。",
        ),
        (
            re.compile(
                r"^Recovered (\d+) suspicious file candidate\(s\), with hashes on (\d+) item\(s\)\.$"
            ),
            lambda m: f"已恢复 {m.group(1)} 条可疑文件候选，其中 {m.group(2)} 条带有文件哈希。",
        ),
        (
            re.compile(r"^Listening ports observed on the host: (.+)\.$"),
            lambda m: f"主机当前观察到的监听端口包括：{m.group(1).replace(', ', '、')}。",
        ),
        (
            re.compile(r"^Access or persistence review surfaces returned notable lines such as: (.+)$"),
            lambda m: f"访问面或持久化复核返回了值得关注的记录，例如：{m.group(1)}",
        ),
        (
            re.compile(r"^Network IOC review produced hits such as: (.+)$"),
            lambda m: f"网络 IOC 复核返回了值得关注的命中，例如：{m.group(1)}",
        ),
        (
            re.compile(
                r"^Runtime evidence shows miner-like execution via (.+), algorithm=(.+), pool=(.+), proxy=(.+), wallet=(.+), password=(.+), cpu_threads=(.+)$"
            ),
            lambda m: (
                f"运行时证据显示存在疑似矿工执行：可执行文件 {m.group(1)}，算法 {m.group(2)}，矿池 {m.group(3)}，代理 {m.group(4)}，"
                f"钱包 {m.group(5)}，口令 {m.group(6)}，CPU 线程 {m.group(7)}"
            ),
        ),
        (
            re.compile(
                r"^Parsed (\d+) runtime profile\(s\): algorithms=(\d+), pools=(\d+), proxies=(\d+), wallets=(\d+)\.$"
            ),
            lambda m: f"已解析 {m.group(1)} 条运行参数画像：算法 {m.group(2)} 项、矿池 {m.group(3)} 项、代理 {m.group(4)} 项、钱包 {m.group(5)} 项。",
        ),
    ]
    for pattern, renderer in pattern_rules:
        match = pattern.match(value)
        if match:
            return renderer(match)
    return value


def zh_report_text(text: str, redact: bool) -> str:
    return sanitize_report_text(localize_auto_text_zh_cn(text), redact)


def finalize_zh_markdown(text: str) -> str:
    text = text.replace("[artifact]", "[产物]")
    text = text.replace("artifact missing", "产物缺失")
    text = text.replace("review full report", "请查看中文全量报告")
    text = re.sub(r"\(\+(\d+) more; 请查看中文全量报告\)", r"（另 \1 项；请查看中文全量报告）", text)
    text = re.sub(r"\.\.\. \(\+(\d+) more\)", r"...（另 \1 项）", text)
    return text


def compact_evidence_chain_zh_cn(
    evidence_ids: list[Any],
    evid_idx: dict[str, dict[str, Any]],
    case_dir: str | None,
    limit: int,
    base_dir: Path | None = None,
) -> str:
    rendered = compact_evidence_chain(evidence_ids, evid_idx, case_dir, limit=limit, base_dir=base_dir)
    rendered = (
        rendered.replace("[artifact]", "[产物]")
        .replace("artifact missing", "产物缺失")
        .replace("review full report", "请查看中文全量报告")
    )
    return re.sub(r"\(\+(\d+) more; 请查看中文全量报告\)", r"（另 \1 项；请查看中文全量报告）", rendered)


def evidence_reference_list_zh_cn(
    evidence_ids: list[Any],
    evid_idx: dict[str, dict[str, Any]],
    case_dir: str | None,
    base_dir: Path | None = None,
) -> str:
    return (
        evidence_reference_list(evidence_ids, evid_idx, case_dir, base_dir=base_dir)
        .replace("[artifact]", "[产物]")
        .replace("artifact missing", "产物缺失")
    )


def build_management_view(data: dict[str, Any], redact: bool, case_dir: str | None = None) -> str:
    ctx = prepare_report_context(data, redact=redact, strict=False, case_dir=case_dir)
    incident = as_dict(data.get("incident"))
    host = as_dict(data.get("host"))
    findings = ctx["findings"]
    evid_idx = ctx["evid_idx"]
    baseline_assessment = ctx["baseline_assessment"]
    posture_info = investigation_posture_payload(ctx)

    def maybe_redact(value: str) -> str:
        return sanitize_report_text(value, redact)

    key_items = top_judgments(findings, evid_idx, limit=5)
    host_display = f"{host.get('name', 'unknown')} ({maybe_redact(str(host.get('ip', 'unknown')))})"
    lines = [anchor_tag("mgmt-top"), f"# {incident.get('title', 'Mining Host Investigation')} - Management Summary", ""]
    if case_dir:
        lines.extend([
            "[Bundle Index](./index.md) | [Case Bundle (ZH-CN)](./index.zh-CN.md) | [Full Report](../report.md) | [Full Report (ZH-CN)](../report.zh-CN.md) | [SOC Summary](./soc-summary.md) | [Management Summary (ZH-CN)](./management-summary.zh-CN.md)",
            "",
        ])
    lines.extend([
        "> Executive view for rapid decision-making. Refer to the full report for detailed evidence and command provenance.",
        "",
        "## Quick Links",
        "- [Management Conclusion](#mgmt-conclusion)",
        "- [Executive Snapshot](#mgmt-snapshot)",
        "- [Risk Overview](#mgmt-risks)",
        "- [Priority Judgments](#mgmt-judgments)",
        "- [Management Caveat](#mgmt-caveat)",
        "",
        anchor_tag("mgmt-conclusion"),
        "## Management Conclusion",
        f"- **Current Position:** {maybe_redact(posture_info['verdict'])}",
        f"- **Confidence Posture:** {confidence_icon(posture_info['posture'])} `{posture_info['posture']}`",
        f"- **Decision Boundary:** {maybe_redact(posture_info['boundary'])}",
        f"- **Immediate Review Focus:** {maybe_redact(posture_info['focus'])}",
        "- **Operational Constraint:** This case bundle reflects read-only collection only; no state-changing action was executed.",
        "",
        anchor_tag("mgmt-snapshot"),
        "## Executive Snapshot",
        render_table(
            ["Metric", "Value"],
            [
                ["Incident ID", str(incident.get("id", "unknown"))],
                ["Case ID", str(data.get("case_id", "unknown"))],
                ["Host", host_display],
                ["Generated At (UTC)", str(data.get("generated_at", now_utc()))],
                ["Confirmed Findings", str(ctx["confirmed_count"])],
                ["Inconclusive Findings", str(ctx["inconclusive_count"])],
                ["Traceable IPs", str(ctx["trace_counts"]["traced"])],
                ["Untraceable / Unknown IPs", str(ctx["trace_counts"]["untraceable"] + ctx["trace_counts"]["unknown"])],
                ["Log Integrity Concerns", str(ctx["log_risk_count"])],
                ["Hypothesis Matrix Entries", str(len(ctx["hypothesis_matrix"]))],
                ["GPU Suspicious Process Count", str(safe_int(ctx["scene_reconstruction"].get("gpu_suspicious_process_count", 0)))],
                ["Expected Workload", maybe_redact(str(data.get("expected_workload", "") or "not provided"))],
            ],
        ),
        "",
        anchor_tag("mgmt-risks"),
        "## Risk Overview",
    ])
    lines.extend(key_risk_lines(data, case_dir=case_dir))
    lines.extend([
        "",
        "## Decision Notes",
        "- Observed facts remain separated from inference and attribution in the full report.",
        "- If workload legitimacy is not evidenced, high compute remains inconclusive.",
        "- Untraceable infrastructure remains labeled as such; no actor attribution is implied.",
    ])
    if baseline_assessment:
        lines.append(f"- Baseline assessment: `{maybe_redact(str(baseline_assessment.get('assessment_status', 'unknown')))}`.")
    lines.extend(["", anchor_tag("mgmt-judgments"), "## Priority Judgments"])
    if key_items:
        for item in key_items:
            evidence_ids = item['evidence_ids'].split(', ') if item['evidence_ids'] != 'none' else []
            lines.extend([
                f"### {status_icon(item['status'])} {item['id']}",
                f"- **Judgment:** {maybe_redact(item['statement'])}",
                f"- **Type / Status / Confidence:** `{claim_type_label(item['claim_type'])}` / `{item['status']}` / `{item['confidence']}`",
                f"- **Hypothesis:** `{maybe_redact(item['hypothesis_id'])}`",
                f"- **Confidence Reason:** {maybe_redact(item['confidence_reason'])}",
                f"- **Evidence Chain:** {compact_evidence_chain(evidence_ids, evid_idx, case_dir, limit=4, base_dir=Path(case_dir) / 'reports' if case_dir else None).replace('](#evidence-', '](../report.md#evidence-')}",
                "",
            ])
    else:
        lines.extend(["- No evidence-backed judgments available yet.", ""])
    lines.extend([
        anchor_tag("mgmt-caveat"),
        "## Management Caveat",
        "- This summary is intentionally concise. Use the full report before authorizing any change or remediation.",
        "- [Back to Top](#mgmt-top) | [Bundle Index](./index.md) | [Full Report](../report.md)",
        "",
    ])
    return "\n".join(lines).strip() + "\n"



def build_management_view_zh_cn(data: dict[str, Any], redact: bool, case_dir: str | None = None) -> str:
    ctx = prepare_report_context(data, redact=redact, strict=False, case_dir=case_dir)
    incident = as_dict(data.get("incident"))
    host = as_dict(data.get("host"))
    findings = ctx["findings"]
    evid_idx = ctx["evid_idx"]
    baseline_assessment = ctx["baseline_assessment"]
    posture_info = investigation_posture_payload(ctx)

    def maybe_redact(value: str) -> str:
        return sanitize_report_text(value, redact)

    def maybe_redact_zh(value: str) -> str:
        return zh_report_text(value, redact)

    def claim_type_label_zh_cn(value: str) -> str:
        return {
            "observed_fact": "观测事实",
            "inference": "推断",
            "attribution": "归因",
        }.get(normalize_claim_type(value), "推断")

    key_items = top_judgments(findings, evid_idx, limit=5)
    host_display = f"{host.get('name', 'unknown')} ({maybe_redact(str(host.get('ip', 'unknown')))})"
    lines = [anchor_tag("mgmt-top"), f"# {incident.get('title', 'Mining Host Investigation')} - 管理摘要", ""]
    if case_dir:
        lines.extend([
            "[案件索引](./index.zh-CN.md) | [英文索引](./index.md) | [中文全量报告](../report.zh-CN.md) | [英文全量报告](../report.md) | [SOC 摘要](./soc-summary.zh-CN.md) | [英文管理摘要](./management-summary.md)",
            "",
        ])
    lines.extend([
        "> 面向管理决策的精简视图。审批任何处置动作前，请回到全量报告核对完整证据链与命令来源。",
        "",
        "## 快速链接",
        "- [核心判断](#mgmt-conclusion)",
        "- [管理快照](#mgmt-snapshot)",
        "- [风险概览](#mgmt-risks)",
        "- [优先研判](#mgmt-judgments)",
        "- [管理提示](#mgmt-caveat)",
        "",
        anchor_tag("mgmt-conclusion"),
        "## 核心判断",
        f"- **当前结论：** {maybe_redact_zh({
            'Direct miner-like runtime indicators were observed during collection.': '本次采集中观察到了直接的挖矿类运行时指标。',
            'No direct miner IOC was observed in this collection. Current results are limited to review surfaces that still require analyst confirmation.': '本次采集中未观察到直接的挖矿 IOC，当前结果主要是需要人工复核的访问面与环境侧线索。',
            'This collection did not produce direct miner evidence or enough review surface to support a compromise conclusion.': '本次采集未形成直接挖矿证据，也未形成足以支撑入侵结论的复核面。',
        }.get(posture_info['verdict'], posture_info['verdict']))}",
        f"- **置信度态势：** {confidence_icon(posture_info['posture'])} `{ {'high':'高','medium':'中','low':'低','unknown':'未知'}.get(posture_info['posture'], posture_info['posture']) }`",
        f"- **判断边界：** {maybe_redact_zh({
            'Triage should proceed as a compromise-oriented case, but attribution still requires additional evidence.': '建议按入侵方向继续排查，但归因仍需补充更多证据。',
            'This does not clear the host. The present output supports review-driven triage, not a confirmed mining-compromise conclusion.': '这并不代表主机可以直接排除风险，当前结果只支撑复核型分诊，不足以确认已发生挖矿入侵。',
            'Absence of indicators in this pass is not proof of absence; visibility, timing, and privilege may still be incomplete.': '本轮未命中指标不等于主机无风险，观察窗口、权限范围和证据残留都可能仍不完整。',
        }.get(posture_info['boundary'], posture_info['boundary']))}",
        f"- **优先方向：** {maybe_redact_zh({
            'Prioritize runtime lineage, parent-child process review, wallet/pool traces, and persistence pivots.': '优先复核运行链路、父子进程关系、钱包/矿池痕迹和持久化落点。',
            'Prioritize surviving access traces, service startup context, container/cloud exposure, and deleted-log fallback artifacts.': '优先复核仍存活的访问痕迹、服务启动上下文、容器/云暴露面，以及日志删除后的替代证据。',
            'Expand time window, privilege visibility, and external telemetry correlation before closing the case.': '在结束案件前应继续扩展观察窗口、权限可见性，并结合外部遥测交叉验证。',
        }.get(posture_info['focus'], posture_info['focus']))}",
        "- **操作边界：** 本摘要对应的案件包仅包含只读采集结果，不包含任何状态变更。",
        "",
        anchor_tag("mgmt-snapshot"),
        "## 管理快照",
        render_table(
            ["指标", "值"],
            [
                ["事件 ID", str(incident.get("id", "unknown"))],
                ["案件 ID", str(data.get("case_id", "unknown"))],
                ["主机", host_display],
                ["生成时间（UTC）", str(data.get("generated_at", now_utc()))],
                ["已确认结论", str(ctx["confirmed_count"])],
                ["待定结论", str(ctx["inconclusive_count"])],
                ["可溯源 IP", str(ctx["trace_counts"]["traced"])],
                ["未溯源 / 未知 IP", str(ctx["trace_counts"]["untraceable"] + ctx["trace_counts"]["unknown"])],
                ["日志完整性风险", str(ctx["log_risk_count"])],
                ["关联矩阵条目", str(len(ctx["hypothesis_matrix"]))],
                ["GPU 可疑进程数量", str(safe_int(ctx["scene_reconstruction"].get("gpu_suspicious_process_count", 0)))],
                ["预期工作负载", maybe_redact(str(data.get("expected_workload", "") or "未提供"))],
            ],
        ),
        "",
        anchor_tag("mgmt-risks"),
        "## 风险概览",
    ])
    lines.extend(key_risk_lines_zh_cn(data, case_dir=case_dir))
    lines.extend([
        "",
        "## 决策提示",
        "- 全量报告中会严格区分观测事实、推断和归因。",
        "- 仅凭高算力现象且缺乏业务佐证时，结论保持待定。",
        "- 未完成溯源的基础设施仅按现状记录，不延伸推断攻击者身份。",
    ])
    if baseline_assessment:
        lines.append(f"- 基线评估：`{maybe_redact(str(baseline_assessment.get('assessment_status', 'unknown')))}`。")
    lines.extend(["", anchor_tag("mgmt-judgments"), "## 优先研判"])
    if key_items:
        for item in key_items:
            evidence_ids = item['evidence_ids'].split(', ') if item['evidence_ids'] != 'none' else []
            lines.extend([
                f"### {status_icon(item['status'])} {item['id']}",
                f"- **研判：** {maybe_redact_zh(item['statement'])}",
                f"- **类型 / 状态 / 置信度：** `{claim_type_label_zh_cn(item['claim_type'])}` / `{ {'confirmed':'已确认','inconclusive':'待定'}.get(item['status'], item['status']) }` / `{ {'high':'高','medium':'中','low':'低','unknown':'未知'}.get(item['confidence'], item['confidence']) }`",
                f"- **假设编号：** `{maybe_redact(item['hypothesis_id'])}`",
                f"- **置信度理由：** {maybe_redact_zh(item['confidence_reason'])}",
                f"- **证据链：** {compact_evidence_chain_zh_cn(evidence_ids, evid_idx, case_dir, limit=4, base_dir=Path(case_dir) / 'reports' if case_dir else None).replace('](#evidence-', '](../report.zh-CN.md#evidence-')}",
                "",
            ])
    else:
        lines.extend(["- 当前暂无有证据支撑的优先研判。", ""])
    lines.extend([
        anchor_tag("mgmt-caveat"),
        "## 管理提示",
        "- 本摘要故意保持精简，只用于快速判断态势，不替代完整取证结论。",
        "- [返回顶部](#mgmt-top) | [案件索引](./index.zh-CN.md) | [中文全量报告](../report.zh-CN.md)",
        "",
    ])
    return "\n".join(lines).strip() + "\n"


def build_soc_view(data: dict[str, Any], redact: bool, case_dir: str | None = None) -> str:
    ctx = prepare_report_context(data, redact=redact, strict=False, case_dir=case_dir)
    incident = as_dict(data.get("incident"))
    host = as_dict(data.get("host"))
    scene_reconstruction = ctx["scene_reconstruction"]
    evid_idx = ctx["evid_idx"]
    key_items = top_judgments(ctx["findings"], evid_idx, limit=8)
    time_norm = ctx["time_norm"]
    posture_info = investigation_posture_payload(ctx)

    def maybe_redact(value: str) -> str:
        return sanitize_report_text(value, redact)

    lines = [anchor_tag("soc-top"), f"# {incident.get('title', 'Mining Host Investigation')} - SOC Summary", ""]
    if case_dir:
        lines.extend([
            "[Bundle Index](./index.md) | [Case Bundle (ZH-CN)](./index.zh-CN.md) | [Full Report](../report.md) | [Full Report (ZH-CN)](../report.zh-CN.md) | [Management Summary](./management-summary.md) | [SOC Summary (ZH-CN)](./soc-summary.zh-CN.md)",
            "",
        ])
    lines.extend([
        "> SOC-facing triage summary. Use the full report for full command context and evidence detail blocks.",
        "",
        "## Quick Links",
        "- [Triage Conclusion](#soc-conclusion)",
        "- [Triage Snapshot](#soc-snapshot)",
        "- [High-Signal Samples](#soc-samples)",
        "- [Key Judgments](#soc-judgments)",
        "",
        anchor_tag("soc-conclusion"),
        "## Triage Conclusion",
        f"- **Triage Verdict:** {maybe_redact(posture_info['verdict'])}",
        f"- **Confidence Posture:** {confidence_icon(posture_info['posture'])} `{posture_info['posture']}`",
        f"- **Immediate Next Pivot:** {maybe_redact(posture_info['focus'])}",
        f"- **Decision Boundary:** {maybe_redact(posture_info['boundary'])}",
        "",
        anchor_tag("soc-snapshot"),
        "## Triage Snapshot",
        render_table(
            ["Field", "Value"],
            [
                ["Incident ID", str(incident.get("id", "unknown"))],
                ["Case ID", str(data.get("case_id", "unknown"))],
                ["Host ID", str(data.get("host_id", "unknown"))],
                ["Host", f"{host.get('name', 'unknown')} ({maybe_redact(str(host.get('ip', 'unknown')))})"],
                ["Collector Version", str(data.get("collector_version", "unknown"))],
                ["Report Normalization Timezone", maybe_redact(str(time_norm.get("report_timezone", data.get("report_timezone_basis", data.get("timezone", "UTC")))))],
                ["Host Reported Timezone", maybe_redact(str(time_norm.get("host_reported_timezone", "unknown")))],
                ["Host NTP Synchronized", maybe_redact(str(time_norm.get("host_ntp_synchronized", "unknown")))],
                ["Findings", f"{ctx['confirmed_count']} confirmed / {ctx['inconclusive_count']} inconclusive"],
                ["Log Integrity Risks", str(ctx["log_risk_count"])],
                ["Hypothesis Matrix Entries", str(len(ctx["hypothesis_matrix"]))],
                ["GPU Suspicious Process Count", str(safe_int(scene_reconstruction.get("gpu_suspicious_process_count", 0)))],
            ],
        ),
        "",
        anchor_tag("soc-samples"),
        "## High-Signal Samples",
        "",
    ])
    append_sample_group(lines, "Auth Source IPs", as_list(scene_reconstruction.get("auth_source_ips")), maybe_redact, limit=4, max_len=80)
    append_sample_group(lines, "Listening Ports", as_list(scene_reconstruction.get("listening_ports")), maybe_redact, limit=6, max_len=80)
    append_sample_group(lines, "Process IOC Samples", as_list(scene_reconstruction.get("process_ioc_samples")), maybe_redact, limit=4, max_len=140)
    append_sample_group(lines, "Network IOC Samples", as_list(scene_reconstruction.get("network_ioc_samples")), maybe_redact, limit=4, max_len=140)
    append_sample_group(lines, "Initial-Access Review Samples", as_list(scene_reconstruction.get("initial_access_review_samples")), maybe_redact, limit=4, max_len=140)
    append_sample_group(lines, "Container / Cloud Review Samples", as_list(scene_reconstruction.get("container_cloud_review_samples")), maybe_redact, limit=4, max_len=140)
    append_sample_group(lines, "Kernel / eBPF Samples", as_list(scene_reconstruction.get("kernel_review_samples")), maybe_redact, limit=4, max_len=140)
    append_sample_group(lines, "GPU Adapter Samples", as_list(scene_reconstruction.get("gpu_adapter_samples")), maybe_redact, limit=4, max_len=140)
    append_sample_group(lines, "GPU Compute Process Samples", as_list(scene_reconstruction.get("gpu_compute_process_samples")), maybe_redact, limit=4, max_len=140)
    append_sample_group(lines, "GPU Suspicious Process Samples", as_list(scene_reconstruction.get("gpu_suspicious_process_samples")), maybe_redact, limit=4, max_len=140)
    lines.extend([anchor_tag("soc-judgments"), "## Key Judgments"])
    if key_items:
        for item in key_items:
            evidence_ids = item['evidence_ids'].split(', ') if item['evidence_ids'] != 'none' else []
            lines.extend([
                f"### {status_icon(item['status'])} {item['id']} | `{item['hypothesis_id']}`",
                f"- **Statement:** {maybe_redact(item['statement'])}",
                f"- **Type / Status / Confidence:** `{claim_type_label(item['claim_type'])}` / `{item['status']}` / `{item['confidence']}`",
                f"- **Confidence Reason:** {maybe_redact(item['confidence_reason'])}",
                f"- **Evidence Chain:** {compact_evidence_chain(evidence_ids, evid_idx, case_dir, limit=4, base_dir=Path(case_dir) / 'reports' if case_dir else None).replace('](#evidence-', '](../report.md#evidence-')}",
                "",
            ])
    else:
        lines.extend(["- No evidence-backed judgments available yet.", ""])
    lines.extend(["- [Back to Top](#soc-top) | [Bundle Index](./index.md) | [Full Report](../report.md)", ""])
    return "\n".join(lines).strip() + "\n"



def build_soc_view_zh_cn(data: dict[str, Any], redact: bool, case_dir: str | None = None) -> str:
    ctx = prepare_report_context(data, redact=redact, strict=False, case_dir=case_dir)
    incident = as_dict(data.get("incident"))
    host = as_dict(data.get("host"))
    scene_reconstruction = ctx["scene_reconstruction"]
    evid_idx = ctx["evid_idx"]
    key_items = top_judgments(ctx["findings"], evid_idx, limit=8)
    time_norm = ctx["time_norm"]
    posture_info = investigation_posture_payload(ctx)

    def maybe_redact(value: str) -> str:
        return sanitize_report_text(value, redact)

    def maybe_redact_zh(value: str) -> str:
        return zh_report_text(value, redact)

    def claim_type_label_zh_cn(value: str) -> str:
        return {
            "observed_fact": "观测事实",
            "inference": "推断",
            "attribution": "归因",
        }.get(normalize_claim_type(value), "推断")

    lines = [anchor_tag("soc-top"), f"# {incident.get('title', 'Mining Host Investigation')} - SOC 摘要", ""]
    if case_dir:
        lines.extend([
            "[案件索引](./index.zh-CN.md) | [英文索引](./index.md) | [中文全量报告](../report.zh-CN.md) | [英文全量报告](../report.md) | [管理摘要](./management-summary.zh-CN.md) | [英文 SOC 摘要](./soc-summary.md)",
            "",
        ])
    lines.extend([
        "> 面向 SOC / 值守团队的快速分诊摘要。完整命令上下文、证据块和产物路径请查看中文全量报告。",
        "",
        "## 快速链接",
        "- [分诊结论](#soc-conclusion)",
        "- [分诊快照](#soc-snapshot)",
        "- [高信号样本](#soc-samples)",
        "- [关键研判](#soc-judgments)",
        "",
        anchor_tag("soc-conclusion"),
        "## 分诊结论",
        f"- **当前判断：** {maybe_redact_zh({
            'Direct miner-like runtime indicators were observed during collection.': '本次采集中观察到了直接的挖矿类运行时指标。',
            'No direct miner IOC was observed in this collection. Current results are limited to review surfaces that still require analyst confirmation.': '本次采集中未观察到直接的挖矿 IOC，当前结果主要是需要人工复核的访问面与环境侧线索。',
            'This collection did not produce direct miner evidence or enough review surface to support a compromise conclusion.': '本次采集未形成直接挖矿证据，也未形成足以支撑入侵结论的复核面。',
        }.get(posture_info['verdict'], posture_info['verdict']))}",
        f"- **置信度态势：** {confidence_icon(posture_info['posture'])} `{ {'high':'高','medium':'中','low':'低','unknown':'未知'}.get(posture_info['posture'], posture_info['posture']) }`",
        f"- **下一步重点：** {maybe_redact_zh({
            'Prioritize runtime lineage, parent-child process review, wallet/pool traces, and persistence pivots.': '优先复核运行链路、父子进程关系、钱包/矿池痕迹和持久化落点。',
            'Prioritize surviving access traces, service startup context, container/cloud exposure, and deleted-log fallback artifacts.': '优先复核仍存活的访问痕迹、服务启动上下文、容器/云暴露面，以及日志删除后的替代证据。',
            'Expand time window, privilege visibility, and external telemetry correlation before closing the case.': '继续扩展观察窗口、权限可见性，并结合外部遥测交叉验证。',
        }.get(posture_info['focus'], posture_info['focus']))}",
        f"- **判断边界：** {maybe_redact_zh({
            'Triage should proceed as a compromise-oriented case, but attribution still requires additional evidence.': '建议按入侵方向继续排查，但归因仍需补充更多证据。',
            'This does not clear the host. The present output supports review-driven triage, not a confirmed mining-compromise conclusion.': '当前结果不构成主机已安全的证明，只支撑复核型分诊，不足以确认已发生挖矿入侵。',
            'Absence of indicators in this pass is not proof of absence; visibility, timing, and privilege may still be incomplete.': '本轮未命中指标不等于主机无风险，观察窗口、权限范围和证据残留都可能仍不完整。',
        }.get(posture_info['boundary'], posture_info['boundary']))}",
        "",
        anchor_tag("soc-snapshot"),
        "## 分诊快照",
        render_table(
            ["字段", "值"],
            [
                ["事件 ID", str(incident.get("id", "unknown"))],
                ["案件 ID", str(data.get("case_id", "unknown"))],
                ["主机 ID", str(data.get("host_id", "unknown"))],
                ["主机", f"{host.get('name', 'unknown')} ({maybe_redact(str(host.get('ip', 'unknown')))})"],
                ["采集器版本", str(data.get("collector_version", "unknown"))],
                ["报告归一化时区", maybe_redact(str(time_norm.get("report_timezone", data.get("report_timezone_basis", data.get("timezone", "UTC")))))],
                ["主机报告时区", maybe_redact(str(time_norm.get("host_reported_timezone", "unknown")))],
                ["主机 NTP 同步", maybe_redact_zh(str(time_norm.get("host_ntp_synchronized", "unknown")))],
                ["已确认 / 待定", f"{ctx['confirmed_count']} / {ctx['inconclusive_count']}"],
                ["日志完整性风险", str(ctx["log_risk_count"])],
                ["关联矩阵条目", str(len(ctx["hypothesis_matrix"]))],
                ["GPU 可疑进程数量", str(safe_int(scene_reconstruction.get("gpu_suspicious_process_count", 0)))],
            ],
        ),
        "",
        anchor_tag("soc-samples"),
        "## 高信号样本",
        "",
    ])
    append_sample_group(lines, "认证来源 IP", as_list(scene_reconstruction.get("auth_source_ips")), maybe_redact, limit=4, max_len=80, empty_label="无。")
    append_sample_group(lines, "监听端口", as_list(scene_reconstruction.get("listening_ports")), maybe_redact, limit=6, max_len=80, empty_label="无。")
    append_sample_group(lines, "进程 IOC 样本", as_list(scene_reconstruction.get("process_ioc_samples")), maybe_redact, limit=4, max_len=140, empty_label="无。")
    append_sample_group(lines, "网络 IOC 样本", as_list(scene_reconstruction.get("network_ioc_samples")), maybe_redact, limit=4, max_len=140, empty_label="无。")
    append_sample_group(lines, "初始访问复核样本", as_list(scene_reconstruction.get("initial_access_review_samples")), maybe_redact, limit=4, max_len=140, empty_label="无。")
    append_sample_group(lines, "容器 / 云侧复核样本", as_list(scene_reconstruction.get("container_cloud_review_samples")), maybe_redact, limit=4, max_len=140, empty_label="无。")
    append_sample_group(lines, "Kernel / eBPF 样本", as_list(scene_reconstruction.get("kernel_review_samples")), maybe_redact, limit=4, max_len=140, empty_label="无。")
    append_sample_group(lines, "GPU 适配器样本", as_list(scene_reconstruction.get("gpu_adapter_samples")), maybe_redact, limit=4, max_len=140, empty_label="无。")
    append_sample_group(lines, "GPU 计算进程样本", as_list(scene_reconstruction.get("gpu_compute_process_samples")), maybe_redact, limit=4, max_len=140, empty_label="无。")
    append_sample_group(lines, "GPU 可疑进程样本", as_list(scene_reconstruction.get("gpu_suspicious_process_samples")), maybe_redact, limit=4, max_len=140, empty_label="无。")
    lines.extend([anchor_tag("soc-judgments"), "## 关键研判"])
    if key_items:
        for item in key_items:
            evidence_ids = item['evidence_ids'].split(', ') if item['evidence_ids'] != 'none' else []
            lines.extend([
                f"### {status_icon(item['status'])} {item['id']} · `{item['hypothesis_id']}`",
                f"- **表述：** {maybe_redact_zh(item['statement'])}",
                f"- **类型 / 状态 / 置信度：** `{claim_type_label_zh_cn(item['claim_type'])}` / `{ {'confirmed':'已确认','inconclusive':'待定'}.get(item['status'], item['status']) }` / `{ {'high':'高','medium':'中','low':'低','unknown':'未知'}.get(item['confidence'], item['confidence']) }`",
                f"- **置信度理由：** {maybe_redact_zh(item['confidence_reason'])}",
                f"- **证据链：** {compact_evidence_chain_zh_cn(evidence_ids, evid_idx, case_dir, limit=4, base_dir=Path(case_dir) / 'reports' if case_dir else None).replace('](#evidence-', '](../report.zh-CN.md#evidence-')}",
                "",
            ])
    else:
        lines.extend(["- 当前暂无有证据支撑的关键研判。", ""])
    lines.extend(["- [返回顶部](#soc-top) | [案件索引](./index.zh-CN.md) | [中文全量报告](../report.zh-CN.md)", ""])
    return "\n".join(lines).strip() + "\n"


def relative_markdown_path(base_dir: Path, target: str | Path) -> str:
    target_path = Path(target)
    try:
        return Path(os.path.relpath(target_path, start=base_dir)).as_posix()
    except ValueError:
        return target_path.as_posix()


def artifact_href(item: dict[str, Any], case_dir: str | None, base_dir: Path | None = None) -> str:
    artifact = str(item.get("artifact", "")).strip()
    if not artifact:
        return ""
    if case_dir:
        start_dir = base_dir or Path(case_dir)
        return relative_markdown_path(start_dir, artifact)
    return Path(artifact).as_posix()


def evidence_anchor(evidence_id: str) -> str:
    return f"evidence-{evidence_id.strip().lower()}"


def evidence_reference(
    evidence_id: str,
    evid_idx: dict[str, dict[str, Any]],
    case_dir: str | None,
    base_dir: Path | None = None,
) -> str:
    ident = evidence_id.strip()
    if not ident:
        return "-"
    anchor_link = f"[{ident}](#{evidence_anchor(ident)})"
    item = evid_idx.get(ident)
    if not item:
        return f"{anchor_link} (artifact missing)"
    href = artifact_href(item, case_dir, base_dir=base_dir)
    if not href:
        return anchor_link
    return f"{anchor_link} / [artifact]({href})"


def evidence_reference_list(
    evidence_ids: list[Any],
    evid_idx: dict[str, dict[str, Any]],
    case_dir: str | None,
    base_dir: Path | None = None,
) -> str:
    refs = [
        evidence_reference(str(evidence_id), evid_idx, case_dir, base_dir=base_dir)
        for evidence_id in evidence_ids
        if str(evidence_id).strip()
    ]
    return "<br>".join(refs) if refs else "-"


def report_link(relative_path: str, label: str) -> str:
    return f"[{label}]({relative_path})"


def anchor_tag(anchor_id: str) -> str:
    return f'<a id="{anchor_id}"></a>'


def compact_evidence_chain(
    evidence_ids: list[Any],
    evid_idx: dict[str, dict[str, Any]],
    case_dir: str | None,
    limit: int,
    base_dir: Path | None = None,
) -> str:
    limited = evidence_ids[:limit]
    rendered = evidence_reference_list(limited, evid_idx, case_dir, base_dir=base_dir)
    if len(evidence_ids) > limit:
        rendered += f"<br>... (+{len(evidence_ids) - limit} more; review full report)"
    return rendered


def case_directory_status(case_dir: str | None) -> list[str]:
    if not case_dir:
        return ["- Artifacts: `unknown`", "- Evidence: `unknown`", "- Metadata: `unknown`", "- Reports: `unknown`"]
    base = Path(case_dir)
    mappings = [
        ("Artifacts", base / "artifacts"),
        ("Evidence", base / "evidence"),
        ("Metadata", base / "meta"),
        ("Reports", base / "reports"),
    ]
    out: list[str] = []
    for label, p in mappings:
        if p.exists() and p.is_dir():
            count = len(list(p.iterdir()))
            out.append(f"- {label}: `present` ({count} item(s))")
        else:
            out.append(f"- {label}: `missing`")
    return out



def case_directory_status_zh_cn(case_dir: str | None) -> list[str]:
    if not case_dir:
        return ["- artifacts：`未知`", "- evidence：`未知`", "- meta：`未知`", "- reports：`未知`"]
    base = Path(case_dir)
    mappings = [
        ("artifacts", base / "artifacts"),
        ("evidence", base / "evidence"),
        ("meta", base / "meta"),
        ("reports", base / "reports"),
    ]
    out: list[str] = []
    for label, p in mappings:
        if p.exists() and p.is_dir():
            count = len(list(p.iterdir()))
            out.append(f"- {label}：`存在`（{count} 项）")
        else:
            out.append(f"- {label}：`缺失`")
    return out




def report_inventory_lines(case_dir: str | None) -> list[str]:
    reports = [
        ("./index.md", "index.md", "Case Bundle", True),
        ("./index.zh-CN.md", "index.zh-CN.md", "Case Bundle (ZH-CN)", True),
        ("../report.md", "report.md", "Full Report", False),
        ("../report.zh-CN.md", "report.zh-CN.md", "Full Report (ZH-CN)", False),
        ("../leadership-report.md", "leadership-report.md", "Leadership Review Report", False),
        ("../leadership-report.zh-CN.md", "leadership-report.zh-CN.md", "Leadership Review Report (ZH-CN)", False),
        ("./management-summary.md", "management-summary.md", "Management Summary", True),
        ("./management-summary.zh-CN.md", "management-summary.zh-CN.md", "Management Summary (ZH-CN)", True),
        ("./soc-summary.md", "soc-summary.md", "SOC Summary", True),
        ("./soc-summary.zh-CN.md", "soc-summary.zh-CN.md", "SOC Summary (ZH-CN)", True),
        ("./operator-brief.md", "operator-brief.md", "Operator Brief", True),
        ("./operator-brief.zh-CN.md", "operator-brief.zh-CN.md", "Operator Brief (ZH-CN)", True),
        ("./operator-brief.json", "operator-brief.json", "Operator Brief (JSON)", True),
        ("./external-evidence-checklist.md", "external-evidence-checklist.md", "External Evidence Checklist", True),
    ]
    out: list[str] = []
    for href, filename, label, in_reports_dir in reports:
        base = Path(case_dir) / "reports" if case_dir and in_reports_dir else Path(case_dir) if case_dir else None
        exists = bool(base and (base / filename).exists())
        out.append(f"- {report_link(href, label)} | status: `{'present' if exists else 'planned'}`")
    return out



def report_inventory_lines_zh_cn(case_dir: str | None) -> list[str]:
    reports = [
        ("./index.md", "index.md", "案件索引（英文）", True),
        ("./index.zh-CN.md", "index.zh-CN.md", "案件索引", True),
        ("../report.md", "report.md", "全量报告（英文）", False),
        ("../report.zh-CN.md", "report.zh-CN.md", "全量报告", False),
        ("../leadership-report.md", "leadership-report.md", "领导复核报告（英文）", False),
        ("../leadership-report.zh-CN.md", "leadership-report.zh-CN.md", "领导复核报告", False),
        ("./management-summary.md", "management-summary.md", "管理摘要（英文）", True),
        ("./management-summary.zh-CN.md", "management-summary.zh-CN.md", "管理摘要", True),
        ("./soc-summary.md", "soc-summary.md", "SOC 摘要（英文）", True),
        ("./soc-summary.zh-CN.md", "soc-summary.zh-CN.md", "SOC 摘要", True),
        ("./operator-brief.md", "operator-brief.md", "操作简报（英文）", True),
        ("./operator-brief.zh-CN.md", "operator-brief.zh-CN.md", "操作简报", True),
        ("./operator-brief.json", "operator-brief.json", "操作简报（JSON）", True),
        ("./external-evidence-checklist.md", "external-evidence-checklist.md", "外部证据补证清单", True),
    ]
    out: list[str] = []
    for href, filename, label, in_reports_dir in reports:
        base = Path(case_dir) / "reports" if case_dir and in_reports_dir else Path(case_dir) if case_dir else None
        exists = bool(base and (base / filename).exists())
        out.append(f"- {report_link(href, label)} | 状态：`{'已生成' if exists else '待生成'}`")
    return out


def latest_judgment_lines(data: dict[str, Any], case_dir: str | None = None, limit: int = 3) -> list[str]:
    findings = [as_dict(x) for x in as_list(data.get("findings"))]
    hypothesis_matrix = [as_dict(x) for x in as_list(data.get("hypothesis_matrix"))]
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    evid_idx = evidence_index(evidence_items)
    items = top_judgments(findings, evid_idx, limit=limit)
    out: list[str] = []
    for item in items:
        evidence_ids = item["evidence_ids"].split(", ") if item["evidence_ids"] != "none" else []
        out.append(
            f"- `{item['id']}` [{claim_type_label(item['claim_type'])}/{item['status']}/{item['confidence']}] {item['statement']} | evidence: {compact_evidence_chain(evidence_ids, evid_idx, case_dir, limit=3, base_dir=Path(case_dir) / 'reports' if case_dir else None)}"
        )
    if not out:
        out.append("- No evidence-backed judgments available yet.")
    return out



def latest_judgment_lines_zh_cn(data: dict[str, Any], case_dir: str | None = None, limit: int = 3) -> list[str]:
    findings = [as_dict(x) for x in as_list(data.get("findings"))]
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    evid_idx = evidence_index(evidence_items)
    items = top_judgments(findings, evid_idx, limit=limit)

    def claim_type_label_zh_cn(value: str) -> str:
        return {
            "observed_fact": "观测事实",
            "inference": "推断",
            "attribution": "归因",
        }.get(normalize_claim_type(value), "推断")

    out: list[str] = []
    for item in items:
        evidence_ids = item["evidence_ids"].split(", ") if item["evidence_ids"] != "none" else []
        chain = compact_evidence_chain_zh_cn(evidence_ids, evid_idx, case_dir, limit=3, base_dir=Path(case_dir) / 'reports' if case_dir else None).replace('](#evidence-', '](../report.zh-CN.md#evidence-')
        status_label = {"confirmed": "已确认", "inconclusive": "待定"}.get(item["status"], item["status"])
        confidence_label = {"high": "高", "medium": "中", "low": "低", "unknown": "未知"}.get(item["confidence"], item["confidence"])
        out.append(
            f"- `{item['id']}` [{claim_type_label_zh_cn(item['claim_type'])}/{status_label}/{confidence_label}] {localize_auto_text_zh_cn(item['statement'])} | 证据：{chain}"
        )
    if not out:
        out.append("- 暂无有证据支撑的研判。")
    return out


def anchor_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
    slug = slug.strip("-")
    return slug or "unknown"


def evidence_source_groups(evidence_items: list[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for item in evidence_items:
        source = str(item.get("source", "unknown")).strip() or "unknown"
        if source not in groups:
            groups[source] = []
            order.append(source)
        groups[source].append(item)
    return [(source, groups[source]) for source in order]


def evidence_source_nav_lines(evidence_items: list[dict[str, Any]], prefix: str = "report-evidence-source") -> list[str]:
    lines: list[str] = []
    for source, items in evidence_source_groups(evidence_items):
        lines.append(f"- [{source}](#{prefix}-{anchor_slug(source)}) (`{len(items)}` item(s))")
    return lines or ["- No evidence sources available."]


def key_risk_lines(data: dict[str, Any], case_dir: str | None = None) -> list[str]:
    findings = [as_dict(x) for x in as_list(data.get("findings"))]
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    ip_traces = [as_dict(x) for x in as_list(data.get("ip_traces"))]
    log_integrity = [as_dict(x) for x in as_list(data.get("log_integrity"))]
    evid_idx = evidence_index(evidence_items)
    confirmed_count, inconclusive_count = finding_status_counts(findings, evid_idx)
    unknown_trace_count = sum(
        1
        for item in ip_traces
        if normalize_trace_status(str(item.get("trace_status", ""))) != "traced"
    )
    log_risk_count = sum(
        1
        for item in log_integrity
        if str(item.get("status", "")).strip().lower() in {"missing", "tampered", "suspicious"}
    )
    lines = [
        f"- Findings confidence state: `{confirmed_count}` confirmed, `{inconclusive_count}` inconclusive.",
        f"- Traceability caveat: `{unknown_trace_count}` IP trace item(s) remain untraced or unknown.",
        f"- Log integrity caveat: `{log_risk_count}` artifact(s) are missing, suspicious, or tampered.",
    ]
    return lines



def key_risk_lines_zh_cn(data: dict[str, Any], case_dir: str | None = None) -> list[str]:
    findings = [as_dict(x) for x in as_list(data.get("findings"))]
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    ip_traces = [as_dict(x) for x in as_list(data.get("ip_traces"))]
    log_integrity = [as_dict(x) for x in as_list(data.get("log_integrity"))]
    evid_idx = evidence_index(evidence_items)
    confirmed_count, inconclusive_count = finding_status_counts(findings, evid_idx)
    unknown_trace_count = sum(
        1
        for item in ip_traces
        if normalize_trace_status(str(item.get("trace_status", ""))) != "traced"
    )
    log_risk_count = sum(
        1
        for item in log_integrity
        if str(item.get("status", "")).strip().lower() in {"missing", "tampered", "suspicious"}
    )
    return [
        f"- 结论状态：`{confirmed_count}` 条已确认，`{inconclusive_count}` 条仍为待定。",
        f"- 溯源提示：`{unknown_trace_count}` 条 IP 记录仍未完成溯源或状态未知。",
        f"- 日志完整性提示：`{log_risk_count}` 个日志相关产物缺失、可疑或疑似被篡改。",
    ]


def reading_order_lines() -> list[str]:
    return [
        "- Step 1: `../leadership-report.md` for the standalone management-ready case narrative.",
        "- Step 2: `index.md` for bundle status and report inventory.",
        "- Step 3: `management-summary.md` or `soc-summary.md` for audience-specific triage.",
        "- Step 4: `operator-brief.md` for non-specialist execution support.",
        "- Step 5: `../report.md` for evidence-backed conclusions and detailed artifacts.",
    ]



def reading_order_lines_zh_cn() -> list[str]:
    return [
        "- 第 1 步：先看 `../leadership-report.zh-CN.md`，直接掌握可提交领导复核的案件全貌。",
        "- 第 2 步：看 `index.zh-CN.md`，确认案件状态、目录完整性和报告清单。",
        "- 第 3 步：按受众选择 `management-summary.zh-CN.md` 或 `soc-summary.zh-CN.md` 做快速研判。",
        "- 第 4 步：看 `operator-brief.zh-CN.md`，给非安全执行人员落地处置。",
        "- 第 5 步：进入 `../report.zh-CN.md` 查看证据链、时间线和详细产物。",
    ]


def is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address((value or "").strip()).is_private
    except ValueError:
        return False


def sort_timeline_entries(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(item: dict[str, Any]) -> tuple[int, str]:
        norm = str(item.get("normalized_time_utc", "")).strip()
        raw = str(item.get("time", "")).strip()
        if norm and norm != "unknown":
            return (0, norm)
        return (1, raw)

    return sorted(items, key=key)


def infer_file_role(item: dict[str, Any]) -> str:
    exe = f"{item.get('path', '')} {item.get('algorithm', '')} {item.get('pool', '')}".lower()
    if any(token in exe for token in ["stratum", "xmrig", "gminer", "lolminer", "trex", "nbminer", "kawpow", "randomx", "ethash", "srb"]):
        return "miner_runtime"
    if any(token in exe for token in ["curl", "wget", "python", "bash", "sh"]):
        return "launcher_or_dropper"
    return str(item.get("role_guess", "")).strip() or "unknown"


def claim_type_emoji(value: str) -> str:
    return {
        "observed_fact": "🔎",
        "inference": "🧠",
        "attribution": "🎯",
    }.get(normalize_claim_type(value), "🔎")


def confidence_emoji(value: str) -> str:
    return {
        "high": "🟢",
        "medium": "🟡",
        "low": "🟠",
        "unknown": "⚪",
    }.get(str(value).strip().lower(), "⚪")


def leadership_payload(ctx: dict[str, Any]) -> dict[str, Any]:
    scene = ctx["scene_reconstruction"]
    timeline = sort_timeline_entries([as_dict(x) for x in as_list(ctx["timeline"])])
    runtime_profiles = [as_dict(x) for x in as_list(scene.get("runtime_profiles"))]
    malware_files = [as_dict(x) for x in as_list(scene.get("malware_file_candidates"))]
    top_cpu = [as_dict(x) for x in as_list(scene.get("top_cpu_processes"))]
    auth_counts = as_dict(scene.get("auth_event_counts"))
    auth_ips = [str(x) for x in as_list(scene.get("auth_source_ips"))]
    listening_ports = [str(x) for x in as_list(scene.get("listening_ports"))]
    findings = [as_dict(x) for x in as_list(ctx["findings"])]
    network_hits = [str(x) for x in as_list(scene.get("network_ioc_samples"))]
    access_hits = [str(x) for x in as_list(scene.get("initial_access_review_samples"))]
    container_hits = [str(x) for x in as_list(scene.get("container_cloud_review_samples"))]
    log_risk = [as_dict(x) for x in as_list(ctx["log_integrity"]) if str(as_dict(x).get("status", "")).strip().lower() in {"missing", "tampered", "suspicious"}]
    internal_auth_ips = [ip for ip in auth_ips if is_private_ip(ip)]

    ingress_hypotheses: list[dict[str, str]] = []
    if safe_int(auth_counts.get("failed")) or safe_int(auth_counts.get("invalid")):
        ingress_hypotheses.append(
            {
                "label": "SSH credential abuse remains a leading hypothesis.",
                "label_zh": "SSH 凭据滥用仍是优先假设。",
                "confidence": "medium",
                "basis": f"failed={auth_counts.get('failed', 0)}, invalid={auth_counts.get('invalid', 0)}, auth_source_ips={', '.join(auth_ips[:6]) or '-'}",
            }
        )
    if "22" in listening_ports:
        ingress_hypotheses.append(
            {
                "label": "SSH exposure is visible on the host and could be an entry path if credential or key abuse occurred.",
                "label_zh": "主机存在 SSH 暴露，若发生弱口令或密钥滥用，可作为入侵入口。",
                "confidence": "low",
                "basis": "listening_port=22",
            }
        )
    exposed_service_ports = [port for port in listening_ports if port not in {"22", "53"}]
    if exposed_service_ports:
        ingress_hypotheses.append(
            {
                "label": "Exposed application services may need exploit-surface review.",
                "label_zh": "暴露业务服务仍需补做漏洞利用面复核。",
                "confidence": "low",
                "basis": f"listening_ports={', '.join(exposed_service_ports[:8])}",
            }
        )
    if container_hits:
        ingress_hypotheses.append(
            {
                "label": "Container/cloud control-plane exposure remains possible and needs external evidence.",
                "label_zh": "容器或云侧控制面入口仍然存在可能，需要结合外部证据补证。",
                "confidence": "low",
                "basis": compact_text(container_hits[0], max_len=180),
            }
        )
    if not ingress_hypotheses:
        ingress_hypotheses.append(
            {
                "label": "No host-only evidence was sufficient to isolate a single initial-access path.",
                "label_zh": "仅凭当前主机侧证据，尚不足以锁定单一入侵入口。",
                "confidence": "low",
                "basis": "host_only_visibility_limit",
            }
        )

    intrusion_time = timeline[0] if timeline else {}
    intrusion_window = str(intrusion_time.get("normalized_time_utc") or intrusion_time.get("time") or ctx["window_start"])

    activity_summary: list[str] = []
    if runtime_profiles:
        p = runtime_profiles[0]
        activity_summary.append(
            f"Runtime evidence shows miner-like execution via {p.get('executable', '-')}, algorithm={p.get('algorithm', '-')}, pool={p.get('pool', '-')}, proxy={p.get('proxy', '-')}, wallet={p.get('wallet', '-')}, password={p.get('password', '-')}, cpu_threads={p.get('cpu_threads', '-')}"
        )
    if access_hits:
        activity_summary.append(f"Access or persistence review surfaces returned notable lines such as: {compact_text(access_hits[0], max_len=200)}")
    if network_hits:
        activity_summary.append(f"Network IOC review produced hits such as: {compact_text(network_hits[0], max_len=200)}")
    if not activity_summary:
        activity_summary.append("No direct miner runtime string was parsed in this pass; conclusions remain bound to review surfaces and visible runtime artifacts only.")

    lateral_status = "not_observed"
    lateral_basis = "No direct host-side lateral-movement indicator was observed in current visibility."
    if internal_auth_ips:
        lateral_status = "possible"
        lateral_basis = f"Internal/private source IPs appeared in authentication evidence: {', '.join(internal_auth_ips[:6])}."
    if any(token in " ".join(access_hits + network_hits).lower() for token in ["ssh ", "scp ", "rsync ", "socat", "ncat", "nc "]):
        lateral_status = "possible"
        lateral_basis = "Transfer or remote-shell tool strings were observed and require deeper pivot review."

    service_exposure = (
        f"Listening ports observed on the host: {', '.join(listening_ports[:12])}."
        if listening_ports
        else "No listening-port list was recovered in this pass."
    )

    enriched_files: list[dict[str, Any]] = []
    for item in malware_files[:12]:
        enriched_files.append(
            {
                **item,
                "role_inference": infer_file_role(item),
            }
        )

    evidence_ids: list[str] = []
    for item in findings[:4]:
        evidence_ids.extend([str(x).strip() for x in as_list(item.get("evidence_ids")) if str(x).strip()])
    if runtime_profiles:
        evidence_ids.extend([str(x.get("evidence_id", "")).strip() for x in runtime_profiles[:3] if str(x.get("evidence_id", "")).strip()])
    evidence_ids = list(dict.fromkeys(evidence_ids))[:6]

    return {
        "intrusion_window": intrusion_window,
        "ingress_hypotheses": ingress_hypotheses,
        "activity_summary": activity_summary,
        "runtime_profiles": runtime_profiles[:6],
        "malware_files": enriched_files,
        "top_cpu": top_cpu[:8],
        "auth_ips": auth_ips[:10],
        "listening_ports": listening_ports[:12],
        "service_exposure": service_exposure,
        "lateral_status": lateral_status,
        "lateral_basis": lateral_basis,
        "log_risk_count": len(log_risk),
        "evidence_excerpt_ids": evidence_ids,
        "gpu_peak": safe_int(scene.get("gpu_peak_utilization_percent", 0)),
        "gpu_suspicious": safe_int(scene.get("gpu_suspicious_process_count", 0)),
        "gpu_visibility_status": str(scene.get("gpu_visibility_status", "unknown")),
        "gpu_visibility_summary": str(scene.get("gpu_visibility_summary", "unknown")),
        "gpu_vendor_hints": [str(x) for x in as_list(scene.get("gpu_vendor_hints"))[:6]],
        "gpu_fallback_markers": [str(x) for x in as_list(scene.get("gpu_fallback_markers"))[:8]],
        "runtime_profile_count": safe_int(scene.get("runtime_profile_count", 0)),
        "top_cpu_keyword_hits": safe_int(scene.get("top_cpu_process_keyword_hit_count", 0)),
    }


def leadership_matrix_rows(ctx: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, str]]:
    posture = investigation_posture_payload(ctx)
    trace_counts = ctx["trace_counts"]
    gpu_status_zh = {
        "suspicious_runtime": "已见可疑运行时",
        "active_no_direct_miner_match": "存在活动但未直接命中矿工",
        "hardware_visible_no_runtime": "硬件可见但未见运行时",
        "tooling_limited": "工具受限",
        "not_observed": "未观察到",
        "unknown": "未知",
    }.get(payload["gpu_visibility_status"], payload["gpu_visibility_status"])
    gpu_summary_zh = (
        f"status={gpu_status_zh}，vendors={'、'.join(payload['gpu_vendor_hints']) or '无'}，"
        f"adapter_lines={len(as_list(ctx['scene_reconstruction'].get('gpu_adapter_samples')))}，"
        f"compute_processes={ctx['scene_reconstruction'].get('gpu_compute_process_count', 0)}，"
        f"suspicious_processes={payload['gpu_suspicious']}，peak_utilization={payload['gpu_peak']}%，"
        f"fallback_markers={'、'.join(payload['gpu_fallback_markers']) or '无'}"
    )
    rows: list[dict[str, str]] = []
    if payload["runtime_profile_count"] or posture["process_hits"] or posture["network_hits"] or posture["gpu_hits"]:
        rows.append(
            {
                "claim_type": "observed_fact",
                "confidence": "medium" if payload["runtime_profile_count"] or posture["gpu_hits"] else "low",
                "statement": "Runtime-facing indicators were recovered during collection.",
                "statement_zh": "本轮采集中已恢复出运行时侧指标。",
                "basis": (
                    f"runtime_profiles={payload['runtime_profile_count']}, process_ioc_hits={posture['process_hits']}, "
                    f"network_ioc_hits={posture['network_hits']}, gpu_suspicious={payload['gpu_suspicious']}"
                ),
                "basis_zh": (
                    f"runtime_profiles={payload['runtime_profile_count']}，process_ioc_hits={posture['process_hits']}，"
                    f"network_ioc_hits={posture['network_hits']}，gpu_suspicious={payload['gpu_suspicious']}"
                ),
            }
        )
    else:
        rows.append(
            {
                "claim_type": "observed_fact",
                "confidence": "low",
                "statement": "No direct miner runtime IOC was recovered in this pass.",
                "statement_zh": "本轮未恢复出直接的矿工运行时 IOC。",
                "basis": (
                    f"runtime_profiles={payload['runtime_profile_count']}, process_ioc_hits={posture['process_hits']}, "
                    f"network_ioc_hits={posture['network_hits']}, gpu_suspicious={payload['gpu_suspicious']}"
                ),
                "basis_zh": (
                    f"runtime_profiles={payload['runtime_profile_count']}，process_ioc_hits={posture['process_hits']}，"
                    f"network_ioc_hits={posture['network_hits']}，gpu_suspicious={payload['gpu_suspicious']}"
                ),
            }
        )
    rows.append(
        {
            "claim_type": "observed_fact",
            "confidence": "medium" if payload["gpu_suspicious"] else "low",
            "statement": "GPU visibility was evaluated through multiple read-only probe paths.",
            "statement_zh": "GPU 已通过多条只读探针路径进行可见性评估。",
            "basis": payload["gpu_visibility_summary"],
            "basis_zh": gpu_summary_zh,
        }
    )
    if payload["ingress_hypotheses"]:
        first = payload["ingress_hypotheses"][0]
        rows.append(
            {
                "claim_type": "inference",
                "confidence": str(first.get("confidence", "low")),
                "statement": str(first.get("label", "Initial-access path remains inconclusive.")),
                "statement_zh": str(first.get("label_zh", "当前入侵入口仍待进一步确认。")),
                "basis": str(first.get("basis", "-")),
                "basis_zh": str(first.get("basis", "-")),
            }
        )
    rows.append(
        {
            "claim_type": "inference",
            "confidence": "medium" if payload["lateral_status"] == "possible" else "low",
            "statement": (
                "Lateral movement remains possible and needs broader pivot review."
                if payload["lateral_status"] == "possible"
                else "No direct host-side lateral movement indicator was observed in current visibility."
            ),
            "statement_zh": (
                "横向移动仍存在可能，需要继续扩展支点复核。"
                if payload["lateral_status"] == "possible"
                else "当前可见性范围内，未直接观察到主机侧横向移动指标。"
            ),
            "basis": payload["lateral_basis"],
            "basis_zh": localize_auto_text_zh_cn(payload["lateral_basis"]),
        }
    )
    rows.append(
        {
            "claim_type": "attribution",
            "confidence": "low",
            "statement": "Current host-only evidence does not establish actor attribution.",
            "statement_zh": "仅凭当前主机侧证据，尚不足以建立攻击者归因。",
            "basis": (
                f"traced={trace_counts.get('traced', 0)}, untraceable={trace_counts.get('untraceable', 0)}, "
                f"unknown={trace_counts.get('unknown', 0)}, log_risk_count={payload['log_risk_count']}"
            ),
            "basis_zh": (
                f"traced={trace_counts.get('traced', 0)}，untraceable={trace_counts.get('untraceable', 0)}，"
                f"unknown={trace_counts.get('unknown', 0)}，log_risk_count={payload['log_risk_count']}"
            ),
        }
    )
    return rows


def build_leadership_report(data: dict[str, Any], redact: bool, case_dir: str | None = None) -> str:
    ctx = prepare_report_context(data, redact=redact, strict=False, case_dir=case_dir)
    payload = leadership_payload(ctx)
    matrix_rows = leadership_matrix_rows(ctx, payload)
    posture = investigation_posture_payload(ctx)

    def maybe_redact(value: str) -> str:
        return sanitize_report_text(value, redact)

    lines = [
        f"# {ctx['title']} - Leadership Review Report",
        "",
        "This standalone report is intended for management review. It is self-contained and does not require jumping across other files.",
        "",
        "## 🚨 Final Summary",
        f"- **Case ID:** `{data.get('case_id', 'unknown')}`",
        f"- **Host:** `{maybe_redact(ctx['host_name'])}` (`{maybe_redact(ctx['host_ip'])}`)",
        f"- **OS:** `{maybe_redact(ctx['os_name'])}`",
        f"- **Observation Window (UTC):** `{ctx['window_start']}` -> `{ctx['window_end']}`",
        f"- **Earliest Relevant Time:** `{maybe_redact(payload['intrusion_window'])}`",
        f"- **Conclusion:** {maybe_redact(posture['verdict'])}",
        f"- **Boundary:** {maybe_redact(posture['boundary'])}",
        f"- **Immediate Focus:** {maybe_redact(posture['focus'])}",
        "",
        "## 🧩 Conclusion Matrix",
    ]
    for row in matrix_rows:
        lines.extend(
            [
                f"### {claim_type_emoji(row['claim_type'])} {claim_type_label(row['claim_type'])} | {confidence_emoji(row['confidence'])} {row['confidence']}",
                f"- **Statement:** {maybe_redact(row['statement'])}",
                f"- **Basis:** {maybe_redact(row['basis'])}",
                "",
            ]
        )
    lines.append("## 🧭 Suspected Initial Access")
    for item in payload["ingress_hypotheses"]:
        lines.append(
            f"- `{item['confidence']}` {maybe_redact(item['label'])} | basis: {maybe_redact(item['basis'])}"
        )
    lines.extend(
        [
            "",
            "## 🔬 What Was Observed After Access",
        ]
    )
    for item in payload["activity_summary"]:
        lines.append(f"- {maybe_redact(item)}")
    lines.extend(
        [
            "",
            "## ⛏️ Mining / Malware Details",
            f"- **Parsed Miner Runtime Profiles:** `{payload['runtime_profile_count']}`",
            f"- **Top-CPU Miner-Keyword Hits:** `{payload['top_cpu_keyword_hits']}`",
            f"- **GPU Suspicious Process Count:** `{payload['gpu_suspicious']}`",
            f"- **GPU Peak Utilization:** `{payload['gpu_peak']}%`",
            f"- **GPU Visibility Status:** `{maybe_redact(payload['gpu_visibility_status'])}`",
            f"- **GPU Vendor Hints:** `{maybe_redact(', '.join(payload['gpu_vendor_hints']) or 'none')}`",
            f"- **GPU Fallback Markers:** `{maybe_redact(', '.join(payload['gpu_fallback_markers']) or 'none')}`",
        ]
    )
    if payload["runtime_profiles"]:
        for item in payload["runtime_profiles"][:4]:
            lines.append(
                f"- runtime: exe=`{maybe_redact(str(item.get('executable', '') or '-'))}`, algo=`{maybe_redact(str(item.get('algorithm', '') or '-'))}`, pool=`{maybe_redact(str(item.get('pool', '') or '-'))}`, proxy=`{maybe_redact(str(item.get('proxy', '') or '-'))}`, wallet=`{maybe_redact(str(item.get('wallet', '') or '-'))}`, password=`{maybe_redact(str(item.get('password', '') or '-'))}`, cpu_threads=`{maybe_redact(str(item.get('cpu_threads', '') or '-'))}`"
            )
    else:
        lines.append("- No parseable miner runtime profile was recovered in this pass.")

    lines.extend(["", "## 📦 Files And Hashes"])
    if payload["malware_files"]:
        for item in payload["malware_files"][:8]:
            lines.append(
                f"- file=`{maybe_redact(str(item.get('path', '') or '-'))}` | sha256=`{maybe_redact(str(item.get('sha256', '') or 'unavailable'))}` | role_inference=`{maybe_redact(str(item.get('role_inference', 'unknown')) or 'unknown')}` | basis=`{maybe_redact(str(item.get('origin_path', '') or str(item.get('evidence_id', 'unknown'))))}`"
            )
    else:
        lines.append("- No suspicious executable file/hash pair was recovered in current visibility.")

    lines.extend(
        [
            "",
            "## 🖥️ System State And Exposure",
            f"- **Service Exposure:** {maybe_redact(payload['service_exposure'])}",
            f"- **Authentication Source IPs:** {maybe_redact(', '.join(payload['auth_ips']) if payload['auth_ips'] else 'none recovered')}",
            f"- **Listening Ports:** {maybe_redact(', '.join(payload['listening_ports']) if payload['listening_ports'] else 'none recovered')}",
        ]
    )
    if payload["top_cpu"]:
        lines.append("- **Current Top CPU Processes:**")
        for item in payload["top_cpu"][:5]:
            lines.append(
                f"  - pid=`{maybe_redact(str(item.get('pid', '') or '-'))}` cpu=`{maybe_redact(str(item.get('cpu_percent', '') or '-'))}` exe=`{maybe_redact(str(item.get('executable', '') or '-'))}` cmd=`{maybe_redact(compact_text(str(item.get('command', '') or '-'), max_len=160))}`"
            )

    lines.extend(
        [
            "",
            "## 🔁 Lateral Movement Assessment",
            f"- **Status:** `{payload['lateral_status']}`",
            f"- **Assessment:** {maybe_redact(payload['lateral_basis'])}",
            "",
            "## 🧾 Log Integrity",
            f"- **Risk Count:** `{payload['log_risk_count']}`",
            "- Missing or tampered logs reduce attribution confidence and require external telemetry correlation.",
            "",
            "## 🔗 Evidence Excerpts",
        ]
    )
    evid_idx = ctx["evid_idx"]
    if payload["evidence_excerpt_ids"]:
        for evid in payload["evidence_excerpt_ids"]:
            item = as_dict(evid_idx.get(evid))
            if not item:
                continue
            excerpt = artifact_excerpt(item, max_lines=2)
            lines.append(f"- **{evid}** source=`{maybe_redact(str(item.get('source', 'unknown')) or 'unknown')}` command=`{maybe_redact(compact_text(str(item.get('command', '') or '-'), max_len=120))}`")
            if excerpt:
                for part in excerpt:
                    lines.append(f"  - {maybe_redact(part)}")
    else:
        lines.append("- No evidence excerpt was selected for this pass.")

    lines.extend(
        [
            "",
            "## ✅ Recommended Response Plan",
            "1. Preserve the current host state. Do not kill processes, delete files, or restart services before approval.",
            "2. If the host is business-critical, isolate network egress through change-controlled controls rather than destructive host actions.",
            "3. Collect external evidence next: bastion/VPN/IdP logs, firewall/NAT/DNS records, cloud audit trails, and Kubernetes audit logs if applicable.",
            "4. Revoke or rotate exposed credentials, keys, and tokens that could plausibly explain the initial-access path.",
            "5. Review each suspicious executable path and hash against threat-intel, package ownership, and known-good baselines before remediation.",
            "6. If mining runtime is confirmed, prepare a rollback-safe containment plan covering process stop, persistence cleanup, credential hygiene, and service recovery validation.",
            "7. If lateral movement remains possible, expand review to peer hosts, bastions, management nodes, and internal source IP pivots named in this report.",
            "",
            "## ℹ️ Operator Notes",
            "- This report separates observed facts from inference and does not fabricate missing steps.",
            "- Any state-changing action still requires explicit approval and business-impact review.",
            "",
        ]
    )
    return "\n".join(lines).strip() + "\n"


def build_leadership_report_zh_cn(data: dict[str, Any], redact: bool, case_dir: str | None = None) -> str:
    ctx = prepare_report_context(data, redact=redact, strict=False, case_dir=case_dir)
    payload = leadership_payload(ctx)
    matrix_rows = leadership_matrix_rows(ctx, payload)

    def maybe_redact(value: str) -> str:
        return zh_report_text(value, redact)

    posture = investigation_posture_payload(ctx)
    gpu_status_zh = {
        "suspicious_runtime": "已见可疑运行时",
        "active_no_direct_miner_match": "存在活动但未直接命中矿工",
        "hardware_visible_no_runtime": "硬件可见但未见运行时",
        "tooling_limited": "工具受限",
        "not_observed": "未观察到",
        "unknown": "未知",
    }.get(payload["gpu_visibility_status"], payload["gpu_visibility_status"])
    lines = [
        f"# {ctx['title']} - 领导复核报告",
        "",
        "这是一份可单独提交的案件汇总件，不依赖其它文件跳转即可了解整体情况。",
        "",
        "## 🚨 最终结论",
        f"- **案件 ID：** `{data.get('case_id', 'unknown')}`",
        f"- **主机：** `{sanitize_report_text(ctx['host_name'], redact)}` (`{sanitize_report_text(ctx['host_ip'], redact)}`)",
        f"- **操作系统：** `{zh_report_text(ctx['os_name'], redact)}`",
        f"- **观察窗口（UTC）：** `{ctx['window_start']}` -> `{ctx['window_end']}`",
        f"- **最早相关时间：** `{sanitize_report_text(payload['intrusion_window'], redact)}`",
        f"- **结论：** {maybe_redact(localize_auto_text_zh_cn(posture['verdict']))}",
        f"- **判断边界：** {maybe_redact(localize_auto_text_zh_cn(posture['boundary']))}",
        f"- **当前重点：** {maybe_redact(localize_auto_text_zh_cn(posture['focus']))}",
        "",
        "## 🧩 结论矩阵",
    ]
    for row in matrix_rows:
        claim_zh = {
            "observed_fact": "观测事实",
            "inference": "推断",
            "attribution": "归因",
        }.get(row["claim_type"], row["claim_type"])
        conf_zh = {
            "high": "高",
            "medium": "中",
            "low": "低",
            "unknown": "未知",
        }.get(row["confidence"], row["confidence"])
        lines.extend(
            [
                f"### {claim_type_emoji(row['claim_type'])} {claim_zh} | {confidence_emoji(row['confidence'])} {conf_zh}",
                f"- **表述：** {maybe_redact(row['statement_zh'])}",
                f"- **依据：** {maybe_redact(str(row.get('basis_zh', localize_auto_text_zh_cn(row['basis']))))}",
                "",
            ]
        )
    lines.append("## 🧭 疑似入侵方式")
    for item in payload["ingress_hypotheses"]:
        conf = {"high": "高", "medium": "中", "low": "低"}.get(item["confidence"], item["confidence"])
        lines.append(f"- `置信度 {conf}` {maybe_redact(item['label_zh'])} | 依据：{maybe_redact(item['basis'])}")
    lines.extend(["", "## 🔬 入侵后做了什么"])
    for item in payload["activity_summary"]:
        lines.append(f"- {maybe_redact(localize_auto_text_zh_cn(item))}")
    lines.extend(
        [
            "",
            "## ⛏️ 挖矿 / 木马信息",
            f"- **运行参数画像数量：** `{payload['runtime_profile_count']}`",
            f"- **高 CPU 进程矿工关键字命中数：** `{payload['top_cpu_keyword_hits']}`",
            f"- **GPU 可疑进程数量：** `{payload['gpu_suspicious']}`",
            f"- **GPU 峰值利用率：** `{payload['gpu_peak']}%`",
            f"- **GPU 可见性状态：** `{maybe_redact(gpu_status_zh)}`",
            f"- **GPU 厂商提示：** `{maybe_redact('、'.join(payload['gpu_vendor_hints']) or '无')}`",
            f"- **GPU 降级标记：** `{maybe_redact('、'.join(payload['gpu_fallback_markers']) or '无')}`",
        ]
    )
    if payload["runtime_profiles"]:
        for item in payload["runtime_profiles"][:4]:
            lines.append(
                f"- 运行参数：exe=`{sanitize_report_text(str(item.get('executable', '') or '-'), redact)}`，algo=`{sanitize_report_text(str(item.get('algorithm', '') or '-'), redact)}`，pool=`{sanitize_report_text(str(item.get('pool', '') or '-'), redact)}`，proxy=`{sanitize_report_text(str(item.get('proxy', '') or '-'), redact)}`，wallet=`{sanitize_report_text(str(item.get('wallet', '') or '-'), redact)}`，password=`{sanitize_report_text(str(item.get('password', '') or '-'), redact)}`，cpu_threads=`{sanitize_report_text(str(item.get('cpu_threads', '') or '-'), redact)}`"
            )
    else:
        lines.append("- 当前未恢复出可直接解析的矿工运行参数画像。")

    lines.extend(["", "## 📦 可疑文件与哈希"])
    if payload["malware_files"]:
        for item in payload["malware_files"][:8]:
            role_label = {
                "miner_runtime": "矿工运行体",
                "launcher_or_dropper": "投放器/启动器",
                "candidate_binary": "可疑二进制候选",
                "unknown": "未知",
            }.get(str(item.get("role_inference", "unknown")), str(item.get("role_inference", "unknown")))
            lines.append(
                f"- 文件=`{sanitize_report_text(str(item.get('path', '') or '-'), redact)}` | sha256=`{sanitize_report_text(str(item.get('sha256', '') or 'unavailable'), redact)}` | 作用判断=`{role_label}` | 依据=`{sanitize_report_text(str(item.get('origin_path', '') or str(item.get('evidence_id', 'unknown'))), redact)}`"
            )
    else:
        lines.append("- 当前视野内未恢复出可疑文件与哈希配对结果。")

    lines.extend(
        [
            "",
            "## 🖥️ 系统状态与暴露面",
            f"- **服务暴露面：** {maybe_redact(localize_auto_text_zh_cn(payload['service_exposure']))}",
            f"- **认证来源 IP：** {sanitize_report_text(', '.join(payload['auth_ips']) if payload['auth_ips'] else '未恢复', redact)}",
            f"- **监听端口：** {sanitize_report_text(', '.join(payload['listening_ports']) if payload['listening_ports'] else '未恢复', redact)}",
        ]
    )
    if payload["top_cpu"]:
        lines.append("- **当前高 CPU 进程：**")
        for item in payload["top_cpu"][:5]:
            lines.append(
                f"  - pid=`{sanitize_report_text(str(item.get('pid', '') or '-'), redact)}` cpu=`{sanitize_report_text(str(item.get('cpu_percent', '') or '-'), redact)}` exe=`{sanitize_report_text(str(item.get('executable', '') or '-'), redact)}` cmd=`{sanitize_report_text(compact_text(str(item.get('command', '') or '-'), max_len=160), redact)}`"
            )

    lateral_label = {"possible": "存在可能", "not_observed": "未直接观察到", "observed": "已观察到"}.get(payload["lateral_status"], payload["lateral_status"])
    lines.extend(
        [
            "",
            "## 🔁 横向渗透判断",
            f"- **状态：** `{lateral_label}`",
            f"- **说明：** {maybe_redact(localize_auto_text_zh_cn(payload['lateral_basis']))}",
            "",
            "## 🧾 日志完整性",
            f"- **风险数量：** `{payload['log_risk_count']}`",
            "- 关键日志缺失或可疑时，攻击链归因置信度必须下调，并补拉外部遥测。",
            "",
            "## 🔗 必要证据摘录",
        ]
    )
    evid_idx = ctx["evid_idx"]
    if payload["evidence_excerpt_ids"]:
        for evid in payload["evidence_excerpt_ids"]:
            item = as_dict(evid_idx.get(evid))
            if not item:
                continue
            excerpt = artifact_excerpt(item, max_lines=2)
            lines.append(f"- **{evid}** 来源=`{sanitize_report_text(str(item.get('source', 'unknown')) or 'unknown', redact)}` 命令=`{sanitize_report_text(compact_text(str(item.get('command', '') or '-'), max_len=120), redact)}`")
            if excerpt:
                for part in excerpt:
                    lines.append(f"  - {sanitize_report_text(part, redact)}")
    else:
        lines.append("- 本轮未选出可摘录证据。")

    lines.extend(
        [
            "",
            "## ✅ 处置建议（可直接给执行人员）",
            "1. 先保现场，禁止未经审批直接杀进程、删文件、停服务或重启。",
            "2. 若主机承载业务，优先通过可回滚的网络侧手段限制异常外联，而不是直接做破坏性主机操作。",
            "3. 立即补拉外部证据：堡垒机/VPN/IdP 登录日志、边界防火墙/NAT/DNS、云审计、Kubernetes 审计。",
            "4. 对可能涉及的口令、密钥、令牌做轮换或吊销，尤其是能够解释本次入口的那一类凭据。",
            "5. 将本报告列出的可疑文件路径和哈希送去做威胁情报、软件包归属和基线对照，不要只凭文件名判断。",
            "6. 若已确认存在挖矿运行体，再制定可回滚的隔离和清理方案，覆盖进程、持久化、凭据和业务恢复验证。",
            "7. 若横向渗透存在可能，继续排查本报告提到的内网来源 IP、跳板机、管理节点和同网段主机。",
            "",
            "## ℹ️ 使用说明",
            "- 本报告区分观测事实与推断，不会补写证据里不存在的步骤。",
            "- 任何状态变更操作仍需明确审批和业务影响评估。",
            "",
        ]
    )
    return "\n".join(lines).strip() + "\n"


def build_case_bundle_index(data: dict[str, Any], case_dir: str | None = None) -> str:
    incident = as_dict(data.get("incident"))
    host = as_dict(data.get("host"))
    scene_reconstruction = as_dict(data.get("scene_reconstruction"))
    lines = [
        anchor_tag("bundle-top"),
        f"# {incident.get('title', 'Mining Host Investigation')} - Case Bundle",
        "",
        "> Landing page for this case bundle. Use this page to jump between reports, evidence, artifacts, and metadata.",
        "",
        "## Quick Links",
        "- [Status Card](#bundle-status)",
        "- [Bundle Summary](#bundle-summary)",
        "- [Key Risks](#bundle-key-risks)",
        "- [Latest Judgments](#bundle-latest-judgments)",
        "- [Suggested Reading Order](#bundle-reading-order)",
        "- [Report Inventory](#bundle-report-inventory)",
        "- [Directory Status](#bundle-directory-status)",
        "- [Case Directories](#bundle-case-directories)",
        "",
        anchor_tag("bundle-status"),
        "## Status Card",
        f"- **Incident ID:** `{incident.get('id', 'unknown')}`",
        f"- **Host:** `{host.get('name', 'unknown')}` (`{host.get('ip', 'unknown')}`)",
        f"- **Evidence Items:** `{len(as_list(data.get('evidence')))}` | **Findings:** `{len(as_list(data.get('findings')))}` | **Timeline:** `{len(as_list(data.get('timeline')))}`",
        f"- **Auth Source IPs:** `{len(as_list(scene_reconstruction.get('auth_source_ips')))}` | **Listening Ports:** `{len(as_list(scene_reconstruction.get('listening_ports')))}`",
        f"- **Hypothesis Matrix:** `{len(as_list(data.get('hypothesis_matrix')))}` | **GPU Suspicious Processes:** `{safe_int(scene_reconstruction.get('gpu_suspicious_process_count', 0))}`",
        "",
        anchor_tag("bundle-summary"),
        "## Bundle Summary",
        f"- **Case ID:** `{data.get('case_id', 'unknown')}`",
        f"- **Generated At (UTC):** `{data.get('generated_at', now_utc())}`",
        f"- **Host Role Context:** `{host.get('os', 'unknown')}` / `{host.get('mining_mode', 'unknown')}`",
        "",
        anchor_tag("bundle-key-risks"),
        "## Key Risks",
    ]
    lines.extend(key_risk_lines(data, case_dir=case_dir))
    lines.extend(["", anchor_tag("bundle-latest-judgments"), "## Latest Judgments"])
    lines.extend(latest_judgment_lines(data, case_dir=case_dir, limit=3))
    lines.extend(["", anchor_tag("bundle-reading-order"), "## Suggested Reading Order"])
    lines.extend(reading_order_lines())
    lines.extend(["", anchor_tag("bundle-report-inventory"), "## Report Inventory"])
    lines.extend(report_inventory_lines(case_dir))
    lines.extend(["", anchor_tag("bundle-directory-status"), "## Directory Status"])
    lines.extend(case_directory_status(case_dir))
    lines.extend([
        "",
        anchor_tag("bundle-case-directories"),
        "## Case Directories",
        f"- {report_link('../artifacts/', 'Artifacts Directory')}",
        f"- {report_link('../evidence/', 'Evidence Directory')}",
        f"- {report_link('../meta/', 'Metadata Directory')}",
        "",
        "## Notes",
        "- Full evidence detail blocks and command provenance are in `../report.md`.",
        "- Companion summaries intentionally shorten evidence chains; use the full report when approving any change.",
        "- [Back to Top](#bundle-top)",
        "",
    ])
    return "\n".join(lines).strip() + "\n"



def build_case_bundle_index_zh_cn(data: dict[str, Any], case_dir: str | None = None) -> str:
    incident = as_dict(data.get("incident"))
    host = as_dict(data.get("host"))
    scene_reconstruction = as_dict(data.get("scene_reconstruction"))
    lines = [
        anchor_tag("bundle-top"),
        f"# {incident.get('title', 'Mining Host Investigation')} - 案件索引",
        "",
        "> 当前案件包的中文入口页，用于在报告、证据、产物和元数据之间快速跳转。",
        "",
        "## 快速链接",
        "- [状态卡片](#bundle-status)",
        "- [案件摘要](#bundle-summary)",
        "- [关键风险](#bundle-key-risks)",
        "- [最新研判](#bundle-latest-judgments)",
        "- [建议阅读顺序](#bundle-reading-order)",
        "- [报告清单](#bundle-report-inventory)",
        "- [目录状态](#bundle-directory-status)",
        "- [案件目录](#bundle-case-directories)",
        "",
        anchor_tag("bundle-status"),
        "## 状态卡片",
        f"- **事件 ID：** `{incident.get('id', 'unknown')}`",
        f"- **主机：** `{host.get('name', 'unknown')}` (`{host.get('ip', 'unknown')}`)",
        f"- **证据项：** `{len(as_list(data.get('evidence')))}` | **研判项：** `{len(as_list(data.get('findings')))}` | **时间线：** `{len(as_list(data.get('timeline')))}`",
        f"- **认证来源 IP：** `{len(as_list(scene_reconstruction.get('auth_source_ips')))}` | **监听端口：** `{len(as_list(scene_reconstruction.get('listening_ports')))}`",
        f"- **关联矩阵：** `{len(as_list(data.get('hypothesis_matrix')))}` | **GPU 可疑进程：** `{safe_int(scene_reconstruction.get('gpu_suspicious_process_count', 0))}`",
        "",
        anchor_tag("bundle-summary"),
        "## 案件摘要",
        f"- **案件 ID：** `{data.get('case_id', 'unknown')}`",
        f"- **生成时间（UTC）：** `{data.get('generated_at', now_utc())}`",
        f"- **主机角色上下文：** `{host.get('os', 'unknown')}` / `{host.get('mining_mode', 'unknown')}`",
        "",
        anchor_tag("bundle-key-risks"),
        "## 关键风险",
    ]
    lines.extend(key_risk_lines_zh_cn(data, case_dir=case_dir))
    lines.extend(["", anchor_tag("bundle-latest-judgments"), "## 最新研判"])
    lines.extend(latest_judgment_lines_zh_cn(data, case_dir=case_dir, limit=3))
    lines.extend(["", anchor_tag("bundle-reading-order"), "## 建议阅读顺序"])
    lines.extend(reading_order_lines_zh_cn())
    lines.extend(["", anchor_tag("bundle-report-inventory"), "## 报告清单"])
    lines.extend(report_inventory_lines_zh_cn(case_dir))
    lines.extend(["", anchor_tag("bundle-directory-status"), "## 目录状态"])
    lines.extend(case_directory_status_zh_cn(case_dir))
    lines.extend([
        "",
        anchor_tag("bundle-case-directories"),
        "## 案件目录",
        f"- {report_link('../artifacts/', 'artifacts 目录')}",
        f"- {report_link('../evidence/', 'evidence 目录')}",
        f"- {report_link('../meta/', 'meta 目录')}",
        "",
        "## 说明",
        "- 完整证据细节、命令来源和原始产物链接都在 `../report.zh-CN.md` 中。",
        "- 摘要类报告会压缩证据链展示；如需审批任何处置动作，请回到全量报告复核。",
        "- [返回顶部](#bundle-top)",
        "",
    ])
    return "\n".join(lines).strip() + "\n"


def compact_text(value: Any, max_len: int = 88) -> str:
    text = " ".join(str(value).split())
    if not text:
        return "-"
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."


def bytes_label(value: Any) -> str:
    try:
        size = int(value)
    except (TypeError, ValueError):
        return "unknown"
    return f"{size} bytes"


def yes_no(value: Any) -> str:
    return "yes" if bool(value) else "no"


def finding_status(item: dict[str, Any], evid_idx: dict[str, dict[str, Any]]) -> str:
    ids = [str(x) for x in as_list(item.get("evidence_ids"))]
    missing = [x for x in ids if x not in evid_idx]
    return "confirmed" if ids and not missing else "inconclusive"


def status_icon(status: str) -> str:
    return {"confirmed": "✅", "inconclusive": "⚠️", "traced": "✅"}.get(status, "•")


def confidence_icon(confidence: str) -> str:
    return {"high": "🟢", "medium": "🟡", "low": "🟠", "unknown": "⚪"}.get(
        str(confidence).strip().lower(),
        "⚪",
    )


def overall_confidence_posture(ctx: dict[str, Any]) -> str:
    confidence_counts = ctx["confidence_counts"]
    high = safe_int(confidence_counts.get("high", 0))
    medium = safe_int(confidence_counts.get("medium", 0))
    low = safe_int(confidence_counts.get("low", 0))
    scene = ctx["scene_reconstruction"]
    direct_hits = (
        safe_int(scene.get("process_ioc_match_count", 0))
        + safe_int(scene.get("network_ioc_hit_count", 0))
        + safe_int(scene.get("runtime_profile_count", 0))
    )
    if direct_hits > 0:
        return "high" if high >= max(1, low) else "medium"
    if low > high + medium:
        return "low"
    if high or medium:
        return "medium"
    if safe_int(ctx.get("confirmed_count", 0)) or safe_int(ctx.get("inconclusive_count", 0)):
        return "low"
    return "unknown"


def investigation_posture_payload(ctx: dict[str, Any]) -> dict[str, Any]:
    scene = ctx["scene_reconstruction"]
    process_hits = safe_int(scene.get("process_ioc_match_count", 0))
    network_hits = safe_int(scene.get("network_ioc_hit_count", 0))
    gpu_hits = safe_int(scene.get("gpu_suspicious_process_count", 0))
    runtime_profile_hits = safe_int(scene.get("runtime_profile_count", 0))
    access_hits = safe_int(scene.get("initial_access_review_hit_count", 0))
    container_hits = safe_int(scene.get("container_cloud_review_hit_count", 0))
    kernel_hits = safe_int(scene.get("kernel_review_hit_count", 0))
    unknown_trace_count = safe_int(ctx["trace_counts"].get("untraceable", 0)) + safe_int(
        ctx["trace_counts"].get("unknown", 0)
    )
    posture = overall_confidence_posture(ctx)

    if process_hits or network_hits or gpu_hits or runtime_profile_hits:
        verdict = "Direct miner-like runtime indicators were observed during collection."
        boundary = "Triage should proceed as a compromise-oriented case, but attribution still requires additional evidence."
        focus = "Prioritize runtime lineage, parent-child process review, wallet/pool traces, and persistence pivots."
    elif access_hits or container_hits or kernel_hits:
        verdict = (
            "No direct miner IOC was observed in this collection. Current results are limited to review surfaces "
            "that still require analyst confirmation."
        )
        boundary = "This does not clear the host. The present output supports review-driven triage, not a confirmed mining-compromise conclusion."
        focus = "Prioritize surviving access traces, service startup context, container/cloud exposure, and deleted-log fallback artifacts."
    else:
        verdict = "This collection did not produce direct miner evidence or enough review surface to support a compromise conclusion."
        boundary = "Absence of indicators in this pass is not proof of absence; visibility, timing, and privilege may still be incomplete."
        focus = "Expand time window, privilege visibility, and external telemetry correlation before closing the case."

    return {
        "posture": posture,
        "verdict": verdict,
        "boundary": boundary,
        "focus": focus,
        "process_hits": process_hits,
        "network_hits": network_hits,
        "gpu_hits": gpu_hits,
        "runtime_profile_hits": runtime_profile_hits,
        "access_hits": access_hits,
        "container_hits": container_hits,
        "kernel_hits": kernel_hits,
        "unknown_trace_count": unknown_trace_count,
    }


def append_sample_group(
    lines: list[str],
    heading: str,
    items: list[Any],
    maybe_redact,
    *,
    limit: int = 4,
    max_len: int = 140,
    empty_label: str = "None.",
) -> None:
    lines.append(f"### {heading}")
    if items:
        for item in items[:limit]:
            lines.append(f"- {maybe_redact(compact_text(item, max_len=max_len))}")
        if len(items) > limit:
            lines.append(f"- ... (+{len(items) - limit} more)")
    else:
        lines.append(f"- {empty_label}")
    lines.append("")


def render_hypothesis_matrix_section(
    lines: list[str],
    matrix_items: list[dict[str, Any]],
    evid_idx: dict[str, dict[str, Any]],
    case_dir: str | None,
    maybe_redact,
) -> None:
    lines.append(anchor_tag("report-hypothesis-matrix"))
    lines.append("## Hypothesis Matrix")
    if not matrix_items:
        lines.extend(["No hypothesis matrix entries were provided.", ""])
        return
    rows: list[list[str]] = []
    for item in matrix_items:
        support = evidence_reference_list(as_list(item.get("supporting_evidence_ids")), evid_idx, case_dir)
        counter = evidence_reference_list(as_list(item.get("counter_evidence_ids")), evid_idx, case_dir)
        rows.append(
            [
                maybe_redact(str(item.get("hypothesis_id", "unknown"))),
                maybe_redact(str(item.get("title", "unknown"))),
                maybe_redact(str(item.get("status", "unknown"))),
                maybe_redact(str(item.get("confidence", "unknown"))),
                support,
                counter if counter != "-" else "-",
                maybe_redact(compact_text(str(item.get("summary", "")), max_len=160)),
            ]
        )
    lines.append(
        render_table(
            ["Hypothesis", "Title", "Status", "Confidence", "Support Evidence", "Counter Evidence", "Summary"],
            rows,
        )
    )
    lines.append("")


def render_hypothesis_matrix_section_zh_cn(
    lines: list[str],
    matrix_items: list[dict[str, Any]],
    evid_idx: dict[str, dict[str, Any]],
    case_dir: str | None,
    maybe_redact,
) -> None:
    lines.append(anchor_tag("report-hypothesis-matrix"))
    lines.append("## 假设-证据关联矩阵")
    if not matrix_items:
        lines.extend(["未提供关联矩阵条目。", ""])
        return
    status_map = {
        "supported": "支持",
        "inconclusive": "待定",
        "not_observed": "未观察到",
        "refuted": "被反证",
    }
    confidence_map = {"high": "高", "medium": "中", "low": "低", "unknown": "未知"}
    title_map = {
        "CPU runtime miner hypothesis": "CPU 运行时挖矿假设",
        "GPU runtime miner hypothesis": "GPU 运行时挖矿假设",
        "Parsed miner runtime profile hypothesis": "矿工运行参数画像假设",
        "Malware file and hash correlation hypothesis": "恶意文件与哈希关联假设",
        "Credential or initial-access abuse hypothesis": "凭据或初始访问滥用假设",
        "Persistence foothold hypothesis": "持久化落点假设",
        "Network IOC and outbound control hypothesis": "网络 IOC 与外联控制假设",
        "Log tampering hypothesis": "日志篡改假设",
    }
    rows: list[list[str]] = []
    for item in matrix_items:
        support = evidence_reference_list_zh_cn(as_list(item.get("supporting_evidence_ids")), evid_idx, case_dir)
        counter = evidence_reference_list_zh_cn(as_list(item.get("counter_evidence_ids")), evid_idx, case_dir)
        rows.append(
            [
                maybe_redact(str(item.get("hypothesis_id", "unknown"))),
                maybe_redact(title_map.get(str(item.get("title", "unknown")), str(item.get("title", "unknown")))),
                maybe_redact(status_map.get(str(item.get("status", "unknown")), str(item.get("status", "unknown")))),
                maybe_redact(confidence_map.get(str(item.get("confidence", "unknown")), str(item.get("confidence", "unknown")))),
                support,
                counter if counter != "-" else "-",
                maybe_redact(localize_auto_text_zh_cn(compact_text(str(item.get("summary", "")), max_len=160))),
            ]
        )
    lines.append(
        render_table(
            ["假设编号", "假设内容", "状态", "置信度", "支撑证据", "反证证据", "说明"],
            rows,
        )
    )
    lines.append("")


def top_conclusion_lines(
    ctx: dict[str, Any],
    maybe_redact,
    case_dir: str | None = None,
    limit: int = 3,
) -> list[str]:
    posture_info = investigation_posture_payload(ctx)
    process_hits = posture_info["process_hits"]
    network_hits = posture_info["network_hits"]
    gpu_hits = posture_info["gpu_hits"]
    runtime_profile_hits = posture_info.get("runtime_profile_hits", 0)
    access_hits = posture_info["access_hits"]
    container_hits = posture_info["container_hits"]
    kernel_hits = posture_info["kernel_hits"]
    unknown_trace_count = posture_info["unknown_trace_count"]
    posture = posture_info["posture"]
    top_items = top_judgments(ctx["findings"], ctx["evid_idx"], limit=limit)
    expected_workload = maybe_redact(ctx["expected_workload"] or "not provided")
    observed_uid = str(ctx["privilege_scope"].get("uid", "unknown")).strip() or "unknown"

    scene = ctx["scene_reconstruction"]
    runtime_profiles = [as_dict(x) for x in as_list(scene.get("runtime_profiles"))]
    runtime_algorithms = as_list(scene.get("runtime_algorithms"))
    runtime_pools = as_list(scene.get("runtime_pools"))
    runtime_proxies = as_list(scene.get("runtime_proxies"))
    runtime_wallets = as_list(scene.get("runtime_wallets"))
    runtime_passwords = as_list(scene.get("runtime_passwords"))
    runtime_cpu_threads = as_list(scene.get("runtime_cpu_threads"))
    lines = [
        anchor_tag("report-conclusion"),
        "## Investigation Conclusion",
        "",
        f"- **Verdict:** {maybe_redact(posture_info['verdict'])}",
        f"- **Confidence Posture:** {confidence_icon(posture)} `{posture}`",
        f"- **Decision Boundary:** {maybe_redact(posture_info['boundary'])}",
        f"- **Read-Only Scope:** `0` state-changing actions executed during this collection.",
        "",
        "### Evidence Basis",
        f"- **Runtime Indicators:** process IOC hits `{process_hits}`, network IOC hits `{network_hits}`, GPU suspicious-process hits `{gpu_hits}`, parsed runtime profiles `{runtime_profile_hits}`.",
        f"- **Review Surfaces:** initial access `{access_hits}`, container/cloud `{container_hits}`, kernel/eBPF `{kernel_hits}`.",
        f"- **Finding State:** `{ctx['confirmed_count']}` confirmed, `{ctx['inconclusive_count']}` inconclusive.",
        f"- **Expected Workload Context:** {expected_workload}.",
    ]
    if runtime_profiles:
        lines.extend(
            [
                "",
                "### Auto-Parsed Miner Runtime Profile",
                f"- **Algorithms:** {maybe_redact(shorten_list(runtime_algorithms, limit=6))}",
                f"- **Pools:** {maybe_redact(shorten_list(runtime_pools, limit=4))}",
                f"- **Proxies:** {maybe_redact(shorten_list(runtime_proxies, limit=4))}",
                f"- **Wallets:** {maybe_redact(shorten_list(runtime_wallets, limit=4))}",
                f"- **Passwords:** {maybe_redact(shorten_list(runtime_passwords, limit=4))}",
                f"- **CPU Threads / Affinity:** {maybe_redact(shorten_list(runtime_cpu_threads, limit=4))}",
                "- **Profile Samples:**",
            ]
        )
        for profile in runtime_profiles[:3]:
            evidence_id = str(profile.get("evidence_id", "")).strip()
            chain = compact_evidence_chain([evidence_id] if evidence_id else [], ctx["evid_idx"], case_dir, limit=1)
            lines.append(
                f"  - exe=`{maybe_redact(str(profile.get('executable', '') or '-'))}` "
                f"algo=`{maybe_redact(str(profile.get('algorithm', '') or '-'))}` "
                f"pool=`{maybe_redact(str(profile.get('pool', '') or '-'))}` "
                f"proxy=`{maybe_redact(str(profile.get('proxy', '') or '-'))}` "
                f"wallet=`{maybe_redact(str(profile.get('wallet', '') or '-'))}` "
                f"password=`{maybe_redact(str(profile.get('password', '') or '-'))}` "
                f"cpu_threads=`{maybe_redact(str(profile.get('cpu_threads', '') or '-'))}` "
                f"origin=`{maybe_redact(str(profile.get('origin_path', '') or '-'))}:{maybe_redact(str(profile.get('origin_line', '') or '-'))}` "
                f"| evidence: {chain}"
            )
    if top_items:
        lines.append("- **Highest-Signal Judgments:**")
        for item in top_items:
            evidence_ids = item["evidence_ids"].split(", ") if item["evidence_ids"] != "none" else []
            chain = compact_evidence_chain(evidence_ids, ctx["evid_idx"], case_dir, limit=3)
            lines.append(
                f"  - `{item['id']}` [{claim_type_label(item['claim_type'])}/{item['status']}/{item['confidence']}] "
                f"{maybe_redact(compact_text(item['statement'], max_len=180))} | evidence: {chain}"
            )
    else:
        lines.append("- **Highest-Signal Judgments:** none yet.")
    lines.extend(
        [
            "",
            "### Remaining Gaps",
            f"- **IP Traceability:** `{unknown_trace_count}` item(s) remain untraced or unknown.",
            f"- **Log Survivability:** `{ctx['log_risk_count']}` artifact(s) are missing, suspicious, or tampered.",
            f"- **Privilege Visibility:** observed UID `{maybe_redact(observed_uid)}`; deeper indicators outside current visibility cannot be treated as absent.",
            "- **Next Reading Path:** [Findings](#report-findings) | [Timeline](#report-timeline) | [Evidence Details](#report-evidence-details)",
            "",
        ]
    )
    return lines


def top_conclusion_lines_zh_cn(
    ctx: dict[str, Any],
    maybe_redact,
    case_dir: str | None = None,
    limit: int = 3,
) -> list[str]:
    posture_info = investigation_posture_payload(ctx)
    process_hits = posture_info["process_hits"]
    network_hits = posture_info["network_hits"]
    gpu_hits = posture_info["gpu_hits"]
    runtime_profile_hits = posture_info.get("runtime_profile_hits", 0)
    access_hits = posture_info["access_hits"]
    container_hits = posture_info["container_hits"]
    kernel_hits = posture_info["kernel_hits"]
    unknown_trace_count = posture_info["unknown_trace_count"]
    posture = posture_info["posture"]
    top_items = top_judgments(ctx["findings"], ctx["evid_idx"], limit=limit)
    expected_workload = maybe_redact(ctx["expected_workload"] or "未提供")
    observed_uid = str(ctx["privilege_scope"].get("uid", "unknown")).strip() or "unknown"
    scene = ctx["scene_reconstruction"]
    runtime_profiles = [as_dict(x) for x in as_list(scene.get("runtime_profiles"))]
    runtime_algorithms = as_list(scene.get("runtime_algorithms"))
    runtime_pools = as_list(scene.get("runtime_pools"))
    runtime_proxies = as_list(scene.get("runtime_proxies"))
    runtime_wallets = as_list(scene.get("runtime_wallets"))
    runtime_passwords = as_list(scene.get("runtime_passwords"))
    runtime_cpu_threads = as_list(scene.get("runtime_cpu_threads"))
    posture_label = {
        "high": "高",
        "medium": "中",
        "low": "低",
        "unknown": "未知",
    }.get(posture, posture)

    lines = [
        anchor_tag("report-conclusion"),
        "## 核心结论",
        "",
        f"- **结论：** {maybe_redact({
            'Direct miner-like runtime indicators were observed during collection.': '本次采集中观察到了直接的挖矿类运行时指标。',
            'No direct miner IOC was observed in this collection. Current results are limited to review surfaces that still require analyst confirmation.': '本次采集中未观察到直接的挖矿 IOC，当前结果主要是需要人工复核的访问面与环境侧线索。',
            'This collection did not produce direct miner evidence or enough review surface to support a compromise conclusion.': '本次采集未形成直接挖矿证据，也未形成足以支撑入侵结论的复核面。',
        }.get(posture_info['verdict'], posture_info['verdict']))}",
        f"- **置信度态势：** {confidence_icon(posture)} `{posture_label}`",
        f"- **判断边界：** {maybe_redact({
            'Triage should proceed as a compromise-oriented case, but attribution still requires additional evidence.': '这足以支持按入侵方向继续排查，但单凭这一点仍不足以完成完整归因。',
            'This does not clear the host. The present output supports review-driven triage, not a confirmed mining-compromise conclusion.': '这并不代表主机可以直接排除风险，只说明当前报告更偏向复核线索，而不是确认已发生挖矿入侵。',
            'Absence of indicators in this pass is not proof of absence; visibility, timing, and privilege may still be incomplete.': '这一轮未命中指标不等于主机无风险，观察窗口、权限范围和证据残留都可能仍不完整。',
        }.get(posture_info['boundary'], posture_info['boundary']))}",
        "- **只读约束：** 本次采集未执行任何状态变更命令。",
        "",
        "### 证据依据",
        f"- **运行时指标：** 进程 IOC 命中 `{process_hits}`，网络 IOC 命中 `{network_hits}`，GPU 可疑进程命中 `{gpu_hits}`，运行参数画像 `{runtime_profile_hits}`。",
        f"- **复核面：** 初始访问 `{access_hits}`，容器/云 `{container_hits}`，内核/eBPF `{kernel_hits}`。",
        f"- **研判状态：** 已确认 `{ctx['confirmed_count']}` 条，待定 `{ctx['inconclusive_count']}` 条。",
        f"- **业务上下文：** 预期工作负载 {expected_workload}。",
    ]
    if runtime_profiles:
        lines.extend(
            [
                "",
                "### 自动解析的矿工运行参数",
                f"- **算法：** {maybe_redact(shorten_list(runtime_algorithms, limit=6))}",
                f"- **矿池：** {maybe_redact(shorten_list(runtime_pools, limit=4))}",
                f"- **代理：** {maybe_redact(shorten_list(runtime_proxies, limit=4))}",
                f"- **钱包：** {maybe_redact(shorten_list(runtime_wallets, limit=4))}",
                f"- **链接密码：** {maybe_redact(shorten_list(runtime_passwords, limit=4))}",
                f"- **CPU 线程/绑核：** {maybe_redact(shorten_list(runtime_cpu_threads, limit=4))}",
                "- **画像样本：**",
            ]
        )
        for profile in runtime_profiles[:3]:
            evidence_id = str(profile.get("evidence_id", "")).strip()
            chain = compact_evidence_chain_zh_cn([evidence_id] if evidence_id else [], ctx["evid_idx"], case_dir, limit=1)
            lines.append(
                f"  - exe=`{maybe_redact(str(profile.get('executable', '') or '-'))}` "
                f"algo=`{maybe_redact(str(profile.get('algorithm', '') or '-'))}` "
                f"pool=`{maybe_redact(str(profile.get('pool', '') or '-'))}` "
                f"proxy=`{maybe_redact(str(profile.get('proxy', '') or '-'))}` "
                f"wallet=`{maybe_redact(str(profile.get('wallet', '') or '-'))}` "
                f"password=`{maybe_redact(str(profile.get('password', '') or '-'))}` "
                f"cpu_threads=`{maybe_redact(str(profile.get('cpu_threads', '') or '-'))}` "
                f"origin=`{maybe_redact(str(profile.get('origin_path', '') or '-'))}:{maybe_redact(str(profile.get('origin_line', '') or '-'))}` "
                f"| 证据：{chain}"
            )
    if top_items:
        lines.append("- **高信号研判：**")
        for item in top_items:
            evidence_ids = item["evidence_ids"].split(", ") if item["evidence_ids"] != "none" else []
            chain = compact_evidence_chain_zh_cn(evidence_ids, ctx["evid_idx"], case_dir, limit=3)
            claim_label = {
                "observed_fact": "观测事实",
                "inference": "推断",
                "attribution": "归因",
            }.get(item["claim_type"], "推断")
            status_label = {
                "confirmed": "已确认",
                "inconclusive": "待定",
            }.get(item["status"], item["status"])
            confidence_label = {
                "high": "高",
                "medium": "中",
                "low": "低",
                "unknown": "未知",
            }.get(item["confidence"], item["confidence"])
            lines.append(
                f"  - `{item['id']}` [{claim_label}/{status_label}/{confidence_label}] "
                f"{maybe_redact(localize_auto_text_zh_cn(compact_text(item['statement'], max_len=180)))} | 证据：{chain}"
            )
    else:
        lines.append("- **高信号研判：** 暂无。")
    lines.extend(
        [
            "",
            "### 未解决缺口",
            f"- **IP 溯源：** 仍有 `{unknown_trace_count}` 项未完成溯源或状态未知。",
            f"- **日志留存：** 仍有 `{ctx['log_risk_count']}` 个日志相关产物缺失、可疑或疑似被篡改。",
            f"- **权限可见性：** 当前观测 UID 为 `{maybe_redact(observed_uid)}`，超出当前权限边界的指标不能直接视为不存在。",
            "- **继续阅读：** [结论与研判](#report-findings) | [时间线](#report-timeline) | [证据详情](#report-evidence-details)",
            "",
        ]
    )
    return lines


def append_sample_section(
    lines: list[str], heading: str, items: list[Any], maybe_redact, limit: int = 8
) -> None:
    lines.append(f"### {heading}")
    if items:
        for item in items[:limit]:
            lines.append(f"- {maybe_redact(compact_text(item, max_len=220))}")
        if len(items) > limit:
            lines.append(f"- ... (+{len(items) - limit} more)")
    else:
        lines.append("- None.")
    lines.append("")


def render_runtime_profile_samples(items: list[dict[str, Any]], limit: int = 8) -> list[str]:
    rows: list[str] = []
    for item in items[:limit]:
        rows.append(
            " | ".join(
                [
                    f"exe={item.get('executable', '-')}",
                    f"algo={item.get('algorithm', '-')}",
                    f"pool={item.get('pool', '-')}",
                    f"proxy={item.get('proxy', '-')}",
                    f"wallet={item.get('wallet', '-')}",
                    f"pass={item.get('password', '-')}",
                    f"threads={item.get('cpu_threads', '-')}",
                    f"origin={item.get('origin_path', '-')}"
                    + (f":{item.get('origin_line', '-')}" if str(item.get("origin_line", "")).strip() else ""),
                ]
            )
        )
    return rows


def render_top_process_samples(items: list[dict[str, Any]], limit: int = 8) -> list[str]:
    rows: list[str] = []
    for item in items[:limit]:
        rows.append(
            " | ".join(
                [
                    f"pid={item.get('pid', '-')}",
                    f"user={item.get('user', '-')}",
                    f"cpu={item.get('cpu_percent', '-')}",
                    f"mem={item.get('mem_percent', '-')}",
                    f"exe={item.get('executable', '-')}",
                    f"cmd={item.get('command', '-')}",
                ]
            )
        )
    return rows


def append_checkpoint_section(
    lines: list[str], heading: str, history: list[dict[str, Any]], maybe_redact, limit: int = 12
) -> None:
    lines.append(heading)
    if history:
        for item in history[:limit]:
            extra = as_dict(item.get("extra"))
            extra_parts = [
                f"{key}={compact_text(maybe_redact(str(value)), max_len=64)}"
                for key, value in extra.items()
            ]
            suffix = f" | extras: {'; '.join(extra_parts[:3])}" if extra_parts else ""
            note = str(item.get("note", "")).strip()
            note_text = f" | note: {maybe_redact(compact_text(note, max_len=96))}" if note else ""
            lines.append(
                f"- `{item.get('time_utc', 'unknown')}` | `{item.get('stage', 'unknown')}` | `{item.get('status', 'unknown')}`{note_text}{suffix}"
            )
        if len(history) > limit:
            lines.append(f"- ... (+{len(history) - limit} more)")
    else:
        lines.append("- No workflow checkpoints were recorded.")
    lines.append("")


def prepare_report_context(
    data: dict[str, Any], redact: bool, strict: bool, case_dir: str | None = None
) -> dict[str, Any]:
    warnings: list[str] = []
    incident = as_dict(data.get("incident"))
    host = as_dict(data.get("host"))
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    findings = [as_dict(x) for x in as_list(data.get("findings"))]
    hypothesis_matrix = [as_dict(x) for x in as_list(data.get("hypothesis_matrix"))]
    ip_traces = [as_dict(x) for x in as_list(data.get("ip_traces"))]
    log_integrity = [as_dict(x) for x in as_list(data.get("log_integrity"))]
    actions = [as_dict(x) for x in as_list(data.get("actions"))]
    timeline = [as_dict(x) for x in as_list(data.get("timeline"))]
    unknowns = as_list(data.get("unknowns"))
    baseline_assessment = load_optional_case_json(case_dir, "meta/baseline_assessment.json")
    case_validation = load_optional_case_json(case_dir, "meta/case_validation.json")
    artifact_hashes = load_optional_case_json(case_dir, "meta/artifact_hashes.json")
    workflow_checkpoints = load_optional_case_json(case_dir, "meta/workflow_checkpoints.json")
    scene_reconstruction = as_dict(data.get("scene_reconstruction"))
    remote_trust = as_dict(data.get("remote_trust"))
    privilege_scope = as_dict(scene_reconstruction.get("privilege_scope"))
    time_norm = as_dict(scene_reconstruction.get("time_normalization"))
    workflow_history = [as_dict(x) for x in as_list(workflow_checkpoints.get("history"))]

    evid_idx = evidence_index(evidence_items)
    for finding in findings:
        ids = [str(x) for x in as_list(finding.get("evidence_ids"))]
        missing = [x for x in ids if x not in evid_idx]
        if not ids:
            warnings.append(f"Finding '{finding.get('id', 'unknown')}' has no evidence_ids.")
        if missing:
            warnings.append(
                f"Finding '{finding.get('id', 'unknown')}' references missing evidence IDs: {', '.join(missing)}"
            )
    for item in hypothesis_matrix:
        support_ids = [str(x) for x in as_list(item.get("supporting_evidence_ids"))]
        counter_ids = [str(x) for x in as_list(item.get("counter_evidence_ids"))]
        missing = [x for x in support_ids + counter_ids if x not in evid_idx]
        if missing:
            warnings.append(
                f"Hypothesis '{item.get('hypothesis_id', 'unknown')}' references missing evidence IDs: {', '.join(sorted(set(missing)))}"
            )

    for ip_item in ip_traces:
        status = normalize_trace_status(str(ip_item.get("trace_status", "")))
        ip_item["trace_status"] = status
        if status != "traced" and not str(ip_item.get("reason", "")).strip():
            warnings.append(
                f"IP trace entry '{ip_item.get('ip', 'unknown')}' is {status} but has no reason."
            )

    for log_item in log_integrity:
        status = str(log_item.get("status", "unknown")).strip().lower()
        if status in {"missing", "tampered"} and not as_list(log_item.get("evidence_ids")):
            warnings.append(
                f"Log integrity entry '{log_item.get('artifact', 'unknown')}' is {status} but has no evidence IDs."
            )

    if strict and warnings:
        raise SystemExit("Strict mode failed:\n- " + "\n- ".join(warnings))

    claim_type_counts = count_by(
        [{**item, "claim_type": normalize_claim_type(str(item.get("claim_type", "")))} for item in findings],
        "claim_type",
    )
    confidence_counts = count_by(findings, "confidence")
    window_start, window_end = evidence_time_window(evidence_items)
    confirmed_count, inconclusive_count = finding_status_counts(findings, evid_idx)
    trace_counts = {"traced": 0, "untraceable": 0, "unknown": 0}
    for item in ip_traces:
        trace_counts[normalize_trace_status(str(item.get("trace_status", "")))] += 1
    log_risk_count = sum(
        1
        for item in log_integrity
        if str(item.get("status", "")).strip().lower() in {"missing", "tampered", "suspicious"}
    )
    pending_approval = sum(
        1 for item in actions if str(item.get("approval", "")).strip().lower() not in {"approved", "yes"}
    )
    change_actions = [
        item
        for item in actions
        if str(item.get("risk_level", "")).strip().lower() in {"medium", "high", "critical"}
        or str(item.get("action", "")).strip()
    ]

    return {
        "warnings": warnings,
        "evidence_items": evidence_items,
        "findings": findings,
        "hypothesis_matrix": hypothesis_matrix,
        "ip_traces": ip_traces,
        "log_integrity": log_integrity,
        "actions": actions,
        "timeline": timeline,
        "unknowns": unknowns,
        "baseline_assessment": baseline_assessment,
        "case_validation": case_validation,
        "artifact_hashes": artifact_hashes,
        "scene_reconstruction": scene_reconstruction,
        "remote_trust": remote_trust,
        "privilege_scope": privilege_scope,
        "time_norm": time_norm,
        "workflow_history": workflow_history,
        "evid_idx": evid_idx,
        "title": str(incident.get("title", "Mining Host Investigation Report")),
        "incident_id": str(incident.get("id", "unknown-incident")),
        "generated_at": str(data.get("generated_at", now_utc())),
        "analyst": str(data.get("analyst", "unknown")),
        "host_name": str(host.get("name", "unknown")),
        "host_ip": str(host.get("ip", "unknown")),
        "mining_mode": str(host.get("mining_mode", "unknown")),
        "os_name": str(host.get("os", "unknown")),
        "summary": str(data.get("summary", "")).strip(),
        "expected_workload": str(data.get("expected_workload", "")).strip(),
        "report_timezone_basis": str(data.get("report_timezone_basis", data.get("timezone", "UTC"))).strip() or "UTC",
        "timezone_semantics": str(data.get("timezone_semantics", "Report normalization basis only; not the host local timezone.")).strip(),
        "claim_type_counts": claim_type_counts,
        "confidence_counts": confidence_counts,
        "window_start": window_start,
        "window_end": window_end,
        "confirmed_count": confirmed_count,
        "inconclusive_count": inconclusive_count,
        "trace_counts": trace_counts,
        "log_risk_count": log_risk_count,
        "pending_approval": pending_approval,
        "change_actions": change_actions,
    }
def build_report(data: dict[str, Any], redact: bool, strict: bool, case_dir: str | None = None) -> tuple[str, list[str]]:
    ctx = prepare_report_context(data, redact=redact, strict=strict, case_dir=case_dir)

    def maybe_redact(value: str) -> str:
        return sanitize_report_text(value, redact)

    host_name = maybe_redact(ctx["host_name"])
    host_ip = maybe_redact(ctx["host_ip"])
    host_display = host_name if host_name == host_ip else f"{host_name} ({host_ip})"
    summary = maybe_redact(ctx["summary"] or "Auto-collected read-only evidence snapshot. Analyst review required.")
    confidence_counts = ctx["confidence_counts"]
    claim_type_counts = ctx["claim_type_counts"]
    trace_counts = ctx["trace_counts"]
    scene_reconstruction = ctx["scene_reconstruction"]
    time_norm = ctx["time_norm"]
    remote_trust = ctx["remote_trust"]
    privilege_scope = ctx["privilege_scope"]
    workflow_history = ctx["workflow_history"]
    case_validation = ctx["case_validation"]
    baseline_assessment = ctx["baseline_assessment"]
    artifact_hashes = ctx["artifact_hashes"]
    evidence_items = ctx["evidence_items"]
    warnings = ctx["warnings"]

    lines: list[str] = [anchor_tag("report-top"), f"# {ctx['title']}", ""]
    if case_dir:
        lines.extend([
            "[Bundle Index](./reports/index.md) | [Full Report (ZH-CN)](./report.zh-CN.md) | [Management Summary](./reports/management-summary.md) | [SOC Summary](./reports/soc-summary.md)",
            "",
        ])
    lines.extend([
        "> Evidence-constrained report. Facts, inferences, and attribution are separated. Missing evidence remains inconclusive.",
        "> Evidence IDs jump to detail blocks, and each detail block links to the collected artifact file.",
        "",
    ])
    lines.extend(top_conclusion_lines(ctx, maybe_redact, case_dir=case_dir, limit=3))
    lines.extend([
        "## Quick Links",
        "- [Investigation Conclusion](#report-conclusion)",
        "- [Metadata](#report-metadata)",
        "- [Executive Snapshot](#report-executive-summary)",
        "- [Key Risks](#report-key-risks)",
        "- [Time Normalization](#report-time-normalization)",
        "- [Trust Bootstrap](#report-trust-bootstrap)",
        "- [Privilege Scope](#report-privilege-scope)",
        "- [Scene Snapshot](#report-scene-snapshot)",
        "- [Workflow Checkpoints](#report-workflow-checkpoints)",
        "- [Evidence Source Navigator](#report-evidence-source-navigator)",
        "- [Evidence Index](#report-evidence-index)",
        "- [Hypothesis Matrix](#report-hypothesis-matrix)",
        "- [Findings](#report-findings)",
        "- [Timeline](#report-timeline)",
        "- [IP Traceability](#report-ip-traceability)",
        "- [Log Integrity](#report-log-integrity)",
        "- [Action Log](#report-action-log)",
        "- [Evidence Details](#report-evidence-details)",
        "- [Unknowns](#report-unknowns)",
        "- [Validation](#report-validation)",
        "",
        anchor_tag("report-metadata"),
        "## Metadata",
        f"- **Incident ID:** `{ctx['incident_id']}`",
        f"- **Case ID:** `{data.get('case_id', 'unknown')}`",
        f"- **Host ID:** `{data.get('host_id', 'unknown')}`",
        f"- **Host:** `{host_display}`",
        f"- **OS:** `{maybe_redact(ctx['os_name'])}`",
        f"- **Mining Mode:** `{maybe_redact(ctx['mining_mode'])}`",
        f"- **Generated At (UTC):** `{ctx['generated_at']}`",
        f"- **Analyst:** `{maybe_redact(ctx['analyst'])}`",
        f"- **Collector Version:** `{maybe_redact(str(data.get('collector_version', 'unknown')))}`",
        f"- **Collection Summary:** {summary}",
        "",
        anchor_tag("report-executive-summary"),
        "## Executive Snapshot",
        f"- **Evidence Items:** `{len(evidence_items)}`",
        f"- **Observation Window (UTC):** `{ctx['window_start']}` -> `{ctx['window_end']}`",
        f"- **Findings:** `{ctx['confirmed_count']}` confirmed, `{ctx['inconclusive_count']}` inconclusive",
        f"- **Traceability:** `{trace_counts['traced']}` traced, `{trace_counts['untraceable']}` untraceable, `{trace_counts['unknown']}` unknown",
        f"- **Log Integrity Risks:** `{ctx['log_risk_count']}` artifact(s)",
        f"- **Action Records:** `{len(ctx['actions'])}` total, `{len(ctx['change_actions'])}` potentially impactful, `{ctx['pending_approval']}` pending approval",
        f"- **Claim Mix:** observed_fact `{claim_type_counts.get('observed_fact', 0)}`, inference `{claim_type_counts.get('inference', 0)}`, attribution `{claim_type_counts.get('attribution', 0)}`",
        f"- **Confidence Mix:** {confidence_icon('high')} high `{confidence_counts.get('high', 0)}`, {confidence_icon('medium')} medium `{confidence_counts.get('medium', 0)}`, {confidence_icon('low')} low `{confidence_counts.get('low', 0)}`, {confidence_icon('unknown')} unknown `{confidence_counts.get('unknown', 0)}`",
        f"- **Expected Workload:** {maybe_redact(ctx['expected_workload'] or 'not provided')}",
        f"- **Artifact Hash Catalog:** `{artifact_hashes.get('count', len(evidence_items))}` item(s), algorithm `{artifact_hashes.get('algorithm', 'unknown')}`",
        "",
        anchor_tag("report-key-risks"),
        "## Key Risks",
    ])
    lines.extend(key_risk_lines(data, case_dir=case_dir))
    lines.extend([
        "",
        anchor_tag("report-time-normalization"),
        "## Time Normalization",
        f"- **Report Normalization Timezone:** `{maybe_redact(ctx['report_timezone_basis'])}`",
        f"- **Host Reported Timezone:** `{maybe_redact(str(time_norm.get('host_reported_timezone', 'unknown')))}`",
        f"- **Host NTP Synchronized:** `{maybe_redact(str(time_norm.get('host_ntp_synchronized', 'unknown')))}`",
        f"- **Event Time Field:** `{maybe_redact(str(time_norm.get('event_time_field', 'unknown')))}`",
        f"- **Clock Offset Assessment:** `{maybe_redact(str(time_norm.get('clock_offset_assessment', 'unknown')))}`",
        f"- **Timezone Semantics:** {maybe_redact(ctx['timezone_semantics'])}",
        "",
        anchor_tag("report-trust-bootstrap"),
        "## Trust Bootstrap",
    ])
    if remote_trust:
        lines.extend([
            f"- **Status:** `{maybe_redact(str(remote_trust.get('status', 'unknown')))}`",
            f"- **Mode:** `{maybe_redact(str(remote_trust.get('mode', 'unknown')))}`",
            f"- **Verification Source:** `{maybe_redact(str(remote_trust.get('verification_source', 'unknown')))}`",
            f"- **Verified Host Key Fingerprint:** `{maybe_redact(str(remote_trust.get('host_key_fingerprint', 'unknown')))}`",
            f"- **Known-Hosts Source:** `{maybe_redact(str(remote_trust.get('known_hosts_path', 'unknown')))}`",
        ])
    else:
        lines.append("- No remote trust metadata was recorded.")
    lines.extend([
        "",
        anchor_tag("report-privilege-scope"),
        "## Privilege Scope",
        f"- **Observed User:** `{maybe_redact(str(privilege_scope.get('user', 'unknown')))}`",
        f"- **Observed UID:** `{maybe_redact(str(privilege_scope.get('uid', 'unknown')))}`",
        f"- **Passwordless Sudo Visible:** `{maybe_redact(str(privilege_scope.get('passwordless_sudo_visible', 'unknown')))}`",
        "- **Interpretation:** Limited visibility means absence of a deeper indicator cannot be treated as proof of absence.",
        "",
        anchor_tag("report-scene-snapshot"),
        "## Scene Snapshot",
        f"- **Auth Source IP Count:** `{len(as_list(scene_reconstruction.get('auth_source_ips')))}`",
        f"- **Listening Port Count:** `{len(as_list(scene_reconstruction.get('listening_ports')))}`",
        f"- **Process IOC Hit Count:** `{scene_reconstruction.get('process_ioc_match_count', 0)}`",
        f"- **Top-CPU Process Count:** `{scene_reconstruction.get('top_cpu_process_count', 0)}`",
        f"- **Top-CPU Miner-Keyword Hit Count:** `{scene_reconstruction.get('top_cpu_process_keyword_hit_count', 0)}`",
        f"- **Network IOC Hit Count:** `{scene_reconstruction.get('network_ioc_hit_count', 0)}`",
        f"- **Initial-Access Review Hit Count:** `{scene_reconstruction.get('initial_access_review_hit_count', 0)}`",
        f"- **Container / Cloud Review Hit Count:** `{scene_reconstruction.get('container_cloud_review_hit_count', 0)}`",
        f"- **Kernel / eBPF Review Hit Count:** `{scene_reconstruction.get('kernel_review_hit_count', 0)}`",
        f"- **Runtime Profile Count:** `{scene_reconstruction.get('runtime_profile_count', 0)}`",
        f"- **Cron Runtime Candidate Count:** `{scene_reconstruction.get('cron_runtime_candidate_count', 0)}`",
        f"- **Command Fallback Marker Count:** `{scene_reconstruction.get('command_fallback_marker_count', 0)}`",
        f"- **GPU Probe Count:** `{len(as_list(scene_reconstruction.get('gpu_probe_ids')))}`",
        f"- **GPU Peak Utilization:** `{scene_reconstruction.get('gpu_peak_utilization_percent', 0)}%`",
        f"- **GPU Compute Process Count:** `{scene_reconstruction.get('gpu_compute_process_count', 0)}`",
        f"- **GPU Suspicious Process Count:** `{scene_reconstruction.get('gpu_suspicious_process_count', 0)}`",
        "",
    ])
    append_sample_section(lines, "Auth Source IPs", as_list(scene_reconstruction.get("auth_source_ips")), maybe_redact, limit=12)
    append_sample_section(lines, "Listening Ports", as_list(scene_reconstruction.get("listening_ports")), maybe_redact, limit=12)
    append_sample_section(lines, "Process IOC Samples", as_list(scene_reconstruction.get("process_ioc_samples")), maybe_redact, limit=8)
    append_sample_section(lines, "Top CPU Process Samples", render_top_process_samples([as_dict(x) for x in as_list(scene_reconstruction.get("top_cpu_processes"))]), maybe_redact, limit=8)
    append_sample_section(lines, "Runtime Profile Samples", render_runtime_profile_samples([as_dict(x) for x in as_list(scene_reconstruction.get("runtime_profiles"))]), maybe_redact, limit=8)
    append_sample_section(lines, "Cron Runtime Candidate Samples", render_runtime_profile_samples([as_dict(x) for x in as_list(scene_reconstruction.get("cron_runtime_candidates"))]), maybe_redact, limit=8)
    append_sample_section(lines, "Network IOC Samples", as_list(scene_reconstruction.get("network_ioc_samples")), maybe_redact, limit=8)
    append_sample_section(lines, "Initial-Access Review Samples", as_list(scene_reconstruction.get("initial_access_review_samples")), maybe_redact, limit=10)
    append_sample_section(lines, "Container / Cloud Review Samples", as_list(scene_reconstruction.get("container_cloud_review_samples")), maybe_redact, limit=10)
    append_sample_section(lines, "Kernel / eBPF Review Samples", as_list(scene_reconstruction.get("kernel_review_samples")), maybe_redact, limit=10)
    append_sample_section(lines, "GPU Adapter Samples", as_list(scene_reconstruction.get("gpu_adapter_samples")), maybe_redact, limit=8)
    append_sample_section(lines, "GPU Compute Process Samples", as_list(scene_reconstruction.get("gpu_compute_process_samples")), maybe_redact, limit=8)
    append_sample_section(lines, "GPU Suspicious Process Samples", as_list(scene_reconstruction.get("gpu_suspicious_process_samples")), maybe_redact, limit=8)
    lines.extend([
        "",
        "## Coverage and False-Positive Control",
        "- **Policy:** High CPU or GPU usage remains inconclusive unless expected workload, baseline, and runtime evidence align.",
        "- **Scope:** Initial access review includes weak credentials, SSH key surfaces, PAM, sudoers, preload, and related access paths.",
        "- **Traceability:** Untraceable or unknown IPs remain explicitly labeled; no actor attribution is implied.",
        f"- **Expected Workload:** {maybe_redact(ctx['expected_workload'] or 'not provided')}",
        f"- **Bundle Validation:** `{case_validation.get('ok', 'unknown')}`",
    ])
    if baseline_assessment:
        lines.append(f"- **Baseline Assessment:** `{maybe_redact(str(baseline_assessment.get('assessment_status', 'unknown')))}`")
    lines.append("")
    render_hypothesis_matrix_section(
        lines,
        ctx["hypothesis_matrix"],
        ctx["evid_idx"],
        case_dir,
        maybe_redact,
    )

    append_checkpoint_section(lines, anchor_tag("report-workflow-checkpoints") + "\n## Workflow Checkpoints", workflow_history, maybe_redact, limit=12)

    lines.append(anchor_tag("report-evidence-source-navigator"))
    lines.append("## Evidence Source Navigator")
    lines.extend(evidence_source_nav_lines(evidence_items, prefix="report-evidence-source"))
    lines.append("")

    lines.append(anchor_tag("report-evidence-index"))
    lines.append("## Evidence Index")
    if evidence_items:
        for source, items in evidence_source_groups(evidence_items):
            lines.append(anchor_tag(f"report-evidence-source-{anchor_slug(source)}"))
            lines.append(f"### Source: `{source}`")
            rows = []
            for item in items:
                evidence_id = str(item.get("id", "unknown"))
                artifact_path = str(item.get("artifact", "")).strip()
                artifact_name = Path(artifact_path).name if artifact_path else "artifact"
                artifact_cell = f"[{artifact_name}]({artifact_href(item, case_dir)})" if artifact_path else "-"
                rows.append([
                    f"[{evidence_id}](#{evidence_anchor(evidence_id)})",
                    str(item.get("observed_at", "unknown")),
                    maybe_redact(compact_text(str(item.get("command", "")), max_len=84)),
                    artifact_cell,
                    "timeout" if bool(item.get("timed_out")) else "-",
                ])
            lines.append(render_table(["Evidence", "Observed At", "Command Preview", "Artifact", "Flag"], rows))
            lines.append("")
    else:
        lines.append("No evidence items were provided.")
        lines.append("")

    lines.append(anchor_tag("report-findings"))
    lines.append("## Findings")
    if ctx["findings"]:
        for item in ctx["findings"]:
            status = finding_status(item, ctx["evid_idx"])
            lines.extend([
                f"### {status_icon(status)} {item.get('id', 'unknown')}",
                f"- **Statement:** {maybe_redact(str(item.get('statement', '')) or 'Not provided.')}",
                f"- **Claim Type:** `{claim_type_label(str(item.get('claim_type', '')))}`",
                f"- **Hypothesis:** `{maybe_redact(str(item.get('hypothesis_id', '-') or '-'))}`",
                f"- **Confidence:** {confidence_icon(str(item.get('confidence', 'unknown')))} `{maybe_redact(str(item.get('confidence', 'unknown')))}`",
                f"- **Status:** `{status}`",
                f"- **Confidence Reason:** {maybe_redact(str(item.get('confidence_reason', '-') or '-'))}",
                f"- **Evidence Chain:** {evidence_reference_list(as_list(item.get('evidence_ids')), ctx['evid_idx'], case_dir)}",
                "",
            ])
    else:
        lines.extend(["No findings were provided.", ""])

    lines.append(anchor_tag("report-timeline"))
    lines.append("## Timeline")
    if ctx["timeline"]:
        for index, item in enumerate(ctx["timeline"], start=1):
            lines.extend([
                f"### Event {index}",
                f"- **Original Time:** `{maybe_redact(str(item.get('time', 'unknown')))}`",
                f"- **Normalized UTC:** `{maybe_redact(str(item.get('normalized_time_utc', 'unknown')))}`",
                f"- **Event:** {maybe_redact(str(item.get('event', '')) or 'Not provided.')}",
                f"- **Source:** `{maybe_redact(str(item.get('source', 'unknown')))}`",
                f"- **Evidence Chain:** {evidence_reference_list(as_list(item.get('evidence_ids')), ctx['evid_idx'], case_dir)}",
                "",
            ])
    else:
        lines.extend(["No timeline entries were provided.", ""])

    lines.append(anchor_tag("report-ip-traceability"))
    lines.append("## IP Traceability")
    if ctx["ip_traces"]:
        for item in ctx["ip_traces"]:
            status = str(item.get("trace_status", "unknown"))
            lines.extend([
                f"### {status_icon(status)} {maybe_redact(str(item.get('ip', 'unknown')))}",
                f"- **Role:** `{maybe_redact(str(item.get('role', 'unknown')))}`",
                f"- **Trace Status:** `{status}`",
                f"- **Reason:** {maybe_redact(str(item.get('reason', 'not provided')))}",
                f"- **Evidence Chain:** {evidence_reference_list(as_list(item.get('evidence_ids')), ctx['evid_idx'], case_dir)}",
                "",
            ])
        if any(str(item.get("trace_status", "")) != "traced" for item in ctx["ip_traces"]):
            lines.extend([
                "- Untraceable or unknown IP entries are preserved as-is; no attribution is inferred beyond the evidence.",
                "",
            ])
    else:
        lines.extend(["No IP trace entries were provided.", ""])

    lines.append(anchor_tag("report-log-integrity"))
    lines.append("## Log Integrity")
    if ctx["log_integrity"]:
        for item in ctx["log_integrity"]:
            status = str(item.get("status", "unknown"))
            icon = "??" if status.lower() in {"missing", "tampered", "suspicious"} else "?"
            lines.extend([
                f"### {icon} {maybe_redact(str(item.get('artifact', 'unknown')))}",
                f"- **Status:** `{status}`",
                f"- **Reason:** {maybe_redact(str(item.get('reason', '-')) or '-')}",
                f"- **Evidence Chain:** {evidence_reference_list(as_list(item.get('evidence_ids')), ctx['evid_idx'], case_dir)}",
                "",
            ])
        if any(str(item.get("status", "")).lower() in {"missing", "tampered"} for item in ctx["log_integrity"]):
            lines.extend([
                "- Attribution confidence must be reduced where primary logs are missing or appear tampered.",
                "",
            ])
    else:
        lines.extend(["No log-integrity entries were provided.", ""])

    lines.append(anchor_tag("report-action-log"))
    lines.append("## Actions and Approval Log")
    if ctx["actions"]:
        for index, item in enumerate(ctx["actions"], start=1):
            lines.extend([
                f"### Action {index}",
                f"- **Time:** `{maybe_redact(str(item.get('time', 'unknown')))}`",
                f"- **Action:** {maybe_redact(str(item.get('action', '')) or 'Not provided.')}",
                f"- **Risk Level:** `{maybe_redact(str(item.get('risk_level', 'unknown')))}`",
                f"- **Approval:** `{maybe_redact(str(item.get('approval', 'missing')))}`",
                f"- **Result:** {maybe_redact(str(item.get('result', '-')) or '-')}",
                "",
            ])
    else:
        lines.extend(["No action log was provided.", ""])

    lines.append(anchor_tag("report-evidence-details"))
    lines.append("## Evidence Details")
    if evidence_items:
        for item in evidence_items:
            evidence_id = str(item.get("id", "unknown"))
            artifact_path = str(item.get("artifact", "")).strip()
            artifact_name = Path(artifact_path).name if artifact_path else "artifact"
            href = artifact_href(item, case_dir)
            lines.append(f'<a id="{evidence_anchor(evidence_id)}"></a>')
            lines.append("<details>")
            lines.append(
                f"<summary><strong>{evidence_id}</strong> ? {maybe_redact(str(item.get('source', 'unknown')))} ? {maybe_redact(str(item.get('observed_at', 'unknown')))} ? {maybe_redact(compact_text(str(item.get('command', '')), max_len=96))}</summary>"
            )
            lines.extend([
                "",
                f"- **Source:** `{maybe_redact(str(item.get('source', 'unknown')))}`",
                f"- **Observed At:** `{maybe_redact(str(item.get('observed_at', 'unknown')))}`",
                f"- **Command Hash:** `{maybe_redact(str(item.get('command_hash', 'unknown')))}`",
                f"- **Artifact Hash:** `{maybe_redact(str(item.get('artifact_hash', 'unknown')))}`",
                f"- **Artifact Size:** `{bytes_label(item.get('artifact_size_bytes'))}`",
                f"- **Timed Out:** `{yes_no(item.get('timed_out'))}`",
            ])
            if href:
                lines.append(f"- **Artifact File:** [{artifact_name}]({href})")
            if artifact_path:
                lines.append(f"- **Artifact Path:** `{maybe_redact(artifact_path)}`")
            lines.append("- **Navigation:** [Back to Evidence Source Navigator](#report-evidence-source-navigator) | [Back to Evidence Index](#report-evidence-index) | [Back to Top](#report-top) | [Bundle Index](./reports/index.md) | [Full Report (ZH-CN)](./report.zh-CN.md)")
            lines.extend([
                "",
                "**Command**",
                "```bash",
                maybe_redact(str(item.get("command", "")).strip() or "# command unavailable"),
                "```",
                "",
                "</details>",
                "",
            ])
    else:
        lines.extend(["No evidence detail blocks were generated.", ""])

    lines.append(anchor_tag("report-unknowns"))
    lines.append("## Unknowns and Gaps")
    if ctx["unknowns"]:
        for item in ctx["unknowns"]:
            lines.append(f"- {maybe_redact(str(item))}")
    else:
        lines.append("- None provided.")
    lines.append("")

    lines.append(anchor_tag("report-validation"))
    lines.append("## Validation Warnings")
    if warnings:
        for warning in warnings:
            lines.append(f"- {maybe_redact(warning)}")
    else:
        lines.append("- None.")
    if as_list(case_validation.get("checks")):
        lines.extend(["", "### Bundle Checks"])
        for item in as_list(case_validation.get("checks")):
            check = as_dict(item)
            lines.append(
                f"- `{'ok' if check.get('ok') else 'fail'}` `{maybe_redact(str(check.get('check', 'unknown')))}` -> `{maybe_redact(str(check.get('path', 'unknown')))}`"
            )
    lines.extend(["", "## Footer", "- [Back to Top](#report-top) | [Bundle Index](./reports/index.md) | [Full Report (ZH-CN)](./report.zh-CN.md) | [Management Summary](./reports/management-summary.md) | [SOC Summary](./reports/soc-summary.md)", ""])
    return "\n".join(lines).strip() + "\n", warnings



def build_report_zh_cn(data: dict[str, Any], redact: bool, strict: bool, case_dir: str | None = None) -> tuple[str, list[str]]:
    ctx = prepare_report_context(data, redact=redact, strict=strict, case_dir=case_dir)

    def maybe_redact(value: str) -> str:
        return sanitize_report_text(value, redact)

    def maybe_redact_zh(value: str) -> str:
        return zh_report_text(value, redact)

    def zh_evidence_refs(values: list[Any]) -> str:
        return evidence_reference_list_zh_cn(values, ctx["evid_idx"], case_dir).replace("](#evidence-", "](./report.zh-CN.md#evidence-")

    def claim_type_label_zh_cn(value: str) -> str:
        return {
            "observed_fact": "观测事实",
            "inference": "推断",
            "attribution": "归因",
        }.get(normalize_claim_type(value), "推断")

    def status_label_zh_cn(value: str) -> str:
        return {
            "confirmed": "已确认",
            "inconclusive": "待定",
            "traced": "已溯源",
            "untraceable": "未溯源",
            "unknown": "未知",
            "missing": "缺失",
            "tampered": "疑似篡改",
            "suspicious": "可疑",
        }.get(str(value).strip().lower(), str(value).strip() or "未知")

    def confidence_label_zh_cn(value: str) -> str:
        return {
            "high": "高",
            "medium": "中",
            "low": "低",
            "unknown": "未知",
        }.get(str(value).strip().lower(), str(value).strip() or "未知")

    def yes_no_zh_cn(value: Any) -> str:
        return "是" if bool(value) else "否"

    def bytes_label_zh_cn(value: Any) -> str:
        try:
            size = int(value)
        except (TypeError, ValueError):
            return "未知"
        return f"{size} 字节"

    def append_sample_section_zh_cn(lines: list[str], heading: str, items: list[Any], limit: int = 8) -> None:
        lines.append(f"### {heading}")
        if items:
            for item in items[:limit]:
                lines.append(f"- {maybe_redact(compact_text(item, max_len=220))}")
            if len(items) > limit:
                lines.append(f"- ...（其余 {len(items) - limit} 项请查看原始产物）")
        else:
            lines.append("- 无。")
        lines.append("")

    def append_checkpoint_section_zh_cn(lines: list[str], history: list[dict[str, Any]], limit: int = 12) -> None:
        lines.extend([anchor_tag("report-workflow-checkpoints"), "## 流程检查点", ""])
        if history:
            for item in history[:limit]:
                extra = as_dict(item.get("extra"))
                extra_parts = [
                    f"{key}={compact_text(maybe_redact(str(value)), max_len=64)}"
                    for key, value in extra.items()
                ]
                suffix = f" | 附加信息：{'；'.join(extra_parts[:3])}" if extra_parts else ""
                note = str(item.get("note", "")).strip()
                note_text = f" | 说明：{maybe_redact(compact_text(note, max_len=96))}" if note else ""
                lines.append(
                    f"- `{item.get('time_utc', 'unknown')}` | `{item.get('stage', 'unknown')}` | `{item.get('status', 'unknown')}`{note_text}{suffix}"
                )
            if len(history) > limit:
                lines.append(f"- ...（其余 {len(history) - limit} 项已省略）")
        else:
            lines.append("- 未记录流程检查点。")
        lines.append("")

    host_name = maybe_redact(ctx["host_name"])
    host_ip = maybe_redact(ctx["host_ip"])
    host_display = host_name if host_name == host_ip else f"{host_name} ({host_ip})"
    summary = maybe_redact_zh(ctx["summary"] or "自动采集的只读证据快照，仍需分析人员复核。")
    confidence_counts = ctx["confidence_counts"]
    claim_type_counts = ctx["claim_type_counts"]
    trace_counts = ctx["trace_counts"]
    scene_reconstruction = ctx["scene_reconstruction"]
    time_norm = ctx["time_norm"]
    remote_trust = ctx["remote_trust"]
    privilege_scope = ctx["privilege_scope"]
    workflow_history = ctx["workflow_history"]
    case_validation = ctx["case_validation"]
    baseline_assessment = ctx["baseline_assessment"]
    artifact_hashes = ctx["artifact_hashes"]
    evidence_items = ctx["evidence_items"]
    warnings = ctx["warnings"]

    lines: list[str] = [anchor_tag("report-top"), f"# {ctx['title']} - 中文全量报告", ""]
    if case_dir:
        lines.extend([
            "[案件索引](./reports/index.zh-CN.md) | [英文全量报告](./report.md) | [管理摘要](./reports/management-summary.zh-CN.md) | [SOC 摘要](./reports/soc-summary.zh-CN.md)",
            "",
        ])
    lines.extend([
        "> 本报告严格受证据约束：观测事实、推断和归因分开展示；证据不足时保持待定。",
        "> 所有证据 ID 都可跳转到详细证据块，每个证据块都链接到实际采集产物。",
        "",
    ])
    lines.extend(top_conclusion_lines_zh_cn(ctx, maybe_redact, case_dir=case_dir, limit=3))
    lines.extend([
        "## 快速链接",
        "- [核心结论](#report-conclusion)",
        "- [元数据](#report-metadata)",
        "- [执行摘要](#report-executive-summary)",
        "- [关键风险](#report-key-risks)",
        "- [时间归一化](#report-time-normalization)",
        "- [信任引导](#report-trust-bootstrap)",
        "- [权限范围](#report-privilege-scope)",
        "- [现场快照](#report-scene-snapshot)",
        "- [流程检查点](#report-workflow-checkpoints)",
        "- [证据来源导航](#report-evidence-source-navigator)",
        "- [证据索引](#report-evidence-index)",
        "- [假设-证据关联矩阵](#report-hypothesis-matrix)",
        "- [结论与研判](#report-findings)",
        "- [时间线](#report-timeline)",
        "- [IP 溯源](#report-ip-traceability)",
        "- [日志完整性](#report-log-integrity)",
        "- [动作记录](#report-action-log)",
        "- [证据详情](#report-evidence-details)",
        "- [未知项与缺口](#report-unknowns)",
        "- [校验告警](#report-validation)",
        "",
        anchor_tag("report-metadata"),
        "## 元数据",
        f"- **事件 ID：** `{ctx['incident_id']}`",
        f"- **案件 ID：** `{data.get('case_id', 'unknown')}`",
        f"- **主机 ID：** `{data.get('host_id', 'unknown')}`",
        f"- **主机：** `{host_display}`",
        f"- **操作系统：** `{maybe_redact(ctx['os_name'])}`",
        f"- **挖矿模式：** `{maybe_redact(ctx['mining_mode'])}`",
        f"- **生成时间（UTC）：** `{ctx['generated_at']}`",
        f"- **分析者：** `{maybe_redact(ctx['analyst'])}`",
        f"- **采集器版本：** `{maybe_redact(str(data.get('collector_version', 'unknown')))}`",
        f"- **采集摘要：** {summary}",
        "",
        anchor_tag("report-executive-summary"),
        "## 执行摘要",
        f"- **证据项数量：** `{len(evidence_items)}`",
        f"- **观察窗口（UTC）：** `{ctx['window_start']}` -> `{ctx['window_end']}`",
        f"- **结论状态：** `{ctx['confirmed_count']}` 条已确认，`{ctx['inconclusive_count']}` 条待定",
        f"- **溯源状态：** `{trace_counts['traced']}` 条已溯源，`{trace_counts['untraceable']}` 条未溯源，`{trace_counts['unknown']}` 条未知",
        f"- **日志完整性风险：** `{ctx['log_risk_count']}` 项",
        f"- **动作记录：** 共 `{len(ctx['actions'])}` 条，其中 `{len(ctx['change_actions'])}` 条可能影响业务，`{ctx['pending_approval']}` 条待审批",
        f"- **结论类型分布：** 观测事实 `{claim_type_counts.get('observed_fact', 0)}`，推断 `{claim_type_counts.get('inference', 0)}`，归因 `{claim_type_counts.get('attribution', 0)}`",
        f"- **置信度分布：** {confidence_icon('high')} 高 `{confidence_counts.get('high', 0)}`，{confidence_icon('medium')} 中 `{confidence_counts.get('medium', 0)}`，{confidence_icon('low')} 低 `{confidence_counts.get('low', 0)}`，{confidence_icon('unknown')} 未知 `{confidence_counts.get('unknown', 0)}`",
        f"- **预期工作负载：** {maybe_redact(ctx['expected_workload'] or '未提供')}",
        f"- **产物哈希目录：** `{artifact_hashes.get('count', len(evidence_items))}` 项，算法 `{artifact_hashes.get('algorithm', 'unknown')}`",
        "",
        anchor_tag("report-key-risks"),
        "## 关键风险",
    ])
    lines.extend(key_risk_lines_zh_cn(data, case_dir=case_dir))
    lines.extend([
        "",
        anchor_tag("report-time-normalization"),
        "## 时间归一化",
        f"- **报告归一化时区：** `{maybe_redact(ctx['report_timezone_basis'])}`",
        f"- **主机报告时区：** `{maybe_redact(str(time_norm.get('host_reported_timezone', 'unknown')))}`",
        f"- **主机 NTP 同步：** `{maybe_redact_zh(str(time_norm.get('host_ntp_synchronized', 'unknown')))}`",
        f"- **事件时间字段：** `{maybe_redact(str(time_norm.get('event_time_field', 'unknown')))}`",
        f"- **时钟偏差评估：** `{maybe_redact(str(time_norm.get('clock_offset_assessment', 'unknown')))}`",
        f"- **时区语义说明：** {maybe_redact_zh(ctx['timezone_semantics'])}",
        "",
        anchor_tag("report-trust-bootstrap"),
        "## 信任引导",
    ])
    if remote_trust:
        lines.extend([
            f"- **状态：** `{maybe_redact(str(remote_trust.get('status', 'unknown')))}`",
            f"- **模式：** `{maybe_redact(str(remote_trust.get('mode', 'unknown')))}`",
            f"- **校验来源：** `{maybe_redact(str(remote_trust.get('verification_source', 'unknown')))}`",
            f"- **已验证主机指纹：** `{maybe_redact(str(remote_trust.get('host_key_fingerprint', 'unknown')))}`",
            f"- **known_hosts 来源：** `{maybe_redact(str(remote_trust.get('known_hosts_path', 'unknown')))}`",
        ])
    else:
        lines.append("- 未记录远程信任元数据。")
    lines.extend([
        "",
        anchor_tag("report-privilege-scope"),
        "## 权限范围",
        f"- **当前用户：** `{maybe_redact(str(privilege_scope.get('user', 'unknown')))}`",
        f"- **当前 UID：** `{maybe_redact(str(privilege_scope.get('uid', 'unknown')))}`",
        f"- **是否可见免密 sudo：** `{maybe_redact_zh(str(privilege_scope.get('passwordless_sudo_visible', 'unknown')))}`",
        "- **解释：** 若当前权限受限，则未观察到更深层指标不能视为其不存在。",
        "",
        anchor_tag("report-scene-snapshot"),
        "## 现场快照",
        f"- **认证来源 IP 数量：** `{len(as_list(scene_reconstruction.get('auth_source_ips')))}`",
        f"- **监听端口数量：** `{len(as_list(scene_reconstruction.get('listening_ports')))}`",
        f"- **进程 IOC 命中数：** `{scene_reconstruction.get('process_ioc_match_count', 0)}`",
        f"- **高 CPU 进程数量：** `{scene_reconstruction.get('top_cpu_process_count', 0)}`",
        f"- **高 CPU 进程矿工关键字命中数：** `{scene_reconstruction.get('top_cpu_process_keyword_hit_count', 0)}`",
        f"- **网络 IOC 命中数：** `{scene_reconstruction.get('network_ioc_hit_count', 0)}`",
        f"- **初始访问复核命中数：** `{scene_reconstruction.get('initial_access_review_hit_count', 0)}`",
        f"- **容器 / 云侧复核命中数：** `{scene_reconstruction.get('container_cloud_review_hit_count', 0)}`",
        f"- **内核 / eBPF 复核命中数：** `{scene_reconstruction.get('kernel_review_hit_count', 0)}`",
        f"- **运行参数画像数量：** `{scene_reconstruction.get('runtime_profile_count', 0)}`",
        f"- **定时任务运行候选数量：** `{scene_reconstruction.get('cron_runtime_candidate_count', 0)}`",
        f"- **命令降级标记数量：** `{scene_reconstruction.get('command_fallback_marker_count', 0)}`",
        f"- **GPU 探针数量：** `{len(as_list(scene_reconstruction.get('gpu_probe_ids')))}`",
        f"- **GPU 峰值利用率：** `{scene_reconstruction.get('gpu_peak_utilization_percent', 0)}%`",
        f"- **GPU 计算进程数量：** `{scene_reconstruction.get('gpu_compute_process_count', 0)}`",
        f"- **GPU 可疑进程数量：** `{scene_reconstruction.get('gpu_suspicious_process_count', 0)}`",
        "",
    ])
    append_sample_section_zh_cn(lines, "认证来源 IP", as_list(scene_reconstruction.get("auth_source_ips")), limit=12)
    append_sample_section_zh_cn(lines, "监听端口", as_list(scene_reconstruction.get("listening_ports")), limit=12)
    append_sample_section_zh_cn(lines, "进程 IOC 样本", as_list(scene_reconstruction.get("process_ioc_samples")), limit=8)
    append_sample_section_zh_cn(lines, "高 CPU 进程样本", render_top_process_samples([as_dict(x) for x in as_list(scene_reconstruction.get("top_cpu_processes"))]), limit=8)
    append_sample_section_zh_cn(lines, "运行参数画像样本", render_runtime_profile_samples([as_dict(x) for x in as_list(scene_reconstruction.get("runtime_profiles"))]), limit=8)
    append_sample_section_zh_cn(lines, "定时任务运行候选样本", render_runtime_profile_samples([as_dict(x) for x in as_list(scene_reconstruction.get("cron_runtime_candidates"))]), limit=8)
    append_sample_section_zh_cn(lines, "网络 IOC 样本", as_list(scene_reconstruction.get("network_ioc_samples")), limit=8)
    append_sample_section_zh_cn(lines, "初始访问复核样本", as_list(scene_reconstruction.get("initial_access_review_samples")), limit=10)
    append_sample_section_zh_cn(lines, "容器 / 云侧复核样本", as_list(scene_reconstruction.get("container_cloud_review_samples")), limit=10)
    append_sample_section_zh_cn(lines, "内核 / eBPF 复核样本", as_list(scene_reconstruction.get("kernel_review_samples")), limit=10)
    append_sample_section_zh_cn(lines, "GPU 适配器样本", as_list(scene_reconstruction.get("gpu_adapter_samples")), limit=8)
    append_sample_section_zh_cn(lines, "GPU 计算进程样本", as_list(scene_reconstruction.get("gpu_compute_process_samples")), limit=8)
    append_sample_section_zh_cn(lines, "GPU 可疑进程样本", as_list(scene_reconstruction.get("gpu_suspicious_process_samples")), limit=8)

    lines.extend([
        "## 覆盖范围与误报控制",
        "- **策略：** 仅出现高 CPU / GPU 占用时，如无法同时满足预期负载、基线和运行时证据，结论保持待定。",
        "- **覆盖：** 初始访问复核覆盖弱口令、SSH 密钥面、PAM、sudoers、preload 等常见入口。",
        "- **溯源：** 对未溯源或未知 IP 仅如实记录，不延伸出超出证据的攻击者归因。",
        f"- **预期工作负载：** {maybe_redact(ctx['expected_workload'] or '未提供')}",
        f"- **案件包校验：** `{case_validation.get('ok', 'unknown')}`",
    ])
    if baseline_assessment:
        lines.append(f"- **基线评估：** `{maybe_redact(str(baseline_assessment.get('assessment_status', 'unknown')))}`")
    lines.append("")

    render_hypothesis_matrix_section_zh_cn(
        lines,
        ctx["hypothesis_matrix"],
        ctx["evid_idx"],
        case_dir,
        maybe_redact,
    )

    append_checkpoint_section_zh_cn(lines, workflow_history, limit=12)

    lines.append(anchor_tag("report-evidence-source-navigator"))
    lines.append("## 证据来源导航")
    groups = evidence_source_groups(evidence_items)
    if groups:
        for source, items in groups:
            lines.append(f"- [{source}](#report-evidence-source-{anchor_slug(source)})（`{len(items)}` 项）")
    else:
        lines.append("- 暂无证据来源。")
    lines.append("")

    lines.append(anchor_tag("report-evidence-index"))
    lines.append("## 证据索引")
    if evidence_items:
        for source, items in groups:
            lines.append(anchor_tag(f"report-evidence-source-{anchor_slug(source)}"))
            lines.append(f"### 来源：`{source}`")
            rows = []
            for item in items:
                evidence_id = str(item.get("id", "unknown"))
                artifact_path = str(item.get("artifact", "")).strip()
                artifact_name = Path(artifact_path).name if artifact_path else "artifact"
                artifact_cell = f"[{artifact_name}]({artifact_href(item, case_dir)})" if artifact_path else "-"
                rows.append([
                    f"[{evidence_id}](#{evidence_anchor(evidence_id)})",
                    str(item.get("observed_at", "unknown")),
                    maybe_redact(compact_text(str(item.get("command", "")), max_len=84)),
                    artifact_cell,
                    "超时" if bool(item.get("timed_out")) else "-",
                ])
            lines.append(render_table(["证据ID", "采集时间", "命令预览", "产物", "标记"], rows))
            lines.append("")
    else:
        lines.extend(["未提供证据项。", ""])

    lines.append(anchor_tag("report-findings"))
    lines.append("## 结论与研判")
    if ctx["findings"]:
        for item in ctx["findings"]:
            status = finding_status(item, ctx["evid_idx"])
            lines.extend([
                f"### {status_icon(status)} {item.get('id', 'unknown')}",
                f"- **表述：** {maybe_redact_zh(str(item.get('statement', '')) or '未提供。')}",
                f"- **结论类型：** `{claim_type_label_zh_cn(str(item.get('claim_type', '')))}`",
                f"- **假设编号：** `{maybe_redact(str(item.get('hypothesis_id', '-') or '-'))}`",
                f"- **置信度：** {confidence_icon(str(item.get('confidence', 'unknown')))} `{confidence_label_zh_cn(str(item.get('confidence', 'unknown')))}`",
                f"- **状态：** `{status_label_zh_cn(status)}`",
                f"- **置信度理由：** {maybe_redact_zh(str(item.get('confidence_reason', '-') or '-'))}",
                f"- **证据链：** {zh_evidence_refs(as_list(item.get('evidence_ids')))}",
                "",
            ])
    else:
        lines.extend(["未提供结论项。", ""])

    lines.append(anchor_tag("report-timeline"))
    lines.append("## 时间线")
    if ctx["timeline"]:
        for index, item in enumerate(ctx["timeline"], start=1):
            lines.extend([
                f"### 事件 {index}",
                f"- **原始时间：** `{maybe_redact(str(item.get('time', 'unknown')))}`",
                f"- **归一化 UTC：** `{maybe_redact(str(item.get('normalized_time_utc', 'unknown')))}`",
                f"- **事件：** {maybe_redact(str(item.get('event', '')) or '未提供。')}",
                f"- **来源：** `{maybe_redact(str(item.get('source', 'unknown')))}`",
                f"- **证据链：** {zh_evidence_refs(as_list(item.get('evidence_ids')))}",
                "",
            ])
    else:
        lines.extend(["未提供时间线条目。", ""])

    lines.append(anchor_tag("report-ip-traceability"))
    lines.append("## IP 溯源")
    if ctx["ip_traces"]:
        for item in ctx["ip_traces"]:
            status = str(item.get("trace_status", "unknown"))
            lines.extend([
                f"### {status_icon(status)} {maybe_redact(str(item.get('ip', 'unknown')))}",
                f"- **角色：** `{maybe_redact(str(item.get('role', 'unknown')))}`",
                f"- **溯源状态：** `{status_label_zh_cn(status)}`",
                f"- **说明：** {maybe_redact_zh(str(item.get('reason', '未提供')))}",
                f"- **证据链：** {zh_evidence_refs(as_list(item.get('evidence_ids')))}",
                "",
            ])
        if any(str(item.get("trace_status", "")) != "traced" for item in ctx["ip_traces"]):
            lines.extend([
                "- 未溯源或状态未知的 IP 条目按原样保留，不据此追加攻击者归因。",
                "",
            ])
    else:
        lines.extend(["未提供 IP 溯源条目。", ""])

    lines.append(anchor_tag("report-log-integrity"))
    lines.append("## 日志完整性")
    if ctx["log_integrity"]:
        for item in ctx["log_integrity"]:
            status = str(item.get("status", "unknown"))
            icon = "⚠️" if status.lower() in {"missing", "tampered", "suspicious"} else "✅"
            lines.extend([
                f"### {icon} {maybe_redact(str(item.get('artifact', 'unknown')))}",
                f"- **状态：** `{status_label_zh_cn(status)}`",
                f"- **原因：** {maybe_redact_zh(str(item.get('reason', '-')) or '-')}",
                f"- **证据链：** {zh_evidence_refs(as_list(item.get('evidence_ids')))}",
                "",
            ])
        if any(str(item.get("status", "")).lower() in {"missing", "tampered"} for item in ctx["log_integrity"]):
            lines.extend([
                "- 关键日志缺失或疑似被篡改时，归因置信度必须相应下调。",
                "",
            ])
    else:
        lines.extend(["未提供日志完整性条目。", ""])

    lines.append(anchor_tag("report-action-log"))
    lines.append("## 动作记录")
    if ctx["actions"]:
        for index, item in enumerate(ctx["actions"], start=1):
            lines.extend([
                f"### 动作 {index}",
                f"- **时间：** `{maybe_redact(str(item.get('time', 'unknown')))}`",
                f"- **动作：** {maybe_redact(str(item.get('action', '')) or '未提供。')}",
                f"- **风险级别：** `{maybe_redact(str(item.get('risk_level', 'unknown')))}`",
                f"- **审批状态：** `{maybe_redact(str(item.get('approval', 'missing')))}`",
                f"- **结果：** {maybe_redact(str(item.get('result', '-')) or '-')}",
                "",
            ])
    else:
        lines.extend(["未提供动作记录。", ""])

    lines.append(anchor_tag("report-evidence-details"))
    lines.append("## 证据详情")
    if evidence_items:
        for item in evidence_items:
            evidence_id = str(item.get("id", "unknown"))
            artifact_path = str(item.get("artifact", "")).strip()
            artifact_name = Path(artifact_path).name if artifact_path else "artifact"
            href = artifact_href(item, case_dir)
            lines.append(f'<a id="{evidence_anchor(evidence_id)}"></a>')
            lines.append("<details>")
            lines.append(
                f"<summary><strong>{evidence_id}</strong> · {maybe_redact(str(item.get('source', 'unknown')))} · {maybe_redact(str(item.get('observed_at', 'unknown')))} · {maybe_redact(compact_text(str(item.get('command', '')), max_len=96))}</summary>"
            )
            lines.extend([
                "",
                f"- **来源：** `{maybe_redact(str(item.get('source', 'unknown')))}`",
                f"- **采集时间：** `{maybe_redact(str(item.get('observed_at', 'unknown')))}`",
                f"- **命令哈希：** `{maybe_redact(str(item.get('command_hash', 'unknown')))}`",
                f"- **产物哈希：** `{maybe_redact(str(item.get('artifact_hash', 'unknown')))}`",
                f"- **产物大小：** `{bytes_label_zh_cn(item.get('artifact_size_bytes'))}`",
                f"- **是否超时：** `{yes_no_zh_cn(item.get('timed_out'))}`",
            ])
            if href:
                lines.append(f"- **产物文件：** [{artifact_name}]({href})")
            if artifact_path:
                lines.append(f"- **产物路径：** `{maybe_redact(artifact_path)}`")
            lines.append("- **导航：** [返回证据来源导航](#report-evidence-source-navigator) | [返回证据索引](#report-evidence-index) | [返回顶部](#report-top) | [案件索引](./reports/index.zh-CN.md) | [英文全量报告](./report.md)")
            lines.extend([
                "",
                "**命令**",
                "```bash",
                maybe_redact(str(item.get("command", "")).strip() or "# command unavailable"),
                "```",
                "",
                "</details>",
                "",
            ])
    else:
        lines.extend(["未生成证据详情块。", ""])

    lines.append(anchor_tag("report-unknowns"))
    lines.append("## 未知项与缺口")
    if ctx["unknowns"]:
        for item in ctx["unknowns"]:
            lines.append(f"- {maybe_redact_zh(str(item))}")
    else:
        lines.append("- 未提供。")
    lines.append("")

    lines.append(anchor_tag("report-validation"))
    lines.append("## 校验告警")
    if warnings:
        for warning in warnings:
            lines.append(f"- {maybe_redact(warning)}")
    else:
        lines.append("- 无。")
    if as_list(case_validation.get("checks")):
        lines.extend(["", "### 案件包检查"])
        for item in as_list(case_validation.get("checks")):
            check = as_dict(item)
            lines.append(
                f"- `{'ok' if check.get('ok') else 'fail'}` `{maybe_redact(str(check.get('check', 'unknown')))}` -> `{maybe_redact(str(check.get('path', 'unknown')))}`"
            )
    lines.extend([
        "",
        "## 页脚",
        "- [返回顶部](#report-top) | [案件索引](./reports/index.zh-CN.md) | [英文全量报告](./report.md) | [管理摘要](./reports/management-summary.zh-CN.md) | [SOC 摘要](./reports/soc-summary.zh-CN.md)",
        "",
    ])
    return "\n".join(lines).strip() + "\n", warnings



def write_companion_reports(case_dir: str | None, data: dict[str, Any], redact: bool, strict: bool) -> list[str]:
    if not case_dir:
        return []
    case_root = Path(case_dir)
    reports_dir = case_root / "reports"
    meta_dir = case_root / "meta"
    reports_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)
    report_zh, _ = build_report_zh_cn(data, redact=redact, strict=strict, case_dir=case_dir)
    leadership_en = build_leadership_report(data, redact=redact, case_dir=case_dir)
    leadership_zh = build_leadership_report_zh_cn(data, redact=redact, case_dir=case_dir)
    legacy_paths = [reports_dir / "report.md", reports_dir / "report.zh-CN.md"]
    for legacy_path in legacy_paths:
        if legacy_path.exists():
            legacy_path.unlink()

    outputs = {
        reports_dir / "index.md": build_case_bundle_index(data, case_dir=case_dir),
        reports_dir / "index.zh-CN.md": finalize_zh_markdown(build_case_bundle_index_zh_cn(data, case_dir=case_dir)),
        reports_dir / "management-summary.md": build_management_view(data, redact=redact, case_dir=case_dir),
        reports_dir / "management-summary.zh-CN.md": finalize_zh_markdown(build_management_view_zh_cn(data, redact=redact, case_dir=case_dir)),
        reports_dir / "soc-summary.md": build_soc_view(data, redact=redact, case_dir=case_dir),
        reports_dir / "soc-summary.zh-CN.md": finalize_zh_markdown(build_soc_view_zh_cn(data, redact=redact, case_dir=case_dir)),
        case_root / "leadership-report.md": leadership_en,
        case_root / "leadership-report.zh-CN.md": finalize_zh_markdown(leadership_zh),
        case_root / "report.zh-CN.md": finalize_zh_markdown(report_zh),
    }
    written: list[str] = []
    for out_path, body in outputs.items():
        out_path.write_text(body, encoding="utf-8")
        written.append(str(out_path))
    required_outputs = sorted(
        {
            str(case_root / "report.md"),
            str(case_root / "report.zh-CN.md"),
            str(case_root / "leadership-report.md"),
            str(case_root / "leadership-report.zh-CN.md"),
            str(reports_dir / "index.md"),
            str(reports_dir / "index.zh-CN.md"),
            str(reports_dir / "management-summary.md"),
            str(reports_dir / "management-summary.zh-CN.md"),
            str(reports_dir / "soc-summary.md"),
            str(reports_dir / "soc-summary.zh-CN.md"),
            str(reports_dir / "operator-brief.md"),
            str(reports_dir / "operator-brief.zh-CN.md"),
            str(reports_dir / "operator-brief.json"),
            str(reports_dir / "external-evidence-checklist.md"),
        }
    )
    manifest = {
        "generated_at_utc": now_utc(),
        "required_outputs": sorted(required_outputs + [str(meta_dir / "report-manifest.json")]),
        "required_output_count": len(required_outputs) + 1,
    }
    manifest_path = meta_dir / "report-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    written.append(str(manifest_path))
    return written


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a fact-constrained investigation report."
    )
    parser.add_argument("--input", required=True, help="Input JSON evidence file.")
    parser.add_argument("--output", help="Output markdown file.")
    parser.add_argument("--case-dir", help="Case directory. If set and --output omitted, writes to case_dir/report.md.")
    parser.add_argument(
        "--redact",
        action="store_true",
        help="Mask sensitive fields (IPs, wallet-like strings, secrets).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if findings or trace entries violate evidence requirements.",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if args.output:
        output_path = Path(args.output)
    elif args.case_dir:
        output_path = Path(args.case_dir) / "report.md"
    else:
        parent = input_path.resolve().parent
        if parent.name == "evidence":
            output_path = parent.parent / "report.md"
        else:
            output_path = parent / "report.md"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = load_json(input_path)
    derived_case_dir = args.case_dir
    if not derived_case_dir and input_path.resolve().parent.name == "evidence":
        derived_case_dir = str(input_path.resolve().parent.parent)
    report_md, warnings = build_report(data, redact=args.redact, strict=args.strict, case_dir=derived_case_dir)
    output_path.write_text(report_md, encoding="utf-8")
    if derived_case_dir:
        legacy_report_path = Path(derived_case_dir) / "reports" / "report.md"
        if legacy_report_path.exists():
            legacy_report_path.unlink()
    companion_paths = write_companion_reports(derived_case_dir, data, redact=args.redact, strict=args.strict)

    print(f"Report written: {output_path}")
    for companion in companion_paths:
        print(f"Companion report written: {companion}")
    print(f"Warnings: {len(warnings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
