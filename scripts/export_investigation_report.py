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
from typing import Any, Callable


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


def derive_platform_os_name(host_os: str, platform_identity: dict[str, Any]) -> str:
    host_value = str(host_os or "").strip()
    if host_value and host_value.lower() != "unknown":
        return host_value
    parts = [
        str(platform_identity.get("os_release_id", "")).strip(),
        str(platform_identity.get("os_release_version", "")).strip(),
        str(platform_identity.get("os_release_codename", "")).strip(),
    ]
    derived = " ".join(part for part in parts if part).strip()
    return derived or "unknown"


def adjusted_log_risk_count(data: dict[str, Any], log_integrity: list[dict[str, Any]]) -> int:
    second_pass = as_dict(data.get("second_pass_review"))
    log_layout = as_dict(second_pass.get("log_layout_review"))
    if "adjusted_primary_log_risk_count" in log_layout:
        return safe_int(log_layout.get("adjusted_primary_log_risk_count", 0))
    return sum(
        1
        for item in log_integrity
        if str(item.get("status", "")).strip().lower() in {"missing", "tampered", "suspicious"}
    )


def collection_failure_info(ctx: dict[str, Any]) -> dict[str, Any]:
    return as_dict(ctx.get("collection_failure"))


def collection_failed(ctx: dict[str, Any]) -> bool:
    return str(collection_failure_info(ctx).get("status", "")).strip().lower() == "failed"


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


def second_pass_pivot_label(value: str) -> str:
    return {
        "identity_boundary_logs": "Identity / boundary authentication logs",
        "peer_host_internal_auth_pivot": "Peer-host / internal-auth pivot review",
        "cloud_control_plane_audit": "Cloud / container control-plane audit",
        "boundary_telemetry_for_log_loss": "Boundary telemetry for reduced host-log visibility",
        "timeline_expansion": "Timeline expansion",
        "contradiction_resolution": "Cross-source contradiction resolution",
        "privesc_change_records": "Priv-esc admin-change corroboration",
    }.get(str(value).strip(), str(value).strip() or "unknown")


def second_pass_pivot_label_zh_cn(value: str) -> str:
    return {
        "identity_boundary_logs": "身份与边界认证日志补证",
        "peer_host_internal_auth_pivot": "同环境主机与内网认证支点复核",
        "cloud_control_plane_audit": "云与容器控制面审计补证",
        "boundary_telemetry_for_log_loss": "日志缺失场景下的边界遥测补证",
        "timeline_expansion": "时间线扩窗复核",
        "contradiction_resolution": "跨来源矛盾消解",
        "privesc_change_records": "本地提权变更记录补证",
    }.get(str(value).strip(), str(value).strip() or "未知")


def timeline_review_label(value: str) -> str:
    return {
        "timeline_not_recovered": "timeline_not_recovered",
        "timeline_not_normalized": "timeline_not_normalized",
        "narrow_window": "timeline_window_narrow",
        "normalized_window_present": "timeline_window_present",
    }.get(str(value).strip(), str(value).strip() or "unknown")


def timeline_review_label_zh_cn(value: str) -> str:
    return {
        "timeline_not_recovered": "未恢复出可用时间线",
        "timeline_not_normalized": "时间线未完成可信 UTC 归一化",
        "narrow_window": "时间线窗口偏窄",
        "normalized_window_present": "时间线窗口可用",
    }.get(str(value).strip(), str(value).strip() or "未知")


def scope_closure_label(value: str) -> str:
    return {
        "needs_external_corroboration": "external_corroboration_needed",
        "host_only_scope_sufficient_for_requested_focus": "host_only_scope_currently_sufficient",
    }.get(str(value).strip(), str(value).strip() or "unknown")


def scope_closure_label_zh_cn(value: str) -> str:
    return {
        "needs_external_corroboration": "仍需外部补证",
        "host_only_scope_sufficient_for_requested_focus": "当前主机侧证据已可支撑本轮范围",
    }.get(str(value).strip(), str(value).strip() or "未知")


def workflow_review_status_label(value: str) -> str:
    return {
        "completed_ready_for_host_only_report": "host_only_report_ready",
        "completed_with_open_gaps": "open_gaps_visible",
        "collection_failed": "collection_failed",
    }.get(str(value).strip(), str(value).strip() or "unknown")


def workflow_review_status_label_zh_cn(value: str) -> str:
    return {
        "completed_ready_for_host_only_report": "主机侧报告闭环条件已满足",
        "completed_with_open_gaps": "仍有未闭环缺口",
        "collection_failed": "主机侧采集失败",
    }.get(str(value).strip(), str(value).strip() or "未知")


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
        "Collection failed before host-side evidence could be gathered.": "主机侧证据尚未建立前，采集流程已经失败。",
        "No investigative conclusion should be drawn from this bundle until host-side collection succeeds.": "在主机侧采集成功前，不能基于这个失败案件包输出任何排查结论。",
        "Fix trust/auth/channel issues, preserve the failure bundle, and use external telemetry only as temporary corroboration before rerunning read-only collection.": "先修复信任、认证或通道问题，保留失败案件包，并且仅把外部遥测作为临时补证；完成后再重新执行只读采集。",
        "Host-side service exposure was not collected because collection failed before probes completed.": "由于探针采集在完成前失败，本轮未取得主机侧服务暴露面信息。",
        "No host-side lateral-movement assessment was possible because collection failed before evidence gathering.": "由于主机侧证据采集未成功，本轮无法对横向移动做主机侧判断。",
        "Direct miner-like runtime indicators were observed during collection.": "本次采集中观察到了直接的挖矿类运行时指标。",
        "Triage should proceed as a compromise-oriented case, but attribution still requires additional evidence.": "当前应按疑似入侵方向继续排查，但攻击者归因仍需更多证据。",
        "No direct miner IOC was observed in this collection. Current results are limited to review surfaces that still require analyst confirmation.": "本次采集中未观察到直接的挖矿 IOC，当前结果主要是需要人工复核的访问面与环境侧线索。",
        "This does not clear the host. The present output supports review-driven triage, not a confirmed mining-compromise conclusion.": "这并不能证明主机安全无虞。当前输出仅支持复核驱动的分诊，不足以下结论为已确认的挖矿入侵。",
        "Absence of indicators in this pass is not proof of absence; visibility, timing, and privilege may still be incomplete.": "本轮未见指标并不等于不存在问题；当前可见性、采集时机和权限范围仍可能不完整。",
        "Prioritize runtime lineage, parent-child process review, wallet/pool traces, and persistence pivots.": "优先复核运行链路、父子进程关系、钱包或矿池痕迹，以及持久化支点。",
        "Prioritize surviving access traces, service startup context, container/cloud exposure, and deleted-log fallback artifacts.": "优先复核现存访问痕迹、服务启动上下文、容器或云侧暴露面，以及日志缺失后的替代证据。",
        "Expand time window, privilege visibility, and external telemetry correlation before closing the case.": "在结案前应继续扩展时间窗口、权限可见性，并补做外部遥测关联。",
        "No direct miner runtime string was parsed in this pass; conclusions remain bound to review surfaces and visible runtime artifacts only.": "本轮未直接解析出矿工运行时字符串，当前结论仍仅限于已见复核面和可见运行时证据。",
        "Current persistence review surfaces are dominated by vendor-managed startup lines or account metadata. That does not independently establish a malicious foothold.": "当前持久化复核面主要由厂商管理的启动项或账号元数据构成，单凭这些内容不足以独立证明恶意落地。",
        "Successful authentication sources exist, but host-only evidence cannot yet distinguish authorized administration from attacker reuse of valid access.": "已观察到成功认证来源，但仅凭主机证据仍无法区分正常运维与攻击者复用现有合法访问。",
        "Second-pass review found no mandatory external corroboration gaps for the requested host-only scope.": "二轮复核认为，就当前指定的主机侧只读范围而言，没有发现必须追加的外部补证门槛。",
        "Second-pass review kept explicit open gaps visible; do not over-close the case on host evidence alone.": "二轮复核保留了明确的未闭环缺口，不能仅凭主机侧证据把案件过度定性为已闭环。",
        "No reconstructable timeline entries were recovered from current host evidence.": "当前主机证据中未恢复出可用于重建的时间线条目。",
        "Timeline-like records exist, but no event time could be normalized into a defensible UTC sequence.": "虽然存在时间线相关记录，但尚无事件时间可被可信地归一化为 UTC 序列。",
        "Recovered event timing is narrow and likely under-scopes earlier ingress or staging activity. Expand the time window before closing the case.": "已恢复的事件时间范围过窄，可能低估更早期的入口或准备阶段活动；在结案前应先扩展时间窗口。",
        "Host-visible authentication sources exist, but authorization and upstream ingress still need non-host corroboration.": "主机侧已经看到认证来源，但其授权性与上游入口仍需结合主机外证据补证。",
        "Private or internal authentication source IPs were observed and can indicate same-environment pivoting.": "已观察到私网或内网认证来源 IP，可能提示同环境横向支点。",
        "Container or cloud review surfaces were present, so control-plane evidence is needed before closing ingress scope.": "已出现容器或云侧复核面，因此在关闭入口范围前仍需控制面证据补证。",
        "Applicable host logs remain missing or suspicious; external telemetry is needed to compensate for reduced host visibility.": "适用的主机日志仍然缺失或可疑，需要借助外部遥测来弥补主机侧可见性下降。",
        "Recovered event timing is incomplete for confident ingress reconstruction.": "当前恢复到的事件时间仍不足以高置信还原入口链路。",
        "Cross-source contradictions remain and should be resolved before stronger attribution or closure.": "跨来源矛盾仍然存在，在做更强归因或结案前应先消解。",
        "Local-privesc exposure remains in scope and needs package backport or admin change-history corroboration.": "本地提权暴露面仍在排查范围内，需要结合软件包回移修复信息或管理员变更记录补证。",
        "Correlate fallback auth artifacts and external telemetry before treating missing logs as attacker-driven.": "在把日志缺失解释为攻击者行为前，应先关联替代认证证据与外部遥测。",
        "Expand the UTC timeline using surviving artifacts and non-host telemetry before closing the ingress sequence.": "在关闭入口链路前，应先利用现存证据与主机外遥测扩展 UTC 时间线。",
        "Review each high-signal startup or policy line directly by evidence ID before any containment step.": "在执行任何处置动作前，应先按证据 ID 逐条复核高信号启动项或策略项。",
        "Validate package backport status and admin workflow before treating local-privesc exposure as exploit use.": "在把本地提权暴露面解释为已被利用前，应先核实软件包回移修复状态与管理员操作流程。",
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
            re.compile(r"^Persistence review still contains high-signal startup or privileged policy lines: (.+)$"),
            lambda m: f"持久化复核面仍存在高信号启动项或高权限策略线索，例如：{m.group(1)}",
        ),
        (
            re.compile(r"^Network IOC review produced hits such as: (.+)$"),
            lambda m: f"网络 IOC 复核返回了值得关注的命中，例如：{m.group(1)}",
        ),
        (
            re.compile(r"^Internal/private source IPs appeared in authentication evidence: (.+)\.$"),
            lambda m: f"认证类证据中出现了内网或私网来源 IP：{m.group(1).replace(', ', '、')}。",
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


def render_compact_judgments_en(
    items: list[dict[str, str]],
    evid_idx: dict[str, dict[str, Any]],
    case_dir: str | None,
    maybe_redact: Callable[[str], str],
    *,
    empty_text: str,
    heading_builder: Callable[[dict[str, str]], str],
    include_hypothesis_line: bool,
) -> list[str]:
    if not items:
        return [empty_text, ""]

    lines: list[str] = []
    for item in items:
        evidence_ids = item["evidence_ids"].split(", ") if item["evidence_ids"] != "none" else []
        lines.extend(
            [
                heading_builder(item),
                f"- **Statement:** {maybe_redact(item['statement'])}",
                f"- **Type / Status / Confidence:** `{claim_type_label(item['claim_type'])}` / `{item['status']}` / `{item['confidence']}`",
            ]
        )
        if include_hypothesis_line:
            lines.append(f"- **Hypothesis:** `{maybe_redact(item['hypothesis_id'])}`")
        lines.extend(
            [
                f"- **Confidence Reason:** {maybe_redact(item['confidence_reason'])}",
                f"- **Evidence Chain:** {compact_evidence_chain(evidence_ids, evid_idx, case_dir, limit=4, base_dir=Path(case_dir) / 'reports' if case_dir else None).replace('](#evidence-', '](../report.md#evidence-')}",
                "",
            ]
        )
    return lines


def render_compact_judgments_zh_cn(
    items: list[dict[str, str]],
    evid_idx: dict[str, dict[str, Any]],
    case_dir: str | None,
    maybe_redact: Callable[[str], str],
    maybe_redact_zh: Callable[[str], str],
    *,
    empty_text: str,
    heading_builder: Callable[[dict[str, str]], str],
    include_hypothesis_line: bool,
) -> list[str]:
    if not items:
        return [empty_text, ""]

    lines: list[str] = []
    for item in items:
        evidence_ids = item["evidence_ids"].split(", ") if item["evidence_ids"] != "none" else []
        lines.extend(
            [
                heading_builder(item),
                f"- **研判：** {maybe_redact_zh(item['statement'])}" if include_hypothesis_line else f"- **表述：** {maybe_redact_zh(item['statement'])}",
                f"- **类型 / 状态 / 置信度：** `{ {'observed_fact':'观测事实','inference':'推断','attribution':'归因'}.get(normalize_claim_type(item['claim_type']), '推断') }` / `{ {'confirmed':'已确认','inconclusive':'待定'}.get(item['status'], item['status']) }` / `{ {'high':'高','medium':'中','low':'低','unknown':'未知'}.get(item['confidence'], item['confidence']) }`",
            ]
        )
        if include_hypothesis_line:
            lines.append(f"- **假设编号：** `{maybe_redact(item['hypothesis_id'])}`")
        lines.extend(
            [
                f"- **置信度理由：** {maybe_redact_zh(item['confidence_reason'])}",
                f"- **证据链：** {compact_evidence_chain_zh_cn(evidence_ids, evid_idx, case_dir, limit=4, base_dir=Path(case_dir) / 'reports' if case_dir else None).replace('](#evidence-', '](../report.zh-CN.md#evidence-')}",
                "",
            ]
        )
    return lines


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
    ])
    if ctx["collection_failed"]:
        lines.extend(
            [
                "## Collection Failure",
                f"- **Failure Phase:** `{maybe_redact(str(ctx['collection_failure'].get('phase', 'unknown')) or 'unknown')}`",
                f"- **Reason:** {maybe_redact(str(ctx['collection_failure'].get('reason', '-')) or '-')}",
                "",
            ]
        )
    lines.extend([anchor_tag("mgmt-risks"), "## Risk Overview"])
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
    lines.extend(
        render_compact_judgments_en(
            key_items,
            evid_idx,
            case_dir,
            maybe_redact,
            empty_text="- No evidence-backed judgments available yet.",
            heading_builder=lambda item: f"### {status_icon(item['status'])} {item['id']}",
            include_hypothesis_line=True,
        )
    )
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
            'Collection failed before host-side evidence could be gathered.': '主机侧证据尚未建立前，采集流程已经失败。',
        }.get(posture_info['verdict'], posture_info['verdict']))}",
        f"- **置信度态势：** {confidence_icon(posture_info['posture'])} `{ {'high':'高','medium':'中','low':'低','unknown':'未知'}.get(posture_info['posture'], posture_info['posture']) }`",
        f"- **判断边界：** {maybe_redact_zh({
            'Triage should proceed as a compromise-oriented case, but attribution still requires additional evidence.': '建议按入侵方向继续排查，但归因仍需补充更多证据。',
            'This does not clear the host. The present output supports review-driven triage, not a confirmed mining-compromise conclusion.': '这并不代表主机可以直接排除风险，当前结果只支撑复核型分诊，不足以确认已发生挖矿入侵。',
            'Absence of indicators in this pass is not proof of absence; visibility, timing, and privilege may still be incomplete.': '本轮未命中指标不等于主机无风险，观察窗口、权限范围和证据残留都可能仍不完整。',
            'No investigative conclusion should be drawn from this bundle until host-side collection succeeds.': '在主机侧采集成功前，不能基于这个失败案件包输出任何排查结论。',
        }.get(posture_info['boundary'], posture_info['boundary']))}",
        f"- **优先方向：** {maybe_redact_zh({
            'Prioritize runtime lineage, parent-child process review, wallet/pool traces, and persistence pivots.': '优先复核运行链路、父子进程关系、钱包/矿池痕迹和持久化落点。',
            'Prioritize surviving access traces, service startup context, container/cloud exposure, and deleted-log fallback artifacts.': '优先复核仍存活的访问痕迹、服务启动上下文、容器/云暴露面，以及日志删除后的替代证据。',
            'Expand time window, privilege visibility, and external telemetry correlation before closing the case.': '在结束案件前应继续扩展观察窗口、权限可见性，并结合外部遥测交叉验证。',
            'Fix trust/auth/channel issues, preserve the failure bundle, and use external telemetry only as temporary corroboration before rerunning read-only collection.': '先修复信任、认证或通道问题，保留失败案件包，并且仅把外部遥测作为临时补证；完成后再重新执行只读采集。',
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
    ])
    if ctx["collection_failed"]:
        lines.extend(
            [
                "## 采集失败",
                f"- **失败阶段：** `{maybe_redact(str(ctx['collection_failure'].get('phase', 'unknown')) or 'unknown')}`",
                f"- **失败原因：** {maybe_redact_zh(str(ctx['collection_failure'].get('reason', '-')) or '-')}",
                "",
            ]
        )
    lines.extend([anchor_tag("mgmt-risks"), "## 风险概览"])
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
    lines.extend(
        render_compact_judgments_zh_cn(
            key_items,
            evid_idx,
            case_dir,
            maybe_redact,
            maybe_redact_zh,
            empty_text="- 当前暂无有证据支撑的优先研判。",
            heading_builder=lambda item: f"### {status_icon(item['status'])} {item['id']}",
            include_hypothesis_line=True,
        )
    )
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
    ])
    if ctx["collection_failed"]:
        lines.extend(
            [
                "## Collection Failure",
                f"- **Failure Phase:** `{maybe_redact(str(ctx['collection_failure'].get('phase', 'unknown')) or 'unknown')}`",
                f"- **Reason:** {maybe_redact(str(ctx['collection_failure'].get('reason', '-')) or '-')}",
                "",
            ]
        )
    lines.extend([anchor_tag("soc-samples"), "## High-Signal Samples", ""])
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
    lines.extend(
        render_compact_judgments_en(
            key_items,
            evid_idx,
            case_dir,
            maybe_redact,
            empty_text="- No evidence-backed judgments available yet.",
            heading_builder=lambda item: f"### {status_icon(item['status'])} {item['id']} | `{item['hypothesis_id']}`",
            include_hypothesis_line=False,
        )
    )
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
            'Collection failed before host-side evidence could be gathered.': '主机侧证据尚未建立前，采集流程已经失败。',
        }.get(posture_info['verdict'], posture_info['verdict']))}",
        f"- **置信度态势：** {confidence_icon(posture_info['posture'])} `{ {'high':'高','medium':'中','low':'低','unknown':'未知'}.get(posture_info['posture'], posture_info['posture']) }`",
        f"- **下一步重点：** {maybe_redact_zh({
            'Prioritize runtime lineage, parent-child process review, wallet/pool traces, and persistence pivots.': '优先复核运行链路、父子进程关系、钱包/矿池痕迹和持久化落点。',
            'Prioritize surviving access traces, service startup context, container/cloud exposure, and deleted-log fallback artifacts.': '优先复核仍存活的访问痕迹、服务启动上下文、容器/云暴露面，以及日志删除后的替代证据。',
            'Expand time window, privilege visibility, and external telemetry correlation before closing the case.': '继续扩展观察窗口、权限可见性，并结合外部遥测交叉验证。',
            'Fix trust/auth/channel issues, preserve the failure bundle, and use external telemetry only as temporary corroboration before rerunning read-only collection.': '先修复信任、认证或通道问题，保留失败案件包，并且仅把外部遥测作为临时补证；完成后再重新执行只读采集。',
        }.get(posture_info['focus'], posture_info['focus']))}",
        f"- **判断边界：** {maybe_redact_zh({
            'Triage should proceed as a compromise-oriented case, but attribution still requires additional evidence.': '建议按入侵方向继续排查，但归因仍需补充更多证据。',
            'This does not clear the host. The present output supports review-driven triage, not a confirmed mining-compromise conclusion.': '当前结果不构成主机已安全的证明，只支撑复核型分诊，不足以确认已发生挖矿入侵。',
            'Absence of indicators in this pass is not proof of absence; visibility, timing, and privilege may still be incomplete.': '本轮未命中指标不等于主机无风险，观察窗口、权限范围和证据残留都可能仍不完整。',
            'No investigative conclusion should be drawn from this bundle until host-side collection succeeds.': '在主机侧采集成功前，不能基于这个失败案件包输出任何排查结论。',
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
    ])
    if ctx["collection_failed"]:
        lines.extend(
            [
                "## 采集失败",
                f"- **失败阶段：** `{maybe_redact(str(ctx['collection_failure'].get('phase', 'unknown')) or 'unknown')}`",
                f"- **失败原因：** {maybe_redact_zh(str(ctx['collection_failure'].get('reason', '-')) or '-')}",
                "",
            ]
        )
    lines.extend([anchor_tag("soc-samples"), "## 高信号样本", ""])
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
    lines.extend(
        render_compact_judgments_zh_cn(
            key_items,
            evid_idx,
            case_dir,
            maybe_redact,
            maybe_redact_zh,
            empty_text="- 当前暂无有证据支撑的关键研判。",
            heading_builder=lambda item: f"### {status_icon(item['status'])} {item['id']} · `{item['hypothesis_id']}`",
            include_hypothesis_line=False,
        )
    )
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
    log_risk_count = adjusted_log_risk_count(data, log_integrity)
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
    log_risk_count = adjusted_log_risk_count(data, log_integrity)
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
    failure = collection_failure_info(ctx)
    if collection_failed(ctx):
        failure_phase = str(failure.get("phase", "unknown"))
        failure_reason = str(
            failure.get("reason", "Host-side collection failed before evidence could be gathered.")
        )
        retry_guidance = str(
            failure.get(
                "retry_guidance",
                "Review SSH trust, authentication, and shell/channel compatibility before retrying.",
            )
        )
        return {
            "intrusion_window": "unknown",
            "ingress_hypotheses": [
                {
                    "label": "No host-side evidence was gathered, so initial-access reconstruction remains unavailable.",
                    "label_zh": "由于未建立主机侧证据，当前无法还原入侵入口。",
                    "confidence": "unknown",
                    "basis": failure_reason,
                }
            ],
            "activity_summary": [
                "Collection failed before host-side evidence could be gathered.",
                f"Failure phase: {failure_phase}",
                failure_reason,
                retry_guidance,
            ],
            "runtime_profiles": [],
            "malware_files": [],
            "top_cpu": [],
            "auth_ips": [],
            "listening_ports": [],
            "service_exposure": "Host-side service exposure was not collected because collection failed before probes completed.",
            "lateral_status": "unknown",
            "lateral_basis": "No host-side lateral-movement assessment was possible because collection failed before evidence gathering.",
            "log_risk_count": safe_int(ctx["log_risk_count"]),
            "log_layout_status": "unknown",
            "log_layout_os_family": "unknown",
            "log_layout_adjusted_count": 0,
            "log_layout_raw_count": 0,
            "log_layout_summary": "",
            "timeline_review_status": "unknown",
            "timeline_review_summary": "No timeline review was possible because host-side collection failed before evidence gathering.",
            "timeline_normalized_event_count": 0,
            "timeline_span_minutes": 0,
            "scope_closure_status": "unknown",
            "scope_closure_summary": "No host-side scope closure review was possible because collection failed before evidence gathering.",
            "scope_external_pivots": [],
            "workflow_review_status": "collection_failed",
            "workflow_review_summary": "Collection failed before host-side evidence could be gathered.",
            "workflow_closure_ready": False,
            "workflow_closure_notes": [failure_reason, retry_guidance],
            "evidence_excerpt_ids": [],
            "gpu_peak": 0,
            "gpu_suspicious": 0,
            "gpu_visibility_status": "unknown",
            "gpu_visibility_summary": "GPU visibility was not assessed because collection failed before host-side probes completed.",
            "gpu_vendor_hints": [],
            "gpu_fallback_markers": [],
            "runtime_profile_count": 0,
            "top_cpu_keyword_hits": 0,
            "collection_failure_phase": failure_phase,
            "collection_failure_reason": failure_reason,
            "collection_retry_guidance": retry_guidance,
        }

    scene = ctx["scene_reconstruction"]
    second_pass = as_dict(ctx.get("second_pass_review"))
    accepted_auth_review = as_dict(second_pass.get("accepted_auth_review") or scene.get("accepted_auth_review"))
    persistence_review = as_dict(second_pass.get("persistence_surface_review") or scene.get("persistence_surface_review"))
    log_layout_review = as_dict(second_pass.get("log_layout_review") or scene.get("log_layout_review"))
    timeline_review = as_dict(second_pass.get("timeline_review") or scene.get("timeline_review"))
    scope_closure_review = as_dict(second_pass.get("scope_closure_review") or scene.get("scope_closure_review"))
    workflow_review = as_dict(second_pass.get("workflow_review") or scene.get("workflow_review"))
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
    accepted_sources = [as_dict(x) for x in as_list(accepted_auth_review.get("sources"))]
    if accepted_sources:
        ingress_hypotheses.append(
            {
                "label": "Successful authentication sources exist, but host-only evidence cannot yet distinguish authorized administration from attacker reuse of valid access.",
                "label_zh": "已观察到成功认证来源，但仅凭主机证据仍无法区分正常运维与攻击者复用现有合法访问。",
                "confidence": "low",
                "basis": (
                    f"current_session_candidates={accepted_auth_review.get('current_session_candidate_count', 0)}, "
                    f"recurring_sources={accepted_auth_review.get('recurring_source_count', 0)}, "
                    f"authorization_unknown={accepted_auth_review.get('authorization_unknown_count', 0)}"
                ),
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
    if str(persistence_review.get("status", "")) == "baseline_or_vendor_dominated":
        activity_summary.append(
            "Current persistence review surfaces are dominated by vendor-managed startup lines or account metadata. That does not independently establish a malicious foothold."
        )
    elif str(persistence_review.get("status", "")) == "high_signal_present":
        activity_summary.append(
            f"Persistence review still contains high-signal startup or privileged policy lines: {compact_text(str(persistence_review.get('summary', '-')), max_len=220)}"
        )
    elif access_hits:
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
        "log_risk_count": safe_int(ctx["log_risk_count"]),
        "log_layout_status": str(log_layout_review.get("status", "unknown")),
        "log_layout_os_family": str(log_layout_review.get("os_family", "unknown")),
        "log_layout_adjusted_count": safe_int(log_layout_review.get("adjusted_primary_log_risk_count", 0)),
        "log_layout_raw_count": safe_int(log_layout_review.get("raw_primary_log_risk_count", 0)),
        "log_layout_summary": str(log_layout_review.get("summary", "")),
        "timeline_review_status": str(timeline_review.get("status", "unknown")),
        "timeline_review_summary": str(timeline_review.get("summary", "")),
        "timeline_normalized_event_count": safe_int(timeline_review.get("normalized_event_count", 0)),
        "timeline_span_minutes": safe_int(timeline_review.get("time_span_minutes", 0)),
        "scope_closure_status": str(scope_closure_review.get("status", "unknown")),
        "scope_closure_summary": str(scope_closure_review.get("summary", "")),
        "scope_external_pivots": [as_dict(x) for x in as_list(scope_closure_review.get("external_pivots"))[:6]],
        "workflow_review_status": str(workflow_review.get("status", "unknown")),
        "workflow_review_summary": str(workflow_review.get("summary", "")),
        "workflow_closure_ready": bool(workflow_review.get("closure_ready_for_host_only_report")),
        "workflow_closure_notes": [str(x) for x in as_list(workflow_review.get("closure_notes"))[:6]],
        "evidence_excerpt_ids": evidence_ids,
        "gpu_peak": safe_int(scene.get("gpu_peak_utilization_percent", 0)),
        "gpu_suspicious": safe_int(scene.get("gpu_suspicious_process_count", 0)),
        "gpu_visibility_status": str(scene.get("gpu_visibility_status", "unknown")),
        "gpu_visibility_summary": str(scene.get("gpu_visibility_summary", "unknown")),
        "gpu_vendor_hints": [str(x) for x in as_list(scene.get("gpu_vendor_hints"))[:6]],
        "gpu_fallback_markers": [str(x) for x in as_list(scene.get("gpu_fallback_markers"))[:8]],
        "runtime_profile_count": safe_int(scene.get("runtime_profile_count", 0)),
        "top_cpu_keyword_hits": safe_int(scene.get("top_cpu_process_keyword_hit_count", 0)),
        "collection_failure_phase": "",
        "collection_failure_reason": "",
        "collection_retry_guidance": "",
    }


def confidence_rank(value: str) -> int:
    return {"high": 3, "medium": 2, "low": 1, "unknown": 0}.get(str(value).strip().lower(), 0)


def natural_join(items: list[str], conjunction: str = "and") -> str:
    cleaned = [str(item).strip() for item in items if str(item).strip()]
    if not cleaned:
        return ""
    if len(cleaned) == 1:
        return cleaned[0]
    if len(cleaned) == 2:
        return f"{cleaned[0]} {conjunction} {cleaned[1]}"
    return f"{', '.join(cleaned[:-1])}, {conjunction} {cleaned[-1]}"


def zh_natural_join(items: list[str]) -> str:
    return "、".join(str(item).strip() for item in items if str(item).strip())


def leadership_case_id(data: dict[str, Any], ctx: dict[str, Any]) -> str:
    return str(data.get("case_id") or ctx.get("incident_id") or "unknown")


def public_scope_pivot_label(value: str) -> str:
    return {
        "identity_boundary_logs": "identity-provider, bastion, or boundary authentication records",
        "peer_host_internal_auth_pivot": "peer-host or internal-authentication records",
        "cloud_control_plane_audit": "cloud or container control-plane records",
        "boundary_telemetry_for_log_loss": "boundary telemetry to compensate for reduced host-log visibility",
        "timeline_expansion": "expanded timeline evidence",
        "contradiction_resolution": "cross-source contradiction review",
        "privesc_change_records": "admin change-history or package-backport records",
    }.get(str(value).strip(), "")


def public_scope_pivot_label_zh_cn(value: str) -> str:
    return {
        "identity_boundary_logs": "身份、堡垒机或边界认证日志",
        "peer_host_internal_auth_pivot": "同环境主机或内网认证记录",
        "cloud_control_plane_audit": "云侧或容器控制面审计",
        "boundary_telemetry_for_log_loss": "用于弥补主机日志缺口的边界遥测",
        "timeline_expansion": "扩展后的时间线证据",
        "contradiction_resolution": "跨来源矛盾消解结果",
        "privesc_change_records": "管理员变更记录或软件包回移修复信息",
    }.get(str(value).strip(), "")


def public_scope_gap_summary(payload: dict[str, Any]) -> str:
    labels: list[str] = []
    for item in as_list(payload.get("scope_external_pivots")):
        label = public_scope_pivot_label(str(as_dict(item).get("id", "")))
        if label and label not in labels:
            labels.append(label)
    if labels:
        return f"Non-host corroboration is still needed from {natural_join(labels[:3])}."
    return str(payload.get("scope_closure_summary", "")).strip()


def public_scope_gap_summary_zh_cn(payload: dict[str, Any]) -> str:
    labels: list[str] = []
    for item in as_list(payload.get("scope_external_pivots")):
        label = public_scope_pivot_label_zh_cn(str(as_dict(item).get("id", "")))
        if label and label not in labels:
            labels.append(label)
    if labels:
        return f"当前仍需补做主机外或跨主机关联，重点补证 {zh_natural_join(labels[:3])}。"
    return localize_auto_text_zh_cn(str(payload.get("scope_closure_summary", "")).strip())


def public_timeline_gap_summary(payload: dict[str, Any]) -> str:
    status = str(payload.get("timeline_review_status", "")).strip()
    if status == "narrow_window":
        return "The recovered host timeline is narrow and may miss earlier ingress or staging activity."
    if status == "timeline_not_recovered":
        return "No reconstructable host timeline was recovered from the current host evidence."
    if status == "timeline_not_normalized":
        return "Recovered host timestamps could not yet be normalized into a defensible UTC sequence."
    if status == "normalized_window_present" and safe_int(payload.get("timeline_span_minutes", 0)):
        return f"The recovered host timeline currently spans about {payload['timeline_span_minutes']} minute(s)."
    return str(payload.get("timeline_review_summary", "")).strip()


def public_timeline_gap_summary_zh_cn(payload: dict[str, Any]) -> str:
    status = str(payload.get("timeline_review_status", "")).strip()
    if status == "narrow_window":
        return "当前恢复出的主机时间线窗口偏窄，可能遗漏更早期的入口或准备阶段活动。"
    if status == "timeline_not_recovered":
        return "当前主机证据尚未恢复出可用于重建的时间线。"
    if status == "timeline_not_normalized":
        return "当前恢复到的时间戳还不能形成可辩护的 UTC 序列。"
    if status == "normalized_window_present" and safe_int(payload.get("timeline_span_minutes", 0)):
        return f"当前恢复出的主机时间线跨度约为 `{payload['timeline_span_minutes']}` 分钟。"
    return localize_auto_text_zh_cn(str(payload.get("timeline_review_summary", "")).strip())


def leadership_entry_items(payload: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
    items = [as_dict(item) for item in as_list(payload.get("ingress_hypotheses"))]
    return sorted(items, key=lambda item: confidence_rank(str(item.get("confidence", "unknown"))), reverse=True)[:limit]


def leadership_file_entries(payload: dict[str, Any], limit: int = 8) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in [as_dict(x) for x in as_list(payload.get("malware_files"))]:
        path = str(item.get("path", "") or item.get("origin_path", "")).strip()
        if not path or path in seen:
            continue
        seen.add(path)
        role = str(item.get("role_inference", "")).strip() or infer_file_role(item)
        out.append(
            {
                "path": path,
                "sha256": str(item.get("sha256", "")).strip() or "unavailable",
                "role_inference": role or "unknown",
                "basis": str(item.get("origin_path", "") or item.get("evidence_id", "unknown")).strip() or "unknown",
            }
        )
    for item in [as_dict(x) for x in as_list(payload.get("runtime_profiles"))]:
        path = str(item.get("executable", "")).strip()
        if not path or path in seen:
            continue
        seen.add(path)
        out.append(
            {
                "path": path,
                "sha256": "unavailable",
                "role_inference": infer_file_role(
                    {
                        "path": path,
                        "algorithm": item.get("algorithm", ""),
                        "pool": item.get("pool", ""),
                    }
                ),
                "basis": str(item.get("origin_path", "") or item.get("evidence_id", "runtime_profile")).strip() or "runtime_profile",
            }
        )
    return out[:limit]


def extract_ipv4s(text: str) -> list[str]:
    out: list[str] = []
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(text or "")):
        try:
            ipaddress.ip_address(match)
        except ValueError:
            continue
        if match not in out:
            out.append(match)
    return out


def leadership_step_signature(item: dict[str, Any]) -> str:
    source = str(item.get("source", "")).strip().lower()
    command = str(item.get("command", "")).strip().lower()
    excerpt = "\n".join(artifact_excerpt(item, max_lines=8, max_chars=260)).lower()
    return "\n".join(part for part in [source, command, excerpt] if part)


def leadership_step_category(item: dict[str, Any]) -> str:
    signature = leadership_step_signature(item)
    if any(token in signature for token in ["failed password", "invalid user", "authentication failure", "auth.log", "secure", "sshd", "lastb", "btmp"]):
        return "auth"
    if any(token in signature for token in ["cron", "crontab", "execstart", "systemctl", "authorized_keys", "sudoers", "pam", "preload", "/var/tmp/.crond", "/etc/rc.local"]):
        return "persistence"
    if any(token in signature for token in ["ssh -fnd", "frp", "frpc", "frps", "socks", "proxy", "autossh", "ngrok", "chisel"]):
        return "tunnel"
    if any(token in signature for token in ["ps aux", "cmdline", "randomx", "stratum", "xmrig", "miner"]) or str(item.get("source", "")).strip().lower() == "process":
        return "process"
    return "general"


def leadership_step_title(category: str) -> str:
    return {
        "auth": "Review Authentication And Brute-Force Traces",
        "persistence": "Review Persistence Artifacts",
        "process": "Review Suspicious Processes",
        "tunnel": "Review Proxy And Tunneling Traces",
        "general": "Review Additional Host Evidence",
    }.get(category, "Review Additional Host Evidence")


def leadership_step_title_zh_cn(category: str) -> str:
    return {
        "auth": "查看认证与爆破痕迹",
        "persistence": "查看持久化",
        "process": "查看可疑进程",
        "tunnel": "查看代理与转发痕迹",
        "general": "查看补充主机证据",
    }.get(category, "查看补充主机证据")


def leadership_findings_by_evidence(ctx: dict[str, Any], evidence_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in ctx["findings"]:
        if evidence_id in [str(x).strip() for x in as_list(item.get("evidence_ids"))]:
            out.append(as_dict(item))
    return out


def leadership_step_summary(ctx: dict[str, Any], payload: dict[str, Any], item: dict[str, Any], category: str) -> str:
    scene = ctx["scene_reconstruction"]
    if category == "auth":
        counts = as_dict(scene.get("auth_event_counts"))
        failed = safe_int(counts.get("failed", 0))
        invalid = safe_int(counts.get("invalid", 0))
        auth_ips = [str(x) for x in as_list(scene.get("auth_source_ips")) if str(x).strip()]
        if failed or invalid or auth_ips:
            return (
                f"Authentication evidence shows {failed} failed-password event(s), {invalid} invalid-user event(s), "
                f"and source IP(s) including {shorten_list(auth_ips, limit=4) or '-'}."
            )
        return "Authentication evidence is present and should be reviewed for brute-force, reused-credential, or unauthorized-login traces."
    if category == "persistence":
        excerpt = " ".join(artifact_excerpt(item, max_lines=2, max_chars=180))
        if excerpt:
            return f"Persistence-related host evidence is present, including startup or scheduling content such as: {excerpt}"
        return "Persistence-related host evidence is present and should be reviewed for startup, cron, or policy abuse."
    if category == "process":
        runtime_sentence = leadership_runtime_sentence(payload)
        if runtime_sentence:
            return runtime_sentence
        top_cpu = [as_dict(x) for x in as_list(payload.get("top_cpu"))]
        if top_cpu:
            top = top_cpu[0]
            return (
                f"High-CPU runtime evidence is visible via pid {top.get('pid', '-')}, executable {top.get('executable', '-')}, "
                f"and command line {compact_text(str(top.get('command', '') or '-'), max_len=180)}."
            )
        return "Process-side evidence is present and should be reviewed for miner or loader behavior."
    if category == "tunnel":
        excerpt = " ".join(artifact_excerpt(item, max_lines=2, max_chars=180))
        if excerpt:
            return f"Host evidence shows proxy, tunnel, or forwarding behavior such as: {excerpt}"
        return "Host evidence suggests proxy, tunnel, or remote-forwarding activity that should be treated as suspicious until explained."
    evidence_id = str(item.get("id", "")).strip()
    findings = leadership_findings_by_evidence(ctx, evidence_id)
    if findings:
        return str(findings[0].get("statement", "")).strip() or "Additional host evidence contributes to the current conclusion."
    return "Additional host evidence contributes to the current conclusion."


def leadership_step_summary_zh_cn(ctx: dict[str, Any], payload: dict[str, Any], item: dict[str, Any], category: str) -> str:
    scene = ctx["scene_reconstruction"]
    if category == "auth":
        counts = as_dict(scene.get("auth_event_counts"))
        failed = safe_int(counts.get("failed", 0))
        invalid = safe_int(counts.get("invalid", 0))
        auth_ips = [str(x) for x in as_list(scene.get("auth_source_ips")) if str(x).strip()]
        if failed or invalid or auth_ips:
            return (
                f"认证类证据显示，当前至少出现失败口令 `{failed}` 次、无效用户 `{invalid}` 次，"
                f"涉及来源 IP 包括 {zh_natural_join(auth_ips[:4]) or '未恢复'}。"
            )
        return "当前已经取得认证类证据，需重点复核是否存在爆破、凭据复用或未授权登录。"
    if category == "persistence":
        excerpt = " ".join(artifact_excerpt(item, max_lines=2, max_chars=180))
        if excerpt:
            return f"当前已观察到与启动项、计划任务或策略面相关的持久化证据，例如：{excerpt}"
        return "当前已观察到与启动项、计划任务或策略面相关的持久化证据。"
    if category == "process":
        runtime_sentence = leadership_runtime_sentence_zh_cn(payload)
        if runtime_sentence:
            return runtime_sentence
        top_cpu = [as_dict(x) for x in as_list(payload.get("top_cpu"))]
        if top_cpu:
            top = top_cpu[0]
            return (
                f"当前已见高 CPU 运行时证据，PID `{top.get('pid', '-')}`，可执行路径 `{top.get('executable', '-')}`，"
                f"命令 `{compact_text(str(top.get('command', '') or '-'), max_len=180)}`。"
            )
        return "当前已取得进程侧证据，需重点复核矿工、投放器或加载器行为。"
    if category == "tunnel":
        excerpt = " ".join(artifact_excerpt(item, max_lines=2, max_chars=180))
        if excerpt:
            return f"当前主机证据显示存在代理、隧道或转发类行为，例如：{excerpt}"
        return "当前主机证据显示存在代理、隧道或转发类行为。"
    evidence_id = str(item.get("id", "")).strip()
    findings = leadership_findings_by_evidence(ctx, evidence_id)
    if findings:
        return localize_auto_text_zh_cn(str(findings[0].get("statement", "")).strip()) or "这部分主机证据对当前结论形成了补充支撑。"
    return "这部分主机证据对当前结论形成了补充支撑。"


def leadership_steps(ctx: dict[str, Any], payload: dict[str, Any], limit: int = 4) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    used_categories: set[str] = set()
    categories_in_order = ["auth", "persistence", "process", "tunnel", "general"]
    evidence_items = leadership_evidence_items(ctx, payload, limit=max(limit * 2, 6))
    categorized: dict[str, list[dict[str, Any]]] = {key: [] for key in categories_in_order}
    for item in evidence_items:
        category = leadership_step_category(item)
        categorized.setdefault(category, []).append(item)
    for category in categories_in_order:
        items = categorized.get(category) or []
        if not items or category in used_categories:
            continue
        used_categories.add(category)
        selected.append({"category": category, "item": items[0]})
        if len(selected) >= limit:
            break
    return selected


def leadership_ip_entries(ctx: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(ip: str, reason: str, reason_zh: str) -> None:
        value = str(ip).strip()
        if not value or value in seen:
            return
        seen.add(value)
        entries.append({"ip": value, "reason": reason, "reason_zh": reason_zh})

    for ip in [str(x) for x in as_list(payload.get("auth_ips"))]:
        add(ip, "Observed in authentication evidence.", "出现在认证类证据中。")
    for item in [as_dict(x) for x in as_list(ctx.get("ip_traces"))]:
        ip = str(item.get("ip", "")).strip()
        if not ip:
            continue
        reason = str(item.get("reason", "")).strip() or "Observed in IP trace records."
        add(ip, reason, localize_auto_text_zh_cn(reason) or "出现在 IP 溯源记录中。")
    for profile in [as_dict(x) for x in as_list(payload.get("runtime_profiles"))]:
        for field in ["pool", "proxy"]:
            for ip in extract_ipv4s(str(profile.get(field, ""))):
                add(ip, "Observed in miner runtime pool/proxy parameters.", "出现在矿工运行参数的矿池或代理字段中。")
    for item in ctx["evidence_items"]:
        signature = leadership_step_signature(item)
        reason = ""
        reason_zh = ""
        if "ssh -fnd" in signature or "frp" in signature or "proxy" in signature or "socks" in signature:
            reason = "Observed in proxy or tunnel evidence."
            reason_zh = "出现在代理或隧道相关证据中。"
        elif leadership_step_category(item) == "auth":
            reason = "Observed in authentication evidence."
            reason_zh = "出现在认证类证据中。"
        if reason:
            for ip in extract_ipv4s(str(item.get("command", "")) + "\n" + "\n".join(artifact_excerpt(item, max_lines=8, max_chars=240))):
                add(ip, reason, reason_zh)
    return entries


def lateral_signal_label_zh_cn(value: str) -> str:
    return {
        "active_connection": "当前活动连接",
        "ssh_toolchain": "SSH 远程操作痕迹",
        "scp_toolchain": "SCP 传输痕迹",
        "sftp_toolchain": "SFTP 传输痕迹",
        "rsync_toolchain": "rsync 传输痕迹",
        "nc_toolchain": "nc 通信痕迹",
        "ncat_toolchain": "ncat 通信痕迹",
        "socat_toolchain": "socat 转发痕迹",
        "curl_toolchain": "curl 远端下载痕迹",
        "wget_toolchain": "wget 远端下载痕迹",
        "autossh_toolchain": "autossh 隧道痕迹",
        "frp_toolchain": "FRP 隧道痕迹",
        "frpc_toolchain": "frpc 隧道痕迹",
        "frps_toolchain": "frps 隧道痕迹",
        "no_live_connection": "当前未见对应活动连接",
    }.get(str(value).strip(), str(value).strip() or "未知信号")


def render_lateral_review_lines_zh_cn(
    scene: dict[str, Any],
    maybe_redact,
    evidence_refs: Callable[[list[Any]], str] | None = None,
) -> list[str]:
    review = as_dict(scene.get("lateral_movement_review"))
    active_peers = [as_dict(x) for x in as_list(review.get("active_outbound_peers"))]
    conservative_targets = [as_dict(x) for x in as_list(review.get("conservative_lateral_targets"))]
    pivot_targets = [as_dict(x) for x in as_list(review.get("external_pivot_required_targets"))]

    lines: list[str] = []
    if active_peers:
        lines.append("### 当前活动外联")
        for item in active_peers:
            signals = "、".join(lateral_signal_label_zh_cn(x) for x in as_list(item.get("supporting_signals")))
            text = (
                f"- `{maybe_redact(str(item.get('ip', 'unknown')))}`"
                f": 进程=`{maybe_redact(str(item.get('process', '-') or '-'))}`"
                f" 路径=`{maybe_redact(str(item.get('path', '-') or '-'))}`"
                f" 远端端口=`{maybe_redact(str(item.get('port', '-') or '-'))}`"
            )
            if signals:
                text += f"；依据={maybe_redact(signals)}"
            if evidence_refs:
                text += f"；证据={evidence_refs(as_list(item.get('evidence_ids')))}"
            lines.append(text)
    else:
        lines.extend(["### 当前活动外联", "- 本轮未恢复出可明确归入外连方向的活动连接。"])

    if conservative_targets:
        lines.append("### 保守疑似横向目标")
        for item in conservative_targets:
            signals = "、".join(lateral_signal_label_zh_cn(x) for x in as_list(item.get("supporting_signals")))
            text = (
                f"- `{maybe_redact(str(item.get('ip', 'unknown')))}`"
                f": 进程=`{maybe_redact(str(item.get('process', '-') or '-'))}`"
                f" 路径=`{maybe_redact(str(item.get('path', '-') or '-'))}`"
                "；结论边界=当前既见活动连接，也见到第二信号，因此只保守标记为疑似横向目标，不直接认定已成功控制对端。"
            )
            if signals:
                text += f"；支撑={maybe_redact(signals)}"
            if evidence_refs:
                text += f"；证据={evidence_refs(as_list(item.get('evidence_ids')))}"
            lines.append(text)
    else:
        lines.extend(["### 保守疑似横向目标", "- 当前没有同时满足“活动连接 + 第二信号”的保守疑似横向目标。"])

    if pivot_targets:
        lines.append("### 仍需外部补证的目标")
        for item in pivot_targets:
            signals = "、".join(lateral_signal_label_zh_cn(x) for x in as_list(item.get("supporting_signals")))
            counters = "、".join(lateral_signal_label_zh_cn(x) for x in as_list(item.get("counter_signals")))
            text = (
                f"- `{maybe_redact(str(item.get('ip', 'unknown')))}`"
                f": 进程=`{maybe_redact(str(item.get('process', '-') or '-'))}`"
                f" 路径=`{maybe_redact(str(item.get('path', '-') or '-'))}`"
                "；原因=当前只看到了远程操作工具链痕迹，未同步观察到对应活动连接，需要结合更多主机外证据补证。"
            )
            if signals:
                text += f"；支撑={maybe_redact(signals)}"
            if counters:
                text += f"；反证/缺口={maybe_redact(counters)}"
            if evidence_refs:
                text += f"；证据={evidence_refs(as_list(item.get('evidence_ids')))}"
            lines.append(text)
    else:
        lines.extend(["### 仍需外部补证的目标", "- 当前没有仅凭工具链痕迹暴露、但仍需额外补证的横向目标。"])
    return lines


def render_hidden_process_review_lines_zh_cn(
    scene: dict[str, Any],
    maybe_redact,
    evidence_refs: Callable[[list[Any]], str] | None = None,
) -> list[str]:
    review = as_dict(scene.get("hidden_process_review"))
    deleted = [as_dict(x) for x in as_list(review.get("deleted_exe_processes"))]
    suspicions = [as_dict(x) for x in as_list(review.get("hidden_process_suspicions"))]
    malware_files = [as_dict(x) for x in as_list(scene.get("malware_file_candidates"))]

    lines: list[str] = []
    if deleted:
        lines.append("### 已删除但仍在运行的可执行体")
        for item in deleted:
            text = (
                f"- PID=`{maybe_redact(str(item.get('pid', 'unknown')))}`"
                f" 路径=`{maybe_redact(str(item.get('path', '-') or '-'))}`"
            )
            if evidence_refs:
                text += f"；证据={evidence_refs(as_list(item.get('evidence_ids')))}"
            lines.append(text)
    else:
        lines.extend(["### 已删除但仍在运行的可执行体", "- 本轮未观察到 `/proc/<pid>/exe -> ... (deleted)` 的直接证据。"])

    if suspicions:
        lines.append("### 隐藏进程与伪装运行体疑点")
        for item in suspicions:
            text = (
                f"- PID=`{maybe_redact(str(item.get('pid', 'unknown')))}`"
                f" 名称=`{maybe_redact(str(item.get('name', '-') or '-'))}`"
                f" 路径=`{maybe_redact(str(item.get('path', '-') or '-'))}`"
                f"；原因={maybe_redact(localize_auto_text_zh_cn(str(item.get('reason', ''))))}"
            )
            if evidence_refs:
                text += f"；证据={evidence_refs(as_list(item.get('evidence_ids')))}"
            lines.append(text)
    else:
        lines.extend(["### 隐藏进程与伪装运行体疑点", "- 当前未形成结构化的隐藏进程疑点条目。"])

    if malware_files:
        lines.append("### 关联文件哈希")
        for item in malware_files[:6]:
            lines.append(
                f"- 路径=`{maybe_redact(str(item.get('path', '') or item.get('origin_path', '-') or '-'))}`"
                f" sha256=`{maybe_redact(str(item.get('sha256', '') or '未获取'))}`"
            )
    return lines


def leadership_evidence_items(ctx: dict[str, Any], payload: dict[str, Any], limit: int = 4) -> list[dict[str, Any]]:
    evid_idx = ctx["evid_idx"]
    ordered_ids: list[str] = []
    for raw in as_list(payload.get("evidence_excerpt_ids")):
        evid = str(raw).strip()
        if evid and evid not in ordered_ids:
            ordered_ids.append(evid)
    for item in ctx["evidence_items"]:
        evid = str(item.get("id", "")).strip()
        if evid and evid not in ordered_ids:
            ordered_ids.append(evid)
        if len(ordered_ids) >= limit:
            break
    selected: list[dict[str, Any]] = []
    for evid in ordered_ids[:limit]:
        item = as_dict(evid_idx.get(evid))
        if item:
            selected.append(item)
    return selected


def leadership_evidence_note(item: dict[str, Any]) -> str:
    source = str(item.get("source", "")).strip().lower()
    if source == "process":
        return "Process-side evidence showing the executable path or command line that was actually captured during collection."
    if source == "auth":
        return "Authentication-side evidence showing login activity preserved in host logs or fallback auth artifacts."
    if source in {"network", "socket"}:
        return "Network-side evidence showing host exposure or remote communication that was directly observed."
    if source in {"file", "filesystem"}:
        return "File-side evidence showing a path or artifact that should be reviewed together with its hash and origin."
    return "Direct excerpt preserved from the collected artifact so the conclusion can be traced back to raw host evidence."


def leadership_evidence_note_zh_cn(item: dict[str, Any]) -> str:
    source = str(item.get("source", "")).strip().lower()
    if source == "process":
        return "这是进程侧证据，用来说明采集当时主机上实际看到的可执行路径或命令行参数。"
    if source == "auth":
        return "这是认证侧证据，用来说明主机日志或替代认证产物里实际记录到的登录行为。"
    if source in {"network", "socket"}:
        return "这是网络侧证据，用来说明主机暴露面或实际观察到的远程通信。"
    if source in {"file", "filesystem"}:
        return "这是文件侧证据，用来说明需要结合路径、来源和哈希一起复核的可疑产物。"
    return "这是直接保留的原始证据摘录，便于把报告结论回溯到主机侧原始事实。"


def leadership_file_role_label(value: str) -> str:
    return {
        "miner_runtime": "miner runtime",
        "launcher_or_dropper": "launcher / dropper",
        "candidate_binary": "suspicious binary candidate",
        "unknown": "unknown",
    }.get(str(value).strip(), str(value).strip() or "unknown")


def leadership_file_role_label_zh_cn(value: str) -> str:
    return {
        "miner_runtime": "矿工运行体",
        "launcher_or_dropper": "投放器或启动器",
        "candidate_binary": "可疑二进制候选",
        "unknown": "未知",
    }.get(str(value).strip(), str(value).strip() or "未知")


def leadership_source_label_zh_cn(value: str) -> str:
    return {
        "process": "进程",
        "auth": "认证",
        "network": "网络",
        "socket": "套接字",
        "file": "文件",
        "filesystem": "文件系统",
        "unknown": "未知",
    }.get(str(value).strip().lower(), str(value).strip() or "未知")


def leadership_runtime_sentence(payload: dict[str, Any]) -> str:
    profiles = [as_dict(item) for item in as_list(payload.get("runtime_profiles"))]
    if not profiles:
        return ""
    item = profiles[0]
    return (
        f"The clearest runtime indicator is `{str(item.get('executable', '') or '-')}` using algorithm "
        f"`{str(item.get('algorithm', '') or '-')}`, pool `{str(item.get('pool', '') or '-')}`, wallet "
        f"`{str(item.get('wallet', '') or '-')}`, and `{str(item.get('cpu_threads', '') or '-')}` CPU thread(s)."
    )


def leadership_runtime_sentence_zh_cn(payload: dict[str, Any]) -> str:
    profiles = [as_dict(item) for item in as_list(payload.get("runtime_profiles"))]
    if not profiles:
        return ""
    item = profiles[0]
    return (
        f"当前最清晰的运行时线索是 `{str(item.get('executable', '') or '-')}`，算法 "
        f"`{str(item.get('algorithm', '') or '-')}`，矿池 `{str(item.get('pool', '') or '-')}`，钱包 "
        f"`{str(item.get('wallet', '') or '-')}`，CPU 线程 `{str(item.get('cpu_threads', '') or '-')}`。"
    )


def leadership_log_status_summary(payload: dict[str, Any]) -> str:
    if safe_int(payload.get("log_risk_count", 0)) <= 0:
        return "No distro-applicable primary-log gap is visible in current host evidence."
    if str(payload.get("log_layout_status", "")).strip() == "reduced_visibility_on_expected_logs":
        adjusted = safe_int(payload.get("log_layout_adjusted_count", 0)) or safe_int(payload.get("log_risk_count", 0))
        return (
            f"Applicable host logs still show {adjusted} missing or suspicious item(s); attribution confidence should be reduced."
        )
    summary = str(payload.get("log_layout_summary", "")).strip()
    if summary:
        return summary
    return f"{payload.get('log_risk_count', 0)} primary-log artifact(s) remain missing, suspicious, or tampered in current visibility."


def leadership_log_status_summary_zh_cn(payload: dict[str, Any]) -> str:
    if safe_int(payload.get("log_risk_count", 0)) <= 0:
        return "当前主机证据里未见适用主日志存在明确缺口。"
    if str(payload.get("log_layout_status", "")).strip() == "reduced_visibility_on_expected_logs":
        adjusted = safe_int(payload.get("log_layout_adjusted_count", 0)) or safe_int(payload.get("log_risk_count", 0))
        return f"适用主日志仍有 `{adjusted}` 项缺失或可疑，攻击链归因置信度应相应下调。"
    summary = str(payload.get("log_layout_summary", "")).strip()
    if summary:
        return localize_auto_text_zh_cn(summary)
    return f"当前仍有 `{payload.get('log_risk_count', 0)}` 项主日志产物缺失、可疑或疑似被篡改。"


def leadership_conclusion_paragraph(ctx: dict[str, Any], payload: dict[str, Any], posture: dict[str, Any]) -> str:
    if collection_failed(ctx):
        reason = str(payload.get("collection_failure_reason", "unknown") or "unknown").rstrip(".")
        return (
            "Based on the current host-side read-only evidence, no compromise conclusion can be made because "
            "collection failed before host-side evidence could be gathered. "
            f"The current blocker is {reason}. "
            "This bundle should be treated as an evidence-preserving failure record until read-only collection succeeds."
        )
    parts = [
        f"Based on the current host-side read-only evidence, the current case picture is as follows: {posture['verdict']}",
    ]
    runtime_sentence = leadership_runtime_sentence(payload)
    if runtime_sentence:
        parts.append(runtime_sentence)
    entry_items = leadership_entry_items(payload, limit=1)
    if entry_items:
        parts.append(f"The leading entry-path hypothesis is: {str(entry_items[0].get('label', '')).strip()}")
    parts.append("Current host-only evidence still does not establish actor attribution.")
    scope_gap = public_scope_gap_summary(payload)
    if scope_gap:
        parts.append(scope_gap)
    return " ".join(part for part in parts if part)


def leadership_conclusion_paragraph_zh_cn(ctx: dict[str, Any], payload: dict[str, Any], posture: dict[str, Any]) -> str:
    if collection_failed(ctx):
        reason = localize_auto_text_zh_cn(str(payload.get("collection_failure_reason", "unknown") or "unknown")).rstrip("。")
        return (
            "基于当前主机侧只读证据，目前无法输出是否被入侵的结论，因为主机侧证据在建立前采集就已经失败。"
            f"当前阻塞点是：{reason}。"
            "在只读采集重新成功前，这个案件包只能作为失败留痕，不能外推出入侵事实。"
        )
    parts = [
        f"基于当前主机侧只读证据，当前案件图景如下：{localize_auto_text_zh_cn(posture['verdict'])}",
    ]
    runtime_sentence = leadership_runtime_sentence_zh_cn(payload)
    if runtime_sentence:
        parts.append(runtime_sentence)
    entry_items = leadership_entry_items(payload, limit=1)
    if entry_items:
        parts.append(f"现阶段最优先的进入路径假设是：{str(entry_items[0].get('label_zh', '')).strip()}")
    parts.append("但仅凭当前主机侧证据，仍无法完成攻击者归因。")
    scope_gap = public_scope_gap_summary_zh_cn(payload)
    if scope_gap:
        parts.append(scope_gap)
    return "".join(part if part.endswith(("。", "！", "？")) else f"{part}" for part in parts)


def build_leadership_report(data: dict[str, Any], redact: bool, case_dir: str | None = None) -> str:
    ctx = prepare_report_context(data, redact=redact, strict=False, case_dir=case_dir)
    payload = leadership_payload(ctx)
    posture = investigation_posture_payload(ctx)

    def maybe_redact(value: str) -> str:
        return sanitize_report_text(value, redact)

    case_id = leadership_case_id(data, ctx)
    lines = [
        f"# {ctx['title']} - Leadership Review Report",
        "",
        "## Conclusion",
        maybe_redact(leadership_conclusion_paragraph(ctx, payload, posture)),
        "",
        f"- **Case ID:** `{maybe_redact(case_id)}`",
        f"- **Host:** `{maybe_redact(ctx['host_name'])}` (`{maybe_redact(ctx['host_ip'])}`)",
        f"- **OS:** `{maybe_redact(ctx['os_name'])}`",
        f"- **Observation Window (UTC):** `{ctx['window_start']}` -> `{ctx['window_end']}`",
        f"- **Earliest Relevant Time:** `{maybe_redact(payload['intrusion_window'])}`",
        "- **Read-Only Scope:** `0` state-changing actions were executed during this collection.",
        "",
    ]
    if ctx["collection_failed"]:
        lines.extend(
            [
                "## Collection Failure",
                "- Collection failed before host-side evidence could be gathered.",
                f"- **Phase:** `{maybe_redact(payload['collection_failure_phase'] or 'unknown')}`",
                f"- **Reason:** {maybe_redact(payload['collection_failure_reason'] or '-')}",
                f"- **Retry Guidance:** {maybe_redact(payload['collection_retry_guidance'] or '-')}",
                "",
            ]
        )
    if not ctx["collection_failed"]:
        lines.extend(["## How The Conclusion Was Reached", ""])
        steps = leadership_steps(ctx, payload, limit=4)
        for index, step in enumerate(steps, start=1):
            item = as_dict(step.get("item"))
            category = str(step.get("category", "general"))
            lines.extend(
                [
                    f"### Step {index}. {leadership_step_title(category)}",
                    maybe_redact(leadership_step_summary(ctx, payload, item, category)),
                    "",
                    "```bash",
                    maybe_redact(str(item.get("command", "")).strip() or "# command unavailable"),
                    "```",
                    "",
                    "```text",
                ]
            )
            excerpt = artifact_excerpt(item, max_lines=8, max_chars=260)
            if excerpt:
                lines.extend(maybe_redact(part) for part in excerpt)
            else:
                lines.append("artifact excerpt unavailable")
            lines.extend(["```", ""])

        lines.extend(["## Affected IPs"])
        ip_entries = leadership_ip_entries(ctx, payload)
        if ip_entries:
            for item in ip_entries:
                lines.append(
                    f"- `{maybe_redact(item['ip'])}`: {maybe_redact(item['reason'])}"
                )
        else:
            lines.append("- No additional affected or related IP was recovered in current host visibility.")
        lines.append("")

    lines.append("## Suspicious Files And Hashes")
    file_entries = leadership_file_entries(payload, limit=8)
    if file_entries:
        for item in file_entries:
            lines.append(
                f"- Path=`{maybe_redact(str(item.get('path', '') or '-'))}` | sha256=`{maybe_redact(str(item.get('sha256', '') or 'unavailable'))}` "
                f"| likely role=`{maybe_redact(leadership_file_role_label(str(item.get('role_inference', 'unknown'))))}` "
                f"| basis=`{maybe_redact(str(item.get('basis', '') or 'unknown'))}`"
            )
    else:
        lines.append("- No suspicious path/hash pair was recovered in current visibility.")

    lines.extend(
        [
            "",
            "## Recommended Response",
            "1. Preserve the current host state and keep the workflow read-only until a separate change approval is granted.",
            "2. If the host is business-critical, prefer rollback-safe network controls over destructive on-host actions.",
            "3. Collect non-host corroboration next: bastion, VPN, identity-provider, firewall, DNS, cloud, and container audit records as applicable.",
            "4. Review every suspicious path and hash against threat intelligence, package ownership, and known-good baselines before remediation.",
            "5. Rotate or revoke the credentials, keys, and tokens that could plausibly explain the suspected entry path.",
            "",
            "## Remaining Uncertainties",
            "- Actor attribution remains unproven from host-only evidence.",
        ]
    )
    if not ctx["collection_failed"]:
        entry_items = leadership_entry_items(payload, limit=1)
        if entry_items:
            lines.append(f"- Leading entry-path hypothesis: {maybe_redact(str(entry_items[0].get('label', '')).strip())}")
        lines.append(f"- {maybe_redact(leadership_log_status_summary(payload))}")
    timeline_gap = public_timeline_gap_summary(payload)
    if timeline_gap:
        lines.append(f"- {maybe_redact(timeline_gap)}")
    scope_gap = public_scope_gap_summary(payload)
    if scope_gap:
        lines.append(f"- {maybe_redact(scope_gap)}")
    if safe_int(payload.get("log_risk_count", 0)) > 0:
        lines.append(f"- {maybe_redact(leadership_log_status_summary(payload))}")
    return "\n".join(lines).strip() + "\n"


def build_leadership_report_zh_cn(data: dict[str, Any], redact: bool, case_dir: str | None = None) -> str:
    ctx = prepare_report_context(data, redact=redact, strict=False, case_dir=case_dir)
    payload = leadership_payload(ctx)
    posture = investigation_posture_payload(ctx)

    def maybe_redact(value: str) -> str:
        return zh_report_text(value, redact)

    case_id = leadership_case_id(data, ctx)
    lines = [
        f"# {ctx['title']} - 领导复核报告",
        "",
        "## 结论",
        maybe_redact(leadership_conclusion_paragraph_zh_cn(ctx, payload, posture)),
        "",
        f"- **案件 ID：** `{sanitize_report_text(case_id, redact)}`",
        f"- **主机：** `{sanitize_report_text(ctx['host_name'], redact)}` (`{sanitize_report_text(ctx['host_ip'], redact)}`)",
        f"- **操作系统：** `{zh_report_text(ctx['os_name'], redact)}`",
        f"- **观察窗口（UTC）：** `{ctx['window_start']}` -> `{ctx['window_end']}`",
        f"- **最早相关时间：** `{sanitize_report_text(payload['intrusion_window'], redact)}`",
        "- **只读约束：** 本次采集未执行任何状态变更命令。",
        "",
    ]
    if ctx["collection_failed"]:
        lines.extend(
            [
                "## 采集失败说明",
                f"- **失败阶段：** `{sanitize_report_text(payload['collection_failure_phase'] or 'unknown', redact)}`",
                f"- **失败原因：** {maybe_redact(str(payload.get('collection_failure_reason', '-') or '-'))}",
                f"- **重试建议：** {maybe_redact(str(payload.get('collection_retry_guidance', '-') or '-'))}",
                "",
            ]
        )
    if not ctx["collection_failed"]:
        lines.extend(["## 发现过程", ""])
        steps = leadership_steps(ctx, payload, limit=4)
        for index, step in enumerate(steps, start=1):
            item = as_dict(step.get("item"))
            category = str(step.get("category", "general"))
            lines.extend(
                [
                    f"### 步骤 {index}：{leadership_step_title_zh_cn(category)}",
                    sanitize_report_text(leadership_step_summary_zh_cn(ctx, payload, item, category), redact),
                    "",
                    "```bash",
                    sanitize_report_text(str(item.get("command", "")).strip() or "# command unavailable", redact),
                    "```",
                    "",
                    "```text",
                ]
            )
            excerpt = artifact_excerpt(item, max_lines=8, max_chars=260)
            if excerpt:
                lines.extend(sanitize_report_text(part, redact) for part in excerpt)
            else:
                lines.append("当前案件包中未保留可直接摘录的原始输出。")
            lines.extend(["```", ""])

        lines.extend(["## 受波及 IP"])
        ip_entries = leadership_ip_entries(ctx, payload)
        if ip_entries:
            for item in ip_entries:
                lines.append(
                    f"- `{sanitize_report_text(item['ip'], redact)}`：{sanitize_report_text(item['reason_zh'], redact)}"
                )
        else:
            lines.append("- 当前主机可见性范围内未恢复出更多受波及或关联 IP。")
        lines.append("")

        lines.extend(["## 当前外联与保守疑似横向目标"])
        lines.extend(render_lateral_review_lines_zh_cn(ctx["scene_reconstruction"], maybe_redact))
        lines.append("")

        lines.extend(["## 隐藏进程与伪装运行体异常"])
        lines.extend(render_hidden_process_review_lines_zh_cn(ctx["scene_reconstruction"], maybe_redact))
        lines.append("")

    lines.append("## 可疑文件与哈希")
    file_entries = leadership_file_entries(payload, limit=8)
    if file_entries:
        for item in file_entries:
            lines.append(
                f"- 路径=`{sanitize_report_text(str(item.get('path', '') or '-'), redact)}` | "
                f"sha256=`{sanitize_report_text(str(item.get('sha256', '') or '未获取'), redact)}` | "
                f"作用判断=`{leadership_file_role_label_zh_cn(str(item.get('role_inference', 'unknown')) )}` | "
                f"依据=`{sanitize_report_text(str(item.get('basis', '') or '未知'), redact)}`"
            )
    else:
        lines.append("- 当前视野内未恢复出可疑路径与哈希配对结果。")

    lines.extend(
        [
            "",
            "## 处置建议",
            "1. 先保现场，继续保持只读，不要在未单独审批前执行杀进程、删文件、停服务或重启。",
            "2. 若主机承载业务，优先通过可回滚的网络侧手段限制异常外联，不要直接做破坏性主机操作。",
            "3. 立即补拉主机外证据：堡垒机、VPN、身份系统、边界防火墙、DNS、云审计与容器审计。",
            "4. 将本报告列出的可疑路径和哈希送去做威胁情报、软件包归属和基线对照，再决定是否进入处置步骤。",
            "5. 对可能解释入口的口令、密钥和令牌做轮换或吊销，但要纳入单独的变更审批流程。",
            "",
            "## 仍待补证与判断边界",
            "- 仅凭当前主机侧证据，仍无法完成攻击者归因。",
        ]
    )
    if not ctx["collection_failed"]:
        entry_items = leadership_entry_items(payload, limit=1)
        if entry_items:
            lines.append(f"- 现阶段最优先的进入路径假设是：{sanitize_report_text(str(entry_items[0].get('label_zh', '')).strip(), redact)}")
        lines.append(f"- {sanitize_report_text(leadership_log_status_summary_zh_cn(payload), redact)}")
    timeline_gap = public_timeline_gap_summary_zh_cn(payload)
    if timeline_gap:
        lines.append(f"- {sanitize_report_text(timeline_gap, redact)}")
    scope_gap = public_scope_gap_summary_zh_cn(payload)
    if scope_gap:
        lines.append(f"- {sanitize_report_text(scope_gap, redact)}")
    if safe_int(payload.get("log_risk_count", 0)) > 0:
        lines.append(f"- {sanitize_report_text(leadership_log_status_summary_zh_cn(payload), redact)}")
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
    failure = collection_failure_info(ctx)
    if collection_failed(ctx):
        return {
            "posture": "unknown",
            "verdict": "Collection failed before host-side evidence could be gathered.",
            "boundary": "No investigative conclusion should be drawn from this bundle until host-side collection succeeds.",
            "focus": "Fix trust/auth/channel issues, preserve the failure bundle, and use external telemetry only as temporary corroboration before rerunning read-only collection.",
            "process_hits": 0,
            "network_hits": 0,
            "gpu_hits": 0,
            "runtime_profile_hits": 0,
            "access_hits": 0,
            "container_hits": 0,
            "kernel_hits": 0,
            "unknown_trace_count": 0,
            "collection_failure_phase": str(failure.get("phase", "unknown")),
            "collection_failure_reason": str(
                failure.get("reason", "Host-side collection failed before evidence could be gathered.")
            ),
            "collection_retry_guidance": str(
                failure.get(
                    "retry_guidance",
                    "Review SSH trust, authentication, and shell/channel compatibility before retrying.",
                )
            ),
            "collection_safe_to_retry": bool(failure.get("safe_to_retry_without_new_credentials", False)),
        }

    scene = ctx["scene_reconstruction"]
    second_pass = as_dict(ctx.get("second_pass_review"))
    persistence_review = as_dict(second_pass.get("persistence_surface_review") or scene.get("persistence_surface_review"))
    process_hits = safe_int(scene.get("process_ioc_match_count", 0))
    network_hits = safe_int(scene.get("network_ioc_hit_count", 0))
    gpu_hits = safe_int(scene.get("gpu_suspicious_process_count", 0))
    runtime_profile_hits = safe_int(scene.get("runtime_profile_count", 0))
    access_hits = (
        safe_int(persistence_review.get("high_signal_count", 0))
        + safe_int(persistence_review.get("policy_signal_count", 0))
    ) or safe_int(scene.get("initial_access_review_hit_count", 0))
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
    contradiction_review = as_dict(ctx["contradiction_review"])
    deception_risk_level = str(contradiction_review.get("deception_risk_level", "unknown")).strip() or "unknown"
    deception_signal_count = int(contradiction_review.get("count", 0) or 0)
    if collection_failed(ctx):
        failure = collection_failure_info(ctx)
        failure_phase = str(failure.get("phase", "unknown")).strip() or "unknown"
        failure_reason = str(
            failure.get("reason", "Host-side collection failed before evidence could be gathered.")
        ).strip()
        retry_guidance = str(
            failure.get(
                "retry_guidance",
                "Review SSH trust, authentication, and shell/channel compatibility before retrying.",
            )
        ).strip()
        return [
            anchor_tag("report-conclusion"),
            "## Investigation Conclusion",
            "",
            f"- **Verdict:** {maybe_redact(posture_info['verdict'])}",
            f"- **Confidence Posture:** {confidence_icon(posture)} `{posture}`",
            f"- **Decision Boundary:** {maybe_redact(posture_info['boundary'])}",
            f"- **Read-Only Scope:** `0` state-changing actions executed during this collection.",
            "",
            "### Collection Failure",
            f"- **Failure Phase:** `{maybe_redact(failure_phase)}`",
            f"- **Reason:** {maybe_redact(failure_reason or '-')}",
            f"- **Retry Guidance:** {maybe_redact(retry_guidance or '-')}",
            "- **Host-Side Evidence Availability:** `none`",
            "",
            "### Remaining Gaps",
            "- **Primary Gap:** No host-side evidence was gathered, so compromise, persistence, and attribution remain unknown.",
            f"- **Deception Risk:** `{deception_risk_level}` with `{deception_signal_count}` contradiction signal(s).",
            "- **Next Reading Path:** [Findings](#report-findings) | [Timeline](#report-timeline) | [Evidence Details](#report-evidence-details)",
            "",
        ]
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
            f"- **Deception Risk:** `{deception_risk_level}` with `{deception_signal_count}` contradiction signal(s).",
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
    contradiction_review = as_dict(ctx["contradiction_review"])
    deception_risk_level = str(contradiction_review.get("deception_risk_level", "unknown")).strip() or "unknown"
    deception_signal_count = int(contradiction_review.get("count", 0) or 0)
    posture_label = {
        "high": "高",
        "medium": "中",
        "low": "低",
        "unknown": "未知",
    }.get(posture, posture)
    if collection_failed(ctx):
        failure = collection_failure_info(ctx)
        failure_phase = str(failure.get("phase", "unknown")).strip() or "unknown"
        failure_reason = str(
            failure.get("reason", "Host-side collection failed before evidence could be gathered.")
        ).strip()
        retry_guidance = str(
            failure.get(
                "retry_guidance",
                "Review SSH trust, authentication, and shell/channel compatibility before retrying.",
            )
        ).strip()
        return [
            anchor_tag("report-conclusion"),
            "## 核心结论",
            "",
            f"- **结论：** {maybe_redact(localize_auto_text_zh_cn(posture_info['verdict']))}",
            f"- **置信度态势：** {confidence_icon(posture)} `{posture_label}`",
            f"- **判断边界：** {maybe_redact(localize_auto_text_zh_cn(posture_info['boundary']))}",
            "- **只读约束：** 本次采集未执行任何状态变更命令。",
            "",
            "### 采集失败",
            f"- **失败阶段：** `{maybe_redact(failure_phase)}`",
            f"- **失败原因：** {maybe_redact(failure_reason or '-')}",
            f"- **重试建议：** {maybe_redact(retry_guidance or '-')}",
            "- **主机侧证据状态：** `未建立`",
            "",
            "### 未解决缺口",
            "- **主要缺口：** 当前没有采集到主机侧证据，因此是否被入侵、是否存在持久化、是否能够归因都仍然未知。",
            f"- **欺骗风险：** `{maybe_redact({'high': '高', 'medium': '中', 'low': '低', 'unknown': '未知'}.get(deception_risk_level, deception_risk_level))}`，共 `{deception_signal_count}` 条矛盾信号。",
            "- **继续阅读：** [结论与研判](#report-findings) | [时间线](#report-timeline) | [证据详情](#report-evidence-details)",
            "",
        ]

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
            f"- **欺骗风险：** `{maybe_redact({'high': '高', 'medium': '中', 'low': '低', 'unknown': '未知'}.get(deception_risk_level, deception_risk_level))}`，共 `{deception_signal_count}` 条矛盾信号。",
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
    investigation_scope = as_dict(data.get("investigation_scope") or scene_reconstruction.get("investigation_scope"))
    platform_identity = as_dict(scene_reconstruction.get("platform_identity"))
    local_privesc_review = as_dict(scene_reconstruction.get("local_privesc_review"))
    environment_constraints = as_dict(scene_reconstruction.get("environment_constraints") or data.get("collection_constraints"))
    contradiction_review = as_dict(scene_reconstruction.get("contradiction_review"))
    second_pass_review = as_dict(data.get("second_pass_review") or scene_reconstruction.get("second_pass_review"))
    collection_failure = as_dict(data.get("collection_failure"))
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
    log_risk_count = adjusted_log_risk_count(data, log_integrity)
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
        "investigation_scope": investigation_scope,
        "platform_identity": platform_identity,
        "local_privesc_review": local_privesc_review,
        "environment_constraints": environment_constraints,
        "contradiction_review": contradiction_review,
        "second_pass_review": second_pass_review,
        "collection_failure": collection_failure,
        "collection_failed": str(collection_failure.get("status", "")).strip().lower() == "failed",
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
        "os_name": derive_platform_os_name(str(host.get("os", "unknown")), platform_identity),
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
    contradiction_review = as_dict(ctx["contradiction_review"])
    environment_constraints = as_dict(ctx["environment_constraints"])

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
        "- [Environment Constraints](#report-environment-constraints)",
        "- [Privilege Scope](#report-privilege-scope)",
        "- [Scene Snapshot](#report-scene-snapshot)",
        "- [Deception Review](#report-deception-review)",
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
        f"- **Requested Focus:** {maybe_redact(', '.join(as_list(ctx['investigation_scope'].get('requested_focus'))) or 'general-compromise-review')}",
        f"- **Expected Workload:** {maybe_redact(ctx['expected_workload'] or 'not provided')}",
        f"- **Artifact Hash Catalog:** `{artifact_hashes.get('count', len(evidence_items))}` item(s), algorithm `{artifact_hashes.get('algorithm', 'unknown')}`",
        f"- **Deception Risk:** `{maybe_redact(str(contradiction_review.get('deception_risk_level', 'unknown')))}`",
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
        anchor_tag("report-environment-constraints"),
        "## Environment Constraints",
        f"- **External Tool Download Required:** `{maybe_redact(str(environment_constraints.get('external_tool_download_required', 'unknown')))}`",
        f"- **External Tool Download Attempted:** `{maybe_redact(str(environment_constraints.get('external_tool_download_attempted', 'unknown')))}`",
        f"- **Network Assessment Mode:** `{maybe_redact(str(environment_constraints.get('network_assessment_mode', 'unknown')))}`",
        f"- **Passive Summary:** {maybe_redact(str(environment_constraints.get('summary', environment_constraints.get('signals', {})) or 'not collected'))}",
        "",
        anchor_tag("report-privilege-scope"),
        "## Privilege Scope",
        f"- **Observed User:** `{maybe_redact(str(privilege_scope.get('user', 'unknown')))}`",
        f"- **Observed UID:** `{maybe_redact(str(privilege_scope.get('uid', 'unknown')))}`",
        f"- **Passwordless Sudo Visible:** `{maybe_redact(str(privilege_scope.get('passwordless_sudo_visible', 'unknown')))}`",
        f"- **Kernel Release:** `{maybe_redact(str(ctx['platform_identity'].get('kernel_release', 'unknown')))}`",
        f"- **OS Release:** `{maybe_redact(str(ctx['platform_identity'].get('os_release_id', 'unknown')))} {maybe_redact(str(ctx['platform_identity'].get('os_release_version', 'unknown')))} {maybe_redact(str(ctx['platform_identity'].get('os_release_codename', 'unknown')))} `".rstrip(),
        f"- **Sudo Package Version:** `{maybe_redact(str(ctx['platform_identity'].get('sudo_package_version', ctx['platform_identity'].get('sudo_version', 'unknown'))))}`",
        f"- **Local Privesc Exposure Summary:** {maybe_redact(str(ctx['local_privesc_review'].get('visibility_summary', 'not collected')))}",
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
        f"- **Possible LPE CVE Count:** `{len(as_list(ctx['local_privesc_review'].get('possible_cves')))}`",
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
    append_sample_section(lines, "Local Privesc Detector Samples", as_list(ctx["local_privesc_review"].get("detector_detail_samples")), maybe_redact, limit=10)
    append_sample_section(lines, "GPU Adapter Samples", as_list(scene_reconstruction.get("gpu_adapter_samples")), maybe_redact, limit=8)
    append_sample_section(lines, "GPU Compute Process Samples", as_list(scene_reconstruction.get("gpu_compute_process_samples")), maybe_redact, limit=8)
    append_sample_section(lines, "GPU Suspicious Process Samples", as_list(scene_reconstruction.get("gpu_suspicious_process_samples")), maybe_redact, limit=8)
    lines.extend([
        "",
        anchor_tag("report-deception-review"),
        "## Deception Review",
        f"- **Risk Level:** `{maybe_redact(str(contradiction_review.get('deception_risk_level', 'unknown')))}`",
        f"- **Contradiction Signal Count:** `{maybe_redact(str(contradiction_review.get('count', 0)))}`",
    ])
    contradiction_items = [as_dict(x) for x in as_list(contradiction_review.get("items"))]
    if contradiction_items:
        for item in contradiction_items[:10]:
            lines.append(
                f"- **{maybe_redact(str(item.get('category', 'unknown')))} / {maybe_redact(str(item.get('severity', 'unknown')))}:** "
                f"{maybe_redact(str(item.get('statement', '')))} | evidence: "
                f"{evidence_reference_list(as_list(item.get('evidence_ids')), ctx['evid_idx'], case_dir)}"
            )
    else:
        lines.append("- No contradiction signals were recorded in this pass.")
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
            marker = (
                "WARN"
                if status.lower() in {"missing", "tampered", "suspicious"}
                else "OK"
                if status.lower() == "ok"
                else "INFO"
            )
            lines.extend([
                f"### {marker} {maybe_redact(str(item.get('artifact', 'unknown')))}",
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
                f"<summary><strong>{evidence_id}</strong> :: {maybe_redact(str(item.get('source', 'unknown')))} :: {maybe_redact(str(item.get('observed_at', 'unknown')))} :: {maybe_redact(compact_text(str(item.get('command', '')), max_len=96))}</summary>"
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
        return evidence_reference_list_zh_cn(values, ctx["evid_idx"], case_dir)

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
    contradiction_review = as_dict(ctx["contradiction_review"])
    environment_constraints = as_dict(ctx["environment_constraints"])

    lines: list[str] = [anchor_tag("report-top"), f"# {ctx['title']} - 中文全量报告", ""]
    if case_dir:
        lines.extend([
            "[领导报告](./leadership-report.md) | [操作简报](./reports/operator-brief.md) | [外部补证清单](./reports/external-evidence-checklist.md)",
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
        "- [环境约束](#report-environment-constraints)",
        "- [权限范围](#report-privilege-scope)",
        "- [现场快照](#report-scene-snapshot)",
        "- [欺骗风险复核](#report-deception-review)",
        "- [流程检查点](#report-workflow-checkpoints)",
        "- [证据来源导航](#report-evidence-source-navigator)",
        "- [证据索引](#report-evidence-index)",
        "- [假设-证据关联矩阵](#report-hypothesis-matrix)",
        "- [结论与研判](#report-findings)",
        "- [时间线](#report-timeline)",
        "- [IP 溯源](#report-ip-traceability)",
        "- [外联与横向目标复核](#report-lateral-review)",
        "- [隐藏进程与伪装运行体复核](#report-hidden-process-review)",
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
        f"- **请求排查焦点：** {maybe_redact(', '.join(as_list(ctx['investigation_scope'].get('requested_focus'))) or 'general-compromise-review')}",
        f"- **预期工作负载：** {maybe_redact(ctx['expected_workload'] or '未提供')}",
        f"- **产物哈希目录：** `{artifact_hashes.get('count', len(evidence_items))}` 项，算法 `{artifact_hashes.get('algorithm', 'unknown')}`",
        f"- **欺骗风险：** `{maybe_redact({'high': '高', 'medium': '中', 'low': '低', 'unknown': '未知'}.get(str(contradiction_review.get('deception_risk_level', 'unknown')), str(contradiction_review.get('deception_risk_level', 'unknown'))))}`",
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
        anchor_tag("report-environment-constraints"),
        "## 环境约束",
        f"- **是否需要外部下载工具：** `{maybe_redact_zh(str(environment_constraints.get('external_tool_download_required', 'unknown')))}`",
        f"- **是否尝试过外部下载工具：** `{maybe_redact_zh(str(environment_constraints.get('external_tool_download_attempted', 'unknown')))}`",
        f"- **网络评估模式：** `{maybe_redact(str(environment_constraints.get('network_assessment_mode', 'unknown')))}`",
        f"- **被动摘要：** {maybe_redact(str(environment_constraints.get('summary', environment_constraints.get('signals', {})) or '未采集'))}",
        "",
        anchor_tag("report-privilege-scope"),
        "## 权限范围",
        f"- **当前用户：** `{maybe_redact(str(privilege_scope.get('user', 'unknown')))}`",
        f"- **当前 UID：** `{maybe_redact(str(privilege_scope.get('uid', 'unknown')))}`",
        f"- **是否可见免密 sudo：** `{maybe_redact_zh(str(privilege_scope.get('passwordless_sudo_visible', 'unknown')))}`",
        f"- **内核版本：** `{maybe_redact(str(ctx['platform_identity'].get('kernel_release', 'unknown')))}`",
        f"- **发行版信息：** `{maybe_redact(str(ctx['platform_identity'].get('os_release_id', 'unknown')))} {maybe_redact(str(ctx['platform_identity'].get('os_release_version', 'unknown')))} {maybe_redact(str(ctx['platform_identity'].get('os_release_codename', 'unknown')))} `".rstrip(),
        f"- **sudo 包版本：** `{maybe_redact(str(ctx['platform_identity'].get('sudo_package_version', ctx['platform_identity'].get('sudo_version', 'unknown'))))}`",
        f"- **本地提权暴露面摘要：** {maybe_redact(str(ctx['local_privesc_review'].get('visibility_summary', '未采集')))}",
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
        f"- **可能的本地提权 CVE 数量：** `{len(as_list(ctx['local_privesc_review'].get('possible_cves')))}`",
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
    append_sample_section_zh_cn(lines, "本地提权检测样本", as_list(ctx["local_privesc_review"].get("detector_detail_samples")), limit=10)
    append_sample_section_zh_cn(lines, "GPU 适配器样本", as_list(scene_reconstruction.get("gpu_adapter_samples")), limit=8)
    append_sample_section_zh_cn(lines, "GPU 计算进程样本", as_list(scene_reconstruction.get("gpu_compute_process_samples")), limit=8)
    append_sample_section_zh_cn(lines, "GPU 可疑进程样本", as_list(scene_reconstruction.get("gpu_suspicious_process_samples")), limit=8)
    lines.extend([
        "## 欺骗风险复核",
        f"- **风险级别：** `{maybe_redact({'high': '高', 'medium': '中', 'low': '低', 'unknown': '未知'}.get(str(contradiction_review.get('deception_risk_level', 'unknown')), str(contradiction_review.get('deception_risk_level', 'unknown'))))}`",
        f"- **矛盾信号数量：** `{maybe_redact(str(contradiction_review.get('count', 0)))}`",
    ])
    contradiction_items = [as_dict(x) for x in as_list(contradiction_review.get("items"))]
    if contradiction_items:
        for item in contradiction_items[:10]:
            lines.append(
                f"- **{maybe_redact(str(item.get('category', 'unknown')))} / {maybe_redact(str(item.get('severity', 'unknown')))}：** "
                f"{maybe_redact_zh(str(item.get('statement', '')))} | 证据："
                f"{zh_evidence_refs(as_list(item.get('evidence_ids')))}"
            )
    else:
        lines.append("- 本轮未记录到结构化矛盾信号。")

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

    lines.extend([anchor_tag("report-lateral-review"), "## 外联与横向目标复核"])
    lines.extend(render_lateral_review_lines_zh_cn(scene_reconstruction, maybe_redact, evidence_refs=zh_evidence_refs))
    lines.append("")

    lines.extend([anchor_tag("report-hidden-process-review"), "## 隐藏进程与伪装运行体复核"])
    lines.extend(render_hidden_process_review_lines_zh_cn(scene_reconstruction, maybe_redact, evidence_refs=zh_evidence_refs))
    lines.append("")

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
            lines.append("- **导航：** [返回证据来源导航](#report-evidence-source-navigator) | [返回证据索引](#report-evidence-index) | [返回顶部](#report-top) | [领导报告](./leadership-report.md) | [操作简报](./reports/operator-brief.md)")
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
        "- [返回顶部](#report-top) | [领导报告](./leadership-report.md) | [操作简报](./reports/operator-brief.md) | [外部补证清单](./reports/external-evidence-checklist.md)",
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
    leadership_zh = build_leadership_report_zh_cn(data, redact=redact, case_dir=case_dir)
    legacy_paths = [
        reports_dir / "report.md",
        reports_dir / "report.zh-CN.md",
        reports_dir / "index.md",
        reports_dir / "index.zh-CN.md",
        reports_dir / "management-summary.md",
        reports_dir / "management-summary.zh-CN.md",
        reports_dir / "soc-summary.md",
        reports_dir / "soc-summary.zh-CN.md",
        reports_dir / "operator-brief.zh-CN.md",
        case_root / "report.zh-CN.md",
        case_root / "leadership-report.zh-CN.md",
    ]
    for legacy_path in legacy_paths:
        if legacy_path.exists():
            legacy_path.unlink()

    outputs = {
        case_root / "leadership-report.md": finalize_zh_markdown(leadership_zh),
    }
    written: list[str] = []
    for out_path, body in outputs.items():
        out_path.write_text(body, encoding="utf-8")
        written.append(str(out_path))
    required_outputs = sorted(
        {
            str(case_root / "report.md"),
            str(case_root / "leadership-report.md"),
            str(reports_dir / "operator-brief.md"),
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


def report_output_targets(output_path: Path, case_dir: str | None) -> list[Path]:
    targets: list[Path] = [output_path]
    if case_dir:
        canonical = Path(case_dir) / "report.md"
        if canonical not in targets:
            targets.append(canonical)
    return targets


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

    data = load_json(input_path)
    derived_case_dir = args.case_dir
    if not derived_case_dir and input_path.resolve().parent.name == "evidence":
        derived_case_dir = str(input_path.resolve().parent.parent)
    report_md, warnings = build_report_zh_cn(data, redact=args.redact, strict=args.strict, case_dir=derived_case_dir)
    written_report_paths: list[Path] = []
    for report_path in report_output_targets(output_path, derived_case_dir):
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report_md, encoding="utf-8")
        written_report_paths.append(report_path)
    if derived_case_dir:
        legacy_report_path = Path(derived_case_dir) / "reports" / "report.md"
        if legacy_report_path.exists():
            legacy_report_path.unlink()
    companion_paths = write_companion_reports(derived_case_dir, data, redact=args.redact, strict=args.strict)

    for report_path in written_report_paths:
        print(f"Report written: {report_path}")
    for companion in companion_paths:
        print(f"Companion report written: {companion}")
    print(f"Warnings: {len(warnings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
