#!/usr/bin/env python3
"""Generate operator-facing concise brief from evidence-bound case data."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON: {exc}")
    if not isinstance(data, dict):
        raise SystemExit("Input JSON must be an object.")
    return data


def evidence_links(evidence_ids: list[Any], limit: int = 4) -> str:
    refs = []
    for item in evidence_ids[:limit]:
        evid = str(item).strip()
        if not evid:
            continue
        refs.append(f"[{evid}](../report.zh-CN.md#evidence-{evid.lower()})")
    if not refs:
        return "-"
    suffix = f"（另 {len(evidence_ids) - limit} 项）" if len(evidence_ids) > limit else ""
    return "、".join(refs) + suffix


def build_brief_payload(data: dict[str, Any]) -> dict[str, Any]:
    scene = as_dict(data.get("scene_reconstruction"))
    matrix = [as_dict(x) for x in as_list(data.get("hypothesis_matrix"))]
    findings = [as_dict(x) for x in as_list(data.get("findings"))]
    ip_traces = [as_dict(x) for x in as_list(data.get("ip_traces"))]
    log_integrity = [as_dict(x) for x in as_list(data.get("log_integrity"))]
    host = as_dict(data.get("host"))
    incident = as_dict(data.get("incident"))

    process_hits = safe_int(scene.get("process_ioc_match_count", 0))
    network_hits = safe_int(scene.get("network_ioc_hit_count", 0))
    gpu_hits = safe_int(scene.get("gpu_suspicious_process_count", 0))
    access_hits = safe_int(scene.get("initial_access_review_hit_count", 0))
    container_hits = safe_int(scene.get("container_cloud_review_hit_count", 0))
    kernel_hits = safe_int(scene.get("kernel_review_hit_count", 0))
    direct_hits = process_hits + network_hits + gpu_hits
    review_hits = access_hits + container_hits + kernel_hits
    log_risk_count = sum(
        1
        for item in log_integrity
        if str(item.get("status", "")).strip().lower() in {"missing", "tampered", "suspicious"}
    )

    if direct_hits > 0:
        verdict = "高疑似：存在直接运行时指标，建议按入侵事件继续处置。"
        level = "high"
    elif review_hits > 0 or log_risk_count > 0:
        verdict = "中疑似：未见直接矿工指标，但存在访问面/持久化/日志风险线索，需要继续复核。"
        level = "medium"
    else:
        verdict = "低疑似：当前未见直接挖矿指标，本轮只能给出待定结论。"
        level = "low"

    traced = sum(1 for item in ip_traces if str(item.get("trace_status", "")).strip().lower() == "traced")
    unknown = len(ip_traces) - traced

    key_hyp = []
    for item in matrix:
        status = str(item.get("status", "")).strip().lower()
        if status in {"supported", "inconclusive"}:
            key_hyp.append(item)
    key_hyp = key_hyp[:4]

    key_findings = findings[:3]
    return {
        "generated_at_utc": now_utc(),
        "incident_id": str(incident.get("id", "unknown")),
        "host_name": str(host.get("name", "unknown")),
        "host_ip": str(host.get("ip", "unknown")),
        "risk_level": level,
        "verdict": verdict,
        "direct_hits": direct_hits,
        "review_hits": review_hits,
        "log_risk_count": log_risk_count,
        "traceable_ip_count": traced,
        "unknown_ip_count": unknown,
        "key_hypothesis": key_hyp,
        "key_findings": key_findings,
        "auth_source_ips": as_list(scene.get("auth_source_ips")),
        "gpu_suspicious_process_count": gpu_hits,
        "gpu_peak_utilization_percent": safe_int(scene.get("gpu_peak_utilization_percent", 0)),
    }


def build_zh_md(payload: dict[str, Any], expected_workload: str) -> str:
    lines = [
        "# 业务排查简报（给非安全专业用户）",
        "",
        f"- 生成时间（UTC）：`{payload['generated_at_utc']}`",
        f"- 事件 ID：`{payload['incident_id']}`",
        f"- 目标主机：`{payload['host_name']}` (`{payload['host_ip']}`)",
        "",
        "## 一句话结论",
        f"- **{payload['verdict']}**",
        "",
        "## 为什么是这个结论",
        f"- 直接运行时命中（进程/网络/GPU）：`{payload['direct_hits']}`",
        f"- 复核面命中（访问/容器云/内核）：`{payload['review_hits']}`",
        f"- 日志完整性风险：`{payload['log_risk_count']}`",
        f"- GPU 可疑进程数量：`{payload['gpu_suspicious_process_count']}`（峰值利用率：`{payload['gpu_peak_utilization_percent']}%`）",
        f"- 预期业务负载：`{expected_workload or '未提供'}`",
        "",
        "## 溯源现状",
        f"- 已溯源 IP：`{payload['traceable_ip_count']}`",
        f"- 未溯源/未知 IP：`{payload['unknown_ip_count']}`",
        f"- 认证来源 IP 样本：{ '、'.join(str(x) for x in payload['auth_source_ips'][:6]) if payload['auth_source_ips'] else '无' }",
        "",
        "## 关键假设（已做证据关联）",
    ]
    if payload["key_hypothesis"]:
        for item in payload["key_hypothesis"]:
            lines.extend(
                [
                    f"- `{item.get('hypothesis_id', 'unknown')}` `{item.get('status', 'unknown')}` / `{item.get('confidence', 'unknown')}`：{item.get('summary', '-')}",
                    f"  证据：{evidence_links(as_list(item.get('supporting_evidence_ids')))}",
                ]
            )
    else:
        lines.append("- 本轮未形成可输出的关联假设。")

    lines.extend(
        [
            "",
            "## 你接下来应该做什么",
            "1. 先看 `../report.zh-CN.md` 的“假设-证据关联矩阵”，确认哪些是假设已被证据支持。",
            "2. 再看 `../reports/soc-summary.zh-CN.md`，按证据 ID 逐条复核关键线索。",
            "3. 如需执行处置（停服务/杀进程/删文件），先做业务影响评估并单独审批。",
            "",
            "## 重要提醒",
            "- 本简报不执行任何改动操作，只总结证据关联结果。",
            "- 证据不足时结论保持待定，不会杜撰“已被入侵”或“绝对安全”。",
            "",
        ]
    )
    return "\n".join(lines)


def build_en_md(payload: dict[str, Any], expected_workload: str) -> str:
    lines = [
        "# Operator Brief (Non-Specialist View)",
        "",
        f"- Generated At (UTC): `{payload['generated_at_utc']}`",
        f"- Incident ID: `{payload['incident_id']}`",
        f"- Host: `{payload['host_name']}` (`{payload['host_ip']}`)",
        "",
        "## One-Line Verdict",
        f"- **{payload['verdict']}**",
        "",
        "## Why",
        f"- Direct runtime hits (process/network/GPU): `{payload['direct_hits']}`",
        f"- Review-surface hits (access/container-cloud/kernel): `{payload['review_hits']}`",
        f"- Log-integrity risks: `{payload['log_risk_count']}`",
        f"- Suspicious GPU process count: `{payload['gpu_suspicious_process_count']}` (peak utilization `{payload['gpu_peak_utilization_percent']}%`)",
        f"- Expected workload: `{expected_workload or 'not provided'}`",
        "",
        "## Traceability Status",
        f"- Traceable IPs: `{payload['traceable_ip_count']}`",
        f"- Untraceable/Unknown IPs: `{payload['unknown_ip_count']}`",
        "",
        "## Next Steps",
        "1. Review the hypothesis matrix in `../report.md` first.",
        "2. Validate key evidence lines in `../reports/soc-summary.md` by evidence ID.",
        "3. Keep remediation actions approval-gated before any state change.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate concise operator brief from case evidence.")
    parser.add_argument("--input", required=True, help="Input evidence JSON file.")
    parser.add_argument("--case-dir", required=True, help="Case directory.")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    case_dir = Path(args.case_dir).resolve()
    reports_dir = case_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    data = load_json(input_path)
    payload = build_brief_payload(data)
    expected_workload = str(data.get("expected_workload", "")).strip()

    zh_path = reports_dir / "operator-brief.zh-CN.md"
    en_path = reports_dir / "operator-brief.md"
    json_path = reports_dir / "operator-brief.json"

    zh_path.write_text(build_zh_md(payload, expected_workload), encoding="utf-8")
    en_path.write_text(build_en_md(payload, expected_workload), encoding="utf-8")
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Operator brief (ZH) written: {zh_path}")
    print(f"Operator brief (EN) written: {en_path}")
    print(f"Operator brief (JSON) written: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

