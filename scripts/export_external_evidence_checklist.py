#!/usr/bin/env python3
"""Generate a per-case external evidence checklist from collected host evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PIVOT_LABELS = {
    "identity_boundary_logs": "补拉同一 UTC 时间窗内的堡垒机、VPN、身份系统、跳板机和边界认证日志。",
    "peer_host_internal_auth_pivot": "复核与内网或私网认证来源 IP 相关的同环境主机、堡垒机和管理节点。",
    "cloud_control_plane_audit": "补拉 Kubernetes 审计日志、镜像拉取历史、云审计轨迹和元数据访问遥测。",
    "boundary_telemetry_for_log_loss": "在主机日志留存不足时，补拉 SIEM、防火墙、NAT、代理、DNS 和快照历史。",
    "timeline_expansion": "在关闭入口还原前，先用上游遥测和历史记录扩展时间窗。",
    "contradiction_resolution": "先消解跨来源矛盾，再提高归因强度或推进结案。",
    "privesc_change_records": "补查软件包回移修复记录、变更单和管理员操作流程，用于本地提权暴露面复核。",
}

SCOPE_STATUS_LABELS = {
    "needs_external_corroboration": "仍需主机外补证",
    "host_only_scope_sufficient_for_requested_focus": "当前主机侧范围已基本满足本轮排查目标",
}

TIMELINE_STATUS_LABELS = {
    "timeline_not_recovered": "尚未恢复出可用时间线",
    "timeline_not_normalized": "时间线尚未完成可信 UTC 归一化",
    "narrow_window": "时间线窗口偏窄",
    "normalized_window_present": "时间线窗口可用",
}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("Input JSON must be an object.")
    return data


def build_checklist(data: dict[str, Any]) -> str:
    incident = as_dict(data.get("incident"))
    host = as_dict(data.get("host"))
    collection_failure = as_dict(data.get("collection_failure"))
    if str(collection_failure.get("status", "")).strip().lower() == "failed":
        safe_to_retry = bool(collection_failure.get("safe_to_retry_without_new_credentials", False))
        lines = [
            f"# 主机外补证清单 - {incident.get('id', 'unknown')}",
            "",
            f"- 主机：`{host.get('name', 'unknown')}` ({host.get('ip', 'unknown')})",
            f"- 案件 ID：`{data.get('case_id', 'unknown')}`",
            "- 目标：保留失败采集现场，先修复信任、认证或通道阻塞点，并在主机侧证据缺失期间同步补拉主机外证据。",
            "",
            "## 采集失败概况",
            f"- 状态：`{collection_failure.get('status', 'unknown')}`",
            f"- 阶段：`{collection_failure.get('phase', 'unknown')}`",
            f"- 原因：{collection_failure.get('reason', '-')}",
            f"- 是否适合直接用同一凭据重试：`{'是' if safe_to_retry else '否'}`",
            f"- 重试建议：{collection_failure.get('retry_guidance', '-')}",
            "",
            "## 优先补证方向",
        ]
        if safe_to_retry:
            lines.append("- 在单次受控重试前，先核对主机指纹信任、远端 shell 可用性和 SSH 传输兼容性。")
        else:
            lines.append("- 不要盲目重复使用同一凭据。继续尝试前，先核对登录失败计数、凭据有效性和访问策略。")
        lines.extend(
            [
                "- 由于主机侧证据尚未建立，优先补拉预期 UTC 时间窗内的堡垒机、VPN、身份系统、跳板机和边界认证日志。",
                "- 保留当前失败案件包、操作者时间点和已固定的信任材料，确保下一次只读复跑仍可追溯。",
                "- 如果远端信任只建立到一半，重新连接前先做带外比对，确认 known_hosts 或指纹来源一致。",
                "",
                "## 建议补拉的来源",
                "- 云审计轨迹：`not_collected`",
                "- Kubernetes 审计日志：`not_collected`",
                "- 镜像仓库拉取历史：`not_collected`",
                "- 身份系统 / 堡垒机日志：`not_collected`",
                "- CI/CD 与密钥存储日志：`not_collected`",
                "- 防火墙 / NAT / 代理 / DNS 遥测：`not_collected`",
                "",
                "## 使用规则",
                "- 哪些来源拿不到，要明确标记，不要脑补其内容。",
                "- 补证时必须记录精确时间窗和时区基准。",
                "- 若后续把外部证据挂回案件包，要保留原始导出文件及其哈希。",
                "",
            ]
        )
        return "\n".join(lines).strip() + "\n"

    scene = as_dict(data.get("scene_reconstruction"))
    second_pass = as_dict(data.get("second_pass_review") or scene.get("second_pass_review"))
    scope_review = as_dict(second_pass.get("scope_closure_review") or scene.get("scope_closure_review"))
    timeline_review = as_dict(second_pass.get("timeline_review") or scene.get("timeline_review"))
    log_layout_review = as_dict(second_pass.get("log_layout_review") or scene.get("log_layout_review"))
    auth_ips = as_list(scene.get("auth_source_ips"))
    has_container_cloud = int(scene.get("container_cloud_review_hit_count", 0) or 0) > 0
    if "adjusted_primary_log_risk_count" in log_layout_review:
        has_log_risk = int(log_layout_review.get("adjusted_primary_log_risk_count", 0) or 0) > 0
    else:
        has_log_risk = any(
            str(item.get("status", "")).strip().lower() in {"missing", "tampered", "suspicious"}
            for item in [as_dict(x) for x in as_list(data.get("log_integrity"))]
        )
    external_pivots = [as_dict(x) for x in as_list(scope_review.get("external_pivots"))]
    lines = [
        f"# 主机外补证清单 - {incident.get('id', 'unknown')}",
        "",
        f"- 主机：`{host.get('name', 'unknown')}` ({host.get('ip', 'unknown')})",
        f"- 案件 ID：`{data.get('case_id', 'unknown')}`",
        "- 目标：利用主机外证据补齐入口、横向和上游归因缺口。",
        f"- 二轮范围闭环状态：`{SCOPE_STATUS_LABELS.get(str(scope_review.get('status', '')), str(scope_review.get('status', 'unknown')) or 'unknown')}`",
        f"- 二轮时间线状态：`{TIMELINE_STATUS_LABELS.get(str(timeline_review.get('status', '')), str(timeline_review.get('status', 'unknown')) or 'unknown')}`",
        "",
        "## 优先补证方向",
    ]
    if external_pivots:
        for item in external_pivots:
            pivot_id = str(item.get("id", "")).strip()
            reason = str(item.get("reason", "")).strip()
            lines.append(f"- {PIVOT_LABELS.get(pivot_id, pivot_id or 'unlabeled pivot')}")
            if reason:
                lines.append(f"  原因：{reason}")
    elif auth_ips:
        lines.append(f"- 主机侧已观察到认证来源 IP：{', '.join(str(x) for x in auth_ips[:10])}")
        lines.append("- 补拉同时间窗内的堡垒机、VPN、身份系统或跳板机认证日志。")
    else:
        lines.append("- 当前未从主机侧提取出认证来源 IP；如果入口路径仍不清晰，优先补拉身份系统和边界日志。")
    if has_container_cloud:
        lines.append("- 已见容器或云侧信号；补拉 Kubernetes 审计日志、镜像拉取历史、云审计和元数据访问遥测。")
    if has_log_risk:
        lines.append("- 主机日志留存能力存在缺口；优先补拉 SIEM、边界防火墙、NAT、DNS 和快照历史。")
    lines.append("")
    lines.extend([
        "## 建议补拉的来源",
        "- 云审计轨迹：`not_collected`",
        "- Kubernetes 审计日志：`not_collected`",
        "- 镜像仓库拉取历史：`not_collected`",
        "- 身份系统 / 堡垒机日志：`not_collected`",
        "- CI/CD 与密钥存储日志：`not_collected`",
        "- 防火墙 / NAT / 代理 / DNS 遥测：`not_collected`",
        "",
        "## 使用规则",
        "- 哪些来源拿不到，要明确标记，不要脑补其内容。",
        "- 补证时必须记录精确时间窗和时区基准。",
        "- 若后续把外部证据挂回案件包，要保留原始导出文件及其哈希。",
        "",
    ])
    return "\n".join(lines).strip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="为案件包生成中文主机外补证清单。")
    parser.add_argument("--input", required=True, help="Input reviewed evidence JSON path.")
    parser.add_argument("--case-dir", help="Case directory. Defaults from input path.")
    parser.add_argument("--output", help="Output markdown path.")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    case_dir = Path(args.case_dir).resolve() if args.case_dir else input_path.parent.parent
    output_path = Path(args.output).resolve() if args.output else (case_dir / "reports" / "external-evidence-checklist.md")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = load_json(input_path)
    body = build_checklist(data)
    output_path.write_text(body, encoding="utf-8")
    print(f"External evidence checklist written: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
