#!/usr/bin/env python3
"""Run a second-pass evidence review before final validation and export."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - Python always provides this in supported runtimes
    ZoneInfo = None  # type: ignore[assignment]


ACCEPTED_AUTH_RE = re.compile(
    r"(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
)
REVIEW_SURFACE_RE = re.compile(
    r"(authorized_keys|sshd_config|/etc/pam\.d|/etc/sudoers|ld\.so\.preload|rc\.local|\.service|/etc/cron|crontab|\.bashrc|\.profile|\.zshrc)",
    re.I,
)
VENDOR_MANAGED_RE = re.compile(
    r"(qcloud|yunjing|barad|cloud-init|waagent|google-guest-agent|amazon-ssm-agent|aliyun|aliyun-service|azure|ecs)",
    re.I,
)
SUSPICIOUS_STARTUP_RE = re.compile(
    r"(/tmp/|/var/tmp/|/dev/shm/|curl\s+.+\|\s*sh|wget\s+.+\|\s*sh|base64\s+-d|chmod\s+\+x|nohup\s|setsid\s|screen\s+-dm|tmux\s+(?:new|new-session)|\b(?:frp|ngrok|clash|autossh|socat|ncat|nc)\b)",
    re.I,
)
POLICY_SIGNAL_RE = re.compile(
    r"(NOPASSWD|!authenticate|PermitRootLogin\s+yes|PasswordAuthentication\s+yes|AuthorizedKeysCommand|ForceCommand|/etc/sudoers|/etc/pam\.d|ld\.so\.preload)",
    re.I,
)
IDENTITY_SURFACE_RE = re.compile(r"(authorized_keys|\.bashrc|\.profile|\.zshrc)", re.I)


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


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def split_artifact_sections(text: str) -> tuple[str, str]:
    marker_stdout = "\n[STDOUT]\n"
    marker_stderr = "\n\n[STDERR]\n"
    if marker_stdout not in text:
        return "", ""
    after = text.split(marker_stdout, 1)[1]
    if marker_stderr in after:
        stdout, stderr = after.split(marker_stderr, 1)
        return stdout, stderr
    return after, ""


def parse_iso_utc(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_private_ip(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        return ipaddress.ip_address(text).is_private
    except ValueError:
        return False


def resolve_timezone(name: str):
    tz_name = str(name or "").strip()
    if tz_name.upper() == "UTC" or not tz_name:
        return timezone.utc
    if ZoneInfo is not None:
        try:
            return ZoneInfo(tz_name)
        except Exception:
            pass
    if tz_name == "Asia/Shanghai":
        return timezone(timedelta(hours=8))
    return timezone.utc


def observation_window(evidence_items: list[dict[str, Any]]) -> tuple[datetime | None, datetime | None]:
    times = [
        parsed
        for parsed in (parse_iso_utc(str(item.get("observed_at", ""))) for item in evidence_items)
        if parsed is not None
    ]
    if not times:
        return None, None
    return min(times), max(times)


def load_stdout_lines(item: dict[str, Any]) -> list[str]:
    artifact = Path(str(item.get("artifact", "")).strip())
    if not artifact.exists():
        return []
    text = artifact.read_text(encoding="utf-8", errors="replace")
    stdout, _ = split_artifact_sections(text)
    return [line.rstrip() for line in stdout.splitlines() if line.strip()]


def parse_log_timestamp(stamp: str, reference_utc: datetime | None, tz_name: str) -> datetime | None:
    if not stamp:
        return None
    zone = resolve_timezone(tz_name)
    ref_local = (reference_utc or datetime.now(timezone.utc)).astimezone(zone)
    try:
        parsed = datetime.strptime(f"{stamp} {ref_local.year}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return None
    local_dt = parsed.replace(tzinfo=zone)
    if local_dt - ref_local > timedelta(days=1):
        local_dt = local_dt.replace(year=local_dt.year - 1)
    return local_dt.astimezone(timezone.utc)


def normalize_source_id_list(values: list[Any]) -> list[str]:
    return sorted({str(value).strip() for value in values if str(value).strip()})


def review_log_layout(data: dict[str, Any], scene: dict[str, Any]) -> dict[str, Any]:
    platform = as_dict(scene.get("platform_identity"))
    os_family = str(platform.get("os_release_id", "")).strip().lower()
    log_integrity = [as_dict(x) for x in as_list(data.get("log_integrity"))]
    raw_risky = [
        item
        for item in log_integrity
        if str(item.get("status", "")).strip().lower() in {"missing", "tampered", "suspicious"}
    ]

    expected_prefixes: tuple[str, ...] = ()
    non_applicable: list[str] = []
    if os_family in {"ubuntu", "debian"}:
        expected_prefixes = ("/var/log/auth.log", "/var/log/syslog")
    elif os_family in {"rhel", "centos", "rocky", "alma", "almalinux", "fedora"}:
        expected_prefixes = ("/var/log/secure", "/var/log/messages")

    adjusted_risky: list[dict[str, Any]] = []
    for item in raw_risky:
        artifact = str(item.get("artifact", "")).strip()
        if expected_prefixes:
            if any(artifact.startswith(prefix) for prefix in expected_prefixes):
                adjusted_risky.append(item)
            else:
                non_applicable.append(artifact)
        else:
            adjusted_risky.append(item)

    if expected_prefixes and not adjusted_risky:
        status = "distro_layout_consistent"
        summary = (
            f"Observed log layout is consistent with the detected {os_family or 'linux'} family. "
            "Previously flagged non-applicable log paths should not be treated as log loss."
        )
    elif adjusted_risky:
        status = "reduced_visibility_on_expected_logs"
        summary = (
            f"Applicable primary log risk remains on {len(adjusted_risky)} expected artifact(s). "
            "Reconstruction confidence should stay reduced until fallback artifacts are fully cross-checked."
        )
    else:
        status = "layout_unknown"
        summary = "Primary log layout could not be normalized against a known distro family from current evidence."

    return {
        "os_family": os_family or "unknown",
        "status": status,
        "expected_primary_artifacts": list(expected_prefixes),
        "non_applicable_artifacts": sorted(set(non_applicable)),
        "adjusted_risky_artifacts": [str(item.get("artifact", "")).strip() for item in adjusted_risky],
        "adjusted_primary_log_risk_count": len(adjusted_risky),
        "raw_primary_log_risk_count": len(raw_risky),
        "summary": summary,
    }


def collect_accepted_auth_events(evidence_items: list[dict[str, Any]], scene: dict[str, Any]) -> list[dict[str, Any]]:
    tz_name = str(as_dict(scene.get("time_normalization")).get("host_reported_timezone", "UTC")).strip() or "UTC"
    events: list[dict[str, Any]] = []
    for item in evidence_items:
        if str(item.get("source", "")).strip() != "auth":
            continue
        lines = load_stdout_lines(item)
        observed_at = parse_iso_utc(str(item.get("observed_at", "")))
        evidence_id = str(item.get("id", "")).strip()
        for line in lines:
            match = ACCEPTED_AUTH_RE.search(line)
            if not match:
                continue
            event_time = parse_log_timestamp(match.group("stamp"), observed_at, tz_name)
            events.append(
                {
                    "ip": match.group("ip"),
                    "user": match.group("user"),
                    "method": match.group("method"),
                    "normalized_time_utc": event_time.replace(microsecond=0).isoformat() if event_time else "unknown",
                    "evidence_id": evidence_id,
                    "raw_line": line.strip(),
                }
            )
    return events


def review_accepted_auth_sources(data: dict[str, Any], scene: dict[str, Any]) -> dict[str, Any]:
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    events = collect_accepted_auth_events(evidence_items, scene)
    window_start, window_end = observation_window(evidence_items)
    breakdown = as_dict(scene.get("auth_source_breakdown"))
    failed_ips = set(str(x).strip() for x in as_list(breakdown.get("failed")))
    invalid_ips = set(str(x).strip() for x in as_list(breakdown.get("invalid")))
    review_by_ip: dict[str, dict[str, Any]] = {}
    privilege_scope = as_dict(scene.get("privilege_scope"))
    operator_user = str(privilege_scope.get("user", "")).strip()

    for event in events:
        ip = str(event.get("ip", "")).strip()
        if not ip:
            continue
        entry = review_by_ip.setdefault(
            ip,
            {
                "ip": ip,
                "accepted_event_count": 0,
                "users": set(),
                "methods": set(),
                "evidence_ids": set(),
                "first_seen_utc": "",
                "last_seen_utc": "",
                "status": "authorization_unknown",
                "summary": "",
            },
        )
        entry["accepted_event_count"] += 1
        entry["users"].add(str(event.get("user", "")).strip())
        entry["methods"].add(str(event.get("method", "")).strip())
        entry["evidence_ids"].add(str(event.get("evidence_id", "")).strip())
        ts = parse_iso_utc(str(event.get("normalized_time_utc", "")))
        if ts is None:
            continue
        ts_text = ts.replace(microsecond=0).isoformat()
        if not entry["first_seen_utc"] or ts_text < entry["first_seen_utc"]:
            entry["first_seen_utc"] = ts_text
        if not entry["last_seen_utc"] or ts_text > entry["last_seen_utc"]:
            entry["last_seen_utc"] = ts_text

    sources: list[dict[str, Any]] = []
    for ip, entry in sorted(review_by_ip.items()):
        last_seen = parse_iso_utc(entry["last_seen_utc"])
        first_seen = parse_iso_utc(entry["first_seen_utc"])
        recurring = entry["accepted_event_count"] >= 2
        close_to_collection = (
            window_end is not None
            and last_seen is not None
            and abs(window_end - last_seen) <= timedelta(minutes=20)
        )
        mixed_signal = ip in failed_ips or ip in invalid_ips
        if close_to_collection and operator_user and operator_user in entry["users"]:
            status = "current_investigation_session_candidate"
            summary = (
                "An accepted login from this source overlaps the current observation window and may be the active investigation session."
            )
        elif mixed_signal:
            status = "mixed_auth_signal_candidate"
            summary = (
                "This source appears in both accepted and failed/invalid authentication evidence. Authorization cannot be assumed."
            )
        elif recurring and first_seen is not None and last_seen is not None:
            status = "recurring_access_candidate"
            summary = (
                "This source shows repeated accepted logins across the collected window. It may reflect normal administration, but host-only evidence cannot prove authorization."
            )
        else:
            status = "authorization_unknown"
            summary = "Accepted access was observed, but host-only evidence cannot distinguish authorized administration from credential misuse."
        sources.append(
            {
                "ip": ip,
                "status": status,
                "accepted_event_count": entry["accepted_event_count"],
                "users": sorted(x for x in entry["users"] if x),
                "methods": sorted(x for x in entry["methods"] if x),
                "first_seen_utc": entry["first_seen_utc"] or "unknown",
                "last_seen_utc": entry["last_seen_utc"] or "unknown",
                "evidence_ids": normalize_source_id_list(list(entry["evidence_ids"])),
                "summary": summary,
            }
        )

    current_count = sum(1 for item in sources if item["status"] == "current_investigation_session_candidate")
    recurring_count = sum(1 for item in sources if item["status"] == "recurring_access_candidate")
    unknown_count = sum(1 for item in sources if item["status"] == "authorization_unknown")
    mixed_count = sum(1 for item in sources if item["status"] == "mixed_auth_signal_candidate")
    if current_count or recurring_count:
        overall = "accepted_access_present_authorization_unconfirmed"
    elif mixed_count:
        overall = "mixed_auth_signals_present"
    elif sources:
        overall = "accepted_access_needs_validation"
    else:
        overall = "no_accepted_access_recovered"

    unresolved = []
    for item in sources:
        if item["status"] != "current_investigation_session_candidate":
            unresolved.append(
                f"Validate whether accepted source {item['ip']} belongs to approved admin infrastructure before treating it as legitimate."
            )

    return {
        "overall_assessment": overall,
        "current_session_candidate_count": current_count,
        "recurring_source_count": recurring_count,
        "authorization_unknown_count": unknown_count,
        "mixed_signal_source_count": mixed_count,
        "sources": sources,
        "unresolved_actions": unresolved,
    }


def collect_persistence_review_lines(evidence_items: list[dict[str, Any]], scene: dict[str, Any]) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in evidence_items:
        source = str(item.get("source", "")).strip()
        if source not in {"auth", "persistence", "service"}:
            continue
        evidence_id = str(item.get("id", "")).strip()
        for line in load_stdout_lines(item):
            stripped = line.strip()
            if not REVIEW_SURFACE_RE.search(stripped):
                continue
            key = (evidence_id, stripped)
            if key in seen:
                continue
            seen.add(key)
            collected.append({"line": stripped, "evidence_ids": [evidence_id]})

    for sample in as_list(scene.get("initial_access_review_samples")):
        stripped = str(sample).strip()
        if not stripped:
            continue
        key = ("scene_sample", stripped)
        if key in seen:
            continue
        seen.add(key)
        collected.append({"line": stripped, "evidence_ids": []})
    return collected


def classify_persistence_line(line: str) -> tuple[str, str]:
    if VENDOR_MANAGED_RE.search(line):
        return "vendor_managed", "neutral"
    if SUSPICIOUS_STARTUP_RE.search(line):
        return "suspicious_startup_signal", "high_signal"
    if POLICY_SIGNAL_RE.search(line):
        return "privileged_policy_signal", "high_signal"
    if IDENTITY_SURFACE_RE.search(line):
        return "identity_surface", "review_surface"
    return "generic_review_surface", "review_surface"


def review_persistence_surfaces(data: dict[str, Any], scene: dict[str, Any]) -> dict[str, Any]:
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    items: list[dict[str, Any]] = []
    vendor_count = 0
    identity_count = 0
    generic_count = 0
    high_signal_count = 0
    policy_signal_count = 0

    for raw in collect_persistence_review_lines(evidence_items, scene):
        line = str(raw.get("line", "")).strip()
        category, severity = classify_persistence_line(line)
        if category == "vendor_managed":
            vendor_count += 1
        elif category == "identity_surface":
            identity_count += 1
        elif category == "privileged_policy_signal":
            policy_signal_count += 1
        elif category == "suspicious_startup_signal":
            high_signal_count += 1
        else:
            generic_count += 1
        items.append(
            {
                "category": category,
                "severity": severity,
                "line": line,
                "evidence_ids": normalize_source_id_list(raw.get("evidence_ids", [])),
            }
        )

    if high_signal_count or policy_signal_count:
        status = "high_signal_present"
        summary = (
            f"Persistence review contains {high_signal_count + policy_signal_count} high-signal line(s) that need direct analyst confirmation."
        )
    elif items and vendor_count + identity_count == len(items):
        status = "baseline_or_vendor_dominated"
        summary = (
            "Persistence review surfaces are currently dominated by vendor-managed startup lines or account metadata. "
            "That is not enough to assert a malicious foothold."
        )
    elif items:
        status = "review_surface_only"
        summary = "Persistence review produced review-surface lines, but none rise to a direct malicious foothold claim."
    else:
        status = "not_observed"
        summary = "No persistence review surface line was recovered in the second-pass review."

    return {
        "status": status,
        "vendor_managed_count": vendor_count,
        "identity_surface_count": identity_count,
        "generic_review_surface_count": generic_count,
        "high_signal_count": high_signal_count,
        "policy_signal_count": policy_signal_count,
        "items": items[:24],
        "summary": summary,
    }


def review_lpe_use(scene: dict[str, Any], persistence_review: dict[str, Any], accepted_auth_review: dict[str, Any]) -> dict[str, Any]:
    lpe = as_dict(scene.get("local_privesc_review"))
    privilege_scope = as_dict(scene.get("privilege_scope"))
    possible_cves = [str(x).strip() for x in as_list(lpe.get("possible_cves")) if str(x).strip()]
    has_exposure = bool(lpe.get("possible_lpe_exposure")) or bool(possible_cves)
    passwordless_sudo = bool(privilege_scope.get("passwordless_sudo_visible"))
    accepted_sources = [as_dict(x) for x in as_list(accepted_auth_review.get("sources"))]
    non_root_access_visible = any(
        any(user and user != "root" for user in as_list(item.get("users")))
        for item in accepted_sources
    )
    high_signal_present = bool(
        persistence_review.get("high_signal_count") or persistence_review.get("policy_signal_count")
    )

    if not has_exposure:
        status = "not_observed"
        summary = "No local privilege-escalation exposure signal remained after second-pass review."
    elif high_signal_present and non_root_access_visible and not passwordless_sudo:
        status = "plausible_used"
        summary = (
            "Local privesc exposure is present, and the surrounding access/persistence pattern keeps a normal-user-to-root escalation path plausible."
        )
    else:
        status = "exposed_only"
        if passwordless_sudo:
            summary = (
                "Local privesc exposure is present, but current evidence does not separate exploit use from ordinary privileged access because passwordless sudo is visible."
            )
        else:
            summary = (
                "Local privesc exposure is present, but the current host-only evidence does not confirm or strongly support actual exploit use."
            )

    return {
        "status": status,
        "possible_cves": possible_cves,
        "passwordless_sudo_visible": passwordless_sudo,
        "summary": summary,
    }


def review_timeline_consistency(data: dict[str, Any], scene: dict[str, Any]) -> dict[str, Any]:
    timeline = [as_dict(x) for x in as_list(data.get("timeline"))]
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    accepted_events = collect_accepted_auth_events(evidence_items, scene)

    normalized_points: list[datetime] = []
    source_labels: set[str] = set()
    for item in timeline:
        candidate = parse_iso_utc(str(item.get("normalized_time_utc") or item.get("time") or ""))
        if candidate is None:
            continue
        normalized_points.append(candidate)
        source = str(item.get("source", "")).strip() or "unknown"
        source_labels.add(source)
    for item in accepted_events:
        candidate = parse_iso_utc(str(item.get("normalized_time_utc", "")))
        if candidate is None:
            continue
        normalized_points.append(candidate)
        source_labels.add("auth.accepted")

    normalized_points.sort()
    earliest = normalized_points[0].replace(microsecond=0).isoformat() if normalized_points else "unknown"
    latest = normalized_points[-1].replace(microsecond=0).isoformat() if normalized_points else "unknown"
    span_minutes = (
        int((normalized_points[-1] - normalized_points[0]).total_seconds() // 60)
        if len(normalized_points) >= 2
        else 0
    )

    if not timeline and not accepted_events:
        status = "timeline_not_recovered"
        summary = "No reconstructable timeline entries were recovered from current host evidence."
    elif not normalized_points:
        status = "timeline_not_normalized"
        summary = "Timeline-like records exist, but no event time could be normalized into a defensible UTC sequence."
    elif span_minutes < 30 and len(source_labels) <= 1:
        status = "narrow_window"
        summary = (
            "Recovered event timing is narrow and likely under-scopes earlier ingress or staging activity. "
            "Expand the time window before closing the case."
        )
    else:
        status = "normalized_window_present"
        summary = (
            f"Recovered event timing spans about {span_minutes} minute(s) across {len(source_labels) or 1} source type(s). "
            "The sequence is usable for host-side reconstruction, but upstream activity can still sit outside current visibility."
        )

    return {
        "status": status,
        "timeline_entry_count": len(timeline),
        "accepted_auth_event_count": len(accepted_events),
        "normalized_event_count": len(normalized_points),
        "source_type_count": len(source_labels),
        "earliest_event_utc": earliest,
        "latest_event_utc": latest,
        "time_span_minutes": span_minutes,
        "summary": summary,
    }


def review_scope_closure(
    data: dict[str, Any],
    scene: dict[str, Any],
    accepted_auth_review: dict[str, Any],
    log_layout_review: dict[str, Any],
    timeline_review: dict[str, Any],
    lpe_review: dict[str, Any],
) -> dict[str, Any]:
    scope = as_dict(data.get("investigation_scope") or scene.get("investigation_scope"))
    auth_ips = [str(x).strip() for x in as_list(scene.get("auth_source_ips")) if str(x).strip()]
    accepted_sources = [as_dict(x) for x in as_list(accepted_auth_review.get("sources"))]
    contradiction_review = as_dict(scene.get("contradiction_review"))
    container_hit_count = int(scene.get("container_cloud_review_hit_count", 0) or 0)
    internal_auth_ips = sorted({ip for ip in auth_ips if is_private_ip(ip)})
    pivot_ids: set[str] = set()
    pivots: list[dict[str, str]] = []

    def add_pivot(pivot_id: str, reason: str) -> None:
        if pivot_id in pivot_ids:
            return
        pivot_ids.add(pivot_id)
        pivots.append({"id": pivot_id, "reason": reason})

    if auth_ips or accepted_sources:
        add_pivot(
            "identity_boundary_logs",
            "Host-visible authentication sources exist, but authorization and upstream ingress still need non-host corroboration.",
        )
    if internal_auth_ips:
        add_pivot(
            "peer_host_internal_auth_pivot",
            "Private or internal authentication source IPs were observed and can indicate same-environment pivoting.",
        )
    if container_hit_count:
        add_pivot(
            "cloud_control_plane_audit",
            "Container or cloud review surfaces were present, so control-plane evidence is needed before closing ingress scope.",
        )
    if str(log_layout_review.get("status", "")) == "reduced_visibility_on_expected_logs":
        add_pivot(
            "boundary_telemetry_for_log_loss",
            "Applicable host logs remain missing or suspicious; external telemetry is needed to compensate for reduced host visibility.",
        )
    if str(timeline_review.get("status", "")) in {"timeline_not_recovered", "timeline_not_normalized", "narrow_window"}:
        add_pivot(
            "timeline_expansion",
            "Recovered event timing is incomplete for confident ingress reconstruction.",
        )
    if int(contradiction_review.get("count", 0) or 0) > 0:
        add_pivot(
            "contradiction_resolution",
            "Cross-source contradictions remain and should be resolved before stronger attribution or closure.",
        )
    if str(lpe_review.get("status", "")) != "not_observed":
        add_pivot(
            "privesc_change_records",
            "Local-privesc exposure remains in scope and needs package backport or admin change-history corroboration.",
        )

    if pivots:
        status = "needs_external_corroboration"
        summary = (
            f"Host-only evidence is not sufficient to close the requested scope. "
            f"{len(pivots)} external or cross-host pivot(s) remain open."
        )
    else:
        status = "host_only_scope_sufficient_for_requested_focus"
        summary = "Current host evidence is sufficient to support the requested read-only review scope without mandatory extra pivots."

    return {
        "status": status,
        "requested_focus": [str(x).strip() for x in as_list(scope.get("requested_focus")) if str(x).strip()],
        "auth_source_ip_count": len(auth_ips),
        "accepted_source_count": len(accepted_sources),
        "internal_auth_ip_count": len(internal_auth_ips),
        "internal_auth_ips": internal_auth_ips[:8],
        "container_cloud_hit_count": container_hit_count,
        "contradiction_count": int(contradiction_review.get("count", 0) or 0),
        "log_visibility_reduced": str(log_layout_review.get("status", "")) == "reduced_visibility_on_expected_logs",
        "external_pivots": pivots,
        "summary": summary,
    }


def build_workflow_review(
    data: dict[str, Any],
    accepted_auth_review: dict[str, Any],
    log_layout_review: dict[str, Any],
    persistence_review: dict[str, Any],
    timeline_review: dict[str, Any],
    scope_closure_review: dict[str, Any],
    lpe_review: dict[str, Any],
) -> dict[str, Any]:
    scene = as_dict(data.get("scene_reconstruction"))
    scope = as_dict(data.get("investigation_scope") or scene.get("investigation_scope"))
    closure_notes = []
    for note in as_list(accepted_auth_review.get("unresolved_actions"))[:6]:
        closure_notes.append(str(note))
    if str(log_layout_review.get("status")) == "reduced_visibility_on_expected_logs":
        closure_notes.append("Correlate fallback auth artifacts and external telemetry before treating missing logs as attacker-driven.")
    if str(timeline_review.get("status")) in {"timeline_not_recovered", "timeline_not_normalized", "narrow_window"}:
        closure_notes.append("Expand the UTC timeline using surviving artifacts and non-host telemetry before closing the ingress sequence.")
    if str(persistence_review.get("status")) == "high_signal_present":
        closure_notes.append("Review each high-signal startup or policy line directly by evidence ID before any containment step.")
    if str(lpe_review.get("status")) != "not_observed":
        closure_notes.append("Validate package backport status and admin workflow before treating local-privesc exposure as exploit use.")
    for item in as_list(scope_closure_review.get("external_pivots"))[:6]:
        reason = str(as_dict(item).get("reason", "")).strip()
        if reason:
            closure_notes.append(reason)
    closure_ready = (
        str(scope_closure_review.get("status", "")) == "host_only_scope_sufficient_for_requested_focus"
        and str(timeline_review.get("status", "")) == "normalized_window_present"
        and str(log_layout_review.get("status", "")) != "reduced_visibility_on_expected_logs"
    )
    return {
        "status": "completed_ready_for_host_only_report" if closure_ready else "completed_with_open_gaps",
        "gates": {
            "scope_bound": bool(as_list(scope.get("requested_focus"))),
            "scope_rechecked": True,
            "timeline_rechecked": True,
            "hypotheses_retested": True,
            "distro_log_layout_rechecked": True,
            "external_pivots_defined": bool(as_list(scope_closure_review.get("external_pivots"))),
            "closure_notes_added": bool(closure_notes),
        },
        "closure_ready_for_host_only_report": closure_ready,
        "open_gap_count": len(closure_notes),
        "closure_notes": closure_notes,
        "summary": (
            "Second-pass review found no mandatory external corroboration gaps for the requested host-only scope."
            if closure_ready
            else "Second-pass review kept explicit open gaps visible; do not over-close the case on host evidence alone."
        ),
    }


def apply_hypothesis_overrides(
    data: dict[str, Any],
    accepted_auth_review: dict[str, Any],
    log_layout_review: dict[str, Any],
    persistence_review: dict[str, Any],
    lpe_review: dict[str, Any],
) -> list[dict[str, Any]]:
    scene = as_dict(data.get("scene_reconstruction"))
    auth_counts = as_dict(scene.get("auth_event_counts"))
    failed = int(auth_counts.get("failed", 0) or 0)
    invalid = int(auth_counts.get("invalid", 0) or 0)
    current_count = int(accepted_auth_review.get("current_session_candidate_count", 0) or 0)
    recurring_count = int(accepted_auth_review.get("recurring_source_count", 0) or 0)
    unknown_count = int(accepted_auth_review.get("authorization_unknown_count", 0) or 0)
    mixed_count = int(accepted_auth_review.get("mixed_signal_source_count", 0) or 0)

    updated: list[dict[str, Any]] = []
    for raw in as_list(data.get("hypothesis_matrix")):
        item = as_dict(raw)
        hypothesis_id = str(item.get("hypothesis_id", "")).strip()
        if hypothesis_id == "H-MATRIX-ACCESS-001":
            item["summary"] = (
                f"Authentication pressure observed (failed={failed}, invalid={invalid}). "
                f"Accepted-access re-review found {current_count} current-session candidate(s), "
                f"{recurring_count} recurring source(s), {mixed_count} mixed-signal source(s), and "
                f"{unknown_count} authorization-unknown source(s). Accepted access alone is not treated as attacker-controlled without corroboration."
            )
        elif hypothesis_id == "H-MATRIX-LOG-001":
            adjusted_count = int(log_layout_review.get("adjusted_primary_log_risk_count", 0) or 0)
            if adjusted_count == 0:
                item["status"] = "not_observed"
                item["confidence"] = "low"
            else:
                item["status"] = "supported" if any(
                    "tampered" in str(x.get("status", "")).lower()
                    for x in as_list(data.get("log_integrity"))
                    if str(x.get("artifact", "")).strip() in set(log_layout_review.get("adjusted_risky_artifacts", []))
                ) else "inconclusive"
                item["confidence"] = "medium" if item["status"] == "supported" else "low"
            item["summary"] = str(log_layout_review.get("summary", item.get("summary", "")))
        elif hypothesis_id == "H-MATRIX-PERSIST-001":
            if str(persistence_review.get("status")) == "high_signal_present":
                item["status"] = "supported"
                item["confidence"] = "medium"
            elif str(persistence_review.get("status")) == "not_observed":
                item["status"] = "not_observed"
                item["confidence"] = "low"
            else:
                item["status"] = "inconclusive"
                item["confidence"] = "low"
            item["summary"] = str(persistence_review.get("summary", item.get("summary", "")))
        elif hypothesis_id == "H-MATRIX-LPE-001":
            if str(lpe_review.get("status")) == "plausible_used":
                item["status"] = "supported"
                item["confidence"] = "medium"
            elif str(lpe_review.get("status")) == "not_observed":
                item["status"] = "not_observed"
                item["confidence"] = "low"
            else:
                item["status"] = "inconclusive"
                item["confidence"] = "low"
            item["summary"] = str(lpe_review.get("summary", item.get("summary", "")))
        updated.append(item)
    return updated


def review(data: dict[str, Any]) -> dict[str, Any]:
    evidence_items = [as_dict(x) for x in as_list(data.get("evidence"))]
    scene = as_dict(data.get("scene_reconstruction"))
    accepted_auth_review = review_accepted_auth_sources(data, scene)
    log_layout_review = review_log_layout(data, scene)
    persistence_review = review_persistence_surfaces(data, scene)
    lpe_review = review_lpe_use(scene, persistence_review, accepted_auth_review)
    timeline_review = review_timeline_consistency(data, scene)
    scope_closure_review = review_scope_closure(
        data,
        scene,
        accepted_auth_review,
        log_layout_review,
        timeline_review,
        lpe_review,
    )
    workflow_review = build_workflow_review(
        data,
        accepted_auth_review,
        log_layout_review,
        persistence_review,
        timeline_review,
        scope_closure_review,
        lpe_review,
    )

    second_pass_review = {
        "generated_at_utc": now_utc(),
        "accepted_auth_review": accepted_auth_review,
        "log_layout_review": log_layout_review,
        "persistence_surface_review": persistence_review,
        "lpe_use_review": lpe_review,
        "timeline_review": timeline_review,
        "scope_closure_review": scope_closure_review,
        "workflow_review": workflow_review,
    }

    scene["accepted_auth_review"] = accepted_auth_review
    scene["log_layout_review"] = log_layout_review
    scene["persistence_surface_review"] = persistence_review
    scene["lpe_use_review"] = lpe_review
    scene["timeline_review"] = timeline_review
    scene["scope_closure_review"] = scope_closure_review
    scene["workflow_review"] = workflow_review
    scene["accepted_auth_current_session_candidate_count"] = int(
        accepted_auth_review.get("current_session_candidate_count", 0) or 0
    )
    scene["accepted_auth_recurring_source_count"] = int(
        accepted_auth_review.get("recurring_source_count", 0) or 0
    )
    scene["accepted_auth_unknown_source_count"] = int(
        accepted_auth_review.get("authorization_unknown_count", 0) or 0
    )
    scene["adjusted_primary_log_risk_count"] = int(
        log_layout_review.get("adjusted_primary_log_risk_count", 0) or 0
    )
    scene["second_pass_high_signal_review_count"] = int(
        persistence_review.get("high_signal_count", 0) or 0
    ) + int(persistence_review.get("policy_signal_count", 0) or 0)
    scene["second_pass_review"] = second_pass_review

    data["scene_reconstruction"] = scene
    data["hypothesis_matrix"] = apply_hypothesis_overrides(
        data,
        accepted_auth_review,
        log_layout_review,
        persistence_review,
        lpe_review,
    )
    data["second_pass_review"] = second_pass_review
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Run second-pass review on enriched case evidence.")
    parser.add_argument("--input", required=True, help="Input evidence JSON file.")
    parser.add_argument("--output", help="Output JSON file. Defaults to overwriting input.")
    parser.add_argument("--case-dir", help="Optional case directory for writing meta/secondary-review.json.")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve() if args.output else input_path
    data = load_json(input_path)
    reviewed = review(data)
    write_json(output_path, reviewed)
    print(f"Second-pass reviewed evidence written: {output_path}")

    if args.case_dir:
        meta_dir = Path(args.case_dir).resolve() / "meta"
        meta_dir.mkdir(parents=True, exist_ok=True)
        meta_path = meta_dir / "secondary-review.json"
        meta_path.write_text(
            json.dumps(as_dict(reviewed.get("second_pass_review")), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"Second-pass review meta written: {meta_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
