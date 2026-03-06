#!/usr/bin/env python3
"""Classify shell commands by operational risk for mining host troubleshooting."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Rule:
    level: str
    pattern: re.Pattern[str]
    reason: str
    consequence: str
    rollback_hint: str
    approval_gate: str = ""


BLOCKED_RULES: tuple[Rule, ...] = (
    Rule(
        "blocked",
        re.compile(r"\brm\s+-rf\s+/(?:\s|$)"),
        "Destructive filesystem wipe pattern.",
        "Immediate and irreversible data loss.",
        "No safe rollback. Require explicit maintenance plan and backups.",
    ),
    Rule(
        "blocked",
        re.compile(r"\bmkfs(\.| )"),
        "Formats a filesystem.",
        "Destroys existing volume data.",
        "Restore from image/backup only.",
    ),
    Rule(
        "blocked",
        re.compile(r"\bdd\s+if=.*\s+of=/dev/"),
        "Writes raw data to a block device.",
        "Can destroy partition tables or OS images.",
        "Restore from known-good disk image.",
    ),
    Rule(
        "blocked",
        re.compile(r"\b(wipefs|fdisk|cfdisk|sfdisk|parted|sgdisk)\b"),
        "Low-level disk partition or signature mutation.",
        "Can make host unbootable or destroy data volumes.",
        "Restore partition table and data from backup.",
    ),
    Rule(
        "blocked",
        re.compile(r":\(\)\s*\{\s*:\|\:&\s*;\s*\}\s*;:"),
        "Fork bomb payload detected.",
        "Can exhaust CPU and process table immediately.",
        "Hard reset may be required.",
    ),
    Rule(
        "blocked",
        re.compile(r"\bchmod\s+-R\s+777\s+/(?:\s|$)"),
        "Global recursive permission broadening on root filesystem.",
        "Severe privilege and integrity compromise risk.",
        "Restore from immutable baseline and permission backups.",
    ),
    Rule(
        "blocked",
        re.compile(r"\bchown\s+-R\s+\S+\s+/(?:\s|$)"),
        "Global ownership rewrite on root filesystem.",
        "Can break system boot and access controls.",
        "Restore filesystem ownership from trusted image.",
    ),
    Rule(
        "blocked",
        re.compile(r"\b(iptables|nft)\b.*(?:\s|^)(-f|flush)(?:\s|$)"),
        "Firewall flush operation.",
        "Can expose host or drop required protections.",
        "Restore firewall rules from known-good backup.",
    ),
    Rule(
        "blocked",
        re.compile(r">\s*/etc/sudoers\b|>>\s*/etc/sudoers\b"),
        "Direct write to sudoers file.",
        "Can immediately break or backdoor privilege control.",
        "Restore sudoers from secure backup and validate with visudo.",
    ),
)


FULL_COMMAND_BLOCKED_RULES: tuple[Rule, ...] = (
    Rule(
        "blocked",
        re.compile(r"(\bcurl\b[^\n|]*\|\s*(sudo\s+)?(bash|sh)\b|\bwget\b[^\n|]*\|\s*(sudo\s+)?(bash|sh)\b)"),
        "Remote script piped directly into a shell.",
        "Can execute unreviewed or malicious payloads.",
        "Rebuild from trusted baseline if compromised.",
    ),
    Rule(
        "blocked",
        re.compile(r":\(\)\s*\{\s*:\|\:&\s*;\s*\}\s*;:"),
        "Fork bomb payload detected.",
        "Can exhaust CPU and process table immediately.",
        "Hard reset may be required.",
    ),
    Rule(
        "blocked",
        re.compile(r"\b(history\s+-c|unset\s+histfile)\b"),
        "Shell history destruction command.",
        "Destroys forensic traces and hinders incident reconstruction.",
        "Recover from remote log aggregation or snapshots if available.",
    ),
    Rule(
        "blocked",
        re.compile(r"(>|>>)\s*~?/?\.?bash_history\b"),
        "Direct mutation of shell history files.",
        "Destroys forensic evidence.",
        "Recover from central logging only.",
    ),
    Rule(
        "blocked",
        re.compile(r"\b(rm|truncate|shred)\b.*(/var/log/auth\.log|/var/log/secure|auth\.log(\.\d+)?|bash_history)\b"),
        "Forensic log/history tampering pattern.",
        "Removes or corrupts critical audit evidence.",
        "Recover from immutable backups or SIEM retention.",
    ),
    Rule(
        "blocked",
        re.compile(r"\bln\s+-s[f]?\s+/dev/null\s+/var/log/"),
        "Log null-routing pattern detected.",
        "Silently disables future logging for targeted files.",
        "Restore log files and verify rsyslog/journald pipeline.",
    ),
    Rule(
        "blocked",
        re.compile(r"\bjournalctl\b.*--vacuum-(time|size|files)\b"),
        "Journal vacuum command detected during incident workflow.",
        "Can destroy or reduce available forensic history.",
        "Recover from remote log retention if available.",
    ),
)


CONFIRM_RULES: tuple[Rule, ...] = (
    Rule(
        "confirm_required",
        re.compile(r"\b(systemctl|service)\s+(restart|stop|start|enable|disable)\b"),
        "Service lifecycle change.",
        "Can interrupt mining jobs or host services.",
        "Revert to previous service state and config backup.",
        "business_interruption",
    ),
    Rule(
        "confirm_required",
        re.compile(r"\b(kill|pkill|killall)\b"),
        "Process termination.",
        "Can drop hashrate or orphan active work.",
        "Restart expected process and validate health checks.",
        "business_interruption",
    ),
    Rule(
        "confirm_required",
        re.compile(r"\b(apt|apt-get|yum|dnf|pacman|zypper)\b.*\b(install|remove|upgrade|downgrade)\b"),
        "Package or dependency mutation.",
        "Can break driver/miner compatibility.",
        "Reinstall pinned package versions.",
        "irreversible_change",
    ),
    Rule(
        "confirm_required",
        re.compile(r"\b(reboot|shutdown|poweroff|init\s+6)\b"),
        "Host power state change.",
        "Guaranteed service interruption.",
        "Boot back with previous startup profile.",
        "business_interruption",
    ),
    Rule(
        "confirm_required",
        re.compile(r"\b(iptables|nft|ufw|firewall-cmd|route|ip\s+route)\b"),
        "Network policy or routing change.",
        "May isolate host or pool connectivity.",
        "Restore previous ruleset backup.",
        "business_interruption",
    ),
    Rule(
        "confirm_required",
        re.compile(r"\b(sed\s+-i|perl\s+-pi|tee\s+.+>|echo\s+.+>)"),
        "Inline file mutation.",
        "Can corrupt miner or system configuration.",
        "Restore from file backup.",
        "irreversible_change",
    ),
    Rule(
        "confirm_required",
        re.compile(
            r"((\b(cp|mv|rm|install|tee|truncate)\b.*(/etc/|\.conf\b|\.service\b))|"
            r"(\b(sed\s+-i|perl\s+-pi|echo)\b.*(/etc/|\.conf\b|\.service\b))|"
            r"((>|>>)\s*(/etc/|[^ ]*\.conf\b|[^ ]*\.service\b)))"
        ),
        "Configuration mutation targeting system paths.",
        "Persistent behavior can change after reboot.",
        "Revert to backup and daemon-reload if needed.",
        "irreversible_change",
    ),
    Rule(
        "confirm_required",
        re.compile(r"\b(nvidia-smi|nvidia-settings|rocm-smi)\b.*(--power-limit|--lock|--set|fan|clock|volt)"),
        "GPU tuning change.",
        "Can destabilize hashrate, thermals, or hardware life.",
        "Reset clocks/power/fan to baseline profile.",
        "reversible_change",
    ),
    Rule(
        "confirm_required",
        re.compile(r"^(useradd|userdel|usermod|passwd|chpasswd)\b"),
        "Identity or credential mutation.",
        "Can lock out operators or change access controls.",
        "Restore previous account settings from IAM policy.",
        "irreversible_change",
    ),
    Rule(
        "confirm_required",
        re.compile(r"\bchattr\b"),
        "File attribute command touches immutable/integrity state.",
        "Can hide or lock configuration and binaries unexpectedly.",
        "Revert attributes to baseline state.",
        "irreversible_change",
    ),
    Rule(
        "confirm_required",
        re.compile(r"\b(crontab|at|systemctl\s+edit)\b"),
        "Persistence/scheduling mutation.",
        "Can introduce hidden recurring changes.",
        "Remove scheduled entries and restore prior unit files.",
        "irreversible_change",
    ),
    Rule(
        "confirm_required",
        re.compile(r"\b(mount|umount)\b"),
        "Filesystem mount state mutation.",
        "Can disrupt miner data paths or host availability.",
        "Restore prior mount options and remount sequence.",
        "business_interruption",
    ),
    Rule(
        "confirm_required",
        re.compile(r"\b(ln|mv|cp)\b.*\b(/usr/bin|/bin|/usr/sbin|/sbin)\b"),
        "System binary path mutation.",
        "Can replace trusted binaries with altered versions.",
        "Restore binaries from package manager or gold image.",
        "irreversible_change",
    ),
    Rule(
        "confirm_required",
        re.compile(r"\blogrotate\b.*(\s-f\b|--force)"),
        "Forced log rotation during active investigation.",
        "May rotate away or compress evidence before capture.",
        "Capture logs first, then rotate under change control.",
        "business_interruption",
    ),
)


SAFE_HINTS: tuple[str, ...] = (
    "alias",
    "type ",
    "command -v",
    "which ",
    "whereis ",
    "cat ",
    "grep ",
    "rg ",
    "awk ",
    "sed ",
    "tail ",
    "head ",
    "less ",
    "journalctl",
    "dmesg",
    "ss ",
    "netstat",
    "lsof ",
    "ps ",
    "top ",
    "htop",
    "free ",
    "uptime",
    "df ",
    "du ",
    "ls ",
    "find ",
    "lsattr ",
    "sha256sum ",
    "md5sum ",
    "stat ",
    "readlink ",
    "realpath ",
    "dpkg -s",
    "dpkg -l",
    "dpkg -v",
    "rpm -q",
    "rpm -v",
    "pacman -q",
    "pacman -qi",
    "debsums",
    "nvidia-smi",
    "rocm-smi",
    "sensors",
    "ip a",
    "ip route",
    "ping ",
    "traceroute",
    "curl ",
)

SAFE_MUTATION_MARKERS: tuple[str, ...] = (
    ">",
    ">>",
    "| tee",
    " sed -i",
    " perl -pi",
    " systemctl ",
    " service ",
    " chattr ",
    " chmod ",
    " chown ",
    " mount ",
    " umount ",
)


def normalize_segment(segment: str) -> str:
    normalized = " ".join(segment.strip().lower().split())
    normalized = re.sub(r"^sudo(\s+-[a-z]+)*\s+", "", normalized)
    if normalized.startswith("env "):
        normalized = normalized[4:].strip()
        # Strip leading KEY=VALUE assignments after env.
        while True:
            match = re.match(r"^[a-z_][a-z0-9_]*=[^\s]+\s+", normalized)
            if not match:
                break
            normalized = normalized[match.end():]
    return normalized


def split_segments(command: str) -> list[str]:
    separators = ("&&", "||", ";", "|")
    segments = [command]
    for sep in separators:
        next_segments: list[str] = []
        for segment in segments:
            next_segments.extend(part.strip() for part in segment.split(sep))
        segments = next_segments
    return [s for s in segments if s]


def approval_gate_for(level: str, rule_gate: str = "") -> str:
    if rule_gate:
        return rule_gate
    if level == "blocked":
        return "blocked"
    if level == "confirm_required":
        return "reversible_change"
    if level == "read_only":
        return "read_only"
    return "unknown_review"


def gate_priority(gate: str) -> int:
    return {
        "blocked": 5,
        "business_interruption": 4,
        "irreversible_change": 3,
        "reversible_change": 2,
        "unknown_review": 1,
        "read_only": 0,
    }.get(gate, 1)


def build_result(segment: str, rule: Rule | None, level: str, reason: str, consequence: str, rollback_hint: str) -> dict[str, str]:
    approval_gate = approval_gate_for(level, rule.approval_gate if rule else "")
    return {
        "segment": segment,
        "level": level,
        "approval_gate": approval_gate,
        "reason": reason,
        "consequence": consequence,
        "rollback_hint": rollback_hint,
    }


def classify_segment(segment: str) -> dict[str, str]:
    normalized = normalize_segment(segment)

    for rule in BLOCKED_RULES:
        if rule.pattern.search(normalized):
            return build_result(segment, rule, rule.level, rule.reason, rule.consequence, rule.rollback_hint)

    safe_match = any(normalized.startswith(prefix) for prefix in SAFE_HINTS)
    safe_with_no_mutation = safe_match and not any(marker in normalized for marker in SAFE_MUTATION_MARKERS)
    if safe_with_no_mutation:
        return build_result(segment, None, "read_only", "Query-style command detected.", "No intended system state mutation.", "No rollback expected.")

    for rule in CONFIRM_RULES:
        if rule.pattern.search(normalized):
            return build_result(segment, rule, rule.level, rule.reason, rule.consequence, rule.rollback_hint)

    return build_result(segment, None, "unknown_review", "Could not confidently classify as read-only.", "Potential hidden side effects.", "Review command intent before running.")


def summarize(results: Iterable[dict[str, str]]) -> str:
    priorities = {"blocked": 4, "confirm_required": 3, "unknown_review": 2, "read_only": 1}
    top = max((priorities.get(r["level"], 0) for r in results), default=0)
    reverse = {v: k for k, v in priorities.items()}
    return reverse.get(top, "unknown_review")


def summarize_gate(results: Iterable[dict[str, str]]) -> str:
    top = max((gate_priority(r.get("approval_gate", "unknown_review")) for r in results), default=1)
    reverse = {
        5: "blocked",
        4: "business_interruption",
        3: "irreversible_change",
        2: "reversible_change",
        1: "unknown_review",
        0: "read_only",
    }
    return reverse.get(top, "unknown_review")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Classify command risk. Use before running host commands."
    )
    parser.add_argument("command", nargs="*", help="Command text to classify.")
    parser.add_argument("--json", action="store_true", help="Emit JSON only.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    raw = " ".join(args.command).strip()
    if not raw:
        raw = sys.stdin.read().strip()
    if not raw:
        parser.error("Provide a command argument or stdin input.")

    full_normalized = normalize_segment(raw)
    for rule in FULL_COMMAND_BLOCKED_RULES:
        if rule.pattern.search(full_normalized):
            results = [build_result(raw, rule, rule.level, rule.reason, rule.consequence, rule.rollback_hint)]
            overall = "blocked"
            overall_gate = "blocked"
            payload = {"command": raw, "overall_level": overall, "overall_gate": overall_gate, "segments": results}
            if args.json:
                print(json.dumps(payload, ensure_ascii=True, indent=2))
                return 0
            print(f"overall_level: {overall}")
            print(f"overall_gate: {overall_gate}")
            print(f"[1] segment: {raw}")
            print(f"    level: {rule.level}")
            print(f"    approval_gate: {overall_gate}")
            print(f"    reason: {rule.reason}")
            print(f"    consequence: {rule.consequence}")
            print(f"    rollback_hint: {rule.rollback_hint}")
            return 0

    segments = split_segments(raw)
    results = [classify_segment(seg) for seg in segments]
    overall = summarize(results)
    overall_gate = summarize_gate(results)

    payload = {"command": raw, "overall_level": overall, "overall_gate": overall_gate, "segments": results}
    if args.json:
        print(json.dumps(payload, ensure_ascii=True, indent=2))
        return 0

    print(f"overall_level: {overall}")
    print(f"overall_gate: {overall_gate}")
    for idx, result in enumerate(results, 1):
        print(f"[{idx}] segment: {result['segment']}")
        print(f"    level: {result['level']}")
        print(f"    approval_gate: {result['approval_gate']}")
        print(f"    reason: {result['reason']}")
        print(f"    consequence: {result['consequence']}")
        print(f"    rollback_hint: {result['rollback_hint']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
