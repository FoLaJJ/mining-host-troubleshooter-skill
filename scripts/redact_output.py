#!/usr/bin/env python3
"""Redact sensitive values from logs and command output."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED_PRIVATE_KEY_BLOCK]",
    ),
    (
        re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\b\s*[:=]\s*([^\s,;]+)"),
        r"\1=[REDACTED_SECRET]",
    ),
    (
        re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
        "[REDACTED_ETH_ADDRESS]",
    ),
    (
        re.compile(r"\b(bc1[a-z0-9]{20,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
        "[REDACTED_BTC_ADDRESS]",
    ),
    (
        re.compile(r"(?i)\b(user(name)?|login)\b\s*[:=]\s*([^\s,;]+)"),
        r"\1=[REDACTED_USER]",
    ),
]


IP_PATTERN = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")


def mask_ip(match: re.Match[str]) -> str:
    ip = match.group(0)
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    try:
        nums = [int(part) for part in parts]
    except ValueError:
        return ip
    if any(n < 0 or n > 255 for n in nums):
        return ip
    return f"{parts[0]}.{parts[1]}.x.x"


def redact(text: str, strict: bool) -> str:
    redacted = text
    for pattern, repl in PATTERNS:
        redacted = pattern.sub(repl, redacted)

    redacted = IP_PATTERN.sub(mask_ip, redacted)

    if strict:
        redacted = re.sub(r"[A-Za-z0-9+/]{24,}={0,2}", "[REDACTED_HIGH_ENTROPY]", redacted)
    return redacted


def read_input(file_path: str | None) -> str:
    if file_path:
        return Path(file_path).read_text(encoding="utf-8", errors="replace")
    return sys.stdin.read()


def main() -> int:
    parser = argparse.ArgumentParser(description="Redact secrets from output text.")
    parser.add_argument("file", nargs="?", help="Optional file path. Defaults to stdin.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Mask high-entropy strings aggressively.",
    )
    args = parser.parse_args()

    text = read_input(args.file)
    if not text:
        return 0

    sys.stdout.write(redact(text, strict=args.strict))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
