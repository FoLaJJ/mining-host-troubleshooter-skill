#!/usr/bin/env python3
"""Build a normal-host baseline profile from one or more known-clean case bundles."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from compare_case_bundles import build_host_scope, parse_case
from enrich_case_evidence import as_dict, as_list, load_json, split_artifact_sections


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def render_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in row) + " |")
    return "\n".join(lines)


def resolve_case_dirs(args: argparse.Namespace) -> list[Path]:
    case_dirs = [Path(x).resolve() for x in args.case]
    if args.reports_root:
        reports_root = Path(args.reports_root).resolve()
        if not reports_root.exists():
            raise SystemExit(f'reports root not found: {reports_root}')
        for child in sorted(reports_root.iterdir()):
            if not child.is_dir() or child.name.startswith('_'):
                continue
            evidence_dir = child / 'evidence'
            if not evidence_dir.exists():
                continue
            case_dirs.append(child)
    if not case_dirs:
        raise SystemExit('Provide at least one --case or a --reports-root containing case bundles.')
    unique: list[Path] = []
    seen: set[str] = set()
    for path in case_dirs:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def extract_case_extras(case_dir: Path, evidence_items: list[dict[str, Any]]) -> dict[str, list[str]]:
    running_services: set[str] = set()
    container_names: set[str] = set()
    container_images: set[str] = set()
    for item in evidence_items:
        source = str(item.get('source', '')).strip()
        command = str(item.get('command', '')).strip()
        artifact = Path(str(item.get('artifact', '')).strip())
        if not artifact.exists():
            continue
        stdout, _ = split_artifact_sections(artifact.read_text(encoding='utf-8', errors='replace'))
        if source == 'service' and command.startswith('systemctl list-units --type=service --state=running --no-pager --no-legend'):
            for line in stdout.splitlines():
                parts = line.split()
                if parts:
                    running_services.add(parts[0])
        if source == 'container' and command.startswith("docker ps --format '{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}'"):
            for line in stdout.splitlines():
                parts = line.split('	')
                if len(parts) >= 3:
                    container_images.add(parts[1].strip())
                    container_names.add(parts[2].strip())
        if source == 'container' and command.startswith("docker ps --format '{{.ID}} {{.Names}} {{.Image}}'"):
            for line in stdout.splitlines():
                if not line.startswith('## '):
                    continue
                parts = line[3:].split()
                if len(parts) >= 3:
                    container_names.add(parts[1].strip())
                    container_images.add(parts[2].strip())
    return {
        'running_services': sorted(running_services),
        'container_names': sorted(container_names),
        'container_images': sorted(container_images),
    }


def intersect_sets(values: list[set[str]]) -> list[str]:
    if not values:
        return []
    acc = set(values[0])
    for value in values[1:]:
        acc &= value
    return sorted(acc)


def union_sets(values: list[set[str]]) -> list[str]:
    out: set[str] = set()
    for value in values:
        out |= value
    return sorted(out)


def majority_sets(values: list[set[str]]) -> list[str]:
    if not values:
        return []
    threshold = max(1, (len(values) + 1) // 2)
    counts: Counter[str] = Counter()
    for value in values:
        for item in value:
            counts[item] += 1
    return sorted([item for item, count in counts.items() if count >= threshold])



def evaluate_baseline_quality(case_count: int) -> dict[str, Any]:
    if case_count <= 1:
        return {
            'level': 'weak',
            'reason': 'Only one known-clean case was used. This is too thin to model normal drift and must not be treated as a host truth set.',
            'constraints': [
                'Do not use this baseline as proof that matching future behavior is benign.',
                'Do not suppress new authentication, persistence, process, or trust anomalies solely because they resemble this baseline.',
                'Use it only as a same-host historical snapshot until more known-clean cases are collected.',
            ],
        }
    if case_count == 2:
        return {
            'level': 'moderate',
            'reason': 'Two known-clean cases were used. This supports basic same-host comparison but still captures only limited normal variation.',
            'constraints': [
                'Do not use this baseline as a clearance decision by itself.',
                'Review all new execution paths, source IPs, persistence changes, and trust anomalies manually.',
            ],
        }
    return {
        'level': 'stronger',
        'reason': 'Three or more known-clean same-host cases were used. This improves noise suppression but still does not prove future benign state.',
        'constraints': [
            'Treat baseline hits as repeated same-host patterns, not as proof of legitimacy.',
            'Any new path, persistence, source IP, IOC, or trust deviation still requires analyst review.',
        ],
    }


def choose_output_root(args: argparse.Namespace, first_case: dict[str, Any]) -> Path:
    if args.output_dir:
        root = Path(args.output_dir).resolve()
    else:
        reports_root = Path(args.reports_root).resolve() if args.reports_root else Path(first_case['case_dir']).resolve().parent
        host_label = str(first_case.get('host_ip') or first_case.get('host_name') or 'host').replace(':', '-').replace('/', '-')
        root = reports_root / '_baselines' / f'{host_label}-baseline-{datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")}'
    root.mkdir(parents=True, exist_ok=True)
    return root


def render_markdown(baseline: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append('# Host Baseline Profile')
    lines.append('')
    lines.append('## Metadata')
    lines.append(f"- Generated At (UTC): `{baseline['generated_at_utc']}`")
    lines.append(f"- Host: `{baseline['host_name']}` ({baseline['host_ip']})")
    quality = as_dict(baseline.get('baseline_quality'))
    lines.append(f"- Cases Used: `{len(as_list(baseline['cases_used']))}`")
    lines.append(f"- Baseline Quality: `{quality.get('level', 'unknown')}`")
    lines.append(f"- Quality Reason: {quality.get('reason', 'not provided')}")
    lines.append('')
    lines.append('## Scope')
    for item in as_list(baseline.get('cases_used')):
        lines.append(f"- `{item['case_name']}` from `{item['generated_at']}`")
    lines.append('')
    sections = [
        ('Stable Listening Ports', baseline['stable']['listening_ports']),
        ('Stable Auth Source IPs', baseline['stable']['auth_source_ips']),
        ('Stable Running Services', baseline['stable']['running_services']),
        ('Stable Container Names', baseline['stable']['container_names']),
        ('Stable Container Images', baseline['stable']['container_images']),
        ('Majority Container Names', baseline['observed_majority']['container_names']),
        ('Majority Container Images', baseline['observed_majority']['container_images']),
    ]
    for title, items in sections:
        lines.append(f'## {title}')
        if items:
            for item in items:
                lines.append(f'- `{item}`')
        else:
            lines.append('- None observed across every input case.')
        lines.append('')
    lines.append('## Observed Union')
    rows = [
        ['Listening Ports', ', '.join(baseline['observed_union']['listening_ports']) or '-'],
        ['Auth Source IPs', ', '.join(baseline['observed_union']['auth_source_ips']) or '-'],
        ['Running Services', ', '.join(baseline['observed_union']['running_services'][:20]) or '-'],
        ['Container Names', ', '.join(baseline['observed_union']['container_names']) or '-'],
        ['Container Images', ', '.join(baseline['observed_union']['container_images']) or '-'],
    ]
    lines.append(render_table(['Metric', 'Values'], rows))
    lines.append('')
    lines.append('## Notes')
    lines.append('- This profile records what was repeatedly observed on a host believed to be clean at collection time.')
    lines.append('- Treat it as a suppression aid and comparison baseline, not as proof that future matches are always benign.')
    lines.append('- Do not suppress findings that introduce new execution paths, new persistence, new source IPs, or trust anomalies without analyst review.')
    for constraint in as_list(quality.get('constraints')):
        lines.append(f'- {constraint}')
    lines.append('')
    return '\n'.join(lines).strip() + '\n'


def main() -> int:
    parser = argparse.ArgumentParser(description='Build a normal-host baseline profile from one or more known-clean case bundles.')
    parser.add_argument('--case', action='append', default=[], help='Case directory. Repeat for multiple cases.')
    parser.add_argument('--reports-root', help='Reports root to scan for candidate case bundles.')
    parser.add_argument('--host-ip', help='Restrict auto-selected cases to this host IP.')
    parser.add_argument('--host-name', help='Restrict auto-selected cases to this host name.')
    parser.add_argument('--output-dir', help='Output directory. Defaults to <reports-root>/_baselines/<host>-baseline-<timestamp>.')
    args = parser.parse_args()

    raw_case_dirs = resolve_case_dirs(args)
    parsed_cases: list[dict[str, Any]] = []
    host_ip_filter = (args.host_ip or '').strip().lower()
    host_name_filter = (args.host_name or '').strip().lower()
    for case_dir in raw_case_dirs:
        parsed = parse_case(case_dir)
        host_ip = str(parsed.get('host_ip', '')).strip().lower()
        host_name = str(parsed.get('host_name', '')).strip().lower()
        if host_ip_filter and host_ip != host_ip_filter:
            continue
        if host_name_filter and host_name != host_name_filter:
            continue
        parsed_cases.append(parsed)
    if not parsed_cases:
        raise SystemExit('No matching case bundles found for baseline generation.')

    first = parsed_cases[0]
    selected: list[dict[str, Any]] = [first]
    for case in parsed_cases[1:]:
        scope = build_host_scope(first, case)
        if not scope.get('match'):
            continue
        selected.append(case)
    if len(selected) == 0:
        raise SystemExit('No same-host cases available after scope filtering.')

    evidence_cache: dict[str, list[dict[str, Any]]] = {}
    service_sets: list[set[str]] = []
    container_name_sets: list[set[str]] = []
    container_image_sets: list[set[str]] = []
    for case in selected:
        evidence_path = Path(case['evidence_path'])
        data = load_json(evidence_path)
        evidence_items = [as_dict(x) for x in as_list(data.get('evidence'))]
        evidence_cache[case['case_dir']] = evidence_items
        extras = extract_case_extras(Path(case['case_dir']), evidence_items)
        service_sets.append(set(extras['running_services']))
        container_name_sets.append(set(extras['container_names']))
        container_image_sets.append(set(extras['container_images']))
        case['running_services'] = extras['running_services']
        case['container_names'] = extras['container_names']
        case['container_images'] = extras['container_images']

    baseline_quality = evaluate_baseline_quality(len(selected))

    baseline = {
        'generated_at_utc': now_utc(),
        'host_name': first.get('host_name', 'unknown'),
        'host_ip': first.get('host_ip', 'unknown'),
        'baseline_quality': {**baseline_quality, 'case_count': len(selected)},
        'cases_used': [
            {
                'case_name': case['case_name'],
                'case_dir': case['case_dir'],
                'generated_at': case['generated_at'],
                'evidence_count': case['evidence_count'],
            }
            for case in selected
        ],
        'stable': {
            'listening_ports': intersect_sets([set(case['listening_ports']) for case in selected]),
            'auth_source_ips': intersect_sets([set(case['auth_source_ips']) for case in selected]),
            'trust_anomalies': intersect_sets([set(case['trust_anomalies']) for case in selected]),
            'process_ioc_lines': intersect_sets([set(case['process_ioc_lines']) for case in selected]),
            'running_services': intersect_sets(service_sets),
            'container_names': intersect_sets(container_name_sets),
            'container_images': intersect_sets(container_image_sets),
        },
        'observed_union': {
            'listening_ports': union_sets([set(case['listening_ports']) for case in selected]),
            'auth_source_ips': union_sets([set(case['auth_source_ips']) for case in selected]),
            'trust_anomalies': union_sets([set(case['trust_anomalies']) for case in selected]),
            'process_ioc_lines': union_sets([set(case['process_ioc_lines']) for case in selected]),
            'running_services': union_sets(service_sets),
            'container_names': union_sets(container_name_sets),
            'container_images': union_sets(container_image_sets),
        },
        'observed_majority': {
            'listening_ports': majority_sets([set(case['listening_ports']) for case in selected]),
            'auth_source_ips': majority_sets([set(case['auth_source_ips']) for case in selected]),
            'trust_anomalies': majority_sets([set(case['trust_anomalies']) for case in selected]),
            'process_ioc_lines': majority_sets([set(case['process_ioc_lines']) for case in selected]),
            'running_services': majority_sets(service_sets),
            'container_names': majority_sets(container_name_sets),
            'container_images': majority_sets(container_image_sets),
        },
        'auth_event_totals': dict(Counter({
            'accepted': sum(int(case['auth_events']['accepted']) for case in selected),
            'failed': sum(int(case['auth_events']['failed']) for case in selected),
            'invalid': sum(int(case['auth_events']['invalid']) for case in selected),
        })),
    }

    out_dir = choose_output_root(args, first)
    json_path = out_dir / 'baseline.json'
    md_path = out_dir / 'baseline.md'
    json_path.write_text(json.dumps(baseline, ensure_ascii=False, indent=2), encoding='utf-8')
    md_path.write_text(render_markdown(baseline), encoding='utf-8')
    print(f'Baseline JSON written: {json_path}')
    print(f'Baseline Markdown written: {md_path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
