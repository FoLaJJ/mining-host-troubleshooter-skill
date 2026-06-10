import sys
import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import export_investigation_report as export_investigation_report  # noqa: E402


class ExportInvestigationReportTests(unittest.TestCase):
    def test_case_dir_mode_always_writes_canonical_report_md(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp)
            case_dir = temp_root / "case"
            case_dir.mkdir()
            input_path = temp_root / "input.json"
            input_path.write_text("{}", encoding="utf-8")
            custom_output = temp_root / "custom-report.md"

            argv = [
                "export_investigation_report.py",
                "--input",
                str(input_path),
                "--case-dir",
                str(case_dir),
                "--output",
                str(custom_output),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(export_investigation_report, "load_json", return_value={}),
                patch.object(export_investigation_report, "build_report", return_value=("report-body", [])),
                patch.object(export_investigation_report, "write_companion_reports", return_value=[]),
            ):
                rc = export_investigation_report.main()

            self.assertEqual(rc, 0)
            self.assertTrue(custom_output.exists(), "Custom output should still be written.")
            self.assertTrue(
                (case_dir / "report.md").exists(),
                "Case bundle mode must always materialize the canonical report.md path.",
            )

    def test_prepare_report_context_prefers_platform_identity_when_host_os_is_unknown(self) -> None:
        data = {
            "host": {"name": "host-1", "ip": "1.2.3.4", "os": "unknown"},
            "scene_reconstruction": {
                "platform_identity": {
                    "os_release_id": "ubuntu",
                    "os_release_version": "22.04",
                    "os_release_codename": "jammy",
                }
            },
        }

        ctx = export_investigation_report.prepare_report_context(data, redact=False, strict=False, case_dir=None)
        self.assertEqual(ctx["os_name"], "ubuntu 22.04 jammy")

    def test_prepare_report_context_prefers_second_pass_adjusted_log_risk_count(self) -> None:
        data = {
            "log_integrity": [
                {"artifact": "/var/log/secure", "status": "missing"},
                {"artifact": "/var/log/messages", "status": "missing"},
            ],
            "second_pass_review": {
                "log_layout_review": {
                    "adjusted_primary_log_risk_count": 0,
                }
            },
        }

        ctx = export_investigation_report.prepare_report_context(data, redact=False, strict=False, case_dir=None)
        self.assertEqual(ctx["log_risk_count"], 0)

    def test_leadership_report_includes_second_pass_scope_and_timeline_review(self) -> None:
        data = {
            "incident": {"id": "INC-1", "title": "Case 1"},
            "host": {"name": "host-1", "ip": "1.2.3.4", "os": "ubuntu"},
            "scene_reconstruction": {},
            "second_pass_review": {
                "log_layout_review": {"adjusted_primary_log_risk_count": 0},
                "timeline_review": {
                    "status": "narrow_window",
                    "normalized_event_count": 1,
                    "time_span_minutes": 0,
                    "summary": "Recovered event timing is narrow and likely under-scopes earlier ingress or staging activity. Expand the time window before closing the case.",
                },
                "scope_closure_review": {
                    "status": "needs_external_corroboration",
                    "summary": "Host-only evidence is not sufficient to close the requested scope. 1 external or cross-host pivot(s) remain open.",
                    "external_pivots": [
                        {
                            "id": "identity_boundary_logs",
                            "reason": "Host-visible authentication sources exist, but authorization and upstream ingress still need non-host corroboration.",
                        }
                    ],
                },
                "workflow_review": {
                    "status": "completed_with_open_gaps",
                    "closure_ready_for_host_only_report": False,
                    "summary": "Second-pass review kept explicit open gaps visible; do not over-close the case on host evidence alone.",
                    "closure_notes": [
                        "Expand the UTC timeline using surviving artifacts and non-host telemetry before closing the ingress sequence."
                    ],
                },
            },
        }

        body = export_investigation_report.build_leadership_report(data, redact=False, case_dir=None)
        self.assertIn("## 🧪 Second-Pass Review", body)
        self.assertIn("timeline_window_narrow", body)
        self.assertIn("Identity / boundary authentication logs", body)

    def test_leadership_report_surfaces_collection_failure(self) -> None:
        data = {
            "incident": {"id": "INC-1", "title": "Case 1"},
            "host": {"name": "host-1", "ip": "1.2.3.4", "os": "ubuntu"},
            "collection_failure": {
                "status": "failed",
                "phase": "remote_command_precheck",
                "reason": "Remote command channel unavailable before collection.",
            },
        }

        body = export_investigation_report.build_leadership_report(data, redact=False, case_dir=None)
        self.assertIn("Collection failed before host-side evidence could be gathered.", body)
        self.assertIn("Remote command channel unavailable before collection.", body)

    def test_english_report_avoids_placeholder_question_mark_formatting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "case"
            case_dir.mkdir()
            artifact = case_dir / "artifact.txt"
            artifact.write_text(
                "[COMMAND]\nps aux | grep miner\n\n[STDOUT]\nroot 1 0.0 0.1 miner\n\n[STDERR]\n",
                encoding="utf-8",
            )
            data = {
                "incident": {"id": "INC-2", "title": "Case 2"},
                "host": {"name": "host-2", "ip": "2.2.2.2", "os": "ubuntu"},
                "generated_at": "2026-06-10T00:00:00+00:00",
                "evidence": [
                    {
                        "id": "E-1",
                        "source": "process",
                        "observed_at": "2026-06-10T00:00:01+00:00",
                        "command": "ps aux | grep miner",
                        "artifact": str(artifact),
                        "command_hash": "c",
                        "artifact_hash": "a",
                        "artifact_size_bytes": 123,
                        "timed_out": False,
                    }
                ],
                "findings": [
                    {
                        "id": "F-1",
                        "statement": "Miner-like process observed",
                        "claim_type": "observed_fact",
                        "confidence": "medium",
                        "confidence_reason": "visible in process list",
                        "hypothesis_id": "H-1",
                        "evidence_ids": ["E-1"],
                    }
                ],
                "timeline": [
                    {
                        "time": "2026-06-10T00:00:01+00:00",
                        "normalized_time_utc": "2026-06-10T00:00:01+00:00",
                        "event": "Miner process observed",
                        "source": "process",
                        "evidence_ids": ["E-1"],
                    }
                ],
                "hypothesis_matrix": [
                    {
                        "hypothesis_id": "H-1",
                        "title": "CPU runtime miner hypothesis",
                        "status": "supported",
                        "confidence": "medium",
                        "summary": "Miner-like process observed",
                        "supporting_evidence_ids": ["E-1"],
                        "counter_evidence_ids": [],
                    }
                ],
                "scene_reconstruction": {
                    "process_ioc_match_count": 1,
                    "runtime_profile_count": 1,
                    "runtime_profiles": [
                        {
                            "executable": "/tmp/xmrig",
                            "algorithm": "randomx",
                            "pool": "pool.example",
                            "proxy": "-",
                            "wallet": "wallet1",
                            "password": "x",
                            "cpu_threads": "8",
                            "origin_path": "/proc/123/cmdline",
                            "origin_line": "1",
                            "evidence_id": "E-1",
                        }
                    ],
                    "runtime_algorithms": ["randomx"],
                    "runtime_pools": ["pool.example"],
                    "runtime_proxies": ["-"],
                    "runtime_wallets": ["wallet1"],
                    "runtime_passwords": ["x"],
                    "runtime_cpu_threads": ["8"],
                },
                "ip_traces": [
                    {
                        "ip": "8.8.8.8",
                        "role": "remote",
                        "trace_status": "unknown",
                        "reason": "not traced",
                        "evidence_ids": ["E-1"],
                    }
                ],
                "log_integrity": [
                    {
                        "artifact": "/var/log/auth.log",
                        "status": "ok",
                        "reason": "present",
                        "evidence_ids": ["E-1"],
                    }
                ],
            }

            body, _ = export_investigation_report.build_report(
                json.loads(json.dumps(data)),
                redact=False,
                strict=False,
                case_dir=str(case_dir),
            )

        self.assertNotIn("<summary><strong>E-1</strong> ?", body)
        self.assertIn("<summary><strong>E-1</strong> :: process :: 2026-06-10T00:00:01+00:00 ::", body)
        self.assertIn("### OK /var/log/auth.log", body)


if __name__ == "__main__":
    unittest.main()
