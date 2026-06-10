import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import generate_operator_brief as generate_operator_brief  # noqa: E402


class GenerateOperatorBriefTests(unittest.TestCase):
    def test_operator_brief_uses_case_root_and_same_directory_summary_links(self) -> None:
        payload = {
            "generated_at_utc": "2026-06-09T00:00:00+00:00",
            "incident_id": "INC-1",
            "host_name": "host-1",
            "host_ip": "1.2.3.4",
            "verdict": "test",
            "requested_focus": ["intrusion-review"],
            "direct_hits": 0,
            "review_hits": 0,
            "log_risk_count": 0,
            "gpu_suspicious_process_count": 0,
            "gpu_peak_utilization_percent": 0,
            "possible_lpe_cves": [],
            "traceable_ip_count": 0,
            "unknown_ip_count": 0,
            "key_hypothesis": [],
            "key_findings": [],
            "auth_source_ips": [],
        }

        zh = generate_operator_brief.build_zh_md(payload, "")
        en = generate_operator_brief.build_en_md(payload, "")

        self.assertIn("../report.zh-CN.md", zh)
        self.assertIn("./soc-summary.zh-CN.md", zh)
        self.assertNotIn("../reports/soc-summary.zh-CN.md", zh)

        self.assertIn("../report.md", en)
        self.assertIn("./soc-summary.md", en)
        self.assertNotIn("../reports/soc-summary.md", en)

    def test_operator_brief_prefers_second_pass_adjusted_log_risk_count(self) -> None:
        data = {
            "scene_reconstruction": {
                "process_ioc_match_count": 0,
                "network_ioc_hit_count": 0,
                "gpu_suspicious_process_count": 0,
                "initial_access_review_hit_count": 0,
                "container_cloud_review_hit_count": 0,
                "kernel_review_hit_count": 0,
                "gpu_peak_utilization_percent": 0,
                "auth_source_ips": [],
                "local_privesc_review": {},
            },
            "investigation_scope": {"requested_focus": ["intrusion-review"]},
            "ip_traces": [],
            "log_integrity": [
                {"artifact": "/var/log/secure", "status": "missing"},
                {"artifact": "/var/log/messages", "status": "missing"},
            ],
            "second_pass_review": {
                "log_layout_review": {
                    "adjusted_primary_log_risk_count": 0,
                }
            },
            "host": {"name": "host-1", "ip": "1.2.3.4"},
            "incident": {"id": "INC-1"},
        }

        payload = generate_operator_brief.build_brief_payload(data)
        self.assertEqual(payload["log_risk_count"], 0)
        self.assertEqual(payload["risk_level"], "low")

    def test_operator_brief_marks_collection_failure_as_unknown(self) -> None:
        data = {
            "collection_failure": {
                "status": "failed",
                "phase": "remote_command_precheck",
                "reason": "Remote command channel unavailable before collection.",
            },
            "host": {"name": "host-1", "ip": "1.2.3.4"},
            "incident": {"id": "INC-1"},
            "investigation_scope": {"requested_focus": ["intrusion-review"]},
        }

        payload = generate_operator_brief.build_brief_payload(data)
        self.assertEqual(payload["risk_level"], "unknown")
        self.assertIn("采集失败", payload["verdict"])


if __name__ == "__main__":
    unittest.main()
