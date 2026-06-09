import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import review_case_evidence as review_case_evidence  # noqa: E402


def artifact_text(stdout: str) -> str:
    return (
        "# source=test\n"
        "# command=test\n"
        "# started=2026-06-09T08:08:21+00:00\n"
        "# ended=2026-06-09T08:08:23+00:00\n"
        "# exit_code=0\n"
        "# timed_out=false\n\n"
        "[STDOUT]\n"
        f"{stdout}\n\n"
        "[STDERR]\n"
    )


class ReviewCaseEvidenceTests(unittest.TestCase):
    def test_log_layout_review_ignores_non_applicable_rhel_paths_on_ubuntu(self) -> None:
        data = {
            "evidence": [],
            "hypothesis_matrix": [
                {
                    "hypothesis_id": "H-MATRIX-LOG-001",
                    "title": "Log tampering hypothesis",
                    "status": "inconclusive",
                    "confidence": "low",
                    "supporting_evidence_ids": ["E-044"],
                    "counter_evidence_ids": [],
                    "summary": "Primary log visibility is reduced.",
                }
            ],
            "log_integrity": [
                {"artifact": "/var/log/auth.log", "status": "ok", "evidence_ids": ["E-044"]},
                {"artifact": "/var/log/syslog", "status": "ok", "evidence_ids": ["E-044"]},
                {"artifact": "/var/log/secure", "status": "missing", "evidence_ids": ["E-044"]},
                {"artifact": "/var/log/messages", "status": "missing", "evidence_ids": ["E-044"]},
            ],
            "scene_reconstruction": {
                "platform_identity": {
                    "os_release_id": "ubuntu",
                    "os_release_version": "22.04",
                    "os_release_codename": "jammy",
                }
            },
        }

        out = review_case_evidence.review(data)
        review = out["second_pass_review"]["log_layout_review"]
        self.assertEqual(review["adjusted_primary_log_risk_count"], 0)
        self.assertEqual(
            sorted(review["non_applicable_artifacts"]),
            ["/var/log/messages", "/var/log/secure"],
        )
        log_items = [
            item for item in out["hypothesis_matrix"] if item.get("hypothesis_id") == "H-MATRIX-LOG-001"
        ]
        self.assertEqual(len(log_items), 1)
        self.assertEqual(log_items[0]["status"], "not_observed")

    def test_auth_review_keeps_recurring_and_current_session_sources_neutral(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "E-015.txt"
            artifact.write_text(
                artifact_text(
                    "\n".join(
                        [
                            "Jun 08 09:57:53 VM-0-11-ubuntu sshd[32352]: Accepted password for ubuntu from 198.51.100.10 port 25200 ssh2",
                            "Jun 08 09:58:53 VM-0-11-ubuntu sshd[42318]: Accepted password for ubuntu from 198.51.100.10 port 25372 ssh2",
                            "Jun 09 16:08:22 VM-0-11-ubuntu sshd[617976]: Accepted password for ubuntu from 203.0.113.20 port 36940 ssh2",
                        ]
                    )
                ),
                encoding="utf-8",
            )
            data = {
                "evidence": [
                    {
                        "id": "E-015",
                        "source": "auth",
                        "observed_at": "2026-06-09T08:08:23+00:00",
                        "artifact": str(artifact),
                        "command": "journalctl -u ssh --no-pager",
                    }
                ],
                "scene_reconstruction": {
                    "time_normalization": {"host_reported_timezone": "Asia/Shanghai"},
                    "privilege_scope": {"user": "ubuntu"},
                },
            }

            out = review_case_evidence.review(data)
            sources = out["second_pass_review"]["accepted_auth_review"]["sources"]
            by_ip = {item["ip"]: item for item in sources}
            self.assertEqual(
                by_ip["203.0.113.20"]["status"],
                "current_investigation_session_candidate",
            )
            self.assertEqual(
                by_ip["198.51.100.10"]["status"],
                "recurring_access_candidate",
            )

    def test_vendor_only_persistence_surfaces_downgrade_supported_persistence_hypothesis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "E-022.txt"
            artifact.write_text(
                artifact_text(
                    "\n".join(
                        [
                            "/etc/rc.local:4:/usr/local/qcloud/irq/net_smp_affinity.sh >/tmp/net_affinity.log 2>&1",
                            "/etc/rc.local:9:/usr/local/qcloud/gpu/nv_gpu_conf.sh >/tmp/nv_gpu_conf.log 2>&1",
                            "2026-05-06 20:10 ubuntu 600 /home/ubuntu/.ssh/authorized_keys",
                        ]
                    )
                ),
                encoding="utf-8",
            )
            data = {
                "evidence": [
                    {
                        "id": "E-022",
                        "source": "persistence",
                        "observed_at": "2026-06-09T08:08:23+00:00",
                        "artifact": str(artifact),
                        "command": "grep -RniE persistence-review",
                    }
                ],
                "hypothesis_matrix": [
                    {
                        "hypothesis_id": "H-MATRIX-PERSIST-001",
                        "title": "Persistence foothold hypothesis",
                        "status": "supported",
                        "confidence": "low",
                        "supporting_evidence_ids": ["E-022"],
                        "counter_evidence_ids": [],
                        "summary": "Persistence review surfaces contain suspicious lines and require analyst confirmation.",
                    }
                ],
                "scene_reconstruction": {
                    "initial_access_review_samples": [
                        "/etc/rc.local:4:/usr/local/qcloud/irq/net_smp_affinity.sh >/tmp/net_affinity.log 2>&1",
                        "2026-05-06 20:10 ubuntu 600 /home/ubuntu/.ssh/authorized_keys",
                    ]
                },
            }

            out = review_case_evidence.review(data)
            persist_review = out["second_pass_review"]["persistence_surface_review"]
            self.assertEqual(persist_review["status"], "baseline_or_vendor_dominated")
            persist_items = [
                item for item in out["hypothesis_matrix"] if item.get("hypothesis_id") == "H-MATRIX-PERSIST-001"
            ]
            self.assertEqual(len(persist_items), 1)
            self.assertEqual(persist_items[0]["status"], "inconclusive")

    def test_lpe_exposure_alone_does_not_remain_supported_after_second_pass_review(self) -> None:
        data = {
            "evidence": [],
            "hypothesis_matrix": [
                {
                    "hypothesis_id": "H-MATRIX-LPE-001",
                    "title": "Local privilege escalation hypothesis",
                    "status": "supported",
                    "confidence": "medium",
                    "supporting_evidence_ids": ["E-061"],
                    "counter_evidence_ids": [],
                    "summary": "Possible LPE exposure indicators were observed.",
                }
            ],
            "scene_reconstruction": {
                "local_privesc_review": {
                    "possible_cves": ["CVE-2026-31431"],
                    "possible_lpe_exposure": True,
                    "lpe_path_plausible": True,
                },
                "privilege_scope": {
                    "user": "ubuntu",
                    "passwordless_sudo_visible": True,
                },
                "initial_access_review_samples": [],
            },
        }

        out = review_case_evidence.review(data)
        lpe_review = out["second_pass_review"]["lpe_use_review"]
        self.assertEqual(lpe_review["status"], "exposed_only")
        lpe_items = [item for item in out["hypothesis_matrix"] if item.get("hypothesis_id") == "H-MATRIX-LPE-001"]
        self.assertEqual(len(lpe_items), 1)
        self.assertEqual(lpe_items[0]["status"], "inconclusive")
        self.assertIn("passwordless sudo", lpe_items[0]["summary"].lower())

    def test_timeline_and_scope_review_keep_open_pivots_visible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "E-015.txt"
            artifact.write_text(
                artifact_text(
                    "Jun 09 16:08:22 VM-0-11-ubuntu sshd[617976]: Accepted password for ubuntu from 10.0.0.5 port 36940 ssh2"
                ),
                encoding="utf-8",
            )
            data = {
                "evidence": [
                    {
                        "id": "E-015",
                        "source": "auth",
                        "observed_at": "2026-06-09T08:08:23+00:00",
                        "artifact": str(artifact),
                        "command": "journalctl -u ssh --no-pager",
                    }
                ],
                "scene_reconstruction": {
                    "time_normalization": {"host_reported_timezone": "Asia/Shanghai"},
                    "privilege_scope": {"user": "ubuntu"},
                    "auth_source_ips": ["10.0.0.5"],
                    "container_cloud_review_hit_count": 1,
                    "contradiction_review": {"count": 1},
                    "investigation_scope": {"requested_focus": ["intrusion-review"]},
                },
                "log_integrity": [],
            }

            out = review_case_evidence.review(data)
            timeline_review = out["second_pass_review"]["timeline_review"]
            scope_review = out["second_pass_review"]["scope_closure_review"]
            workflow_review = out["second_pass_review"]["workflow_review"]

            self.assertEqual(timeline_review["status"], "narrow_window")
            self.assertEqual(scope_review["status"], "needs_external_corroboration")
            pivot_ids = {item["id"] for item in scope_review["external_pivots"]}
            self.assertIn("identity_boundary_logs", pivot_ids)
            self.assertIn("peer_host_internal_auth_pivot", pivot_ids)
            self.assertIn("cloud_control_plane_audit", pivot_ids)
            self.assertIn("timeline_expansion", pivot_ids)
            self.assertIn("contradiction_resolution", pivot_ids)
            self.assertEqual(workflow_review["status"], "completed_with_open_gaps")
            self.assertFalse(workflow_review["closure_ready_for_host_only_report"])


if __name__ == "__main__":
    unittest.main()
