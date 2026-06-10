import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import enrich_case_evidence as enrich_case_evidence  # noqa: E402


class EnrichCaseEvidenceTests(unittest.TestCase):
    def test_missing_logs_keep_log_tampering_hypothesis_inconclusive(self) -> None:
        data = {
            "evidence": [],
            "findings": [],
            "timeline": [],
            "ip_traces": [],
            "unknowns": [],
            "log_integrity": [
                {
                    "artifact": "/var/log/auth.log",
                    "status": "missing",
                    "reason": "Log artifact not found at collection time.",
                    "evidence_ids": ["E-001"],
                }
            ],
            "investigation_scope": {
                "requested_focus": ["intrusion-review"],
                "readonly_only": True,
                "state_change_allowed": False,
            },
        }

        out = enrich_case_evidence.enrich(data)
        log_items = [
            item
            for item in out["hypothesis_matrix"]
            if item.get("hypothesis_id") == "H-MATRIX-LOG-001"
        ]
        self.assertEqual(len(log_items), 1, json.dumps(out["hypothesis_matrix"], ensure_ascii=False, indent=2))
        self.assertEqual(log_items[0]["status"], "inconclusive")
        self.assertIn("visibility", log_items[0]["summary"].lower())

    def test_enrich_extracts_established_connections_and_current_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_root = Path(tmp)
            network_artifact = case_root / "network.txt"
            network_artifact.write_text(
                "[COMMAND]\n"
                "ss -tnp state established | grep -v '127.0.0.1\\|::1'; ss -lntup\n"
                "# exit_code=0\n"
                "[STDOUT]\n"
                "## ss_established\n"
                "Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                "0 0 10.0.0.5:22 198.51.100.7:38812 users:((\"sshd\",pid=1181,fd=3))\n"
                "0 0 127.0.0.1:8080 127.0.0.1:41412 users:((\"python\",pid=2048,fd=7))\n"
                "## ss_listening\n"
                "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1181,fd=3))\n"
                "tcp LISTEN 0 128 0.0.0.0:5555 0.0.0.0:* users:((\"python\",pid=2048,fd=9))\n"
                "\n[STDERR]\n",
                encoding="utf-8",
            )
            auth_artifact = case_root / "auth-session.txt"
            auth_artifact.write_text(
                "[COMMAND]\n"
                "who -a; w; loginctl list-sessions; ps -ef | grep '[s]shd'\n"
                "# exit_code=0\n"
                "[STDOUT]\n"
                "## who_a\n"
                "ubuntu pts/0 2026-06-10 08:00 (198.51.100.7)\n"
                "root pts/1 2026-06-10 08:05 (203.0.113.9)\n"
                "## w\n"
                "USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT\n"
                "ubuntu pts/0 198.51.100.7 08:00 0.00s 0.10s 0.00s -bash\n"
                "## loginctl_list\n"
                "SESSION UID USER SEAT TTY\n"
                "2 1000 ubuntu - pts/0\n"
                "## sshd_processes\n"
                "root 1181 1 0 08:00 ? 00:00:00 sshd: ubuntu [priv]\n"
                "\n[STDERR]\n",
                encoding="utf-8",
            )
            data = {
                "evidence": [
                    {
                        "id": "E-NET-001",
                        "source": "network",
                        "observed_at": "2026-06-10T00:05:00+00:00",
                        "command": "ss -tnp state established | grep -v '127.0.0.1\\|::1'; ss -lntup",
                        "artifact": str(network_artifact),
                    },
                    {
                        "id": "E-AUTH-001",
                        "source": "auth",
                        "observed_at": "2026-06-10T00:06:00+00:00",
                        "command": "who -a; w; loginctl list-sessions; ps -ef | grep '[s]shd'",
                        "artifact": str(auth_artifact),
                    },
                ],
                "findings": [],
                "timeline": [],
                "ip_traces": [],
                "unknowns": [],
                "log_integrity": [],
                "investigation_scope": {
                    "requested_focus": ["intrusion-review"],
                    "readonly_only": True,
                    "state_change_allowed": False,
                },
            }

            out = enrich_case_evidence.enrich(data)
            scene = out["scene_reconstruction"]

            self.assertEqual(scene["listening_ports"], ["22", "5555"])
            self.assertEqual(scene["established_connection_count"], 1)
            self.assertEqual(scene["established_remote_ips"], ["198.51.100.7"])
            self.assertEqual(scene["current_session_usernames"], ["root", "ubuntu"])
            self.assertEqual(scene["current_session_remote_ips"], ["198.51.100.7", "203.0.113.9"])
            self.assertTrue(
                any(item.get("role") == "current_session_source" and item.get("ip") == "198.51.100.7" for item in out["ip_traces"])
            )
            self.assertTrue(
                any(item.get("process") == "sshd" and item.get("remote_ip") == "198.51.100.7" for item in scene["established_connections"])
            )


if __name__ == "__main__":
    unittest.main()
