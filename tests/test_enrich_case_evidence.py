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

    def test_enrich_separates_auth_sources_and_classifies_lateral_targets_conservatively(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_root = Path(tmp)
            auth_artifact = case_root / "auth.txt"
            auth_artifact.write_text(
                "[COMMAND]\n"
                "grep -H -E 'Failed password|Accepted password|Invalid user' /var/log/auth.log\n"
                "# exit_code=0\n"
                "[STDOUT]\n"
                "/var/log/auth.log:Jun 10 00:01:01 host sshd[100]: Failed password for invalid user admin from 198.51.100.7 port 38812 ssh2\n"
                "/var/log/auth.log:Jun 10 00:02:02 host sshd[101]: Accepted password for ubuntu from 203.0.113.9 port 38813 ssh2\n"
                "\n[STDERR]\n",
                encoding="utf-8",
            )
            session_artifact = case_root / "session.txt"
            session_artifact.write_text(
                "[COMMAND]\n"
                "who -a; w; loginctl list-sessions; ps -ef | grep '[s]shd'\n"
                "# exit_code=0\n"
                "[STDOUT]\n"
                "## who_a\n"
                "ubuntu pts/0 2026-06-10 08:00 (192.0.2.55)\n"
                "## w\n"
                "ubuntu pts/0 192.0.2.55 08:00 0.00s 0.10s 0.00s -bash\n"
                "## loginctl_list\n"
                "SESSION UID USER SEAT TTY\n"
                "2 1000 ubuntu - pts/0\n"
                "\n[STDERR]\n",
                encoding="utf-8",
            )
            network_artifact = case_root / "network.txt"
            network_artifact.write_text(
                "[COMMAND]\n"
                "ss -tnp state established | grep -v '127.0.0.1\\|::1'\n"
                "# exit_code=0\n"
                "[STDOUT]\n"
                "## ss_established\n"
                "Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
                "0 0 10.0.0.5:50522 10.9.8.7:22 users:((\"ssh\",pid=4321,fd=3))\n"
                "0 0 10.0.0.5:44444 10.9.8.10:8080 users:((\"python\",pid=7331,fd=9))\n"
                "\n[STDERR]\n",
                encoding="utf-8",
            )
            process_artifact = case_root / "process.txt"
            process_artifact.write_text(
                "[COMMAND]\n"
                "for pid in $(ps -eo pid= --sort=-%cpu | head -n 30); do ...\n"
                "# exit_code=0\n"
                "[STDOUT]\n"
                "4321|/tmp/.cache/sshd|ssh root@10.9.8.7\n"
                "7331|/usr/bin/python3|python3 -m http.server\n"
                "5555|/usr/bin/rsync|rsync /tmp/a admin@10.9.8.9:/tmp/\n"
                "\n[STDERR]\n",
                encoding="utf-8",
            )
            deleted_artifact = case_root / "deleted.txt"
            deleted_artifact.write_text(
                "[COMMAND]\n"
                "ls -l /proc/*/exe 2>/dev/null | grep ' (deleted)$' || true\n"
                "# exit_code=0\n"
                "[STDOUT]\n"
                "lrwxrwxrwx 1 root root 0 Jun 10 08:01 /proc/4321/exe -> /tmp/.cache/sshd (deleted)\n"
                "\n[STDERR]\n",
                encoding="utf-8",
            )
            hash_artifact = case_root / "hash.txt"
            hash_artifact.write_text(
                "[COMMAND]\n"
                "sha256 process hashes\n"
                "# exit_code=0\n"
                "[STDOUT]\n"
                "4321|/tmp/.cache/sshd|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                "7331|/usr/bin/python3|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
                "\n[STDERR]\n",
                encoding="utf-8",
            )
            data = {
                "evidence": [
                    {"id": "E-AUTH-1", "source": "auth", "observed_at": "2026-06-10T00:01:01+00:00", "command": "grep -H -E 'Failed password|Accepted password|Invalid user' /var/log/auth.log", "artifact": str(auth_artifact)},
                    {"id": "E-AUTH-2", "source": "auth", "observed_at": "2026-06-10T00:03:00+00:00", "command": "who -a; w; loginctl list-sessions; ps -ef | grep '[s]shd'", "artifact": str(session_artifact)},
                    {"id": "E-NET-2", "source": "network", "observed_at": "2026-06-10T00:04:00+00:00", "command": "ss -tnp state established | grep -v '127.0.0.1\\|::1'", "artifact": str(network_artifact)},
                    {"id": "E-PROC-2", "source": "process", "observed_at": "2026-06-10T00:05:00+00:00", "command": "for pid in $(ps -eo pid= --sort=-%cpu | head -n 30); do ...", "artifact": str(process_artifact)},
                    {"id": "E-PROC-3", "source": "process", "observed_at": "2026-06-10T00:06:00+00:00", "command": "ls -l /proc/*/exe 2>/dev/null | grep ' (deleted)$' || true", "artifact": str(deleted_artifact)},
                    {"id": "E-HASH-1", "source": "binary_hash", "observed_at": "2026-06-10T00:06:30+00:00", "command": "sha256 process hashes", "artifact": str(hash_artifact)},
                ],
                "findings": [],
                "timeline": [],
                "ip_traces": [],
                "unknowns": [],
                "log_integrity": [],
                "investigation_scope": {
                    "requested_focus": ["intrusion-review", "lateral-movement-review"],
                    "readonly_only": True,
                    "state_change_allowed": False,
                },
            }

            out = enrich_case_evidence.enrich(data)
            scene = out["scene_reconstruction"]
            auth_review = scene["auth_attack_review"]
            lateral_review = scene["lateral_movement_review"]
            hidden_review = scene["hidden_process_review"]

            self.assertEqual(auth_review["failed_auth_source_ips"], ["198.51.100.7"])
            self.assertEqual(auth_review["accepted_auth_source_ips"], ["203.0.113.9"])
            self.assertEqual(auth_review["current_session_source_ips"], ["192.0.2.55"])
            self.assertEqual(
                [item["ip"] for item in lateral_review["active_outbound_peers"]],
                ["10.9.8.7", "10.9.8.10"],
            )
            self.assertEqual(
                [item["ip"] for item in lateral_review["conservative_lateral_targets"]],
                ["10.9.8.7"],
            )
            self.assertEqual(
                [item["ip"] for item in lateral_review["external_pivot_required_targets"]],
                ["10.9.8.9"],
            )
            self.assertTrue(
                any(item.get("pid") == "4321" for item in hidden_review["deleted_exe_processes"])
            )
            self.assertTrue(
                any(item.get("role") == "conservative_lateral_target" and item.get("ip") == "10.9.8.7" for item in out["ip_traces"])
            )


if __name__ == "__main__":
    unittest.main()
