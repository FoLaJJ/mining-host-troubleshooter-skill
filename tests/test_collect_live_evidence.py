import os
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import collect_live_evidence as collect_live_evidence  # noqa: E402


class CollectLiveEvidenceTests(unittest.TestCase):
    def test_default_case_root_is_current_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = Path.cwd()
            try:
                os.chdir(tmp)
                self.assertEqual(
                    collect_live_evidence.default_case_root(),
                    str(Path(tmp).resolve()),
                )
            finally:
                os.chdir(old_cwd)

    def test_build_case_layout_creates_case_under_current_directory_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = Path.cwd()
            try:
                os.chdir(tmp)
                args = Namespace(
                    case_dir=None,
                    case_tag="host-1-20260609-000000",
                    case_root=collect_live_evidence.default_case_root(),
                    output=None,
                )
                layout = collect_live_evidence.build_case_layout(args)
                self.assertEqual(
                    layout["case_dir"],
                    Path(tmp).resolve() / "host-1-20260609-000000",
                )
            finally:
                os.chdir(old_cwd)

    def test_running_services_probe_is_not_duplicated(self) -> None:
        service_probe_count = sum(
            1
            for probe in collect_live_evidence.BASE_PROBES
            if probe.command == collect_live_evidence.RUNNING_SERVICES_CMD
        )
        self.assertEqual(
            service_probe_count,
            1,
            "Running service collection should appear once in the readonly probe set.",
        )

    def test_network_probes_include_established_non_loopback_and_listening_views(self) -> None:
        network_commands = [
            probe.command
            for probe in collect_live_evidence.BASE_PROBES
            if probe.source == "network"
        ]
        self.assertTrue(
            any("state established" in command for command in network_commands),
            "Readonly network coverage should include an established-session view.",
        )
        self.assertTrue(
            any("127.0.0.1\\|::1" in command for command in network_commands),
            "Established-session collection should explicitly filter loopback-only noise.",
        )
        self.assertTrue(
            any(
                token in command
                for command in network_commands
                for token in ("ss -lntup", "netstat -lntup", "lsof -nPiTCP -sTCP:LISTEN")
            ),
            "Readonly network coverage should include a listening-socket view.",
        )

    def test_auth_probes_include_current_session_activity_views(self) -> None:
        auth_commands = [
            probe.command
            for probe in collect_live_evidence.BASE_PROBES
            if probe.source == "auth"
        ]
        self.assertTrue(
            any("who -a" in command for command in auth_commands),
            "Readonly auth coverage should include current session enumeration.",
        )
        self.assertTrue(
            any("loginctl list-sessions" in command for command in auth_commands),
            "Readonly auth coverage should inspect loginctl session state when available.",
        )
        self.assertTrue(
            any("grep '[s]shd'" in command for command in auth_commands),
            "Readonly auth coverage should correlate current sshd processes.",
        )

    def test_gitignore_excludes_superpowers_docs(self) -> None:
        gitignore_text = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(
            "docs/superpowers/",
            gitignore_text,
            "Superpowers design/planning docs should stay out of version control.",
        )

    def test_transport_negotiation_stops_after_auth_failure(self) -> None:
        attempts = []

        def first(_command: str) -> tuple[int, str, str]:
            attempts.append("paramiko_password")
            return 255, "", "paramiko_auth_failed"

        def second(_command: str) -> tuple[int, str, str]:
            attempts.append("sshpass_password")
            return 0, "__MHT_REMOTE_OK__", ""

        candidate, diag = collect_live_evidence.negotiate_remote_transport(
            [
                collect_live_evidence.RemoteTransportCandidate("paramiko_password", first),
                collect_live_evidence.RemoteTransportCandidate("sshpass_password", second),
            ],
            "printf '__MHT_REMOTE_OK__'",
            max_attempts=2,
        )

        self.assertIsNone(candidate)
        self.assertEqual(attempts, ["paramiko_password"])
        self.assertEqual(diag[0]["failure_class"], "auth_failed")

    def test_transport_negotiation_falls_back_once_for_non_auth_failure(self) -> None:
        attempts = []

        def first(_command: str) -> tuple[int, str, str]:
            attempts.append("paramiko_password")
            return 255, "", "paramiko_transport_unavailable"

        def second(_command: str) -> tuple[int, str, str]:
            attempts.append("sshpass_password")
            return 0, "__MHT_REMOTE_OK__", ""

        candidate, diag = collect_live_evidence.negotiate_remote_transport(
            [
                collect_live_evidence.RemoteTransportCandidate("paramiko_password", first),
                collect_live_evidence.RemoteTransportCandidate("sshpass_password", second),
            ],
            "printf '__MHT_REMOTE_OK__'",
            max_attempts=2,
        )

        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.name, "sshpass_password")
        self.assertEqual(attempts, ["paramiko_password", "sshpass_password"])
        self.assertEqual(diag[0]["failure_class"], "transport_unavailable")
        self.assertEqual(diag[1]["status"], "selected")


if __name__ == "__main__":
    unittest.main()
