import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import nl_control as nl_control  # noqa: E402


class NaturalLanguageControlTests(unittest.TestCase):
    def test_explicit_regeneration_request_routes_to_bundle_report_generation(self) -> None:
        parsed = nl_control.parse_request("根据现有证据生成报告，不要重新采集，直接出报告")

        cmd, _ = nl_control.build_command(
            parsed,
            analyst="analyst-1",
            case_root=str(Path("/tmp/case-root")),
            request_summary="根据现有证据生成报告，不要重新采集，直接出报告",
        )

        self.assertEqual(Path(cmd[1]).name, "generate_reports_from_bundle.py")
        self.assertEqual(cmd, [sys.executable, cmd[1], "--case-dir", str(Path("/tmp/case-root"))])

    def test_generic_investigation_request_stays_on_readonly_workflow(self) -> None:
        request = "排查这台机器是否被入侵，默认只读"
        parsed = nl_control.parse_request(request)

        cmd, _ = nl_control.build_command(
            parsed,
            analyst="analyst-1",
            case_root=str(Path("/tmp/case-root")),
            request_summary=request,
        )

        self.assertEqual(Path(cmd[1]).name, "run_readonly_workflow.py")
        self.assertIn("--request-summary", cmd)
        self.assertIn("--focus", cmd)
        self.assertIn("intrusion-review", cmd)

    def test_evidence_like_investigation_request_stays_on_readonly_workflow(self) -> None:
        request = "结合现有证据和 artifacts 排查这台机器是否被入侵，默认只读"
        parsed = nl_control.parse_request(request)

        cmd, _ = nl_control.build_command(
            parsed,
            analyst="analyst-1",
            case_root=str(Path("/tmp/case-root")),
            request_summary=request,
        )

        self.assertEqual(Path(cmd[1]).name, "run_readonly_workflow.py")
        self.assertFalse(parsed["report_regeneration_only"])
        self.assertIn("--request-summary", cmd)
        self.assertIn("intrusion-review", cmd)

    def test_remote_request_preserves_auth_and_redact_flags_on_normal_path(self) -> None:
        request = "用 root@203.0.113.7 排查是否被入侵，密码: s3cr3t 脱敏 默认只读"
        parsed = nl_control.parse_request(request)

        cmd, env = nl_control.build_command(
            parsed,
            analyst="analyst-1",
            case_root=str(Path("/tmp/case-root")),
            request_summary=nl_control.sanitize_request_summary(request, parsed),
        )

        self.assertEqual(Path(cmd[1]).name, "run_readonly_workflow.py")
        self.assertIn("--remote-user", cmd)
        self.assertIn("root", cmd)
        self.assertIn("--remote-ip", cmd)
        self.assertIn("203.0.113.7", cmd)
        self.assertIn("--password-env", cmd)
        self.assertIn("MHT_NL_REMOTE_PASSWORD", cmd)
        self.assertIn("--redact", cmd)
        self.assertEqual(env["MHT_NL_REMOTE_PASSWORD"], "s3cr3t")

    def test_regeneration_request_note_does_not_claim_evidence_collection(self) -> None:
        argv = [
            "nl_control.py",
            "--request",
            "根据现有证据生成报告，不要重新采集，直接出报告，删除旧结论",
            "--analyst",
            "analyst-1",
            "--case-root",
            str(Path("/tmp/case-root")),
        ]

        stdout = io.StringIO()
        with (
            patch.object(sys, "argv", argv),
            patch.object(nl_control.subprocess, "run", return_value=type("Proc", (), {"returncode": 0})()),
            redirect_stdout(stdout),
        ):
            rc = nl_control.main()

        output = stdout.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("[NOTE]", output)
        self.assertNotIn("run read-only evidence collection only", output)
        self.assertIn("avoid state-changing host actions", output)


if __name__ == "__main__":
    unittest.main()
