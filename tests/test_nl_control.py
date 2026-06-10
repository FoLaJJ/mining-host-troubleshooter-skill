import sys
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
