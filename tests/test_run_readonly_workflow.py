import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import run_readonly_workflow as run_readonly_workflow  # noqa: E402


class RunReadonlyWorkflowTests(unittest.TestCase):
    def test_workflow_invokes_second_pass_review_between_enrich_and_validate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "case"
            evidence_dir = case_dir / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            raw_path = evidence_dir / "evidence.raw.json"
            raw_path.write_text("{}", encoding="utf-8")

            step_order = []

            def fake_run_step(name: str, cmd: list[str]) -> tuple[int, str]:
                step_order.append(name)
                if name == "collect_live_evidence":
                    return 0, (
                        f"Evidence JSON written: {raw_path}\n"
                        f"Case dir: {case_dir}\n"
                    )
                if name == "validate_case_bundle":
                    return 0, json.dumps({"ok": True})
                return 0, ""

            argv = [
                "run_readonly_workflow.py",
                "--remote-user",
                "ubuntu",
                "--remote-ip",
                "203.0.113.10",
                "--password-env",
                "MHT_TEST_PASSWORD",
                "--skip-export",
            ]

            with (
                patch.dict(os.environ, {"MHT_TEST_PASSWORD": "secret"}, clear=False),
                patch.object(sys, "argv", argv),
                patch.object(run_readonly_workflow, "run_step", side_effect=fake_run_step),
                patch.object(run_readonly_workflow, "export_sidecar_summaries"),
                patch.object(run_readonly_workflow, "export_scene_reconstruction"),
                patch.object(run_readonly_workflow, "verify_expected_report_outputs"),
            ):
                rc = run_readonly_workflow.main()

            self.assertEqual(rc, 0)
            self.assertEqual(
                step_order,
                [
                    "collect_live_evidence",
                    "enrich_case_evidence",
                    "review_case_evidence",
                    "validate_case_bundle",
                ],
            )


if __name__ == "__main__":
    unittest.main()
