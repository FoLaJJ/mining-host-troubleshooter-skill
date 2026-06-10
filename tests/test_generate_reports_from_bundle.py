import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
SCRIPT_PATH = SCRIPTS_DIR / "generate_reports_from_bundle.py"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


class GenerateReportsFromBundleTests(unittest.TestCase):
    def load_module(self):
        if not SCRIPT_PATH.exists():
            self.fail(f"Missing script: {SCRIPT_PATH}")
        spec = importlib.util.spec_from_file_location("generate_reports_from_bundle_under_test", SCRIPT_PATH)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_reviewed_bundle_regenerates_reports_without_collection(self) -> None:
        generate_reports_from_bundle = self.load_module()

        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "case"
            evidence_dir = case_dir / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            reviewed = evidence_dir / "evidence.reviewed.json"
            reviewed.write_text("{}", encoding="utf-8")
            commands = []

            def fake_run_step(name: str, cmd: list[str]) -> tuple[int, str]:
                commands.append((name, cmd))
                return 0, "{}"

            argv = ["generate_reports_from_bundle.py", "--case-dir", str(case_dir)]
            with (
                patch.object(sys, "argv", argv),
                patch.object(generate_reports_from_bundle, "run_step", side_effect=fake_run_step),
                patch.object(generate_reports_from_bundle, "verify_expected_report_outputs"),
            ):
                rc = generate_reports_from_bundle.main()

            self.assertEqual(rc, 0)
            self.assertEqual(
                [name for name, _ in commands],
                [
                    "validate_case_bundle",
                    "generate_operator_brief",
                    "export_external_evidence_checklist",
                    "export_investigation_report",
                ],
            )
            validate_cmd = commands[0][1]
            export_cmd = commands[-1][1]
            self.assertEqual(validate_cmd[validate_cmd.index("--input") + 1], str(reviewed))
            self.assertEqual(export_cmd[export_cmd.index("--input") + 1], str(reviewed))

            checkpoints = json.loads((case_dir / "meta" / "workflow_checkpoints.json").read_text(encoding="utf-8"))
            self.assertIn("report_regeneration_started", [entry["stage"] for entry in checkpoints["history"]])
            self.assertEqual(checkpoints["latest"]["stage"], "report_regeneration_completed")

    def test_raw_only_bundle_runs_enrich_and_review_before_export(self) -> None:
        generate_reports_from_bundle = self.load_module()

        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "case"
            evidence_dir = case_dir / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            raw = evidence_dir / "evidence.raw.json"
            raw.write_text("{}", encoding="utf-8")
            reviewed_auto = evidence_dir / "evidence.reviewed.auto.json"
            commands = []

            def fake_run_step(name: str, cmd: list[str]) -> tuple[int, str]:
                commands.append((name, cmd))
                if "--output" in cmd:
                    output_path = Path(cmd[cmd.index("--output") + 1])
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text("{}", encoding="utf-8")
                return 0, "{}"

            argv = ["generate_reports_from_bundle.py", "--case-dir", str(case_dir)]
            with (
                patch.object(sys, "argv", argv),
                patch.object(generate_reports_from_bundle, "run_step", side_effect=fake_run_step),
                patch.object(generate_reports_from_bundle, "verify_expected_report_outputs"),
            ):
                rc = generate_reports_from_bundle.main()

            self.assertEqual(rc, 0)
            self.assertEqual(
                [name for name, _ in commands],
                [
                    "enrich_case_evidence",
                    "review_case_evidence",
                    "validate_case_bundle",
                    "generate_operator_brief",
                    "export_external_evidence_checklist",
                    "export_investigation_report",
                ],
            )
            validate_cmd = commands[2][1]
            brief_cmd = commands[3][1]
            export_cmd = commands[-1][1]
            self.assertEqual(validate_cmd[validate_cmd.index("--input") + 1], str(reviewed_auto))
            self.assertEqual(brief_cmd[brief_cmd.index("--input") + 1], str(reviewed_auto))
            self.assertEqual(export_cmd[export_cmd.index("--input") + 1], str(reviewed_auto))

    def test_failure_bundle_skips_validate_and_records_checkpoint_reason(self) -> None:
        generate_reports_from_bundle = self.load_module()

        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "case"
            evidence_dir = case_dir / "evidence"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            failed = evidence_dir / "evidence.collection.failed.json"
            failed.write_text(
                json.dumps(
                    {
                        "collection_failure": {
                            "status": "failed",
                            "phase": "remote_command_precheck",
                            "reason": "Remote command channel unavailable before collection.",
                        }
                    }
                ),
                encoding="utf-8",
            )
            commands = []

            def fake_run_step(name: str, cmd: list[str]) -> tuple[int, str]:
                commands.append((name, cmd))
                return 0, "{}"

            argv = ["generate_reports_from_bundle.py", "--case-dir", str(case_dir)]
            with (
                patch.object(sys, "argv", argv),
                patch.object(generate_reports_from_bundle, "run_step", side_effect=fake_run_step),
                patch.object(generate_reports_from_bundle, "verify_expected_report_outputs"),
            ):
                rc = generate_reports_from_bundle.main()

            self.assertEqual(rc, 0)
            self.assertEqual(
                [name for name, _ in commands],
                [
                    "generate_operator_brief",
                    "export_external_evidence_checklist",
                    "export_investigation_report",
                ],
            )
            checkpoints = json.loads((case_dir / "meta" / "workflow_checkpoints.json").read_text(encoding="utf-8"))
            skipped = [
                entry
                for entry in checkpoints["history"]
                if entry["stage"] == "report_regeneration_validation_complete"
            ]
            self.assertEqual(len(skipped), 1)
            self.assertEqual(skipped[0]["status"], "skipped")
            self.assertIn("Remote command channel unavailable before collection.", skipped[0]["note"])
            started = [
                entry
                for entry in checkpoints["history"]
                if entry["stage"] == "report_regeneration_started"
            ]
            self.assertEqual(len(started), 1)
            self.assertEqual(started[0]["status"], "degraded")
            self.assertEqual(started[0]["extra"]["input_kind"], "failure_bundle")
            self.assertEqual(checkpoints["latest"]["stage"], "report_regeneration_completed")

    def test_missing_supported_evidence_json_fails_clearly(self) -> None:
        generate_reports_from_bundle = self.load_module()

        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "case"
            (case_dir / "evidence").mkdir(parents=True, exist_ok=True)

            argv = ["generate_reports_from_bundle.py", "--case-dir", str(case_dir)]
            with patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit) as ctx:
                    generate_reports_from_bundle.main()

            self.assertIn("No supported evidence JSON", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
