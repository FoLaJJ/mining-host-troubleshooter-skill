import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
