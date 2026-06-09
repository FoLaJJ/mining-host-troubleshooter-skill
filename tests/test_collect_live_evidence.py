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


if __name__ == "__main__":
    unittest.main()
