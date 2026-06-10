import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import export_external_evidence_checklist as export_external_evidence_checklist  # noqa: E402


class ExportExternalEvidenceChecklistTests(unittest.TestCase):
    def test_checklist_prefers_second_pass_scope_pivots(self) -> None:
        data = {
            "incident": {"id": "INC-1"},
            "host": {"name": "host-1", "ip": "1.2.3.4"},
            "scene_reconstruction": {"auth_source_ips": ["1.2.3.4"]},
            "second_pass_review": {
                "scope_closure_review": {
                    "status": "needs_external_corroboration",
                    "external_pivots": [
                        {
                            "id": "timeline_expansion",
                            "reason": "Recovered event timing is incomplete for confident ingress reconstruction.",
                        }
                    ],
                },
                "timeline_review": {"status": "narrow_window"},
                "log_layout_review": {"adjusted_primary_log_risk_count": 0},
            },
        }

        body = export_external_evidence_checklist.build_checklist(data)
        self.assertIn("timeline_window_narrow", body)
        self.assertIn("Expand the time window using upstream telemetry", body)
        self.assertIn("Recovered event timing is incomplete for confident ingress reconstruction.", body)

    def test_checklist_highlights_collection_failure(self) -> None:
        data = {
            "incident": {"id": "INC-1"},
            "host": {"name": "host-1", "ip": "1.2.3.4"},
            "collection_failure": {
                "status": "failed",
                "phase": "remote_command_precheck",
                "reason": "Remote command channel unavailable before collection.",
            },
        }

        body = export_external_evidence_checklist.build_checklist(data)
        self.assertIn("Collection failure", body)
        self.assertIn("Remote command channel unavailable before collection.", body)


if __name__ == "__main__":
    unittest.main()
