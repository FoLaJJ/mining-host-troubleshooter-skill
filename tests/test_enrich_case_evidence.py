import json
import sys
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


if __name__ == "__main__":
    unittest.main()
