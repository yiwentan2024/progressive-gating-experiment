from __future__ import annotations

import unittest

from tools.pg_common import ALL_SCENARIOS, read_json
from tools.pg_protocol import PROTOCOL_PATH, _check_protocol, build_protocol


class ProtocolTests(unittest.TestCase):
    def test_generated_protocol_is_internally_consistent(self):
        protocol = build_protocol()
        self.assertEqual(_check_protocol(protocol), [])
        self.assertEqual(protocol["schema"], "pg-protocol-1")
        self.assertEqual(protocol["batch_plan"]["formal"]["runs"], 36)
        self.assertEqual(protocol["batch_plan"]["formal"]["pairs"], 18)
        self.assertEqual(protocol["batch_plan"]["formal"]["workflow_runs"], 18)
        self.assertEqual(protocol["batch_plan"]["formal"]["attempts_per_workflow_run"], 2)
        self.assertEqual(protocol["batch_plan"]["calibration"]["runs"], 6)
        self.assertEqual(protocol["batch_plan"]["calibration"]["pairs"], 3)
        self.assertEqual(protocol["batch_plan"]["calibration"]["workflow_runs"], 3)
        self.assertEqual(protocol["batch_plan"]["calibration"]["attempts_per_workflow_run"], 2)
        self.assertEqual([row["id"] for row in protocol["scenarios"]], list(ALL_SCENARIOS))
        self.assertEqual(len(protocol["hashes"]), len({row["path"] for row in protocol["hashes"]}))
        self.assertEqual(
            protocol["scope"]["scenario_families"],
            {
                "N01": "PG-N01",
                "B01": "PG-ART",
                "B02": "PG-QA",
                "C01": "PG-DISP",
                "C02": "PG-SEQ",
                "I01": "PG-INFO",
            },
        )
        paths = {row["path"] for row in protocol["hashes"]}
        for required in (
            "verifier/closure_audit.py",
            "scenarios/build_case.py",
            "infra/compose.pg.yml",
            ".github/workflows/progressive-gating.yml",
            "tools/pg_promote.py",
            "progressive-gating/README_Reproduction.txt",
        ):
            self.assertIn(required, paths)

    def test_committed_protocol_matches_current_inputs(self):
        self.assertTrue(PROTOCOL_PATH.is_file(), "run python -m tools.pg_protocol build")
        self.assertEqual(_check_protocol(read_json(PROTOCOL_PATH)), [])

    def test_official_variant_mapping_keeps_b0_out(self):
        protocol = build_protocol()
        self.assertEqual(protocol["variant_mapping"]["implemented"], {"P0": "B1", "P1": "B2"})
        self.assertIn("B0", protocol["variant_mapping"]["not_implemented"])
        self.assertEqual(protocol["verifier"]["modified"], False)


if __name__ == "__main__":
    unittest.main()
