from __future__ import annotations

import re
import unittest
from pathlib import Path

from tools.pg_common import PG_ROOT, ROOT

WORKFLOW = ROOT / ".github/workflows/progressive-gating.yml"
README = PG_ROOT / "README_Reproduction.txt"


def _gate_sources() -> list:
    paths = [README, WORKFLOW]
    paths.extend(sorted((ROOT / "tools").glob("pg_*.py")))
    paths.extend(sorted((PG_ROOT / "cases").glob("PG-*.json")))
    paths.extend(sorted((ROOT / "tests_pg").glob("*.py")))
    return paths


class WorkflowConventionTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_runner_action_and_permissions_match_repository_ci(self):
        self.assertIn("runs-on: ubuntu-24.04", self.text)
        self.assertIn("python-version: \"3.12.13\"", self.text)
        self.assertIn("uses: actions/attest@v4", self.text)
        self.assertIn("artifact-metadata: write", self.text)
        self.assertIn("python tools/check_frozen_manifest.py", self.text)

    def test_protocol_and_harness_gates_run_before_build(self):
        protocol = self.text.index("python -m tools.pg_protocol check")
        tests = self.text.index("python -m unittest discover -s tests_pg -t . -v")
        build = self.text.index("python -m tools.pg_build build")
        self.assertLess(protocol, build)
        self.assertLess(tests, build)

    def test_formal_matrix_is_not_overridable_from_dispatch(self):
        self.assertIn("options: [formal, calibration, pair]", self.text)
        self.assertNotIn("\n      repeats:", self.text)
        self.assertNotIn("\n      order:", self.text)
        self.assertIn("--github-job-id \"$GITHUB_JOB\"", self.text)
        self.assertIn('if [ "$PG_MODE" = "formal" ]; then', self.text)
        self.assertIn("--require-complete", self.text)

    def test_pair_dispatch_selects_one_frozen_cell(self):
        self.assertIn('run-name: "pg ${{ inputs.mode }}', self.text)
        self.assertIn("r${{ inputs.repeat_index }} a${{ inputs.attempt }}", self.text)
        self.assertIn("repeat_index:", self.text)
        self.assertIn("pair mode requires scenario", self.text)
        self.assertIn("pair mode requires repeat_index", self.text)
        self.assertIn("pair mode repeat_index must be 1, 2, or 3", self.text)
        self.assertIn('args+=(--scenario "$PG_SCENARIO" --repeat-index "$PG_REPEAT")', self.text)
        self.assertIn("__${safe_scenario}__r${PG_REPEAT}", self.text)

    def test_attestation_record_keeps_command_and_tool_version(self):
        self.assertIn("--command \"$command\"", self.text)
        self.assertIn("--tool-version \"$tool_version\"", self.text)
        self.assertIn("gh attestation verify dist/release_app.pyz", self.text)

    def test_job_environment_uses_an_allowed_context(self):
        self.assertIn("BUILD_DIR: ${{ github.workspace }}/../pg-build", self.text)
        self.assertNotIn("${{ runner.", self.text)

    def test_verified_evidence_is_packaged_with_the_source_snapshot(self):
        verify = self.text.index("python -m tools.pg_ledger verify --root progressive-gating")
        package = self.text.index("python -m tools.pg_archive package")
        self.assertLess(verify, package)
        self.assertIn("--source-from .", self.text)
        self.assertIn("--artifact dist/release_app.pyz", self.text)
        self.assertIn("progressive-gating-final-*.zip", self.text)
        self.assertIn("progressive-gating-final-*.zip.sha256", self.text)
        self.assertIn("progressive-gating-final-*.zip.manifest.json", self.text)


class ReadmeCommandTests(unittest.TestCase):
    def setUp(self):
        self.text = README.read_text(encoding="utf-8")

    def test_readme_commands_match_the_harness(self):
        for command in (
            "python -m tools.pg_build build",
            "python -m tools.pg_run",
            "python -m tools.pg_protocol check",
            "python -m tools.pg_ledger finalize --root progressive-gating",
            "python -m tools.pg_ledger verify --root progressive-gating",
            "python -m tools.pg_archive package",
            "python -m unittest discover -s tests_pg -t . -v",
        ):
            self.assertIn(command, self.text)

    def test_readme_documents_one_pair_per_workflow_run(self):
        self.assertIn("21 workflow runs (3 calibration + 18", self.text)
        self.assertIn("produce 42 attempts", self.text)
        self.assertIn("one build", self.text)
        self.assertIn("per workflow run (one pair)", self.text)
        self.assertIn("progressive-gating-<UTC>.zip", self.text)
        self.assertNotIn("review-bundle", self.text)
        self.assertNotIn("pg_bundle", self.text)

class ExternalTextHygieneTests(unittest.TestCase):
    def test_gate_delivery_text_has_no_cjk(self):
        cjk = re.compile("[\u4e00-\u9fff]")
        for path in _gate_sources():
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertIsNone(cjk.search(path.read_text(encoding="utf-8")))

    def test_gate_delivery_text_has_no_tool_traces(self):
        words = (
            "pi" + "lot",
            "hon" + "est",
            "ZH" + "FB",
            "L" + "LM",
            "G" + "PT",
            "Clau" + "de",
            "Copi" + "lot",
            "assis" + "tant",
            "TO" + "DO",
            "FIX" + "ME",
            "coordi" + "nation",
            "adjudi" + "cation",
        )
        pattern = re.compile(r"\b(?:" + "|".join(words) + r")\b", re.IGNORECASE)
        for path in _gate_sources():
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertIsNone(pattern.search(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
