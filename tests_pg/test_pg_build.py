from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from tools.pg_build import record_attestation, verify


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class AttestationEvidenceTests(unittest.TestCase):
    def _fixture(self, root: Path, exit_code: int = 0) -> Path:
        artifact = root / "release_app.pyz"
        artifact.write_bytes(b"deterministic artifact bytes")
        manifest_path = root / "build_manifest.json"
        manifest = {
            "artifact": {"path": str(artifact), "sha256": sha256_file(artifact)},
            "status": "OK",
            "attestation": {"mode": "github", "status": "PENDING", "binding": {}},
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        (root / "verify.exit").write_text(f"{exit_code}\n", encoding="utf-8")
        (root / "verify.json").write_text('{"verified": true}\n', encoding="utf-8")
        (root / "verify.stderr").write_text("", encoding="utf-8")
        return manifest_path

    def _record(self, manifest_path: Path, root: Path) -> int:
        args = Namespace(
            manifest=str(manifest_path),
            exit_file=str(root / "verify.exit"),
            command="gh attestation verify dist/release_app.pyz --repo example/repo --format json",
            tool_version="gh version 2.80.0",
            json=None,
            stderr=None,
            json_file=str(root / "verify.json"),
            stderr_file=str(root / "verify.stderr"),
        )
        with contextlib.redirect_stdout(io.StringIO()):
            return record_attestation(args)

    def _verify(self, manifest_path: Path) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return verify(Namespace(manifest=str(manifest_path), artifact=None))

    def test_record_attestation_copies_hashed_evidence_and_tamper_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = self._fixture(root)
            self.assertEqual(self._record(manifest_path, root), 0)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            attestation = manifest["attestation"]
            for key in ("verify_json_file", "verify_stderr_file"):
                item = attestation[key]
                copied = manifest_path.parent / item["path"]
                self.assertTrue(copied.is_file())
                self.assertEqual(item["sha256"], sha256_file(copied))
                self.assertEqual(item["bytes"], copied.stat().st_size)
            self.assertEqual(attestation["status"], "PASS")
            self.assertEqual(attestation["verify_command"], self._record_command)
            self.assertEqual(attestation["verify_tool_version"], "gh version 2.80.0")
            self.assertIsNotNone(attestation["binding"]["verified_binding"])
            self.assertEqual(self._verify(manifest_path), 0)

            copied_json = manifest_path.parent / attestation["verify_json_file"]["path"]
            copied_json.write_text('{"verified": false}\n', encoding="utf-8")
            self.assertEqual(self._verify(manifest_path), 3)

    _record_command = "gh attestation verify dist/release_app.pyz --repo example/repo --format json"

    def test_missing_verification_command_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = self._fixture(root)
            self.assertEqual(self._record(manifest_path, root), 0)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["attestation"]["verify_tool_version"] = None
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(self._verify(manifest_path), 4)

    def test_failed_verification_blocks_promotion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = self._fixture(root, exit_code=1)
            self.assertEqual(self._record(manifest_path, root), 1)
            attestation = json.loads(manifest_path.read_text(encoding="utf-8"))["attestation"]
            self.assertEqual(attestation["status"], "FAIL")
            self.assertIsNone(attestation["binding"]["verified_binding"])
            self.assertEqual(self._verify(manifest_path), 2)


if __name__ == "__main__":
    unittest.main()
