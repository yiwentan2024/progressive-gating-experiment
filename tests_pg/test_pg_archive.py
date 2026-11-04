from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools import pg_archive


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)

        self.repo = self.base / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        (self.repo / "app.py").write_text("value = 1\n", encoding="utf-8")
        (self.repo / "tests").mkdir()
        (self.repo / "tests" / "test_app.py").write_text("def test_app():\n    pass\n", encoding="utf-8")
        _git(self.repo, "add", ".")
        _git(
            self.repo,
            "-c", "user.name=test",
            "-c", "user.email=test@example.com",
            "commit", "-q", "-m", "init",
        )
        self.commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(self.repo),
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        self.evidence = self.base / "progressive-gating"
        (self.evidence / "build" / "b1").mkdir(parents=True)
        (self.evidence / "build" / "b1" / "build_manifest.json").write_text("{}\n", encoding="utf-8")
        (self.evidence / "runs" / "r1" / "raw").mkdir(parents=True)
        (self.evidence / "runs" / "r1" / "raw" / "events.jsonl").write_text("{}\n", encoding="utf-8")
        self.artifact = self.base / "release_app.pyz"
        self.artifact.write_bytes(b"subject artifact\n")
        self.zip_path = self.base / "gate-final.zip"

    def _package(self) -> None:
        code = pg_archive.main([
            "package",
            "--root", str(self.evidence),
            "--source-from", str(self.repo),
            "--artifact", str(self.artifact),
            "--out", str(self.zip_path),
        ])
        self.assertEqual(code, 0)

    def test_archive_contains_evidence_source_and_reproduce_note(self):
        self._package()
        with zipfile.ZipFile(self.zip_path) as archive:
            names = set(archive.namelist())
        self.assertIn("progressive-gating/build/b1/build_manifest.json", names)
        self.assertIn("progressive-gating/runs/r1/raw/events.jsonl", names)
        self.assertIn("source/app.py", names)
        self.assertIn("source/tests/test_app.py", names)
        self.assertIn("artifact/release_app.pyz", names)
        self.assertIn("REPRODUCE.md", names)
        self.assertFalse(any(name.startswith("source/.git/") for name in names))

    def test_sidecars_describe_the_archive_and_source_commit(self):
        self._package()
        digest = hashlib.sha256(self.zip_path.read_bytes()).hexdigest()
        sidecar = self.base / "gate-final.zip.sha256"
        self.assertEqual(sidecar.read_text(encoding="utf-8").split()[0], digest)
        manifest = json.loads(
            (self.base / "gate-final.zip.manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["archive"], self.zip_path.name)
        self.assertEqual(manifest["sha256"], digest)
        self.assertEqual(manifest["source_commit"], self.commit)
        self.assertEqual(manifest["evidence_file_count"], 2)
        self.assertEqual(manifest["source_file_count"], 2)
        self.assertEqual(manifest["file_count"], 6)
        self.assertEqual(manifest["artifact"]["path"], "artifact/release_app.pyz")
        self.assertEqual(
            manifest["artifact"]["sha256"],
            hashlib.sha256(self.artifact.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            manifest["contains"],
            ["progressive-gating/", "source/", "artifact/", "REPRODUCE.md"],
        )

    def test_untracked_files_are_not_in_the_source_snapshot(self):
        (self.repo / "untracked.txt").write_text("not committed\n", encoding="utf-8")
        self._package()
        with zipfile.ZipFile(self.zip_path) as archive:
            names = set(archive.namelist())
        self.assertNotIn("source/untracked.txt", names)

    def test_package_rejects_an_empty_evidence_root(self):
        empty = self.base / "empty"
        empty.mkdir()
        with self.assertRaises(SystemExit) as caught:
            pg_archive.main([
                "package",
                "--root", str(empty),
                "--source-from", str(self.repo),
                "--out", str(self.base / "empty.zip"),
            ])
        self.assertEqual(caught.exception.code, 2)

    def test_package_rejects_output_inside_the_evidence_root(self):
        with self.assertRaises(SystemExit) as caught:
            pg_archive.main([
                "package",
                "--root", str(self.evidence),
                "--source-from", str(self.repo),
                "--out", str(self.evidence / "nested.zip"),
            ])
        self.assertEqual(caught.exception.code, 2)

    def test_package_rejects_a_missing_artifact(self):
        with self.assertRaises(SystemExit) as caught:
            pg_archive.main([
                "package",
                "--root", str(self.evidence),
                "--source-from", str(self.repo),
                "--artifact", str(self.base / "absent.pyz"),
                "--out", str(self.base / "absent.zip"),
            ])
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
