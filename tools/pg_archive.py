"""Package the progressive-gating evidence tree with an exact source snapshot.

The archive mirrors the existing experiment packaging: one zip contains the
evidence tree, the source tree at the recorded commit, and a reproduction note.
A .sha256 and a .manifest.json sidecar describe the archive.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REPRODUCE_MD = """\
# Reproduction

This archive contains the progressive-gating evidence under
`progressive-gating/`, the exact source snapshot under `source/`
(commit `{sha}`), and {artifact_clause}.

## Verify the archive offline

```bash
cd source
python -m unittest discover -s tests -v
python -m unittest discover -s tests_pg -t . -v
python -m tools.pg_protocol check
python -m tools.pg_ledger verify --root ../progressive-gating
{verify_command}
```

{attestation_note}## Re-run on GitHub

Push the contents of `source/` to a repository, then dispatch
`.github/workflows/progressive-gating.yml` with `mode=formal` or
`mode=calibration`. A re-run creates new run and build identities; it does not
change this archive.
"""


def _fail(message: str) -> None:
    print(f"pg_archive: {message}", file=sys.stderr)
    raise SystemExit(2)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(args: list, cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        text=True,
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        _fail(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _evidence_files(root: Path) -> list:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.name != ".DS_Store"
    )


def _sidecar_path(zip_path: Path, suffix: str) -> Path:
    return zip_path.with_suffix(f".zip.{suffix}")


def package(args) -> int:
    root = Path(args.root)
    if not root.is_absolute():
        root = ROOT / root
    root = root.resolve()
    if not root.is_dir():
        _fail(f"evidence root missing: {root}")
    source = Path(args.source_from)
    if not source.is_absolute():
        source = ROOT / source
    source = source.resolve()
    if not source.is_dir():
        _fail(f"source worktree missing: {source}")
    if _git(["rev-parse", "--is-inside-work-tree"], source) != "true":
        _fail(f"source is not a git worktree: {source}")
    commit = _git(["rev-parse", "HEAD"], source)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    zip_path = Path(args.out) if args.out else source / f"{root.name}-final-{stamp}.zip"
    if not zip_path.is_absolute():
        zip_path = Path.cwd() / zip_path
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    zip_path = zip_path.resolve()
    if root in zip_path.parents:
        _fail("output archive must be outside the evidence root")

    evidence = _evidence_files(root)
    if not evidence:
        _fail(f"evidence root is empty: {root}")

    artifact_record = None
    artifact_file = None
    if args.artifact:
        artifact_file = Path(args.artifact)
        if not artifact_file.is_absolute():
            artifact_file = ROOT / artifact_file
        artifact_file = artifact_file.resolve()
        if not artifact_file.is_file():
            _fail(f"artifact missing: {artifact_file}")
        if root in artifact_file.parents:
            _fail("artifact must be outside the evidence root")
        artifact_record = {
            "path": f"artifact/{artifact_file.name}",
            "sha256": _sha256_file(artifact_file),
            "bytes": artifact_file.stat().st_size,
        }

    source_names = []
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in evidence:
            archive.write(path, (Path(root.name) / path.relative_to(root)).as_posix())
        with tempfile.NamedTemporaryFile(suffix=".zip") as handle:
            subprocess.run(
                ["git", "archive", "--format=zip", "HEAD", "-o", handle.name],
                cwd=str(source),
                check=True,
                timeout=120,
            )
            with zipfile.ZipFile(handle.name) as source_zip:
                for name in source_zip.namelist():
                    if name.endswith("/"):
                        continue
                    archive.writestr(f"source/{name}", source_zip.read(name))
                    source_names.append(name)
        if artifact_record:
            archive.write(artifact_file, artifact_record["path"])
        if artifact_record:
            artifact_clause = "the built subject under `artifact/`"
            verify_command = (
                "python -m tools.pg_build verify --manifest "
                "../progressive-gating/build/<build-dir>/build_manifest.json "
                f"--artifact ../artifact/{artifact_file.name}"
            )
            attestation_note = (
                f"In GitHub mode, the attestation subject is `artifact/{artifact_file.name}`. "
                "When the repository is public, verify it with\n"
                f"`gh attestation verify artifact/{artifact_file.name} --repo <owner>/<repo>`.\n\n"
            )
        else:
            artifact_clause = "no built artifact"
            verify_command = (
                "# The build manifest records the subject digest; rebuild the subject before\n"
                "# running: python -m tools.pg_build verify --manifest <build_manifest.json>"
            )
            attestation_note = ""
        archive.writestr(
            "REPRODUCE.md",
            REPRODUCE_MD.format(
                sha=commit[:12],
                artifact_clause=artifact_clause,
                verify_command=verify_command,
                attestation_note=attestation_note,
            ),
        )

    digest = _sha256_file(zip_path)
    _sidecar_path(zip_path, "sha256").write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8")
    contains = [f"{root.name}/", "source/"]
    if artifact_record:
        contains.append("artifact/")
    contains.append("REPRODUCE.md")
    manifest = {
        "archive": zip_path.name,
        "sha256": digest,
        "file_count": len(evidence) + len(source_names) + (1 if artifact_record else 0) + 1,
        "evidence_file_count": len(evidence),
        "source_file_count": len(source_names),
        "artifact": artifact_record,
        "source_commit": commit,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "contains": contains,
    }
    _sidecar_path(zip_path, "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    if args.verify:
        with zipfile.ZipFile(zip_path) as archive:
            names = set(archive.namelist())
            for path in evidence:
                rel = (Path(root.name) / path.relative_to(root)).as_posix()
                if rel not in names or _sha256_bytes(archive.read(rel)) != _sha256_file(path):
                    _fail(f"archive verification failed: {rel}")
            if "REPRODUCE.md" not in names:
                _fail("archive verification failed: REPRODUCE.md missing")
            packed_source = [name for name in names if name.startswith("source/")]
            if len(packed_source) != len(source_names):
                _fail("archive verification failed: source file count differs")
            if artifact_record:
                rel = artifact_record["path"]
                if rel not in names or _sha256_bytes(archive.read(rel)) != artifact_record["sha256"]:
                    _fail("archive verification failed: artifact")
    print(json.dumps(manifest, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    pack = sub.add_parser("package", help="write the final evidence + source zip")
    pack.add_argument("--root", default="progressive-gating", help="evidence root")
    pack.add_argument("--source-from", default=".", help="git worktree to snapshot at HEAD")
    pack.add_argument("--out", default=None, help="output zip path")
    pack.add_argument("--artifact", default=None, help="built subject artifact to include")
    pack.add_argument("--verify", dest="verify", action="store_true", default=True)
    pack.add_argument("--no-verify", dest="verify", action="store_false")
    pack.set_defaults(func=package)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
