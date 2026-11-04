"""Build the single subject artifact/image for a progressive-gating pair or batch.

The existing tools/build.py and infra/Dockerfile are invoked, not copied or
changed. The manifest records the pyz digest, Docker image identity, unit-test
exit and (for GitHub) the separately verified attestation result.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import sys
from pathlib import Path

from tools.pg_common import (
    ROOT,
    git_commit,
    git_dirty,
    python_version,
    read_json,
    run_cmd,
    sanitize_name,
    sha256_file,
    utc_now,
    write_json,
)


def _build_id(batch: str, commit: str) -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{sanitize_name(batch)}-{stamp}-{(commit or 'unknown')[:8]}".lower()


def _unit_exit_from_file(path: Path) -> int | None:
    try:
        return int(Path(path).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _tool_version(cmd: list) -> str | None:
    result = run_cmd(cmd, cwd=ROOT, timeout=30)
    lines = (result["stdout"] or result["stderr"]).strip().splitlines()
    return lines[0] if result["exit"] == 0 and lines else None


def build(args) -> int:
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.mkdir(parents=True, exist_ok=True)
    commit = args.source_commit or git_commit()
    build_id = args.build_id or _build_id(args.batch, commit)
    image_tag = args.tag or f"closure-eval:pg-{build_id}"
    if not image_tag.startswith("closure-eval:"):
        image_tag = "closure-eval:" + sanitize_name(image_tag)

    unit_exit = _unit_exit_from_file(Path(args.unit_exit_file)) if args.unit_exit_file else None
    if args.skip_unit_tests:
        if unit_exit is None:
            raise SystemExit("--skip-unit-tests requires --unit-exit-file with an integer")
        unit_result = {"exit": unit_exit, "log": str(args.unit_exit_file), "reused": True}
    else:
        cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
        result = run_cmd(cmd, cwd=ROOT, timeout=300, log_path=out / "unit_tests.log")
        unit_exit = result["exit"]
        unit_result = {
            "command": cmd,
            "exit": unit_exit,
            "log": "unit_tests.log",
            "reused": False,
        }
    if unit_exit != 0:
        manifest = {
            "schema": "pg-build-1",
            "batch": args.batch,
            "build_id": build_id,
            "built_at_utc": utc_now(),
            "source_commit": commit,
            "source_tree_dirty": git_dirty(),
            "python": python_version(),
            "platform": platform.platform(),
            "docker": _tool_version(["docker", "--version"]),
            "docker_compose": _tool_version(["docker", "compose", "version"]),
            "unit_tests": unit_result,
            "status": "UNIT_TESTS_FAILED",
        }
        write_json(out / "build_manifest.json", manifest)
        print("unit tests failed; build aborted")
        return 1

    build_result = run_cmd(
        [sys.executable, "tools/build.py"],
        cwd=ROOT,
        timeout=120,
        log_path=out / "artifact_build.log",
    )
    artifact_path = ROOT / "dist" / "release_app.pyz"
    artifact_sha = sha256_file(artifact_path) if artifact_path.is_file() else None
    artifact_bytes = artifact_path.stat().st_size if artifact_path.is_file() else None
    if build_result["exit"] != 0 or not artifact_sha:
        manifest = {
            "schema": "pg-build-1",
            "batch": args.batch,
            "build_id": build_id,
            "built_at_utc": utc_now(),
            "source_commit": commit,
            "source_tree_dirty": git_dirty(),
            "python": python_version(),
            "platform": platform.platform(),
            "docker": _tool_version(["docker", "--version"]),
            "docker_compose": _tool_version(["docker", "compose", "version"]),
            "unit_tests": unit_result,
            "artifact": {
                "path": "dist/release_app.pyz",
                "sha256": artifact_sha,
                "bytes": artifact_bytes,
                "build_exit": build_result["exit"],
                "build_log": "artifact_build.log",
            },
            "status": "ARTIFACT_BUILD_FAILED",
        }
        write_json(out / "build_manifest.json", manifest)
        print("artifact build failed")
        return 1

    docker = run_cmd(
        [
            "docker",
            "build",
            "-f",
            "infra/Dockerfile",
            "-t",
            image_tag,
            "--label",
            f"pg.batch={args.batch}",
            "--label",
            f"pg.artifact.sha256={artifact_sha}",
            "--label",
            f"pg.source.commit={commit}",
            "--label",
            "pg.harness=progressive-gating",
            ".",
        ],
        cwd=ROOT,
        timeout=900,
        log_path=out / "docker_build.log",
    )
    inspect = run_cmd(
        ["docker", "image", "inspect", image_tag, "--format", "{{.Id}}"],
        cwd=ROOT,
        timeout=60,
        log_path=out / "docker_image_inspect.log",
    )
    image_id = inspect["stdout"].strip() if inspect["exit"] == 0 else None
    attestation = {
        "mode": args.attestation_mode,
        "status": "PENDING_GITHUB_ATTESTATION" if args.attestation_mode == "github" else "NOT_AVAILABLE_LOCAL",
        "subject_path": "dist/release_app.pyz",
        "subject_sha256": artifact_sha,
        "verify_exit": None,
        "verify_command": None,
        "verify_tool_version": None,
        "recorded_at_utc": None,
        "verify_json": None,
        "verify_stderr": None,
        "binding": {
            "subject_identity_type": "pyz file sha256",
            "deployed_identity_type": "pyz file sha256 measured inside the running stage container",
            "oci_identity_type": "Docker image config digest recorded separately; never compared numerically to the pyz digest",
            "verified_binding": None,
        },
    }
    manifest = {
        "schema": "pg-build-1",
        "batch": args.batch,
        "build_id": build_id,
        "built_at_utc": utc_now(),
        "source_commit": commit,
        "source_tree_dirty": git_dirty(),
        "python": python_version(),
        "platform": platform.platform(),
        "docker": _tool_version(["docker", "--version"]),
        "docker_compose": _tool_version(["docker", "compose", "version"]),
        "repo_root": ".",
        "unit_tests": unit_result,
        "artifact": {
            "path": "dist/release_app.pyz",
            "sha256": artifact_sha,
            "bytes": artifact_bytes,
            "build_exit": build_result["exit"],
            "build_log": "artifact_build.log",
            "sha256_command": "sha256 of the bytes written by tools/build.py; recomputed independently",
        },
        "image": {
            "tag": image_tag,
            "id": image_id,
            "build_exit": docker["exit"],
            "build_log": "docker_build.log",
            "dockerfile": "infra/Dockerfile",
            "dockerfile_sha256": sha256_file(ROOT / "infra" / "Dockerfile"),
        },
        "attestation": attestation,
        "workflow": {
            "path": ".github/workflows/progressive-gating.yml",
            "sha256": sha256_file(ROOT / ".github/workflows/progressive-gating.yml")
            if (ROOT / ".github/workflows/progressive-gating.yml").is_file()
            else None,
        },
        "status": "OK" if docker["exit"] == 0 and image_id else "DOCKER_BUILD_FAILED",
    }
    if manifest["status"] != "OK":
        write_json(out / "build_manifest.json", manifest)
        print("docker image build failed")
        return 1
    write_json(out / "build_manifest.json", manifest)
    (out / "artifact.sha256").write_text(f"{artifact_sha}  dist/release_app.pyz\n", encoding="utf-8")
    print(json.dumps({"build_id": build_id, "artifact_sha256": artifact_sha, "image": image_tag, "image_id": image_id}, indent=2))
    return 0


def record_attestation(args) -> int:
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = ROOT / manifest_path
    manifest = read_json(manifest_path)
    exit_code = _unit_exit_from_file(Path(args.exit_file))
    if exit_code is None:
        raise SystemExit("attestation exit file is missing or not an integer")
    out = manifest_path.parent
    attestation = manifest.setdefault("attestation", {})
    attestation["verify_exit"] = exit_code
    attestation["verify_command"] = args.command or None
    attestation["verify_tool_version"] = args.tool_version or None
    attestation["recorded_at_utc"] = utc_now()
    attestation["verify_json"] = args.json or None
    attestation["verify_stderr"] = args.stderr or None
    for key, source in (("verify_json_file", args.json_file), ("verify_stderr_file", args.stderr_file)):
        if not source:
            continue
        source_path = Path(source)
        if not source_path.is_absolute():
            source_path = ROOT / source_path
        if source_path.is_file():
            target = out / source_path.name
            target.write_bytes(source_path.read_bytes())
            attestation[key] = {
                "path": target.name,
                "sha256": sha256_file(target),
                "bytes": target.stat().st_size,
            }
    attestation["status"] = "PASS" if exit_code == 0 else "FAIL"
    if exit_code == 0:
        attestation["binding"]["verified_binding"] = (
            "attestation subject sha256 == pinned build artifact sha256; "
            "each passing stage independently measures the same pyz sha256 inside its container. "
            "The OCI image digest is recorded as a separate identity type."
        )
    else:
        attestation["binding"]["verified_binding"] = None
    write_json(manifest_path, manifest)
    print(json.dumps({"attestation_status": attestation["status"], "exit": exit_code}, indent=2))
    return 0 if exit_code == 0 else 1


def verify(args) -> int:
    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = ROOT / manifest_path
    manifest = read_json(manifest_path)
    if args.artifact:
        artifact = Path(args.artifact)
        if not artifact.is_absolute():
            artifact = Path.cwd() / artifact
    else:
        artifact = ROOT / manifest["artifact"]["path"]
    actual = sha256_file(artifact) if artifact.is_file() else None
    expected = manifest["artifact"]["sha256"]
    ok = actual == expected and manifest.get("status") == "OK"
    print(json.dumps({"ok": ok, "expected_sha256": expected, "actual_sha256": actual, "status": manifest.get("status")}, indent=2))
    if not ok:
        return 1
    attestation = manifest.get("attestation", {})
    if attestation.get("mode") == "github":
        if attestation.get("status") != "PASS" or attestation.get("verify_exit") != 0:
            print("github attestation did not pass")
            return 2
        if not attestation.get("verify_command") or not attestation.get("verify_tool_version"):
            print("attestation record is missing the verification command or tool version")
            return 4
        for key in ("verify_json_file", "verify_stderr_file"):
            item = attestation.get(key)
            if not item:
                continue
            path = manifest_path.parent / item["path"]
            if not path.is_file() or sha256_file(path) != item.get("sha256"):
                print(f"attestation evidence changed or missing: {item.get('path')}")
                return 3
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("build")
    p.add_argument("--batch", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--tag", default=None)
    p.add_argument("--build-id", default=None)
    p.add_argument("--source-commit", default=None)
    p.add_argument("--attestation-mode", choices=["github", "local-unavailable"], required=True)
    p.add_argument("--unit-exit-file", default=None)
    p.add_argument("--skip-unit-tests", action="store_true")
    p.set_defaults(func=build)

    p = sub.add_parser("record-attestation")
    p.add_argument("--manifest", required=True)
    p.add_argument("--exit-file", required=True)
    p.add_argument("--command", default=None, help="exact verification command line")
    p.add_argument("--tool-version", default=None, help="verification tool version string")
    p.add_argument("--json", default=None)
    p.add_argument("--stderr", default=None)
    p.add_argument("--json-file", default=None)
    p.add_argument("--stderr-file", default=None)
    p.set_defaults(func=record_attestation)

    p = sub.add_parser("verify")
    p.add_argument("--manifest", required=True)
    p.add_argument("--artifact", default=None, help="artifact path; defaults to the manifest path under the source tree")
    p.set_defaults(func=verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
