"""Shared constants and helpers for the progressive-gating experiment.

verifier/closure_audit.py is not modified. This harness lives under
tools/pg_*.py with evidence under progressive-gating/.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from verifier.closure_audit import VERSION as VERIFIER_VERSION
from verifier.closure_audit import sha

ROOT = Path(__file__).resolve().parents[1]
PG_ROOT = ROOT / "progressive-gating"
CASES = PG_ROOT / "cases"
STAGES = ("dev", "qa", "staging")
DEFAULT_PORTS = {"dev": 19081, "qa": 19082, "staging": 19083}
INJECTOR_VERSION = "pg-inject-1.0.0"

COLLECTOR_RULE = {
    "collector": "pg-collector",
    "version": "1.0.0",
    "transport": "live HTTP GET /health per stage",
    "window": "dev -> qa -> staging, one signal per deployed stage",
    "disposition_authority": "CI_health_gate",
    "inventory": "bounded stage-health inventory emitted by the staged runner",
}
QUERY_RULE_HASH = sha(COLLECTOR_RULE)

AUDIT_SCENARIOS = {"PG-N01", "PG-DISP", "PG-SEQ", "PG-INFO"}
CALIBRATION_SCENARIOS = ("PG-N01", "PG-ART", "PG-DISP")
ALL_SCENARIOS = ("PG-N01", "PG-ART", "PG-QA", "PG-DISP", "PG-SEQ", "PG-INFO")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def iso_utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_ts(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(x, ensure_ascii=False, sort_keys=True) + "\n" for x in rows),
        encoding="utf-8",
    )


def read_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def artifact_sha_from_file(path: Path) -> str:
    return "sha256:" + sha256_file(path)


def sanitize_name(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9_.-]+", "-", value).strip("-")
    return value[:90] or "run"


def stage_ports() -> dict:
    return {
        stage: int(os.environ.get(f"PG_{stage.upper()}_PORT", DEFAULT_PORTS[stage]))
        for stage in STAGES
    }


def run_cmd(cmd, cwd=None, env=None, timeout=120, log_path=None):
    started = utc_now()
    timed_out = False
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = 124
        out = exc.stdout or ""
        err = exc.stderr or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
    except OSError as exc:
        rc, out, err = 127, "", str(exc)
    result = {
        "command": [str(x) for x in cmd],
        "cwd": str(cwd) if cwd else None,
        "started_at_utc": started,
        "finished_at_utc": utc_now(),
        "exit": rc,
        "timed_out": timed_out,
        "stdout": out,
        "stderr": err,
    }
    if log_path is not None:
        log_path = Path(log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            "$ " + " ".join(result["command"]) + "\n"
            + f"exit={rc} timed_out={timed_out}\n"
            + "--- stdout ---\n" + out
            + "\n--- stderr ---\n" + err + "\n",
            encoding="utf-8",
        )
    return result


def load_designs() -> dict:
    designs = {}
    for path in sorted(CASES.glob("PG-*.json")):
        design = read_json(path)
        designs[design["id"]] = design
    missing = set(ALL_SCENARIOS) - set(designs)
    if missing:
        raise RuntimeError(f"missing scenario designs: {sorted(missing)}")
    extra = set(designs) - set(ALL_SCENARIOS)
    if extra:
        raise RuntimeError(f"unknown scenario designs: {sorted(extra)}")
    return designs


def design_sha(design: dict) -> str:
    return sha(design)


def protocol_hash() -> str:
    return sha256_file(PG_ROOT / "protocol.json")


def verifier_hash() -> str:
    return sha256_file(ROOT / "verifier" / "closure_audit.py")


def git_commit() -> str:
    result = run_cmd(["git", "rev-parse", "HEAD"], cwd=ROOT, timeout=15)
    return result["stdout"].strip() if result["exit"] == 0 else "UNKNOWN"


def git_dirty() -> bool:
    result = run_cmd(["git", "status", "--porcelain"], cwd=ROOT, timeout=15)
    return bool(result["stdout"].strip()) if result["exit"] == 0 else True


def python_version() -> str:
    return sys.version.split()[0]


def relative(root: Path, path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(path)
