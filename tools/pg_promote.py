"""Execute a real, sequential dev -> qa -> staging promotion with live gates.

Only tools launched by this run are touched. A failure stops promotion; the
downstream services are then queried directly rather than inferred from a
skipped CI job.
"""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

from tools.pg_common import (
    ROOT,
    STAGES,
    read_json,
    run_cmd,
    sha256_file,
    utc_now,
    write_json,
    write_jsonl,
)


def stage_specs(
    design: dict,
    original_image: str,
    tampered_image: str | None,
    pinned_sha: str,
    original_image_id: str,
    tampered_image_id: str | None,
    attestation: dict,
) -> list:
    scenario = design["id"]
    specs = []
    for stage in STAGES:
        image = original_image
        image_id = original_image_id
        fail_health = False
        if stage == "qa" and scenario == "PG-ART":
            if not tampered_image or not tampered_image_id:
                raise RuntimeError("PG-ART requires a tampered image")
            image = tampered_image
            image_id = tampered_image_id
        if stage == "qa" and scenario == "PG-QA":
            fail_health = True
        specs.append(
            {
                "stage": stage,
                "image": image,
                "expected_image_id": image_id,
                "expected_sha256": pinned_sha,
                "fail_health": fail_health,
                "attestation": attestation,
            }
        )
    return specs


def downstream_stages(failure_stage: str) -> list:
    index = STAGES.index(failure_stage)
    return list(STAGES[index + 1 :])


class PromotionRunner:
    def __init__(
        self,
        out_dir: Path,
        run_key: str,
        arm: str,
        project: str,
        ports: dict,
        *,
        attempt: int = 1,
        repeat_index: int = 1,
        github_run_id: str | None = None,
        github_job_id: str | None = None,
    ):
        self.out_dir = Path(out_dir)
        self.run_key = run_key
        self.arm = arm
        self.project = project
        self.ports = ports
        self.attempt = attempt
        self.repeat_index = repeat_index
        self.github_run_id = github_run_id
        self.github_job_id = github_job_id
        self.events = []
        self.seq = 0
        self.raw_dir = self.out_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.raw_dir / "stage_events.jsonl"
        self.compose_logs = self.raw_dir / "compose"
        self.compose_logs.mkdir(parents=True, exist_ok=True)
        self.stage_logs = self.raw_dir / "stage_logs"
        self.stage_logs.mkdir(parents=True, exist_ok=True)
        self.containers = {}

    def event(self, stage: str | None, event_type: str, **fields) -> dict:
        self.seq += 1
        item = {
            "event_id": f"evt-{self.run_key}-{self.seq:03d}",
            "seq": self.seq,
            "run_key": self.run_key,
            "arm": self.arm,
            "attempt": self.attempt,
            "repeat_index": self.repeat_index,
            "github_run_id": self.github_run_id,
            "github_job_id": self.github_job_id,
            "stage": stage,
            "event_type": event_type,
            "utc": utc_now(),
        }
        item.update(fields)
        self.events.append(item)
        write_jsonl(self.events_path, self.events)
        return item

    def _compose_env(self, images: dict, qa_fail_health: bool) -> dict:
        env = os.environ.copy()
        env.update(
            {
                "PG_DEV_IMAGE": images["dev"],
                "PG_QA_IMAGE": images["qa"],
                "PG_STAGING_IMAGE": images["staging"],
                "PG_DEV_PORT": str(self.ports["dev"]),
                "PG_QA_PORT": str(self.ports["qa"]),
                "PG_STAGING_PORT": str(self.ports["staging"]),
                "PG_QA_FAIL_HEALTH": "1" if qa_fail_health else "0",
            }
        )
        return env

    def _compose(self, action: str, stage: str, images: dict, qa_fail_health: bool, log_name: str):
        cmd = [
            "docker",
            "compose",
            "-p",
            self.project,
            "-f",
            "infra/compose.pg.yml",
        ]
        if action == "up":
            cmd += ["up", "-d", "--no-build", stage]
        elif action == "down":
            cmd += ["down", "--remove-orphans", "--volumes"]
        elif action == "ps":
            cmd += ["ps", "-a", "--format", "json"]
        else:
            raise ValueError(action)
        return run_cmd(
            cmd,
            cwd=ROOT,
            env=self._compose_env(images, qa_fail_health),
            timeout=120,
            log_path=self.compose_logs / log_name,
        )

    def _container_id(self, stage: str, include_stopped: bool = False) -> str | None:
        flag = "-aq" if include_stopped else "-q"
        result = run_cmd(
            [
                "docker",
                "ps",
                flag,
                "--filter",
                f"label=com.docker.compose.project={self.project}",
                "--filter",
                f"label=com.docker.compose.service={stage}",
            ],
            timeout=30,
        )
        ids = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
        if not ids:
            return None
        return ids[0]

    def _inspect(self, container_id: str) -> dict:
        result = run_cmd(["docker", "inspect", container_id], timeout=30)
        if result["exit"] != 0:
            return {"error": result["stderr"].strip(), "exit": result["exit"]}
        try:
            return json.loads(result["stdout"])[0]
        except (ValueError, IndexError) as exc:
            return {"error": f"inspect parse: {exc}", "raw": result["stdout"][:2000]}

    def _measure(self, container_id: str) -> dict:
        result = run_cmd(
            ["docker", "exec", container_id, "sha256sum", "/srv/release_app.pyz"],
            timeout=30,
            log_path=self.raw_dir / f"measure_{container_id[:12]}.log",
        )
        digest = None
        if result["exit"] == 0 and result["stdout"].split():
            digest = result["stdout"].split()[0]
        return {"exit": result["exit"], "sha256": digest, "stdout": result["stdout"], "stderr": result["stderr"]}

    def _health(self, stage: str) -> dict:
        url = f"http://127.0.0.1:{self.ports[stage]}/health"
        attempts = 0
        last_error = None
        for attempts in range(1, 41):
            try:
                with urllib.request.urlopen(url, timeout=2) as response:
                    body = json.loads(response.read().decode("utf-8"))
                    return {
                        "url": url,
                        "http_status": response.status,
                        "body": body,
                        "attempts": attempts,
                        "error": None,
                        "observed_at_utc": utc_now(),
                    }
            except urllib.error.HTTPError as exc:
                try:
                    body = json.loads(exc.read().decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    body = {}
                return {
                    "url": url,
                    "http_status": exc.code,
                    "body": body,
                    "attempts": attempts,
                    "error": None,
                    "observed_at_utc": utc_now(),
                }
            except (ConnectionError, TimeoutError, urllib.error.URLError, OSError) as exc:
                last_error = str(exc)
                time.sleep(0.25)
        return {
            "url": url,
            "http_status": None,
            "body": {},
            "attempts": attempts,
            "error": last_error or "unreachable",
            "observed_at_utc": utc_now(),
        }

    def _capture_logs(self, stage: str, container_id: str) -> None:
        result = run_cmd(
            ["docker", "logs", "--timestamps", container_id],
            timeout=30,
            log_path=self.stage_logs / f"{stage}.log",
        )
        result["stage"] = stage

    def _wait_port_free(self, port: int, timeout: float = 15.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                if sock.connect_ex(("127.0.0.1", port)) != 0:
                    return True
            time.sleep(0.25)
        return False

    def _query_downstream(self, stages: list, suffix: str) -> dict:
        observed = {}
        for stage in stages:
            result = run_cmd(
                [
                    "docker",
                    "ps",
                    "-aq",
                    "--filter",
                    f"label=com.docker.compose.project={self.project}",
                    "--filter",
                    f"label=com.docker.compose.service={stage}",
                ],
                timeout=30,
            )
            ids = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
            cid = ids[0] if ids else None
            observed[stage] = {
                "container_id": cid,
                "deployed": (cid is not None) if result["exit"] == 0 else None,
                "observation_exit": result["exit"],
            }
        ps = run_cmd(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"label=com.docker.compose.project={self.project}",
            ],
            timeout=30,
        )
        (self.raw_dir / f"docker_ps_after_failure_{suffix}.txt").write_text(
            ps["stdout"] + "\n--- stderr ---\n" + ps["stderr"], encoding="utf-8"
        )
        return observed

    def _stage_record(self, stage: str, spec: dict, gate_status: str, failure_code, gate: dict, **overrides) -> dict:
        record = {
            "stage": stage,
            "gate_status": gate_status,
            "first_failure_code": failure_code,
            "gate_event_id": gate["event_id"],
            "event_time": gate["utc"],
            "ingest_time": gate["utc"],
            "gate_time": gate["utc"],
            "http_status": None,
            "source_url": f"http://127.0.0.1:{self.ports[stage]}/health",
            "signal_id": f"health:{stage}",
            "expected_sha256": spec["expected_sha256"],
            "expected_image_id": spec["expected_image_id"],
            "deployed_sha256": None,
            "container_id": None,
            "image_id": None,
            "image_tag": spec["image"],
            "image_identity_check": "NOT_EXECUTED",
            "digest_check": "NOT_EXECUTED",
            "attestation_binding": "NOT_EXECUTED",
            "health_check": "NOT_EXECUTED",
        }
        record.update(overrides)
        return record

    def run_stage(self, spec: dict, images: dict, parent_gate_event_id: str | None) -> dict:
        stage = spec["stage"]
        expected = spec["expected_sha256"]
        expected_image_id = spec["expected_image_id"]
        attestation = spec.get("attestation") or {}
        deploy_requested = self.event(
            stage,
            "deploy_requested",
            image=spec["image"],
            expected_image_id=expected_image_id,
            expected_artifact_sha256=expected,
            compose_project=self.project,
            host_port=self.ports[stage],
            parent_gate_event_id=parent_gate_event_id,
        )
        up = self._compose("up", stage, images, spec["fail_health"], f"{stage}_up.log")
        if up["exit"] != 0:
            failed = self.event(
                stage,
                "deploy_failed",
                parent_event_id=deploy_requested["event_id"],
                exit=up["exit"],
                reason="compose_up_failed",
                stderr=up["stderr"][-2000:],
            )
            gate = self.event(
                stage,
                "gate_decided",
                parent_event_id=failed["event_id"],
                status="TOOL_FAILURE",
                code="COMPOSE_UP_FAILED",
            )
            return self._stage_record(stage, spec, "TOOL_FAILURE", "COMPOSE_UP_FAILED", gate)

        container_id = self._container_id(stage)
        if not container_id:
            failed = self.event(
                stage,
                "deploy_failed",
                parent_event_id=deploy_requested["event_id"],
                reason="container_not_found_after_compose_up",
            )
            gate = self.event(
                stage,
                "gate_decided",
                parent_event_id=failed["event_id"],
                status="TOOL_FAILURE",
                code="CONTAINER_NOT_STARTED",
            )
            return self._stage_record(stage, spec, "TOOL_FAILURE", "CONTAINER_NOT_STARTED", gate)

        self.containers[stage] = container_id
        inspect = self._inspect(container_id)
        if "error" in inspect:
            gate = self.event(
                stage,
                "gate_decided",
                parent_event_id=deploy_requested["event_id"],
                status="TOOL_FAILURE",
                code="DOCKER_INSPECT_FAILED",
                error=inspect.get("error"),
            )
            return self._stage_record(
                stage, spec, "TOOL_FAILURE", "DOCKER_INSPECT_FAILED", gate, container_id=container_id
            )

        image_id = inspect.get("Image")
        started = self.event(
            stage,
            "deploy_started",
            parent_event_id=deploy_requested["event_id"],
            container_id=container_id,
            image_id=image_id,
            container_status=(inspect.get("State") or {}).get("Status"),
        )
        image_pass = bool(expected_image_id) and image_id == expected_image_id
        image_check = self.event(
            stage,
            "check_finished",
            parent_event_id=started["event_id"],
            check="image_identity",
            result="PASS" if image_pass else "FAIL",
            expected_image_id=expected_image_id,
            actual_image_id=image_id,
            identity_type="Docker image config digest; never compared numerically with the pyz digest",
        )
        if not image_pass:
            gate = self.event(
                stage,
                "gate_decided",
                parent_event_id=image_check["event_id"],
                status="FAIL",
                code="IMAGE_IDENTITY_MISMATCH",
                digest_check="NOT_EXECUTED",
                attestation_binding="NOT_EXECUTED",
                health_check="NOT_EXECUTED",
            )
            return self._stage_record(
                stage,
                spec,
                "FAIL",
                "IMAGE_IDENTITY_MISMATCH",
                gate,
                event_time=image_check["utc"],
                ingest_time=image_check["utc"],
                container_id=container_id,
                image_id=image_id,
                image_identity_check="FAIL",
            )

        measure = self._measure(container_id)
        observed = self.event(
            stage,
            "running_identity_observed",
            parent_event_id=image_check["event_id"],
            container_id=container_id,
            image_id=image_id,
            container_stage=(inspect.get("Config") or {}).get("Labels", {}).get("com.docker.compose.service"),
            expected_artifact_sha256=expected,
            measured_artifact_sha256=measure["sha256"],
            measurement={"command": "docker exec <running> sha256sum /srv/release_app.pyz", "exit": measure["exit"]},
            identity_types={
                "pyz": "sha256 of file bytes inside the running container",
                "image_id": "Docker image config digest; not numerically comparable to the pyz digest",
            },
        )

        if measure["exit"] != 0 or not measure["sha256"]:
            gate = self.event(
                stage,
                "gate_decided",
                parent_event_id=observed["event_id"],
                status="TOOL_FAILURE",
                code="ARTIFACT_MEASUREMENT_FAILED",
                measurement_exit=measure["exit"],
            )
            return self._stage_record(
                stage,
                spec,
                "TOOL_FAILURE",
                "ARTIFACT_MEASUREMENT_FAILED",
                gate,
                container_id=container_id,
                image_id=image_id,
                image_identity_check="PASS",
            )

        digest_pass = measure["sha256"] == expected
        digest_check = self.event(
            stage,
            "check_finished",
            parent_event_id=observed["event_id"],
            check="artifact_digest",
            result="PASS" if digest_pass else "FAIL",
            expected_sha256=expected,
            measured_sha256=measure["sha256"],
            command="docker exec <running> sha256sum /srv/release_app.pyz",
        )
        if not digest_pass:
            gate = self.event(
                stage,
                "gate_decided",
                parent_event_id=digest_check["event_id"],
                status="FAIL",
                code="ARTIFACT_DIGEST_MISMATCH",
                attestation_binding="NOT_EXECUTED",
                health_check="NOT_EXECUTED",
            )
            return self._stage_record(
                stage,
                spec,
                "FAIL",
                "ARTIFACT_DIGEST_MISMATCH",
                gate,
                event_time=digest_check["utc"],
                ingest_time=digest_check["utc"],
                container_id=container_id,
                image_id=image_id,
                image_identity_check="PASS",
                digest_check="FAIL",
                deployed_sha256=measure["sha256"],
            )

        binding_mode = attestation.get("mode")
        binding_subject = attestation.get("subject_sha256")
        binding_pass = attestation.get("status") == "PASS" and binding_subject == measure["sha256"]
        binding_result = "PASS" if binding_pass else "FAIL"
        binding_check = self.event(
            stage,
            "check_finished",
            parent_event_id=digest_check["event_id"],
            check="attestation_binding",
            result=binding_result,
            attestation_mode=binding_mode,
            attestation_status=attestation.get("status"),
            subject_sha256=binding_subject,
            deployed_sha256=measure["sha256"],
            rule="attestation subject equals the pyz digest measured inside this stage",
        )
        if not binding_pass:
            gate = self.event(
                stage,
                "gate_decided",
                parent_event_id=binding_check["event_id"],
                status="FAIL",
                code="ATTESTATION_BINDING_FAILED",
                health_check="NOT_EXECUTED",
            )
            return self._stage_record(
                stage,
                spec,
                "FAIL",
                "ATTESTATION_BINDING_FAILED",
                gate,
                event_time=binding_check["utc"],
                ingest_time=binding_check["utc"],
                container_id=container_id,
                image_id=image_id,
                image_identity_check="PASS",
                digest_check="PASS",
                attestation_binding="FAIL",
                deployed_sha256=measure["sha256"],
            )

        health = self._health(stage)
        body_stage = (health.get("body") or {}).get("stage")
        health_pass = health.get("http_status") == 200 and body_stage == stage
        health_check = self.event(
            stage,
            "check_finished",
            parent_event_id=binding_check["event_id"],
            check="live_http_health",
            result="PASS" if health_pass else "FAIL",
            url=health["url"],
            http_status=health.get("http_status"),
            response=health.get("body"),
            error=health.get("error"),
            attempts=health.get("attempts"),
        )
        gate = self.event(
            stage,
            "gate_decided",
            parent_event_id=health_check["event_id"],
            status="PASS" if health_pass else "FAIL",
            code=None if health_pass else "HEALTH_CHECK_FAILED",
            reason=None if health_pass else f"http_status={health.get('http_status')} body_stage={body_stage}",
        )
        return self._stage_record(
            stage,
            spec,
            "PASS" if health_pass else "FAIL",
            None if health_pass else "HEALTH_CHECK_FAILED",
            gate,
            event_time=health_check["utc"],
            ingest_time=health["observed_at_utc"],
            http_status=health.get("http_status"),
            source_url=health["url"],
            container_id=container_id,
            image_id=image_id,
            image_identity_check="PASS",
            digest_check="PASS",
            attestation_binding=binding_result,
            deployed_sha256=measure["sha256"],
            health_check="PASS" if health_pass else "FAIL",
            health_response=health.get("body"),
        )

    def run_chain(
        self,
        design: dict,
        original_image: str,
        tampered_image: str | None,
        pinned_sha: str,
        original_image_id: str,
        tampered_image_id: str | None,
        attestation: dict,
    ) -> dict:
        specs = stage_specs(
            design,
            original_image,
            tampered_image,
            pinned_sha,
            original_image_id,
            tampered_image_id,
            attestation,
        )
        images = {spec["stage"]: spec["image"] for spec in specs}
        self._compose("down", "dev", images, False, "precleanup_down.log")
        for port in self.ports.values():
            self._wait_port_free(port)

        stages = {}
        first_failure = None
        parent_gate = None
        downstream_before = None
        downstream_after = None
        try:
            for spec in specs:
                record = self.run_stage(spec, images, parent_gate)
                stages[spec["stage"]] = record
                if record["gate_status"] == "PASS":
                    parent_gate = record["gate_event_id"]
                    continue
                first_failure = record
                break
        finally:
            # Query before teardown: cleanup must not erase the downstream-absence evidence.
            if first_failure:
                downstream = downstream_stages(first_failure["stage"])
                downstream_before = self._query_downstream(downstream, "pre_cleanup")
            for stage, cid in self.containers.items():
                self._capture_logs(stage, cid)
            down = self._compose("down", "dev", images, False, "cleanup_down.log")
            ps = self._compose("ps", "dev", images, False, "cleanup_ps.log")
            if first_failure:
                downstream = downstream_stages(first_failure["stage"])
                downstream_after = self._query_downstream(downstream, "post_cleanup")
            ports_free = {stage: self._wait_port_free(port) for stage, port in self.ports.items()}
            cleanup = {
                "down_exit": down["exit"],
                "ps_exit": ps["exit"],
                "ports_free": ports_free,
                "containers": dict(self.containers),
                "downstream_before_cleanup": downstream_before,
                "downstream_after_cleanup": downstream_after,
            }
            write_json(self.raw_dir / "cleanup.json", cleanup)

        if first_failure:
            downstream = downstream_stages(first_failure["stage"])
            observed = downstream_before
            self.event(
                first_failure["stage"],
                "downstream_not_deployed",
                parent_gate_event_id=first_failure["gate_event_id"],
                downstream_stages=downstream,
                observed=observed,
                observed_after_cleanup=downstream_after,
                evidence="docker ps -a filtered by compose project/service BEFORE teardown",
            )
            code = first_failure.get("first_failure_code")
            status = "FAIL" if code in {"ARTIFACT_DIGEST_MISMATCH", "HEALTH_CHECK_FAILED"} else "TOOL_FAILURE"
            chain = {
                "status": status,
                "first_failure_stage": first_failure["stage"],
                "first_failure_code": code,
                "stages": stages,
                "downstream": observed,
                "downstream_after_cleanup": downstream_after,
                "cleanup": cleanup,
            }
        else:
            observed = {stage: {"container_id": stages[stage]["container_id"], "deployed": True} for stage in STAGES}
            self.event(
                "staging",
                "chain_completed",
                parent_gate_event_id=parent_gate,
                downstream_stages=[],
                observed=observed,
            )
            chain = {
                "status": "PASS",
                "first_failure_stage": None,
                "first_failure_code": None,
                "stages": stages,
                "downstream": observed,
                "cleanup": cleanup,
            }
        chain["events_path"] = "raw/stage_events.jsonl"
        write_json(self.raw_dir / "chain_result.json", chain)
        measurements = {
            stage: {
                "stage": stage,
                "expected_sha256": rec.get("expected_sha256"),
                "deployed_sha256": rec.get("deployed_sha256"),
                "expected_image_id": rec.get("expected_image_id"),
                "image_id": rec.get("image_id"),
                "image_tag": rec.get("image_tag"),
                "container_id": rec.get("container_id"),
                "image_identity_check": rec.get("image_identity_check"),
                "digest_check": rec.get("digest_check"),
                "attestation_binding": rec.get("attestation_binding"),
                "health_check": rec.get("health_check"),
                "measurement": "docker exec <running> sha256sum /srv/release_app.pyz",
            }
            for stage, rec in stages.items()
        }
        write_json(self.raw_dir / "artifact_measurements.json", measurements)
        return chain
