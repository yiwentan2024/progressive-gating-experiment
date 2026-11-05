Progressive-gating staged-promotion experiment - reproduction guide
====================================================================

0. Prerequisites
----------------
- A checkout of this repository at the recorded source commit.
- Python 3.12 and Docker Engine with the docker compose plugin.
- The harness and the verifier use only the Python standard library.
- CI reproduction requires GitHub Actions with attestation permissions.


1. Purpose
----------
This directory contains a self-contained experiment that measures whether a
closure audit adds a detectable diagnosis after a release has already passed a
conventional staged promotion gate.

The experiment promotes one deterministic artifact through three real Docker
stages in order (dev -> qa -> staging). Each stage must pass an image identity
check, a pinned artifact digest check, an attestation binding check and a live
HTTP health check before the next stage may be requested. Two arms use the
same build, the same image, the same promotion chain and the same collector:

  P0  baseline configuration B1: staged promotion + minimal collector,
      closure audit not configured
  P1  closure audit configuration B2: same staged promotion + same collector,
      closure audit runs after the staging gate passes

The comparison is conditional: P0 and P1 must receive the same semantic audit
input and must both pass their baseline stages. The experiment reports CLOSED,
OPEN and NFI decisions, the diagnostic codes attached to machine OPEN, and the
baseline-control pairs separately.


2. Scope
--------
- The audit observes after the staging gate passes; this batch does not test
  blocking.
- The collector scope attestation is self-declared for the bounded three-stage
  chain.
- The GitHub attestation subject is the pyz file. The deployed object is an OCI
  image. The Docker image ID and the pyz digest are different identity types and
  are never compared numerically.
- Three repeats per scenario are consistency checks, not three independent
  scenarios.


3. Experiment design
--------------------
3.1 Promotion chain
    build once -> deploy dev -> gate dev -> deploy qa -> gate qa ->
    deploy staging -> gate staging -> collect -> P0 not configured / P1 audit

    Stages are deployed one at a time. A stage deploy request is made only after
    the previous stage gate returned PASS. Each stage records:

      deploy_requested -> deploy_started -> running_identity_observed ->
      check_finished(image_identity) -> check_finished(artifact_digest) ->
      check_finished(attestation_binding) -> check_finished(live_http_health) ->
      gate_decided

    The image identity check compares the running container image ID with the
    image ID recorded by the build. The digest check runs
    `docker exec <running> sha256sum /srv/release_app.pyz` and compares the result
    with the pinned pyz digest. The attestation binding check requires the
    attestation subject to equal the pyz digest measured inside the running
    container. The health check is a live HTTP GET /health that must return 200
    and body.stage == stage.

    Stage health is retried up to 40 times with a 2 s request timeout, compose up
    has a 120 s timeout and port release is awaited for up to 15 s.

    A failure stops promotion. The downstream containers are queried directly
    before teardown, so "not deployed" is an observation, not an inference from a
    skipped job. If that query fails, the state is recorded as UNKNOWN rather
    than as absent. Later checks that cannot run are recorded as NOT_EXECUTED;
    they are never recorded as PASS.

3.2 Artifact and build identity
    One build produces dist/release_app.pyz and one Docker image. Both arms reuse
    the same build_id, the same pyz digest and the same image. The build manifest
    records the source commit, the pyz sha256, the Docker image ID, the unit-test
    exit, the Python platform, the Docker and docker compose versions, and (in
    GitHub mode) the attestation verification command, tool version, raw output,
    exit code and evidence hashes. The container base image is python:3.12-slim.

3.3 Audit input and pairing
    The native case.json is built from retained stage evidence and is the input
    to verifier/closure_audit.py. It keeps native timestamps and host ports.
    semantic_projection.json maps native stage timestamps to fixed per-stage
    ordinals and normalizes host ports; it is used only to decide whether the two
    arms received the same audit input. The verifier's order relations are not
    changed by the projection. The input generator is deterministic.

    The verifier is not modified. Its exit code is retained but is not used as
    the machine decision. The decision is read from result.json
    (machine_decision, evidence_status, failure_codes).


4. Scenarios and expected outcomes
----------------------------------
Scenario designs are frozen in cases/PG-*.json.

  scenario_id  family  baseline behavior                  P0 / P1 audit result
  -----------  ------  --------------------------------   ---------------------
  PG-N01       N01     all three stages PASS              P0 NOT_CONFIGURED, P1 CLOSED
  PG-ART       B01     QA digest mismatch; staging absent  both NOT_RUN_UPSTREAM_BLOCKED
  PG-QA        B02     QA HTTP 503; staging absent         both NOT_RUN_UPSTREAM_BLOCKED
  PG-DISP      C01     all three stages PASS              P1 OPEN, A1_EFFECTIVE_DISPOSITION_COUNT,
                                                          evidence NOT_APPLICABLE
  PG-SEQ       C02     all three stages PASS              P1 OPEN, A2_REQUIREMENT_TEMPORAL_ORDER,
                                                          evidence OPEN
  PG-INFO      I01     all three stages PASS              P1 OPEN, A1_SCOPE_NOT_ATTESTED,
                                                          evidence NFI

PG-ART and PG-QA are baseline controls. The baseline gate rejects, the downstream
stage is absent, and neither arm runs the audit. They are reported separately and
are never added to the "baseline passed and the audit additionally found OPEN"
numerator.

The injection record for each run is runs/<run-key>/injection.json. It records
the injector version, the change point, the before/after values, the observed
effect, whether the injection actually hit and whether it is intended to affect
the baseline gate.


5. Repository layout
--------------------
  progressive-gating/
    README_Reproduction.txt    this file
    protocol.json              frozen scenarios, denominators, pairing rules,
                               collector rule and input byte hashes
    cases/PG-*.json            six frozen scenario designs
    .gitignore                 excludes generated evidence from the source tree

Generated evidence (created by a run, uploaded by CI, not committed):
    build/<pair-key>/          build manifest, unit-test and Docker logs,
                               attestation verification output; one build
                               per workflow run (one pair)
    runs/<run-key>/raw/        stage_events.jsonl, chain_result.json,
                               artifact_measurements.json, cleanup.json,
                               container and compose logs
    runs/<run-key>/normalized/ case.json, collector.json,
                               semantic_projection.json
    runs/<run-key>/verifier/   verifier log, result.json, audit_record.json,
                               input and implementation hashes
    runs/<run-key>/injection.json
    runs/<run-key>/run_meta.json, sha256sums.txt
    runs.csv                   one row per actual run attempt
    comparisons.csv            one row per selected comparable pair
    summary.json               planned matrix, denominators, missing evidence,
                               anomalies and scenario-level results
    workflow/                  exact workflow bytes used by the run
    MANIFEST.sha256            byte hashes of every other member under
                               progressive-gating/


6. Reproducing the batch in CI
------------------------------
Trigger .github/workflows/progressive-gating.yml with workflow_dispatch.
The workflow uses ubuntu-24.04, Python 3.12.13, actions/attest@v4 and the
repository's frozen-reference check.

  mode=pair         one scenario x one repeat = one P0/P1 pair, dispatched as
                    one workflow run. batch PG-FORMAL-01 or PG-CAL-01 selects
                    the frozen batch; scenario and repeat_index select the
                    pair. Both arms share the build, image and attestation
                    from that workflow run.
                    formal:      6 scenarios x 3 repeats = 18 workflow runs
                                  (36 attempts)
                    calibration: 3 scenarios x 1 repeat  = 3 workflow runs
                                  (6 attempts)
  mode=formal       batch PG-FORMAL-01 in one workflow run
                    6 scenarios x 2 arms x 3 repeats = 36 attempts / 18 pairs
                    one build; both arms reuse the same image
                    finalizes with --require-complete
  mode=calibration  batch PG-CAL-01 in one workflow run
                    PG-N01, PG-ART, PG-DISP, one pair each = 6 attempts / 3 pairs
                    excluded from the formal denominator

The delivered batch uses mode=pair: 21 workflow runs (3 calibration + 18
formal) produce 42 attempts. Every attempt row carries the run ID and URL of
its pair's workflow run; the two arms of one pair share that run ID because
they share one build and one image. Arm order is fixed by protocol.json.
A retry uses a higher attempt number; the original attempt and its failure
reason are retained. comparisons.csv selects the first comparable attempt per
(batch, scenario, repeat); all attempts remain in runs.csv with an exclusion
reason.

When every protocol, test, promotion and ledger check has passed, the workflow
packages the result into one archive:

  progressive-gating-final-<UTC>.zip
    progressive-gating/    evidence tree, including MANIFEST.sha256
    source/                exact source tree at the checked-out commit
    artifact/              the built subject, release_app.pyz
    REPRODUCE.md

The archive is uploaded with its .zip.sha256 and .zip.manifest.json sidecars. A
run that fails a check uploads the partial evidence tree as a diagnostics
artifact instead.

The harness commands are:

  python -m tools.pg_build build --batch <batch> --out <dir> \
      --source-commit <sha>
  python -m tools.pg_run --manifest <build_manifest.json> --mode pair \
      --batch <batch> --scenario <id> --repeat-index <n> --attempt <n> \
      --github-run-id <id> --github-job-id <id>
  python -m tools.pg_ledger finalize --root progressive-gating
  python -m tools.pg_ledger verify --root progressive-gating
  python -m tools.pg_archive package --root progressive-gating \
      --source-from . --artifact dist/release_app.pyz

Stage ports default to dev=19081, qa=19082 and staging=19083 and can be
overridden with PG_DEV_PORT, PG_QA_PORT and PG_STAGING_PORT.


7. Offline verification of an archived package
----------------------------------------------
Extract progressive-gating-final-<UTC>.zip and enter the embedded snapshot:

  cd source
  python -m unittest discover -s tests -v
  python -m unittest discover -s tests_pg -t . -v
  python -m tools.pg_protocol check
  python -m tools.pg_build verify \
      --manifest ../progressive-gating/build/<pair-key>/build_manifest.json \
      --artifact ../artifact/release_app.pyz
  python -m tools.pg_ledger verify --root ../progressive-gating
  python -m tools.pg_ledger verify --root ../progressive-gating --require-complete

The last command is only for a complete formal batch. `pg_protocol check`
verifies every input byte hash and every scenario design hash. `pg_ledger verify`
verifies the file set and byte hashes in MANIFEST.sha256 and checks the protocol
input hashes. Offline verification does not run Docker and does not change any
run identity, artifact digest or attestation. Re-running the workflow creates a
new run identity and a new build_id; artifact bytes match only when the source
and toolchain are unchanged.

MANIFEST.sha256 paths are relative to progressive-gating/ and the manifest does
not list itself. summary.json records the protocol hash, the verifier hash and
per-run input, canonical-input and semantic hashes for cross-checking.

tests_pg/ is a dependency-free self-test suite for the harness mechanics. It
checks scenario construction, semantic projection, ledger arithmetic,
attestation evidence handling and workflow/document alignment. It does not feed
expected labels into the verifier.


8. Ledger fields and counting rules
-----------------------------------
runs.csv has one row per actual attempt. Columns include batch, scenario,
scenario family, arm and baseline variant (P0=B1, P1=B2), repeat, attempt,
GitHub run and job IDs, source and workflow hashes, verifier and collector
hashes, expected pyz digest, per-stage requested image tag, measured pyz digest
and image ID, per-stage image identity, digest, attestation binding and gate
status, first failure stage and code, observed downstream deployment, audit
status, machine decision, evidence status, diagnostic codes, expected match,
inclusion/exclusion reason, input hashes and the evidence path. Planned but
never-started cells are listed in summary.json as missing evidence. The single
expected_artifact_sha256 column is the pinned
pyz digest requested at every stage; the per-stage image tag is recorded
separately.

comparisons.csv has one row per selected comparable pair. It records both run
keys, same_build, same_artifact_digest, same_scenario_design,
semantic_inputs_match, baseline_outcomes_match, both stage-gate sequences, first
rejection, audit results, expected diagnostic hits, baseline_pass_and_p1_open
and baseline_failure_control.

summary.json separates formal and calibration runs. It reports the
planned matrix, actual starts, valid and eligible runs, selected comparable
pairs, missing cells, reruns, anomalies, per-stage counts and scenario-level
results. In the per-stage counts, PASS, FAIL and TOOL_FAILURE mean the stage was
deployed and its gate ran; NOT_DEPLOYED means no container was observed;
UPSTREAM_NOT_RUN means the chain stopped earlier; UNKNOWN means the observation
could not be made. NFI is a subclass of machine OPEN: the summary reports machine
OPEN total, OPEN with evidence OPEN and OPEN with evidence NFI separately, and
never adds NFI to the OPEN total a second time.


9. Delivery archive
-------------------
The final delivery is one archive assembled from the 21 pair packages:

  progressive-gating-<UTC>.zip
    progressive-gating/   combined evidence: runs/, build/, workflow/,
                          runs.csv, comparisons.csv, summary.json,
                          MANIFEST.sha256
    source/               exact executed source snapshot
    REPRODUCE.md
    manifest.json

A .zip.sha256 sidecar sits beside the archive. Pair packages downloaded from
each workflow run are intermediate files; they are not part of the delivery.
After the merge, the combined evidence tree is finalized and verified with
--require-complete, then the archive is written and read back for verification.

The source snapshot contains the gate code and protocol but not generated
evidence; build/, runs/, runs.csv, comparisons.csv, summary.json, workflow/ and
MANIFEST.sha256 are produced by a run and are excluded from the source tree by
.gitignore.


10. Cleanup and failure handling
--------------------------------
Each run, in a finally block:

  - queries downstream containers before teardown (docker ps -a filtered by
    compose project and service) and saves that observation;
  - captures container and compose logs;
  - runs docker compose -p <project> down --remove-orphans --volumes;
  - waits for the three ports to be released.

The workflow also removes containers and images labeled
pg.harness=progressive-gating. Failure evidence is not erased by cleanup. If a
run is interrupted, inspect
`docker ps -a --filter label=pg.harness=progressive-gating` and remove only the
containers belonging to that run.


11. Exit codes and diagnostics
------------------------------
  python -m tools.pg_build build ...                0 success; 1 unit test,
                                                    artifact or image failure
  python -m tools.pg_build record-attestation ...   0 verification passed;
                                                    1 verification failed
  python -m tools.pg_build verify ...               0 passed; 1 artifact or
                                                    build status failed;
                                                    2 attestation failed;
                                                    3 evidence file missing or
                                                    changed; 4 verification
                                                    command or tool version
                                                    missing
  python -m tools.pg_protocol check                 0 passed; 2 input or design
                                                    hash mismatch
  python -m tools.pg_run ...                        0 all runs valid; 2 a tool
                                                    failure occurred
  python -m tools.pg_ledger finalize ...            0 written; 2 require-complete
                                                    not satisfied
  python -m tools.pg_ledger verify ...              0 manifest and protocol
                                                    consistent; 2 inconsistent
  python -m tools.pg_archive package ...            0 archive written and
                                                    verified; 2 missing or empty
                                                    input, source snapshot
                                                    failure, or write conflict
  python -m verifier.closure_audit ... --allow-open 0 tool executed (OPEN or
                                                    CLOSED); 2 invalid input;
                                                    3 parse or runtime failure

Do not infer the machine decision from the verifier exit code. The decision,
evidence status and failure codes are read from result.json and retained beside
the exit code, raw output and audit_record.json.

Audit statuses are explicit: NOT_CONFIGURED (P0), NOT_RUN_UPSTREAM_BLOCKED
(baseline rejected), TOOL_FAILURE (the harness or verifier did not produce a
valid decision) and RUN (a valid machine decision exists). result.json's
evidence_status may be PENDING, OPEN, NFI or NOT_APPLICABLE; NOT_APPLICABLE means
the evidence status does not apply to that decision, not that evidence was
missing.
