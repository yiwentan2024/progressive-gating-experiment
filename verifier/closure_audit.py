"""Dual-timepoint closure audit verifier: audits whether release obligations
are closed by evidence that existed before cutoff. No external dependencies.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

VERSION = 'closure-audit-verifier-0.4.0'
# 0.4.0: batch_protocol schema revision — summary carries only fields defined
# by this study's batch protocol; scope string renamed accordingly. Decision
# logic unchanged from 0.3.1 (enum conformance).
# 0.3.1: evidence_status conformance — (1) scope-attestation failure now classified
# as an audit-time insufficiency so an unconfirmable observation scope yields NFI
# (six-boundary rule: unverifiable scope must not silently drop out); (2) fully
# verified successor obligations resolve to NOT_APPLICABLE instead of CLOSED,
# keeping evidence_status within {PENDING, OPEN, NFI, NOT_APPLICABLE}.

def canonical_bytes(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')

def sha(obj):
    return 'sha256:' + hashlib.sha256(canonical_bytes(obj)).hexdigest()

def when(s):
    if not isinstance(s, str):
        raise ValueError('timestamp must be ISO8601 string')
    value = dt.datetime.fromisoformat(s.replace('Z', '+00:00'))
    if value.utcoffset() is None:
        raise ValueError('timezone offset is required')
    return value.astimezone(dt.timezone.utc)

def verify(case):
    """Return auditable result. Unsupported data fail-closed; NFI stays distinct."""
    if not isinstance(case, dict):
        raise ValueError('top-level input must be JSON object')
    cutoff = when(case['source_cutoff'])
    audit = when(case['audit_time'])
    if audit < cutoff:
        raise ValueError('audit_time precedes source_cutoff')
    historical = []
    later = []
    obligations = []
    def fail(code, reason, where='historical', evidence='OPEN'):
        item = {'code': code, 'reason': reason, 'evidence_status': evidence, 'component': where}
        (historical if where == 'historical' else later).append(item)

    policy = case.get('policy') or {}
    scope = case.get('scope') or {}
    raw = case.get('raw_signals') or []
    disp = case.get('dispositions') or []
    candidates = case.get('candidates') or []
    if not isinstance(raw, list) or not isinstance(disp, list) or not isinstance(candidates, list):
        raise ValueError('raw_signals, dispositions and candidates must be arrays')
    att = scope.get('collector_attestation') or {}
    if att.get('complete') is not True or not att.get('query_rule_hash') or not att.get('collector_version'):
        fail('A1_SCOPE_NOT_ATTESTED','bounded monitored source/window not verifiably declared',where='audit',evidence='NFI')
    if att.get('inventory_sha256') != sha(raw):
        fail('A1_INVENTORY_DIGEST_MISMATCH','raw inventory bytes do not match recorded collection attestation')
    if att.get('source_type') != 'INDEPENDENT_UPSTREAM_EXPORT':
        # A self-declared scope claim is not independent field completeness.
        # Disclose it in result, but do not mislabel as independently proven.
        pass
    if not scope.get('service_id') or not scope.get('approved_sources'):
        fail('A1_SOURCE_SCOPE_MISSING','service/source scope is missing',evidence='NFI')
    else:
        for r in raw:
            if r.get('source_id') not in scope['approved_sources']:
                fail('A1_UNAPPROVED_SIGNAL_SOURCE', str(r.get('signal_id')))
    ids = [r.get('signal_id') for r in raw]
    if len(set(ids)) != len(ids) or not all(isinstance(x,str) and x for x in ids):
        fail('A1_DUPLICATE_RAW_ID', 'raw signal identities must be unique and nonempty')
    for r in raw:
        sid = r.get('signal_id', '?')
        if r.get('payload_sha256') != sha(r.get('payload')):
            fail('A1_SIGNAL_DIGEST_INVALID', sid)
        try:
            if when(r.get('event_time')) > cutoff or when(r.get('ingest_time')) > cutoff:
                fail('A1_LATE_SIGNAL', sid)
        except ValueError:
            fail('A1_SIGNAL_TIME_INVALID', sid, evidence='NFI')
    for sid in set(ids):
        effective = [d for d in disp if d.get('signal_id') == sid and d.get('effective') is True]
        if len(effective) != 1:
            fail('A1_EFFECTIVE_DISPOSITION_COUNT', f'{sid}: {len(effective)} effective dispositions')
            continue
        d = effective[0]
        try:
            if when(d.get('decision_time')) > cutoff:
                fail('A1_LATE_DISPOSITION',sid)
        except ValueError:
            fail('A1_DISPOSITION_TIME_INVALID',sid,evidence='NFI')
        if d.get('decision') == 'UNRESOLVED':
            fail('A1_UNRESOLVED_SIGNAL',sid)
        elif d.get('decision') == 'AUTHORIZED_EXCLUDED':
            if (d.get('actor') not in policy.get('exclusion_authorities', []) or
                d.get('authorized') is not True or not d.get('reason')):
                fail('A1_UNAUTHORIZED_EXCLUSION',sid)
        elif d.get('decision') != 'RESOLVED':
            fail('A1_INVALID_DISPOSITION',sid)
        cc = [c for c in candidates if c.get('signal_id')==sid]
        if len(cc) != 1 or cc[0].get('disposition_id') != d.get('disposition_id'):
            fail('A1_CANDIDATE_MAPPING_INVALID',sid)
        elif cc[0].get('state') not in ('RESOLVED','EXCLUDED'):
            fail('A1_CANDIDATE_UNRESOLVED',sid)
    for d in disp:
        if d.get('signal_id') not in ids:
            fail('A1_ORPHAN_DISPOSITION',str(d.get('signal_id')))
    for c in candidates:
        if c.get('signal_id') not in ids:
            fail('A1_ORPHAN_CANDIDATE',str(c.get('signal_id')))
    gates = case.get('gates') or []
    if not gates:
        fail('POLICY_GATES_MISSING','no gate evidence',evidence='NFI')
    for g in gates:
        if g.get('required') is False:
            continue
        try:
            late = when(g.get('evaluated_at')) > cutoff
        except ValueError:
            late = True
        if late:
            fail('GATE_POST_CUTOFF',str(g.get('gate_id')))
        status = g.get('status')
        if status == 'PASS':
            continue
        if status == 'WAIVED':
            waiver = g.get('waiver') or {}
            try:
                timing_ok = when(waiver['approved_at']) <= cutoff
            except (ValueError,KeyError):
                timing_ok = False
            if not (g.get('gate_id') in policy.get('waivable_gates',[]) and
                    waiver.get('approved_by') in policy.get('waiver_approvers',[]) and timing_ok):
                fail('GATE_WAIVER_INVALID',str(g.get('gate_id')))
        else:
            fail('GATE_REQUIRED_FAILED',f"{g.get('gate_id')}={status}")
    artifact = case.get('artifact') or {}
    if artifact.get('expected_sha256') != artifact.get('deployed_sha256') or not artifact.get('expected_sha256'):
        fail('ARTIFACT_DIGEST_MISMATCH','deployed artifact digest differs from pinned build')
    snapshot = case.get('snapshot') or {}
    frozen = snapshot.get('frozen_payload')
    if not isinstance(frozen,dict) or snapshot.get('frozen_sha256') != sha(frozen):
        fail('HISTORICAL_SNAPSHOT_INVALID','frozen snapshot digest missing or invalid',evidence='NFI')
    else:
        if snapshot.get('current_payload') != frozen:
            # Later snapshot rewrite attempt must NOT change past immutable H.
            fail('A2_FROZEN_SNAPSHOT_REWRITE','observed snapshot differs from frozen source',where='audit')
        try:
            if when(snapshot.get('frozen_at')) > cutoff:
                fail('HISTORICAL_SNAPSHOT_AFTER_CUTOFF','snapshot created after decision cutoff',evidence='NFI')
        except ValueError:
            fail('HISTORICAL_FREEZE_TIME_INVALID','no valid freeze time',evidence='NFI')
    historical_closed = not historical

    if scope.get('finding_observation_complete') is not True:
        fail('A2_FINDING_SCOPE_NOT_ATTESTED','unable to show absence of triggering Findings',where='audit',evidence='NFI')
    observed_findings = []
    for f in case.get('findings') or []:
        try:
            if when(f['observed_at']) > audit:
                continue
        except (KeyError,ValueError):
            fail('A2_FINDING_TIME_INVALID',str(f.get('finding_id')),where='audit',evidence='NFI')
            continue
        observed_findings.append(f)
        fid = f.get('finding_id','?')
        if f.get('source_release_id') is None:
            ob = {'finding_id':fid,'status':'NFI','code':'A2_UNRESOLVED_SOURCE_ATTRIBUTION'}
        elif f['source_release_id'] != case.get('release_id'):
            # Independently verified unrelated source is out-of-scope.
            # The fixture never uses this branch as an 'absence of finding' proof.
            continue
        else:
            link = f.get('requirement_link') or {}
            if not link.get('requirement_id') or link.get('created_by_finding_id') != fid:
                ob = {'finding_id':fid,'status':'NFI','code':'A2_FINDING_REQUIREMENT_INVALID'}
            else:
                try:
                    if when(link['accepted_at']) < when(f['observed_at']):
                        ob = {'finding_id':fid,'status':'OPEN','code':'A2_REQUIREMENT_TEMPORAL_ORDER'}
                    else:
                        target = f.get('target') or {}
                        due_at = when(target['due_at'])
                        if audit < due_at:
                            ob = {'finding_id':fid,'status':'PENDING','code':'A2_TARGET_NOT_DUE'}
                        elif not target.get('release_id') or target.get('service_id') != scope.get('service_id'):
                            ob = {'finding_id':fid,'status':'NFI','code':'A2_TARGET_IDENTITY_UNKNOWN'}
                        elif target.get('closed') is False or target.get('test_passed') is False:
                            ob = {'finding_id':fid,'status':'OPEN','code':'A2_TARGET_VALIDATION_FAILED'}
                        elif not all(target.get(k) is True for k in ('manifest_complete','coverage_complete','selected_path_valid','closed','test_passed')):
                            ob = {'finding_id':fid,'status':'NFI','code':'A2_TARGET_EVIDENCE_INSUFFICIENT'}
                        elif when(target['verified_at']) > audit:
                            ob = {'finding_id':fid,'status':'NFI','code':'A2_TARGET_VERIFICATION_NOT_YET_VISIBLE'}
                        else:
                            ob = {'finding_id':fid,'status':'CLOSED','code':'A2_TARGET_VALIDATED'}
                except (ValueError,KeyError):
                    ob = {'finding_id':fid,'status':'NFI','code':'A2_TARGET_TIME_INCOMPLETE'}
        obligations.append(ob)
        if ob['status'] != 'CLOSED':
            fail(ob['code'],fid,where='audit',evidence=ob['status'])

    status_candidates = [x['evidence_status'] for x in later]
    if 'OPEN' in status_candidates:
        evidence_status = 'OPEN'
    elif 'NFI' in status_candidates:
        evidence_status = 'NFI'
    elif 'PENDING' in status_candidates:
        evidence_status = 'PENDING'
    elif observed_findings:
        evidence_status = 'NOT_APPLICABLE'
    else:
        evidence_status = 'NOT_APPLICABLE' if scope.get('finding_observation_complete') is True else 'NFI'
    audit_closed = historical_closed and not later
    return {
        'implementation': VERSION,
        'scope': 'NEW_EXECUTABLE_SUBSET_NOT_FROZEN_107_16',
        'collector_scope_provenance': att.get('source_type','UNKNOWN'),
        'release_id':case.get('release_id'),
        'source_cutoff':case['source_cutoff'],
        'audit_time':case['audit_time'],
        'historical_closed_as_of':historical_closed,
        'audit_closed_as_of':audit_closed,
        'machine_decision':'CLOSED' if audit_closed else 'OPEN',
        'evidence_status':evidence_status,
        'historical_failures':historical,
        'audit_failures':later,
        'failure_codes':[x['code'] for x in historical + later],
        'obligations':obligations,
        'input_sha256':sha(case),
    }

def cli():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--allow-open',action='store_true',help='do not signal process failure for OPEN experimental decisions')
    args=p.parse_args()
    try:
        data=json.loads(args.input.read_text(encoding='utf-8'))
        result=verify(data)
        code=0 if result['machine_decision']=='CLOSED' or args.allow_open else 2
    except (OSError,ValueError,KeyError,TypeError) as exc:
        result={'implementation':VERSION,'machine_decision':'OPEN','evidence_status':'NFI',
                'failure_codes':['INPUT_INVALID'],'error':str(exc),'input_file':str(args.input)}
        code=3
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(f"{result['machine_decision']} {result['failure_codes']}")
    return code

if __name__=='__main__':
    sys.exit(cli())
