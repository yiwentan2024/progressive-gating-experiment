"""Build traceable controlled evidence for an approved scenario.

Mutations are confined to the source-event layer and fully disclosed.
"""
from __future__ import annotations
import argparse, copy, hashlib, json, datetime as dt
from pathlib import Path
from verifier.closure_audit import sha

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT/'scenarios/manifest.json').read_text(encoding='utf-8'))
SCENARIOS = {x['id']:x for x in MANIFEST['scenarios']}
CUTOFF='2026-10-19T10:00:00Z'
AUDIT='2026-10-21T12:00:00Z'

def base_case():
    raw=[];disp=[];cands=[]
    for ix, (sid, tm) in enumerate([('SIG-001','09:10:00'),('SIG-002','09:15:00'),('SIG-003','09:20:00')]):
        payload={'workflow_step':'stage-health','signal_no':ix+1,'check':'pass'}
        raw.append({'signal_id':sid,'source_id':'ci-health','event_time':f'2026-10-19T{tm}Z',
                    'ingest_time':f'2026-10-19T{tm}Z','payload':payload,'payload_sha256':sha(payload)})
        disp.append({'disposition_id':f'DISP-{ix+1:03d}','signal_id':sid,'decision':'RESOLVED',
                     'decision_time':'2026-10-19T09:30:00Z','actor':'qa','authorized':True,'effective':True,
                     'reason':'explicit health PASS'})
        cands.append({'candidate_id':f'C-{ix+1:03d}','signal_id':sid,'disposition_id':f'DISP-{ix+1:03d}','state':'RESOLVED'})
    frozen={'release_id':'LAB-R1','cutoff':CUTOFF,'policy_version':'P-1','artifact_reference':'sha256:pinned'}
    case={
       'schema_version':'E2-case-1', 'release_id':'LAB-R1', 'source_cutoff':CUTOFF, 'audit_time':AUDIT,
       'policy':{'version':'P-1','waivable_gates':['scan'], 'waiver_approvers':['release-manager'], 'exclusion_authorities':['qa-lead']},
       'scope':{'service_id':'closure-demo','approved_sources':['ci-health'],'finding_observation_complete':True,
                'collector_attestation':{'complete':True,'query_rule_hash':'sha256:declared-collection-rule',
                    'collector_version':'e2-lab-v3','source_type':'CONTROLLED_SELF_ATTESTED','inventory_sha256':''}},
       'raw_signals':raw,'dispositions':disp,'candidates':cands,
       'gates':[{'gate_id':'unit','required':True,'status':'PASS','evaluated_at':'2026-10-19T09:40:00Z'},
                {'gate_id':'scan','required':True,'status':'PASS','evaluated_at':'2026-10-19T09:42:00Z'},
                {'gate_id':'staging','required':True,'status':'PASS','evaluated_at':'2026-10-19T09:45:00Z'}],
       'artifact':{'expected_sha256':'sha256:synthetic-artifact-digest','deployed_sha256':'sha256:synthetic-artifact-digest'},
       'snapshot':{'frozen_payload':frozen, 'frozen_sha256':sha(frozen),
                   'current_payload':copy.deepcopy(frozen),'frozen_at':'2026-10-19T09:55:00Z'},
       'findings':[]
    }
    return case

def finding(case=None):
    if case and case.get('time_model') == 'MIXED_LIVE_STAGE_SCRIPTED_A2':
        def fmt(d):return d.astimezone(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
        c=dt.datetime.fromisoformat(case['source_cutoff'].replace('Z','+00:00'))
        a=dt.datetime.fromisoformat(case['audit_time'].replace('Z','+00:00'))
        return {'finding_id':'F-01','observed_at':fmt(c+dt.timedelta(hours=2)),'source_release_id':case['release_id'],
                'requirement_link':{'requirement_id':'REQ-F-01-r1','created_by_finding_id':'F-01','accepted_at':fmt(c+dt.timedelta(hours=3))},
                'target':{'release_id':'LAB-R2','service_id':'closure-demo','due_at':fmt(a-dt.timedelta(hours=12)),
                 'verified_at':fmt(a-dt.timedelta(hours=16)), 'manifest_complete':True,'coverage_complete':True,
                 'selected_path_valid':True,'closed':True,'test_passed':True}}
    return {'finding_id':'F-01','observed_at':'2026-10-19T12:00:00Z','source_release_id':'LAB-R1',
            'requirement_link':{'requirement_id':'REQ-F-01-r1','created_by_finding_id':'F-01','accepted_at':'2026-10-19T13:00:00Z'},
            'target':{'release_id':'LAB-R2','service_id':'closure-demo','due_at':'2026-10-20T12:00:00Z',
                      'verified_at':'2026-10-20T10:00:00Z','manifest_complete':True,
                      'coverage_complete':True,'selected_path_valid':True,'closed':True,'test_passed':True}}

def incorporate_live_stage_observations(c, stage_dir):
    """Map real HTTP stage events, without calling this a complete production inventory.
    The source jsonl files are retained by check_stages.py; A2 successor time is scripted.
    """
    stage_dir=Path(stage_dir)
    def jl(path):return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines() if x.strip()]
    events=jl(stage_dir/'raw/inventory.jsonl')
    decisions=jl(stage_dir/'raw/dispositions.jsonl')
    if not events or not decisions:
        raise RuntimeError('Live stage files are empty')
    by_id={x['signal_id']:x for x in decisions}
    if any(x['signal_id'] not in by_id for x in events):
        raise RuntimeError('stage disposition source incomplete, cannot label green')
    raw=[];disp=[];cands=[]
    for ix,event in enumerate(events):
        sid=event['signal_id'];decision=by_id[sid]
        raw.append({'signal_id':sid,'source_id':'live_HTTP_request','event_time':event['event_time'],
                    'ingest_time':event['event_time'],'payload':event,'payload_sha256':sha(event)})
        disp.append({'disposition_id':f'DISP-{ix+1:03d}','signal_id':sid,
                     'decision':'RESOLVED' if decision['decision']=='PASS' else 'UNRESOLVED',
                     'decision_time':decision['decision_time'],'actor':'CI_health_gate',
                     'authorized':True,'effective':True,'reason':decision.get('reason','CI recorded decision')})
        cands.append({'candidate_id':f'C-{ix+1:03d}','signal_id':sid,
                      'disposition_id':f'DISP-{ix+1:03d}',
                      'state':'RESOLVED' if decision['decision']=='PASS' else 'OPEN'})
    c['raw_signals']=raw;c['dispositions']=disp;c['candidates']=cands
    c['scope']['approved_sources']=['live_HTTP_request']
    c['scope']['collector_attestation']['source_type']='OBSERVED_CI_STAGE_HTTP_SELF_ATTESTED'
    latest=max(dt.datetime.fromisoformat(x['event_time'].replace('Z','+00:00')) for x in events)
    max_disp=max(dt.datetime.fromisoformat(x['decision_time'].replace('Z','+00:00')) for x in decisions)
    frozen_at=max(latest,max_disp)+dt.timedelta(seconds=1)
    cutoff=frozen_at+dt.timedelta(seconds=10)
    audit=cutoff+dt.timedelta(days=2)
    def fmt(d):return d.astimezone(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
    c['source_cutoff']=fmt(cutoff);c['audit_time']=fmt(audit)
    c['snapshot']['frozen_payload'].update({'cutoff':c['source_cutoff'],'stage_source':'live_HTTP_request'})
    c['snapshot']['current_payload']=copy.deepcopy(c['snapshot']['frozen_payload'])
    c['snapshot']['frozen_sha256']=sha(c['snapshot']['frozen_payload'])
    c['snapshot']['frozen_at']=fmt(frozen_at)
    for g in c['gates']:
        g['evaluated_at']=fmt(max_disp)
    c['time_model']='MIXED_LIVE_STAGE_SCRIPTED_A2'
    return c

def build(sid, stage_dir=None):
    if sid not in SCENARIOS:
        raise ValueError(f'Unknown scenario: {sid}')
    if SCENARIOS[sid]['source'].startswith('REAL_'):
        raise RuntimeError(f'{sid}: BLOCKED — requires actual independent project export and source verification; no fake fixture generated')
    c=base_case()
    if stage_dir is not None:c=incorporate_live_stage_observations(c,stage_dir)
    target_sid=c['raw_signals'][1]['signal_id']
    if sid=='N02':
        g=c['gates'][1];g['status']='WAIVED'
        g['waiver']={'approved_by':'release-manager','approved_at':'2026-10-19T09:41:00Z'}
    elif sid=='N03':c['findings']=[finding(c)]
    elif sid=='A101':c['dispositions']=[x for x in c['dispositions'] if x['signal_id']!=target_sid]
    elif sid=='A102':
        d=copy.deepcopy(c['dispositions'][1]);d['disposition_id']='DISP-DUP';c['dispositions'].append(d)
    elif sid=='A103':
        c['dispositions'][1]['decision']='UNRESOLVED';c['candidates'][1]['state']='OPEN'
    elif sid=='A104':
        c['dispositions'][1].update({'decision':'AUTHORIZED_EXCLUDED','actor':'new-intern','authorized':False})
        c['candidates'][1]['state']='EXCLUDED'
    elif sid=='A105':c['raw_signals'][1]['payload']['injected_mutation']='payload_changed_but_digest_kept'
    elif sid=='A201':
        c['raw_signals'][1]['event_time']=c['audit_time']
        c['raw_signals'][1]['ingest_time']=c['audit_time']
    elif sid=='A202':
        f=finding(c);f['requirement_link']['created_by_finding_id']='F-WRONG';c['findings']=[f]
    elif sid=='A203':
        f=finding(c);f['target']['test_passed']=False;c['findings']=[f]
    elif sid=='A204':c['snapshot']['current_payload']['artifact_reference']='sha256:unauthorized-rewrite'
    elif sid=='U01':c['scope']['collector_attestation'].update({'complete':False,'query_rule_hash':None})
    elif sid=='U02':
        f=finding(c);f['source_release_id']=None;c['findings']=[f]
    elif sid=='B01':c['gates'][0]['status']='FAIL'
    elif sid=='B02':c['artifact']['deployed_sha256']='sha256:changed-after-signature'
    c['scope']['collector_attestation']['inventory_sha256']=sha(c['raw_signals'])
    return c

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--scenario',required=True,choices=sorted(SCENARIOS))
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--artifact-original-hash',default=None,help='real SHA256 of artifact before tamper')
    ap.add_argument('--artifact-current-hash',default=None,help='real SHA256 of deployed/verified artifact')
    ap.add_argument('--unit-rc',type=int,default=None,help='real unittest exit code, if available')
    ap.add_argument('--stage-evidence-dir',type=Path,default=None,help='real HTTP stage inventory / dispositions from check_stages.py')
    args=ap.parse_args()
    try:c=build(args.scenario,stage_dir=args.stage_evidence_dir)
    except (RuntimeError,FileNotFoundError,ValueError,KeyError) as exc:
        print(str(exc));return 4
    if args.artifact_original_hash:
        c['artifact']['expected_sha256']='sha256:'+args.artifact_original_hash.removeprefix('sha256:')
        if args.artifact_current_hash:
            c['artifact']['deployed_sha256']='sha256:'+args.artifact_current_hash.removeprefix('sha256:')
        else:c['artifact']['deployed_sha256']=c['artifact']['expected_sha256']
    if args.unit_rc is not None:
        c['gates'][0]['status']='PASS' if args.unit_rc==0 else 'FAIL'
    args.out.mkdir(parents=True,exist_ok=True)
    def write(path,obj):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(obj,sort_keys=True,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    write(args.out/'case.json',c)
    write(args.out/'injection_manifest.json',{'scenario':args.scenario,'version':MANIFEST['version'],
        'injection_description':SCENARIOS[args.scenario]['injection'],
        'source':'CONTROLLED',        'measured_run_results_must_be_populated_by_CI':True,
        'time_model':c.get('time_model','FULLY_SCRIPTED_CONTROLLED_TIMESTAMP')})
    write(args.out/'scenario_design.json',SCENARIOS[args.scenario])
    rawdir=args.out/'source';rawdir.mkdir(exist_ok=True)
    for nm,key in [('raw_inventory','raw_signals'),('dispositions','dispositions'),('candidates','candidates'),('findings','findings')]:
        (rawdir/(nm+'.jsonl')).write_text(''.join(json.dumps(row,sort_keys=True)+'\n' for row in c[key]),encoding='utf-8')
    print(f"created {args.scenario}: {args.out/'case.json'}")
    return 0

if __name__=='__main__':raise SystemExit(main())
