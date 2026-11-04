"""Save faithful multi-layer outcomes. Does not infer tool 'missed' from N/A.

Summary schema (batch_protocol revision): describes the executed batch protocol —
preregistered oracle, replicate index, protocol reference. Decision fields are
untouched; timestamps flag remains factual by construction.
"""
import argparse, datetime, hashlib, json
from pathlib import Path

def read_rc(path):
    try:return int(Path(path).read_text().strip())
    except (ValueError,FileNotFoundError):return None

def protocol_state(repo_root):
    p = Path(repo_root)
    oracle = (p/'protocols'/'oracle_locked.csv').is_file()
    protocol = (p/'protocols'/'batch_protocol.md').is_file()
    return oracle and protocol

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--scenario',required=True)
    ap.add_argument('--variant',required=True,choices=['B0','B1','B2'])
    ap.add_argument('--replicate',type=int,default=1)
    ap.add_argument('--github-run-id',default='LOCAL_NOT_GITHUB')
    ap.add_argument('--repo-root',type=Path,default=Path('.'))
    args=ap.parse_args()
    d=args.out;d.mkdir(parents=True,exist_ok=True)
    def j(path):
        try:return json.loads((d/path).read_text())
        except (OSError,json.JSONDecodeError):return None
    unit=read_rc(d/'raw/unit_exit.txt');stage=read_rc(d/'raw/stage_exit.txt')
    checksum=read_rc(d/'raw/digest_pinned_exit.txt')
    att=read_rc(d/'raw/attestation_verify_exit.txt') if args.variant!='B0' else None
    base_checks={'unittest':unit,'three_stage_checks':stage,'pinned_digest':checksum}
    checks={**base_checks,'attestation':att if args.variant!='B0' else 'NOT_ENABLED_B0'}
    ran=all(x is not None for x in base_checks.values()) and (args.variant=='B0' or att is not None)
    observed='INCOMPLETE' if not ran else ('PASS' if all(x==0 for x in base_checks.values()) and (args.variant=='B0' or att==0) else 'FAIL')
    case=j('case/case.json')
    b2=j('results/b2_decision.json') if args.variant=='B2' else None
    report={
       'scenario_id':args.scenario, 'variant':args.variant,
       'replicate_index':args.replicate,
       'source_type':'CONTROLLED_EVALUATION_WITH_REAL_CI_STAGE_CHECKS',
       'github_run_id':args.github_run_id,
       'completed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
       'observed_baseline_gate_result':observed,
       'actual_exit_codes':checks,
       'b2_machine_decision':b2['machine_decision'] if b2 else 'NOT_EXECUTED',
       'b2_failure_codes':b2.get('failure_codes',[]) if b2 else [],
       'b2_evidence_status':b2.get('evidence_status') if b2 else None,
       'real_live_health_events_in_case':case.get('time_model')=='MIXED_LIVE_STAGE_SCRIPTED_A2' if case else False,
       'scripted_A2_timestamps_used':True,
       'oracle_preregistered_before_runs':protocol_state(args.repo_root),
       'batch_protocol':'protocols/batch_protocol.md',
    }
    (d/'results').mkdir(exist_ok=True)
    (d/'results/observed_summary.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    manifest=[]
    for path in sorted(d.rglob('*')):
        if path.is_file() and path.name not in ('sha256sums.txt','manifest.json'):
            manifest.append({'path':str(path.relative_to(d)), 'bytes':path.stat().st_size,
                 'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    (d/'manifest.json').write_text(json.dumps({'files':manifest,'summary':report},ensure_ascii=False,indent=2)+'\n')
    manifest_path=d/'manifest.json'
    manifest_hash=hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    (d/'sha256sums.txt').write_text(''.join(f"{x['sha256']}  {x['path']}\n" for x in manifest) + f'{manifest_hash}  manifest.json\n')
    print(json.dumps(report,ensure_ascii=False,indent=2))
    return 0
if __name__=='__main__':raise SystemExit(main())
