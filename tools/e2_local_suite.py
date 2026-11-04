"""Run 16 controlled case builder + closure verifier for smoke/regression.

This is NOT 16 independent Oracle decisions and cannot substitute actual
B0/B1 runs on GitHub. Real-data cases are never generated locally.
"""
import json,tempfile,subprocess,sys
from pathlib import Path
from scenarios.build_case import build, MANIFEST
from verifier.closure_audit import verify

def main():
    root=Path(__file__).resolve().parents[1]
    rows=[]
    for scene in MANIFEST['scenarios']:
        sid=scene['id']
        if scene['source']!='CONTROLLED':
            rows.append({'scenario_id':sid,'execution':'BLOCKED_SOURCE_REQUIRED','pass':None})
            continue
        case=build(sid)
        out=verify(case)
        passed=out['machine_decision']==scene['expected_b2'] and set(scene['primary_codes']).issubset(out['failure_codes'])
        rows.append({'scenario_id':sid,'execution':'LOCAL_ONLY','pass':passed,
                     'design_hypothesis':scene['expected_b2'],'observed_machine_decision':out['machine_decision'],
                     'codes':out['failure_codes'],'historical_closed':out['historical_closed_as_of'],
                     'audit_closed':out['audit_closed_as_of']})
    p=root/'runs'/'local_e2_design_smoke.json';p.parent.mkdir(exist_ok=True)
    p.write_text(json.dumps({'warning':'local smoke output only','rows':rows},indent=2)+'\n')
    print('\n'.join(f"{r['scenario_id']} {r['execution']} {r.get('pass')}" for r in rows))
    print('Written:',p)
    return 0 if all(r['pass'] for r in rows if r['pass'] is not None) else 2
if __name__=='__main__':raise SystemExit(main())
