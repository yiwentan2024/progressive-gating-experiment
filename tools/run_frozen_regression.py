"""Run original 107 tests/S20 or optional full authoritative mutation run.
All report outputs are stored outside the frozen_reference directory. Never rewrite frozen files.
"""
import argparse,datetime,hashlib,json,platform,subprocess,sys,time
from pathlib import Path
from tools.check_frozen_manifest import CORE,check
TEST_MODULES=['S3_test_analyze_evidence.py','S3_adversarial_review_tests.py',
              'S3_v18_semantic_tests.py','S3_terminal_review_counterexamples.py']
def run(label,cmd,dest,timeout):
    start=time.monotonic()
    try:
        p=subprocess.run(cmd,cwd=CORE,text=True,capture_output=True,timeout=timeout)
        code=p.returncode;out=p.stdout;err=p.stderr;timed_out=False
    except subprocess.TimeoutExpired as exc:
        code=124;out=(exc.stdout or b'').decode('utf-8','replace') if isinstance(exc.stdout,bytes) else (exc.stdout or '')
        err=(exc.stderr or b'').decode('utf-8','replace') if isinstance(exc.stderr,bytes) else (exc.stderr or '')
        timed_out=True
    (dest/(label+'.stdout.log')).write_text(out,encoding='utf-8')
    (dest/(label+'.stderr.log')).write_text(err,encoding='utf-8')
    return {'name':label,'command':cmd,'exit_code':code,'timeout':timed_out,'elapsed_seconds':round(time.monotonic()-start,3),
            'stdout_sha256':hashlib.sha256(out.encode()).hexdigest(),'stderr_sha256':hashlib.sha256(err.encode()).hexdigest()}
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--mode',choices=['smoke','full'],default='smoke',help='smoke=107+S20; full=authoritative 107+mutations')
    ap.add_argument('--out',default='runs/frozen_reference_recheck')
    ap.add_argument('--timeout',type=int,default=900)
    args=ap.parse_args()
    dst=Path(args.out).resolve()
    if dst==CORE or CORE in dst.parents:ap.error('--out must be OUTSIDE frozen_reference')
    dst.mkdir(parents=True,exist_ok=True)
    before=check()
    report={'mode':args.mode,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'python':platform.python_version(),'platform':platform.platform(), 'frozen_precheck':before,'runs':[]}
    if before['passed']:
        if args.mode=='smoke':
            report['runs'].append(run('107_tests',[sys.executable,'-m','unittest','-v',*TEST_MODULES],dst,180))
            report['runs'].append(run('S20',[sys.executable,'S20_check_consistency.py','--output',str(dst/'S20_runtime.json')],dst,120))
            if (dst/'S20_runtime.json').is_file():
                report['S20_runtime_sha256']=hashlib.sha256((dst/'S20_runtime.json').read_bytes()).hexdigest()
        else:
            report['runs'].append(run('authoritative_full',[sys.executable,'EvidenceClosure_authoritative_verifier.py','--output',str(dst/'authoritative_report.json')],dst,args.timeout))
            if (dst/'authoritative_report.json').is_file():
                try:
                    r=json.loads((dst/'authoritative_report.json').read_text());report['authoritative_passed']=r.get('passed')
                except (json.JSONDecodeError,OSError): report['authoritative_passed']=False
    report['frozen_postcheck']=check()
    report['passed']=bool(before['passed'] and report['frozen_postcheck']['passed'] and all(x['exit_code']==0 and not x['timeout'] for x in report['runs']) and (args.mode!='full' or report.get('authoritative_passed') is True))
    (dst/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'mode':report['mode'],'passed':report['passed'],'out':str(dst),'exit_codes':[(x['name'],x['exit_code']) for x in report['runs']],'s9_mismatches':len(report['frozen_postcheck']['mismatches'])},ensure_ascii=False,indent=2))
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
