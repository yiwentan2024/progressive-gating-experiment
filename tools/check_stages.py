"""Health check and independently preserve observed events vs gate dispositions."""
import argparse,datetime,json,time,urllib.request,urllib.error
from pathlib import Path

def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')
def write_json(path,obj):
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
 p.write_text(json.dumps(obj,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8')
def write_jsonl(path,items):
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
 p.write_text(''.join(json.dumps(x,sort_keys=True)+'\n' for x in items),encoding='utf-8')

def collect(endpoints,out):
    # Each event is created from an actual HTTP request to the running stage.
    events=[];dispositions=[];checks=[]
    for name,port in endpoints:
        url=f'http://127.0.0.1:{port}/health';response_code=None;content={}
        for attempt in range(30):
            try:
                with urllib.request.urlopen(url,timeout=2) as res:
                    response_code=res.status;content=json.loads(res.read());break
            except urllib.error.HTTPError as exc:
                response_code=exc.code; content=json.loads(exc.read());break
            except (ConnectionError,TimeoutError,urllib.error.URLError):
                time.sleep(.25)
        now=utc();sid=f'health:{name}'
        event={'signal_id':sid,'event_type':'health-check','source_url':url,'http_status':response_code,
               'event_time':now,'stage':name,'source':'live_HTTP_request'}
        events.append(event)
        if response_code is None: decision='FAIL';reason='unreachable'
        elif response_code==200:decision='PASS';reason='HTTP 200'
        else:decision='FAIL';reason=f'HTTP {response_code}'
        dispositions.append({'signal_id':sid,'decision':decision,'decision_time':now,'actor':'CI_health_gate','reason':reason})
        checks.append({'stage':name,'http_status':response_code,'gate_result':decision,'observed_time':now,'response':content})
    write_jsonl(out/'raw'/'inventory.jsonl',events)
    write_jsonl(out/'raw'/'dispositions.jsonl',dispositions)
    write_json(out/'raw'/'stage_check.json',checks)
    return all(x['gate_result']=='PASS' for x in checks)

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True)
 parser.add_argument('--dev-port',type=int,default=18081);parser.add_argument('--qa-port',type=int,default=18082)
 parser.add_argument('--staging-port',type=int,default=18083)
 args=parser.parse_args()
 ok=collect([('dev',args.dev_port),('qa',args.qa_port),('staging',args.staging_port)],args.out)
 print('B0 stage gates:', 'PASS' if ok else 'FAIL');return 0 if ok else 1
if __name__=='__main__':raise SystemExit(main())
