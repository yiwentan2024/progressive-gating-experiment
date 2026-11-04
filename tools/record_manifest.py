"""Create SHA-256 manifest excluding itself for immutable evidence archiving."""
import argparse,hashlib,json,datetime
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('run_dir',type=Path);args=p.parse_args()
base=args.run_dir;entries={str(p.relative_to(base)):hashlib.sha256(p.read_bytes()).hexdigest()
 for p in sorted(base.rglob('*')) if p.is_file() and p.name!='manifest.json'}
(base/'manifest.json').write_text(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'files':entries},indent=2)+'\n')
print('wrote',base/'manifest.json',len(entries),'files')
