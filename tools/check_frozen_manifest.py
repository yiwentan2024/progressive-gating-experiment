"""Verify SHA256 and size for every S9-listed frozen reference file, without changing any file."""
import csv,hashlib,json,sys
from pathlib import Path
CORE=Path(__file__).resolve().parents[1]/'frozen_reference'/'EvidenceClosure'
def check():
    issues=[]
    rows=list(csv.DictReader((CORE/'S9_package_manifest.csv').open(encoding='utf-8-sig',newline='')))
    for row in rows:
        p=CORE/row['relative_path']
        if not p.is_file():issues.append([row['relative_path'],'MISSING']);continue
        data=p.read_bytes()
        if len(data)!=int(row['bytes']):issues.append([row['relative_path'],'SIZE'])
        if hashlib.sha256(data).hexdigest()!=row['sha256']:issues.append([row['relative_path'],'SHA256'])
    return {'source':'S9_package_manifest.csv','checked_files':len(rows),'mismatches':issues,'passed':not issues}
if __name__=='__main__':
    r=check();print(json.dumps(r,ensure_ascii=False,indent=2));sys.exit(0 if r['passed'] else 1)
