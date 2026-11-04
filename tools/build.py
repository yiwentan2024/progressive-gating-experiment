"""Deterministically zip the tiny service as a Python .pyz artifact."""
import hashlib, json, zipfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
out=root/'dist/release_app.pyz';out.parent.mkdir(exist_ok=True)
main=(root/'app/__main__.py').read_bytes()
with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    info=zipfile.ZipInfo('__main__.py',date_time=(2020,1,1,0,0,0))
    info.compress_type=zipfile.ZIP_DEFLATED
    info.external_attr=(0o644 << 16)
    z.writestr(info,main)
digest=hashlib.sha256(out.read_bytes()).hexdigest()
print(json.dumps({'artifact':str(out),'sha256':digest,'bytes':out.stat().st_size},indent=2))
