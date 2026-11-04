"""Reject real-data case IDs without source-verified records."""
import sys
from scenarios.build_case import SCENARIOS
sid=sys.argv[1] if len(sys.argv)>1 else ''
if sid not in SCENARIOS:
    raise SystemExit('UNKNOWN_SCENARIO:'+sid)
if SCENARIOS[sid]['source']!='CONTROLLED':
    raise SystemExit(f'BLOCKED_REAL_DATA:{sid}: project source export + independent facts not provided')
print('CONTROLLED_CASE_ENABLED:', sid)
