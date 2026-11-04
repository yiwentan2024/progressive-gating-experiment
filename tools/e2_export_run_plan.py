"""Export the frozen controlled-run plan (16 scenarios x 3 variants x 3 replicates).

Usage:
  python -m tools.e2_export_run_plan                # preview to stdout
  python -m tools.e2_export_run_plan --out PATH     # write 144-row CSV

The plan is preregistered as NOT_RUN; this tool only reproduces
protocols/E2_Controlled_Run_Plan.csv (committed with the initial commit).
It never writes to protocols/ unless explicitly told to with --out.
"""
import argparse
import csv
import io
import sys
from pathlib import Path

from scenarios.build_case import MANIFEST

HEADER = ['scenario_id', 'variant', 'replicate_index', 'planned_source',
          'oracle_ref', 'github_run_id', 'observed_baseline', 'observed_B2',
          'status']


def plan_rows():
    for item in MANIFEST['scenarios']:
        if item['source'] != 'CONTROLLED':
            continue
        for variant in ('B0', 'B1', 'B2'):
            for rep in (1, 2, 3):
                yield [item['id'], variant, str(rep), 'CONTROLLED',
                       item['expected_b2'], '', '', '', 'NOT_RUN']


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', default='', help='output CSV path (default: preview to stdout)')
    args = ap.parse_args()
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\n')
    w.writerow(HEADER)
    n = 0
    for row in plan_rows():
        w.writerow(row)
        n += 1
    if args.out:
        Path(args.out).write_text(buf.getvalue(), encoding='utf-8-sig')
        print(f'{args.out}: {n} run rows')
    else:
        sys.stdout.write(buf.getvalue())
        print(f'# {n} run rows (preview; use --out PATH to write)', file=sys.stderr)


if __name__ == '__main__':
    main()
