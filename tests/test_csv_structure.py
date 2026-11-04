"""Structural CSV checks for every CSV this repository ships at protocol level.

frozen_reference/ is byte-identical upstream data (S9-locked) and is excluded:
several frozen CSVs (e.g. S7, S21) are internally ragged by upstream design and
must not be reformatted.
"""
import csv
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_CSVS = sorted((ROOT / 'protocols').glob('*.csv'))


class TestProtocolCsvStructure(unittest.TestCase):

    def test_protocol_csvs_exist(self):
        self.assertGreaterEqual(len(PROTOCOL_CSVS), 2,
                                'expected oracle + run plan under protocols/')

    def test_every_row_has_header_column_count(self):
        for path in PROTOCOL_CSVS:
            with self.subTest(csv=path.name):
                rows = [r for r in csv.reader(path.read_text(encoding='utf-8-sig').splitlines())
                        if r and not ''.join(r).startswith('#')]
                widths = {len(r) for r in rows}
                self.assertEqual(
                    len(widths), 1,
                    f'{path.name}: ragged rows (column widths {sorted(widths)}); '
                    'fields containing commas must be quoted')

    def test_run_plan_is_144_preregistered_rows(self):
        plan = list(csv.DictReader(
            (ROOT / 'protocols' / 'E2_Controlled_Run_Plan.csv').read_text(encoding='utf-8-sig').splitlines()))
        self.assertEqual(len(plan), 144)
        self.assertEqual({r['status'] for r in plan}, {'NOT_RUN'})
        self.assertTrue(all(r['oracle_ref'] for r in plan))


if __name__ == '__main__':
    unittest.main()
