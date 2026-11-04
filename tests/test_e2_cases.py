"""Deterministic engineering self-tests, explicitly NOT independent Oracle."""
import unittest
from scenarios.build_case import build, MANIFEST
from verifier.closure_audit import verify

class DesignSmoke(unittest.TestCase):
    def test_sixteen_controlled_design_cases(self):
        for s in MANIFEST['scenarios']:
            if s['source']!='CONTROLLED':continue
            with self.subTest(scenario_id=s['id']):
                r=verify(build(s['id']))
                self.assertEqual(r['machine_decision'],s['expected_b2'])
                self.assertTrue(set(s['primary_codes']).issubset(set(r['failure_codes'])))
    def test_a204_cannot_rewrite_historical_snapshot(self):
        r=verify(build('A204'))
        self.assertTrue(r['historical_closed_as_of'])
        self.assertFalse(r['audit_closed_as_of'])
    def test_missing_binding_does_not_vanish(self):
        r=verify(build('A202'))
        self.assertEqual(len(r['obligations']),1)
        self.assertEqual(r['obligations'][0]['status'],'NFI')
    def test_evidence_insufficiency_distinct_from_violation(self):
        r=verify(build('U01'))
        self.assertEqual(r['machine_decision'],'OPEN')
        scope=[x for x in r['audit_failures'] if x['code']=='A1_SCOPE_NOT_ATTESTED']
        self.assertEqual(scope[0]['evidence_status'],'NFI')
        self.assertEqual(r['evidence_status'],'NFI')
    def test_real_data_cases_require_source_records(self):
        for sid in ('ZH-R2','ZH-R3','ZH-R4'):
            with self.subTest(sid=sid),self.assertRaises(RuntimeError):build(sid)
