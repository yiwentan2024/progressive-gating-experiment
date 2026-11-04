"""Six A2 time-ordering boundary tests (new suite, counted separately).

Boundary rules (upstream continuation task list):
  B1 positive proof of no triggered Finding -> NOT_APPLICABLE; absence of records is not proof
  B2 Finding without valid Requirement binding -> OPEN, never silently cleared
  B3 unattributable Finding source -> NFI, never silently dropped from scope
  B4 target release not yet due -> PENDING (not a violation, not CLOSED)
  B5 due target without decisive validation material -> NFI blocks closure
  B6 verified target updates the audit; frozen history never changes

B1's first half doubles as the required normal path. Inputs are constructed from
frozen controlled cases; no network or GitHub execution is involved.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scenarios.build_case import build
from verifier.closure_audit import verify


class SixBoundaries(unittest.TestCase):

    def test_b1_absence_of_finding_requires_positive_proof(self):
        r = verify(build('N01'))
        self.assertEqual(r['machine_decision'], 'CLOSED')
        self.assertEqual(r['evidence_status'], 'NOT_APPLICABLE')
        c = build('N01')
        c['scope']['finding_observation_complete'] = False
        r = verify(c)
        self.assertEqual(r['machine_decision'], 'OPEN')
        self.assertEqual(r['evidence_status'], 'NFI')
        self.assertIn('A2_FINDING_SCOPE_NOT_ATTESTED', r['failure_codes'])

    def test_b2_finding_without_requirement_binding_stays_open(self):
        c = build('N03')
        c['findings'][0]['requirement_link'] = {}
        r = verify(c)
        self.assertEqual(r['machine_decision'], 'OPEN')
        self.assertIn('A2_FINDING_REQUIREMENT_INVALID', r['failure_codes'])

    def test_b3_unattributable_source_is_nfi_not_silently_dropped(self):
        r = verify(build('U02'))
        self.assertEqual(r['machine_decision'], 'OPEN')
        self.assertEqual(r['evidence_status'], 'NFI')
        self.assertIn('A2_UNRESOLVED_SOURCE_ATTRIBUTION', r['failure_codes'])

    def test_b4_target_not_yet_due_is_pending(self):
        c = build('N03')
        c['findings'][0]['target']['due_at'] = '2027-01-01T00:00:00Z'
        r = verify(c)
        self.assertEqual(r['machine_decision'], 'OPEN')
        self.assertEqual(r['evidence_status'], 'PENDING')
        self.assertIn('A2_TARGET_NOT_DUE', r['failure_codes'])

    def test_b5_due_target_without_decisive_evidence_is_nfi(self):
        c = build('N03')
        c['findings'][0]['target']['manifest_complete'] = False
        r = verify(c)
        self.assertEqual(r['machine_decision'], 'OPEN')
        self.assertEqual(r['evidence_status'], 'NFI')
        self.assertIn('A2_TARGET_EVIDENCE_INSUFFICIENT', r['failure_codes'])

    def test_b6_verified_target_updates_audit_but_not_history(self):
        r = verify(build('N03'))
        self.assertTrue(r['historical_closed_as_of'])
        self.assertTrue(r['audit_closed_as_of'])
        r = verify(build('A204'))
        self.assertTrue(r['historical_closed_as_of'])
        self.assertFalse(r['audit_closed_as_of'])
        self.assertIn('A2_FROZEN_SNAPSHOT_REWRITE', r['failure_codes'])


if __name__ == '__main__':
    unittest.main()
