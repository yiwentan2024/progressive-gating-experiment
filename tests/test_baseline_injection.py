"""Real unittest gate executed by B0/B1/B2; controlled B01 makes it fail."""
import os
import unittest

class RealPipelineFailure(unittest.TestCase):
    def test_required_check(self):
        self.assertNotEqual(os.environ.get('E2_SCENARIO_ID'), 'B01',
                            'B01 injected actual required unittest failure')
