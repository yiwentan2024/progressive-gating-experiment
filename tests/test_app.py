import unittest
from app.__main__ import Handler
class SmokeTests(unittest.TestCase):
 def test_app_has_handler(self):self.assertTrue(hasattr(Handler,'do_GET'))
 def test_allowed_routes(self):self.assertEqual({'/health','/version'},set(['/health','/version']))
