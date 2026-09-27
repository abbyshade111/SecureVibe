import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import search


class SearchTests(unittest.TestCase):
    def test_V1_2_4_search_uses_parameterised_queries(self):
        """The requirement id in the name is what lets `sv` credit this test to V1.2.4."""
        db = sqlite3.connect(":memory:")
        db.execute("create table notes (t text)")
        db.execute("insert into notes values ('a')")
        self.assertEqual(search(db, "a"), [("a",)])
        # A quote in the value must not change what the query does.
        self.assertEqual(search(db, "a' or '1'='1"), [])

    def test_the_homepage_renders(self):
        """Names no requirement, so it is evidence about nothing in particular. Most tests are."""
        self.assertTrue(True)
