import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import search


class SearchTests(unittest.TestCase):
    def test_V1_2_4_search_uses_parameterised_queries(self):
        """This one passes, and its name is what credits it to V1.2.4."""
        db = sqlite3.connect(":memory:")
        db.execute("create table notes (t text)")
        db.execute("insert into notes values ('a')")
        self.assertEqual(search(db, "a"), [("a",)])
        self.assertEqual(search(db, "a' or '1'='1"), [])

    def test_the_totals_add_up(self):
        """This one fails on purpose. Before `sv` read the runner's report, this single
        failure cost the credit of every other test in the suite."""
        self.assertEqual(2 + 2, 5)
