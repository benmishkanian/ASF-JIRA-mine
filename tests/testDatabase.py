import unittest

from jiradb.database import JIRADB
from jiradb.schema import Issue


class TestDatabase(unittest.TestCase):
    PROJECT_NAME = 'helix'

    def setUp(self):
        self.jiradb = JIRADB()

    def test_persistIssues(self):
        self.jiradb.persistIssues([self.PROJECT_NAME])
        self.assertTrue(self.jiradb.session.query(Issue).count() != 0)
