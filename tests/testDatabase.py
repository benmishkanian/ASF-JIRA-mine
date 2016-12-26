import unittest

from jiradb.database import JIRADB
from jiradb.schema import Issue


class TestDatabase(unittest.TestCase):
    PROJECT_NAME = 'helix'

    def setUp(self):
        # TODO: requires SSH tunnel to MySQL at ghtorrent.org; this dependency should be mocked and injected
        # TODO: same issue for csvanaly database dependency
        self.jiradb = JIRADB("mysql+mysqlconnector://ght:@127.0.0.1/ghtorrent", None, None)

    def test_persistIssues(self):
        self.jiradb.persistIssues([self.PROJECT_NAME])
        self.assertTrue(self.jiradb.session.query(Issue).count() != 0)
