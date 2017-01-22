import unittest

from examples.logUtil import configureLogger
from jiradb.database import JIRADB
from jiradb.schema import Issue
from tests.arguments import REPO_DOWNLOAD_DIR, GHTORRENT_DB_STRING, GIT_DB_USER, GIT_DB_PASS, DB_STRING, GH_TOKEN


class TestDatabase(unittest.TestCase):
    PROJECT_NAME = 'helix'

    def setUp(self):
        # TODO: requires SSH tunnel to MySQL at ghtorrent.org; this dependency should be mocked and injected
        # TODO: same issue for csvanaly database dependency
        self.jiradb = JIRADB(GHTORRENT_DB_STRING, GIT_DB_USER, GIT_DB_PASS, dbstring=DB_STRING, ghtoken=GH_TOKEN)

    def test_persistIssues(self):
        self.jiradb.populate([self.PROJECT_NAME], REPO_DOWNLOAD_DIR)
        self.assertTrue(self.jiradb.session.query(Issue).count() != 0)

if __name__ == '__main__':
    configureLogger("testDatabase")
    unittest.main()
