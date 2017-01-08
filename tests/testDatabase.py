import unittest

from jiradb.database import JIRADB
from jiradb.schema import Issue
from examples.logUtil import configureLogger
import os
from arguments import GHTORRENT_DB_STRING, GIT_DB_USER, GIT_DB_PASS, DB_STRING, GH_TOKEN


class TestDatabase(unittest.TestCase):
    PROJECT_NAME = 'helix'

    def setUp(self):
        # TODO: requires SSH tunnel to MySQL at ghtorrent.org; this dependency should be mocked and injected
        # TODO: same issue for csvanaly database dependency
        self.jiradb = JIRADB(GHTORRENT_DB_STRING, GIT_DB_USER, GIT_DB_PASS, dbstring=DB_STRING, ghtoken=GH_TOKEN)

    def test_persistIssues(self):
        self.jiradb.persistIssues([self.PROJECT_NAME], 'C:\\Python27\\python.exe', os.getenv('APPDATA') + '\\Python\\Python27\\site-packages\\cvsanaly2-2.1.0-py2.7.egg\\EGG-INFO\\scripts\\cvsanaly2', 'I:/temp/ASF_projects')
        self.assertTrue(self.jiradb.session.query(Issue).count() != 0)

if __name__ == '__main__':
    configureLogger("testDatabase")
    unittest.main()
