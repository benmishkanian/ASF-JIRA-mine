import unittest

from jiradb import *
from args import *


class TestJIRADB(unittest.TestCase):
    PROJECT_NAME = 'helix'

    def setUp(self):
        self.jiradb = JIRADB(dbstring=dbstring, ghtorrentdbstring=ghtorrentdbstring,
                             ghusersextendeddbstring=ghusersextendeddbstring, gitdbuser=gitdbuser, gitdbpass=gitdbpass,
                             ghtoken=ghtoken)

    def test_persistIssues(self):
        self.jiradb.persistIssues([self.PROJECT_NAME])
        self.assertTrue(self.jiradb.session.query(Issue).count() != 0)


if __name__ == '__main__':
    log.setLevel(logging.INFO)
    # Add console log handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(message)s'))
    log.addHandler(ch)
    # Add file log handler
    fh = logging.FileHandler('jiradbtest.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('[%(levelname)s @ %(asctime)s]: %(message)s'))
    log.addHandler(fh)
    unittest.main()
