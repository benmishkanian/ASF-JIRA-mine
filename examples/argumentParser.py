import getpass

from jiradb.database import EMAIL_GH_LOGIN_TABLE_NAME


def getArguments():
    # Parse script arguments. Returns a dict.
    import argparse
    parser = argparse.ArgumentParser(description='Mine ASF JIRA data.')
    parser.add_argument('-c', '--cached', dest='cached', action='store_true', help='Mines data from the caching DB')
    parser.add_argument('--dbstring', action='store', default='sqlite:///sqlite.db',
                        help='The output database connection string')
    parser.add_argument('--gkeyfile', action='store',
                        help='File that contains a Google Custom Search API key enciphered by simple-crypt. If not specified, a cache of search results will be used instead.')
    parser.add_argument('--ghtoken', help='A github authentication token')
    parser.add_argument('--emailGHLoginDBName', action='store',
                        help='DB connection string for database containing a table named ' + EMAIL_GH_LOGIN_TABLE_NAME + ' that relates email addresses to Github usernames using column names "email" and "login". It improves performance by reducing usage of the Github API.')
    parser.add_argument('--ghtorrentdbstring', action='store',
                        help='The connection string for a ghtorrent database', required=True)
    parser.add_argument('--ghscanlimit', type=int, default=10, action='store',
                        help='Maximum number of results to analyze per Github search')
    parser.add_argument('--gitdbuser', default=getpass.getuser(),
                        help='Username for MySQL server containing cvsanaly databases for all projects', )
    parser.add_argument('--gitdbpass', help='Password for MySQL server containing cvsanaly databases for all projects')
    parser.add_argument('--gitdbhostname', default='localhost',
                        help='Hostname for MySQL server containing cvsanaly databases for all projects')
    parser.add_argument('--startdate', help='Persist only data points occurring after this date')
    parser.add_argument('--enddate', help='Persist only data points occurring before this date')
    parser.add_argument('projects', nargs='+', help='Name of an ASF project (case sensitive)')
    return vars(parser.parse_args())
