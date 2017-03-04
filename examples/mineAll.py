from examples.argumentParser import getArguments
from examples.logUtil import configureLogger
from jiradb.database import JIRADB

if __name__ == "__main__":
    configureLogger('mineAll')

    args = getArguments()
    jiradb = JIRADB(**args)
    if args['projects'][0] == 'all':
        args['projects'] = [''.join(resultTuple) for resultTuple in
                         jiradb.ghtorrentsession.query(jiradb.ghtorrentprojects.c.name).join(
                             jiradb.ghtorrentusers).filter('apache' == jiradb.ghtorrentusers.c.login).all()]
    jiradb.populate(args['projects'])
