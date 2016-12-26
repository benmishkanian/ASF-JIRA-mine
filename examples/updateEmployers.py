from examples.argumentParser import getArguments
from examples.logUtil import configureLogger
from jiradb.analysis import getImportantAccounts
from jiradb.database import *


def waitForSearchQuota(jiradb):
    if not jiradb.googleSearchEnabled:
        jiradb.session.commit()
        log.warn('Exhausted search quota. Waiting a day...')
        time.sleep(60 * 60 * 24)
        jiradb.googleSearchEnabled = True


if __name__ == "__main__":
    configureLogger('updateEmployers')

    args = getArguments()
    jiradb = JIRADB(**args)
    projectList = args['projects']
    for project in projectList:
        log.info('Updating employers for contributors to project ' + project)
        accountProjectRows = getImportantAccounts(jiradb.session, project, 0.80)
        for accountProjectRow in accountProjectRows:
            log.debug('Updating employer of ' + accountProjectRow.displayName)
            # update googlecache rows
            time.sleep(300)
            jiradb.getLinkedInEmployer(accountProjectRow.displayName, project)
            waitForSearchQuota(jiradb)
        # flush DB
        jiradb.session.commit()
    log.info('Done updating employers for all contributors for all projects')
