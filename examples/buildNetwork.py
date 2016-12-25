import logging

from examples.logUtil import configureLogger
from jiradb.database import getArguments, JIRADB

if __name__ == "__main__":
    log = logging.getLogger(__name__)
    configureLogger('buildNetwork')

    args = getArguments()
    jiradb = JIRADB(**args)
    projectList = args['projects']
    missedCommitsDict = jiradb.buildCompanyProjectNetwork(projectList, 0.80)
    for key in missedCommitsDict:
        log.info('%s/%s commits were missed in project %s', missedCommitsDict[key][0], missedCommitsDict[key][1], key)
