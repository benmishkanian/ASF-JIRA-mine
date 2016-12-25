from examples.logUtil import configureLogger
from jiradb.database import *

if __name__ == "__main__":
    configureLogger('buildContributorCompany')

    args = getArguments()
    jiradb = JIRADB(**args)
    projectList = args['projects']
    jiradb.buildContributorCompanyTable(projectList, 0.80)
    log.info('Done updating contributorcompanies for all contributors for all projects')
