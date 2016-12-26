from examples.logUtil import configureLogger
from jiradb.database import JIRADB
from examples.argumentParser import getArguments

if __name__ == "__main__":
    configureLogger('loadDatabase')

    args = getArguments()
    jiradb = JIRADB(**args)
    jiradb.persistIssues(args['projects'])
