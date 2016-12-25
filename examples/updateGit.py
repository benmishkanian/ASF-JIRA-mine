from examples.logUtil import configureLogger
from jiradb.database import *

if __name__ == "__main__":
    configureLogger('updateGit')

    args = getArguments()
    jiradb = JIRADB(**args)
    projectList = args['projects']
    for project in projectList:
        jiradb.getGitDB(project).update()
