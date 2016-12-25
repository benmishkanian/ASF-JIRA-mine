from examples.logUtil import configureLogger
from jiradb.database import *

if __name__ == "__main__":
    configureLogger('updateOrganizations')
    log = logging.getLogger(__name__)

    args = getArguments()
    jiradb = JIRADB(**args)
    projectList = args['projects']
    for project in projectList:
        # get contributors for this project
        projectContributors = jiradb.session.query(Contributor).join(ContributorAccount).join(AccountProject).filter(AccountProject.project == project)
        for projectContributor in projectContributors:
            # update organizations for this github login
            jiradb.persistOrganizations(projectContributor)
    jiradb.session.commit()
    log.info('Done updating')