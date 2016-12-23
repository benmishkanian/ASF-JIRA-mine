from jiradb import *

if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    # Add console log handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(message)s'))
    log.addHandler(ch)
    # Add file log handler
    fh = logging.FileHandler('updateOrganizations.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('[%(levelname)s @ %(asctime)s]: %(message)s'))
    log.addHandler(fh)
    # Add error file log handler
    efh = logging.FileHandler('updateOrganizationsErrors.log')
    efh.setLevel(logging.ERROR)
    efh.setFormatter(logging.Formatter('[%(levelname)s @ %(asctime)s]: %(message)s'))
    log.addHandler(efh)

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