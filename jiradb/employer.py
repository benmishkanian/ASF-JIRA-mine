from .database import Contributor, AccountProject, ContributorAccount, log
from sqlalchemy import func, desc


def getLikelyLinkedInEmployer(jiradb, contributorId):
    """
    Gets a list of possible employers for the contributor based off of the employer of each of their accounts.
    :param jiradb: JIRADB object
    :param contributorId:
    :return: a list of possible employer names for this contributor
    """
    accountProjectRows = jiradb.session.query(Contributor, AccountProject.LinkedInEmployer,
                                              AccountProject.project).join(ContributorAccount).join(
        AccountProject).filter(Contributor.id == contributorId)
    possibleEmployers = []
    projects = []
    for accountProjectRow in accountProjectRows:
        if accountProjectRow.LinkedInEmployer not in possibleEmployers:
            possibleEmployers.append(accountProjectRow.LinkedInEmployer)
        if accountProjectRow.project not in projects:
            projects.append(accountProjectRow.project)
    if len(projects) == 1:
        mainProject = projects[0]
    elif len(projects) > 1:
        # The main project is the one this person did the most commits to
        countSubq = jiradb.session.query(AccountProject.project, func.sum(
            AccountProject.BHCommitCount + AccountProject.NonBHCommitCount).label('commitcount')).join(
            ContributorAccount).join(Contributor).filter(Contributor.id == contributorId).group_by(
            AccountProject.project).subquery()
        mainRow = jiradb.session.query(countSubq).order_by(desc('commitcount')).first()
        assert mainRow is not None, 'Found 0 projects for contributor ' + contributorId
        mainProject = mainRow.project
    else:
        raise RuntimeError('contributor {} has no projects'.format(contributorId))
    log.info('contributor # %s contributed to project(s): %s', contributorId, projects)
    companyRankings = jiradb.getProjectCompaniesByCommits(mainProject)
    for companyRanking in companyRankings:
        if companyRanking.LinkedInEmployer in possibleEmployers:
            return companyRanking.LinkedInEmployer
    log.warning('%s has uncommon employer; taking first of: %s', contributorId, possibleEmployers)
    return possibleEmployers[0]
