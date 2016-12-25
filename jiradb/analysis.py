from sqlalchemy import func, asc

import logging
from jiradb.schema import EmailProjectCommitCount, Contributor, ContributorAccount

log = logging.getLogger(__name__)


def getTopContributorCount(jiradb, projects, requiredProjectCommitCoverage):
    """
    Get the minimum number of contributors required to provide commit coverage over all projects.

    :param jiradb: a JIRADB object
    :param projects: the projects to cover
    :param requiredProjectCommitCoverage: fraction of commits in each project that must be covered
    :return: the number of contributors required
    """
    requiredContributorCount = 0
    for project in projects:
        requiredContributorCount += len(getTopContributors(jiradb.session, project, requiredProjectCommitCoverage))
    return requiredContributorCount


def getTopContributors(session, project: str, requiredCommitCoverage: float):
    """
    Make a list of the top contributors for this project in terms of commit count. We keep appending contributors
    until at least requiredCommitCoverage percent of the commits are covered by a contributor in the list.

    :param session: JIRADB session
    :param project: name of the project
    :param requiredCommitCoverage: percentage of commits in project that must have been authored by a contributor in the list
    :return: a minimal list of the top contributors
    """
    assert 0 <= requiredCommitCoverage <= 1
    requiredCommitCount = requiredCommitCoverage * session.query(func.sum(EmailProjectCommitCount.commitcount)).filter(EmailProjectCommitCount.project == project).first()[0]
    coveredCommitCount = 0
    topContributors = []
    # Get the list of contributors, ordered by commit count, ascending
    subq = session.query(Contributor.id, ContributorAccount.email, EmailProjectCommitCount.commitcount).join(
        ContributorAccount).join(EmailProjectCommitCount,
                                 EmailProjectCommitCount.email == ContributorAccount.email).filter(EmailProjectCommitCount.project == project).distinct().subquery()
    subq2 = session.query(subq.c.id, func.sum(subq.c.commitcount).label('commitcount')).group_by(subq.c.id).subquery()
    contributorCommits = session.query(subq2).order_by(asc('commitcount')).all()
    # Append to topContributors until we have sufficient commit coverage
    while coveredCommitCount < requiredCommitCount:
        contributorCommitTuple = contributorCommits.pop()
        topContributors.append(contributorCommitTuple[0])
        coveredCommitCount = coveredCommitCount + contributorCommitTuple[1]
    log.info('%d contributors authored at least %f fraction of the commits in %s', len(topContributors), requiredCommitCoverage, project)
    return topContributors


def getImportantAccounts(session, project, requiredCommitCoverage):
    """
    Returns the display names of accounts of top contributors for the given project.

    :param session: JIRADB session
    :param project: name of the project
    :param requiredCommitCoverage: percentage of commit
    :return:
    """
    topContributorIds = getTopContributors(session, project, requiredCommitCoverage)
    # get accounts of these contributors
    return session.query(ContributorAccount.displayName).filter(
        ContributorAccount.contributors_id.in_(topContributorIds))
