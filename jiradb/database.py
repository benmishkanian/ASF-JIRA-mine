import csv
import getpass
import logging
import os
import re
import time
from datetime import datetime, MAXYEAR

import pytz
from apiclient.errors import HttpError
from github3 import GitHub, login
from github3.exceptions import UnprocessableEntity
from github3.null import NullObject
from jira import JIRA
from jira.exceptions import JIRAError
from sqlalchemy import MetaData, Table, Column, Integer, VARCHAR, create_engine, asc, func
from sqlalchemy.orm import aliased
from sqlalchemy.orm import sessionmaker

from jiradb.analysis import getTopContributors
from jiradb.email import isEmailDomainAdmin
from jiradb.employer import getLikelyLinkedInEmployer
from jiradb.git import GitDB
from ._internal_utils import equalsIgnoreCase
from .github import GitHubDB
from .schema import Base, Issue, IssueAssignment, Contributor, ContributorAccount, AccountProject, ContributorCompany, EmailProjectCommitCount, Company, CompanyProject, ContributorOrganization, CompanyProjectEdge, \
    GoogleCache, GithubOrganization

NO_USERNAME = '<N/A>'

EMAIL_GH_LOGIN_TABLE_NAME = 'ghusers_extended'

DATE_FORMAT = '%Y-%m-%d'
JIRA_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f%z'
JQL_TIME_FORMAT = '%Y-%m-%d %H:%M'
CVSANALY_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

MIN_COMMITS = 20
MAX_SEARCH_RESULT_SCAN = 5

log = logging.getLogger('jiradb')

try:
    from getEmployer import getEmployer

    canGetEmployers = True
except ImportError:
    print('No mechanism available to get employer names.')
    canGetEmployers = False

VOLUNTEER_DOMAINS = ["hotmail.com", "apache.org", "yahoo.com", "gmail.com", "aol.com", "outlook.com", "live.com",
                     "mac.com", "icloud.com", "me.com", "yandex.com", "mail.com"]
EMAIL_DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
SCHEMA_REGEX = re.compile('.+/([^/?]+)\?*[^/]*')

LINKEDIN_SEARCH_ID = '008656707069871259401:vpdorsx4z_o'


class MockPerson(object):
    """Represents a JIRA user object. Construct this object when username, displayName, and emailAddress are known, but the JIRA user object is not available."""

    def __init__(self, username, displayName, emailAddress):
        self.name = username
        self.displayName = displayName
        self.emailAddress = emailAddress


def TableReflector(engine, schema, metadata=None):
    if metadata is None:
        metadata = MetaData(engine)

    def reflectTable(tableName, includedColumns=None):
        nonlocal engine, metadata, schema
        return Table(tableName, metadata, autoload_with=engine, schema=schema, include_columns=includedColumns)
    return reflectTable


class JIRADB(object):
    # noinspection PyUnusedLocal
    def __init__(self, ghtorrentdbstring, gitdbuser, gitdbpass, emailGHLoginDBName=None, ghtoken=None,
                 dbstring='sqlite:///sqlite.db', gkeyfile=None, ghscanlimit=10,
                 gitdbhostname='localhost', **unusedKwargs):
        """
        Initializes database connections/resources, and creates the necessary tables if they do not already exist.

        :param gitdbuser: the username for a DBMS account that has access to cvsanaly databases (if None, shows interactive prompt)
        :param gitdbpass: the password for gitdbuser (if None, shows interactive prompt)
        """
        self.dbstring = dbstring
        self.gkeyfile = gkeyfile
        self.ghtoken = ghtoken
        self.emailGHLoginDBName = emailGHLoginDBName
        self.ghscanlimit = ghscanlimit
        self.gitdbuser = gitdbuser
        self.gitdbpass = gitdbpass
        self.gitdbhostname = gitdbhostname
        self.jira = JIRA('https://issues.apache.org/jira')

        # Establish output DB connection
        self.engine = create_engine(self.dbstring)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        # Create tables if not exists
        Base.metadata.create_all(self.engine)

        # Make map of project to total commit count
        self.projectCommitCounts = dict(self.session.query(AccountProject.project, func.sum(
            AccountProject.BHCommitCount + AccountProject.NonBHCommitCount).label('commitcount')).group_by(
            AccountProject.project).all())

        # DB connection for ghtorrent
        ghtorrentengine = create_engine(ghtorrentdbstring)
        ghtorrentmetadata = MetaData(ghtorrentengine)
        ghtorrentschema = SCHEMA_REGEX.search(ghtorrentdbstring).group(1)
        ghtTable = TableReflector(ghtorrentengine, ghtorrentschema, ghtorrentmetadata)
        # TODO: GHTorrent.org blocks SHOW CREATE TABLE, requiring workaround
        self.ghtorrentusers = Table('users', ghtorrentmetadata,
                                                 Column('id', Integer, primary_key=True),
                                                 Column('login', VARCHAR(255)),
                                                 Column('type', VARCHAR(255)),
                                                 schema=ghtorrentschema)
        self.ghtorrentprojects = ghtTable('projects')
        self.ghtorrentorganization_members = ghtTable('organization_members')
        self.ghtorrentproject_commits = ghtTable('project_commits')
        self.ghtorrentcommits = ghtTable('commits')
        GHTorrentSession = sessionmaker(bind=ghtorrentengine)
        self.ghtorrentsession = GHTorrentSession()

        self.googleSearchEnabled = False
        if self.gkeyfile is not None:
            # Enable Google Search
            self.googleSearchEnabled = True
            from simplecrypt import decrypt
            from apiclient.discovery import build
            gpass = getpass.getpass('Enter Google Search key password:')
            with open(self.gkeyfile, 'rb') as gkeyfilereader:
                ciphertext = gkeyfilereader.read()
            searchService = build('customsearch', 'v1', developerKey=decrypt(gpass, ciphertext))
            self.customSearch = searchService.cse()
        if self.emailGHLoginDBName is not None:
            # Reflect table relating email to Github username
            ghusersextendeddbengine = create_engine(self.emailGHLoginDBName)
            self.emailGHLoginTable = Table(EMAIL_GH_LOGIN_TABLE_NAME, MetaData(ghusersextendeddbengine),
                                           autoload_with=ghusersextendeddbengine)
            GHUsersExtendedSession = sessionmaker(bind=ghusersextendeddbengine)
            self.ghusersextendedsession = GHUsersExtendedSession()

        # Get handle to Github API
        if self.ghtoken is not None and self.ghtoken != '':
            self.gh = login(token=self.ghtoken)
        else:
            log.warning('Using unauthenticated access to Github API. This will result in severe rate limiting.')
            self.gh = GitHub()
        self.githubDB = GitHubDB(self.gh)
        # Show interactive prompt(s) if credentials for git database are not provided
        if self.gitdbuser is None:
            self.gitdbuser = getpass.getuser()
        if self.gitdbpass is None:
            self.gitdbpass = getpass.getpass('Enter password for MySQL server containing cvsanaly dumps:')

    def buildContributorCompanyTable(self, projects, requiredCommitCoverage):
        for project in projects:
            topContributorIds = getTopContributors(self.session, project, requiredCommitCoverage)
            for contributorId in topContributorIds:
                # get row if not exists
                contributorCompany = self.session.query(ContributorCompany).filter(
                    ContributorCompany.contributors_id == contributorId).first()
                if contributorCompany is None:
                    contributorCompany = ContributorCompany(
                        contributor=self.session.query(Contributor).filter(Contributor.id == contributorId).one(),
                        company=None)
                if contributorCompany.company is None:
                    contributorCompany.company = getLikelyLinkedInEmployer(self, contributorId)
                    self.session.add(contributorCompany)
            self.session.commit()

    def buildCompanyProjectNetwork(self, projects, requiredCommitCoverage):
        """
        Creates an edge list from companies to the projects they contribute to, using the commit counts as edge values.

        :param requiredCommitCoverage: fraction of commits in each project that must be covered
        :param projects: a list of projects to include
        """
        missedCommitsDict = dict()
        for project in projects:
            # delete prior data
            self.deleteRows(CompanyProjectEdge, func.lower(CompanyProjectEdge.project) == func.lower(project))
            topContributorIds = getTopContributors(self.session, project, requiredCommitCoverage)
            # get AccountProjects of these contributors for this project
            topContributorAccounts = self.session.query(Contributor, AccountProject.BHCommitCount,
                                                        AccountProject.NonBHCommitCount).join(ContributorAccount).join(
                AccountProject).filter(
                Contributor.id.in_(topContributorIds), AccountProject.project == project)
            missedCommitsDict[project] = [0, 0]
            missedContributorIds = []
            for account in topContributorAccounts:
                accountCommits = account.BHCommitCount + account.NonBHCommitCount
                companyAttribution = getLikelyLinkedInEmployer(self, account.Contributor.id)
                if companyAttribution is not None and companyAttribution != '':
                    # create company-project edge if not exists
                    edge = self.session.query(CompanyProjectEdge).filter(
                        CompanyProjectEdge.company == companyAttribution,
                        CompanyProjectEdge.project == project).one_or_none()
                    if edge is None:
                        edge = CompanyProjectEdge(company=companyAttribution, project=project, commits=0)
                    # add commits to edge
                    edge.commits += accountCommits
                    self.session.add(edge)
                    # add to total commit count
                    missedCommitsDict[project][1] += accountCommits
                else:
                    log.warning('No company attribution found for contributor # %s', account.Contributor.id)
                    if account.Contributor.id not in missedContributorIds:
                        missedContributorIds.append(account.Contributor.id)
                    # keep track of missed commit company attribution
                    missedCommitsDict[project][0] += accountCommits
                    missedCommitsDict[project][1] += accountCommits
            # write info for missing accounts to worksheet
            requiredAccountRows = self.session.query(Contributor, ContributorAccount, AccountProject).join(
                ContributorAccount).join(AccountProject).filter(Contributor.id.in_(missedContributorIds)).order_by(
                asc(Contributor.id)).all()
            with open(project + '.csv', 'w', newline='') as worksheet:
                worksheetWriter = csv.writer(worksheet)
                # write csv header
                worksheetWriter.writerow(
                    ['id', 'ghLogin', 'ghProfileCompany', 'ghProfileLocation', 'username', 'service', 'displayName',
                     'email', 'project'])
                for requiredAccountRow in requiredAccountRows:
                    worksheetWriter.writerow([requiredAccountRow.Contributor.id, requiredAccountRow.Contributor.ghLogin,
                                              requiredAccountRow.Contributor.ghProfileCompany,
                                              requiredAccountRow.Contributor.ghProfileLocation,
                                              requiredAccountRow.ContributorAccount.username,
                                              requiredAccountRow.ContributorAccount.service,
                                              requiredAccountRow.ContributorAccount.displayName,
                                              requiredAccountRow.ContributorAccount.email,
                                              requiredAccountRow.AccountProject.project
                                              ])
            self.session.commit()
        return missedCommitsDict

    def updateTopContributorEmployers(self, project: str, requiredCommitCoverage: float, delayBetweenQueries: int):
        topContributorIds = getTopContributors(self.session, project, requiredCommitCoverage)
        topContributorAccounts = self.session.query(Contributor).join(ContributorAccount).filter(
            Contributor.id.in_(topContributorIds))
        for account in topContributorAccounts:
            self.getLinkedInEmployer(account.displayName, project)
            time.sleep(delayBetweenQueries)

    def deleteRows(self, table, *filterArgs):
        return self.session.query(table).filter(*filterArgs).delete(synchronize_session='fetch')

    def hasNoChildren(self, parentTable, childTable, idColumn):
        """Returns a filter clause for the condition where parentTable.id is not referenced by any childTable row."""
        return ~(self.session.query(childTable).filter(idColumn == parentTable.id).exists())

    def deleteUnusedEntries(self, table, *childTableIDTuples):
        """childTableIDTuples should each be a tuple of the form (<childTableName>, <idColumn>)."""
        return self.deleteRows(table, *[self.hasNoChildren(table, childTuple[0], childTuple[1]) for childTuple in childTableIDTuples])

    def populate(self, projectList, gitCloningDir=os.curdir, startdate=None, enddate=None):
        """Replace the DB data with fresh data"""
        startDate = pytz.utc.localize(
            datetime(1000, 1, 1) if startdate is None else datetime.strptime(startdate, DATE_FORMAT))
        endDate = pytz.utc.localize(
            datetime(MAXYEAR, 1, 1) if enddate is None else datetime.strptime(enddate, DATE_FORMAT))
        excludedProjects = []
        for project in projectList:
            # Find out when the apache project repo was created
            projectRepo = self.ghtorrentsession.query(
                self.ghtorrentprojects.c.created_at.label('project_creation_date')).join(self.ghtorrentusers, self.ghtorrentprojects.c.owner_id == self.ghtorrentusers.c.id).filter(
                self.ghtorrentusers.c.login == 'apache',
                self.ghtorrentprojects.c.name == project).first()
            if projectRepo is None:
                log.error('Failed to find any Apache repos for project %s', project)
                excludedProjects.append(project)
                continue
            else:
                apacheProjectCreationDate = projectRepo.project_creation_date

            log.info('Scanning ghtorrent to find out which companies may be working on this project...')
            if not self.persistRelatedGithubOrganizations(project, apacheProjectCreationDate):
                log.error('Failed to find any pre-Apache repos for project %s', project)
                excludedProjects.append(project)
                continue

            self.deleteOldData(project)

            log.info("Scanning project %s...", project)
            scanStartTime = time.time()
            try:
                JQLQuery = 'project = "{0}" AND created < "{1}" AND (created > "{2}" OR resolved < "{1}")'\
                    .format(project, endDate.strftime(JQL_TIME_FORMAT), startDate.strftime(JQL_TIME_FORMAT))
                log.debug('JQL Query: %s', JQLQuery)
                issuePool = self.jira.search_issues(JQLQuery, maxResults=False, expand='changelog')
            except JIRAError as e:
                log.error('Failed to find project %s on JIRA', project, exc_info=e)
                excludedProjects.append(project)
                continue
            log.info('Parsed %d issues in %.2f seconds', len(issuePool), time.time() - scanStartTime)

            # Get DB containing git data for this project
            gitDB = GitDB(project, self.engine, Base.metadata, self.session, gitCloningDir)

            # Verify that there are enough commits
            if gitDB.session.query(gitDB.log).filter(gitDB.log.c.author_date > startDate,
                                                     gitDB.log.c.author_date < endDate).count() < MIN_COMMITS:
                log.warning('Project %s had less than %s commits in the given time window and will be excluded', project, MIN_COMMITS)
                excludedProjects.append(project)
                continue

            log.info("Persisting issues...")
            self.persistIssues(issuePool, gitDB, project, startDate, endDate)
            self.session.commit()
            log.info('Persisting git contributors...')
            gitPeopleRows = gitDB.session.query(gitDB.people)
            for row in gitPeopleRows:
                self.persistContributor(MockPerson(None, row.name, row.email), project, "git", gitDB, startDate, endDate)
            self.session.commit()

            log.info('Persisting JIRA issue assignments...')
            self.persistIssueAssignments(issuePool, gitDB, project, startDate, endDate)
            self.session.commit()
            log.info("Refreshed DB for project %s", project)
        self.session.commit()
        log.info('Finished persisting projects. %s projects were excluded: %s', len(excludedProjects), excludedProjects)

    def persistRelatedGithubOrganizations(self, project, apacheProjectCreationDate):
        foundPotentialPredecessorProject = False
        rows = self.ghtorrentsession.query(self.ghtorrentprojects).join(self.ghtorrentusers,
                                                                        self.ghtorrentprojects.c.owner_id == self.ghtorrentusers.c.id).add_columns(
            self.ghtorrentusers.c.login).filter(
            self.ghtorrentusers.c.type == 'ORG',
            self.ghtorrentprojects.c.name == project,
            self.ghtorrentprojects.c.created_at < apacheProjectCreationDate).order_by(
            asc(self.ghtorrentprojects.c.created_at))
        if rows.count() != 0:
            foundPotentialPredecessorProject = True
            for row in rows:
                # Store Company if not seen
                if self.session.query(Company).filter(Company.ghlogin == row.login).count() == 0:
                    companyDomain = None
                    githubUser = self.githubDB.getGithubUserForLogin(row.login, self.session)
                    # Ignore any organization that cannot be found on live Github
                    if not isinstance(githubUser, NullObject):
                        companyEmail = githubUser.email
                        if companyEmail is not None and not isinstance(companyEmail, NullObject):
                            companyDomainMatch = EMAIL_DOMAIN_REGEX.search(companyEmail)
                            if companyDomainMatch is not None:
                                companyDomain = companyDomainMatch.group(1)
                        newCompany = Company(ghlogin=row.login, name=githubUser.name, domain=companyDomain)
                        self.session.add(newCompany)
                        newCompanyProject = CompanyProject(company=newCompany, project=project)
                        self.session.add(newCompanyProject)
        return foundPotentialPredecessorProject

    def deleteOldData(self, project):
        # Delete existing entries for this project related to contribution activity
        for table in [Issue, IssueAssignment, AccountProject, EmailProjectCommitCount]:
            log.info("deleted %d entries for project %s",
                     self.deleteRows(table, func.lower(table.project) == func.lower(project)), project)

        # Delete accounts that have no projects and no issues and no issue assignments
        log.info("deleted %d unused accounts", self.deleteUnusedEntries(ContributorAccount,
                                                                        (AccountProject,
                                                                         AccountProject.contributoraccounts_id),
                                                                        (Issue, Issue.reporter_id),
                                                                        (Issue, Issue.resolver_id),
                                                                        (IssueAssignment, IssueAssignment.assigner_id),
                                                                        (IssueAssignment, IssueAssignment.assignee_id)))
        # Delete contributors that have no accounts
        log.info("deleted %d unused contributors", self.deleteUnusedEntries(Contributor,
                                                                            (ContributorAccount,
                                                                             ContributorAccount.contributors_id)))

    def persistIssues(self, issuePool, gitDB, project, startDate, endDate):
        for issue in issuePool:
            # Check if issue was created in the specified time window
            creationDate = datetime.strptime(issue.fields.created, JIRA_DATE_FORMAT)
            if endDate is not None and creationDate > endDate:
                log.debug(
                    'Issue %s created on %s has a creation date after the specified time window and will be skipped.',
                    issue.key, issue.fields.created)
                continue
            # Get current priority
            currentPriority = issue.fields.priority.name if issue.fields.priority is not None else None
            # Scan changelog
            foundOriginalPriority = False
            originalPriority = currentPriority
            isResolved = issue.fields.status.name == 'Resolved'
            resolverJiraObject = None
            for event in issue.changelog.histories:
                for item in event.items:
                    eventDate = datetime.strptime(event.created, JIRA_DATE_FORMAT)
                    if isResolved and item.field == 'status' and item.toString == 'Resolved' and eventDate > startDate and eventDate < endDate:
                        # Get most recent resolver in this time window
                        try:
                            resolverJiraObject = event.author
                        except AttributeError:
                            log.warning('Issue %s was resolved by an anonymous user', issue.key)
                    elif not foundOriginalPriority and item.field == 'priority':
                        # Get original priority
                        originalPriority = item.fromString
                        foundOriginalPriority = True
            # XXX: We only persist issues that were reported or resolved in the window. If the issue was reported
            # outside of the window, reporter is None, and if the issue was never resolved in the window, resolver is None.
            if resolverJiraObject is not None or creationDate > startDate:
                # This issue was reported and/or resolved in the window
                reporterAccountProject = None
                if creationDate > startDate:
                    if issue.fields.reporter is None:
                        log.warning('Issue %s was reported by an anonymous user', issue.key)
                    else:
                        reporterAccountProject = self.persistContributor(issue.fields.reporter, project, "jira",
                                                                         gitDB, startDate, endDate)
                        reporterAccountProject.issuesReported += 1
                resolverAccountProject = None
                if resolverJiraObject is not None:
                    resolverAccountProject = self.persistContributor(resolverJiraObject, project, "jira", gitDB,
                                                                     startDate, endDate)
                    resolverAccountProject.issuesResolved += 1

                # Persist issue
                newIssue = Issue(
                    reporter=reporterAccountProject.account if reporterAccountProject is not None else None,
                    resolver=resolverAccountProject.account if resolverAccountProject is not None else None,
                    isResolved=isResolved,
                    currentPriority=currentPriority,
                    originalPriority=originalPriority,
                    project=project)
                self.session.add(newIssue)

    def persistIssueAssignments(self, issuePool, gitDB, project, startDate, endDate):
        for issue in issuePool:
            for event in issue.changelog.histories:
                eventDate = datetime.strptime(event.created, JIRA_DATE_FORMAT)
                for item in event.items:
                    # TODO: do we care when contributors clear the assignee field (i.e. item.to = None)?
                    if item.field == 'assignee' and item.to is not None:
                        # Check if the assignee is using a known account (may be same as assigner's account)
                        contributorAccountList = [ca for ca in
                                                  self.session.query(ContributorAccount).filter(
                                                      ContributorAccount.service == "jira",
                                                      ContributorAccount.username == item.to)]
                        assert len(
                            contributorAccountList) < 2, "Too many JIRA accounts returned for username " + item.to
                        if len(contributorAccountList) == 1:
                            # Increment assignments from this account to the assignee account
                            # TODO: possible that event.author could raise AtrributeError if author is anonymous?
                            assignerAccountProject = self.persistContributor(event.author, project, "jira", gitDB,
                                                                             startDate, endDate)
                            assigneeAccount = contributorAccountList[0]
                            issueAssignment = self.session.query(IssueAssignment).filter(
                                IssueAssignment.project == project,
                                IssueAssignment.assigner == assignerAccountProject.account,
                                IssueAssignment.assignee == assigneeAccount).first()
                            if issueAssignment is None:
                                issueAssignment = IssueAssignment(project=project,
                                                                  assigner=assignerAccountProject.account,
                                                                  assignee=assigneeAccount,
                                                                  count=0, countInWindow=0)
                            # Increment count of times this assigner assigned to this assignee
                            issueAssignment.count += 1
                            if eventDate > startDate and eventDate < endDate:
                                # Increment count of times this assigner assigned to this assignee within the window
                                issueAssignment.countInWindow += 1
                            self.session.add(issueAssignment)
                        else:
                            log.warning('%s assigned %s to unknown contributor %s. Ignoring.', event.author,
                                        issue.key,
                                        item.to)

    def persistContributor(self, person: MockPerson, project, service, gitDB, startDate, endDate):
        """Persist the contributor to the DB unless they are already there. Returns the Contributor object."""
        if person.name is None:
            log.info('No username is associated with email %s', person.emailAddress)
        contributorEmail = person.emailAddress
        # Convert email format to standard format
        contributorEmail = contributorEmail.replace(" dot ", ".").replace(" at ", "@")
        if len(contributorEmail) > 64:
            log.warning("Truncating the following email to 64 characters: %s", contributorEmail)
            contributorEmail = contributorEmail[:64]
        # Find out if there is a contributor with an account that has the same email or (the same username on the same service)
        if contributorEmail == 'dev-null@apache.org' and person.name is not None:
            # We can't match using this anonymous email. Check username and service only.
            contributor = self.session.query(Contributor).join(ContributorAccount).filter(
                (ContributorAccount.username == person.name) & (
                    ContributorAccount.service == service)).first()
        else:
            if person.name is None:
                contributor = self.session.query(Contributor).join(ContributorAccount).filter(
                    ContributorAccount.email == contributorEmail).first()
            else:
                contributor = self.session.query(Contributor).join(ContributorAccount).filter(
                    (ContributorAccount.email == contributorEmail) | (
                        (ContributorAccount.username == person.name) & (
                            ContributorAccount.service == service))).first()

        if contributor is None:
            # Match if there is an AccountProject with the same displayName and project
            contributor = self.session.query(Contributor).join(ContributorAccount).join(AccountProject).filter(
                (ContributorAccount.displayName == person.displayName) & (
                        func.lower(AccountProject.project) == func.lower(project))).first()

        # TODO: it may be good to rank matchings based on what matched (e.g. displayName-only match is low ranking)

        if contributor is None:
            log.debug(
                'Adding a new contributor for username %s, displayName %s, service %s, project %s',
                NO_USERNAME if person.name is None else person.name, person.displayName, service, project)

            # Try to get information from Github profile
            ghMatchedUser = None
            if self.emailGHLoginDBName is not None:
                # Attempt to use emailGHLogin table for a quick Github username match
                rows = self.ghusersextendedsession.query(self.emailGHLoginTable).filter(
                    self.emailGHLoginTable.c.email == contributorEmail)
                for ghAccount in rows:
                    potentialUser = self.githubDB.getGithubUserForLogin(ghAccount.login, self.session)
                    if not isinstance(potentialUser, NullObject):
                        # valid GitHub username
                        ghMatchedUser = potentialUser
                        log.debug('Matched email %s to GitHub user %s', contributorEmail, ghMatchedUser.name)
                        break

            if ghMatchedUser is None:
                # Search email prefix on github
                userResults = self.githubDB.searchGithubUsers(contributorEmail.split('@')[0] + ' in:email')
                if userResults.total_count > self.ghscanlimit:
                    # Too many results to scan through. Add full name to search.
                    userResults = self.githubDB.searchGithubUsers(
                        contributorEmail.split('@')[0] + ' in:email ' + person.displayName + ' in:name')
                    if userResults.total_count > self.ghscanlimit and person.name is not None:
                        # Still too many results. Add username to search.
                        userResults = self.githubDB.searchGithubUsers(contributorEmail.split('@')[
                                                               0] + ' in:email ' + person.displayName + ' in:name ' + person.name + ' in:login')

                def matchGHUser(userResults, verificationFunction):
                    nonlocal ghMatchedUser
                    if ghMatchedUser is None:
                        userIndex = 0
                        while ghMatchedUser is None and userIndex < self.ghscanlimit:
                            try:
                                ghUserResult = userResults.next()
                                userIndex += 1
                                ghUser = self.githubDB.refreshGithubUser(ghUserResult.user)
                                if verificationFunction(ghUser, person):
                                    ghMatchedUser = ghUser
                            except StopIteration:
                                break
                            except UnprocessableEntity as e:
                                log.error("Aborting search for user with email %s due to GitHub API error", person.emailAddress, exc_info=e)
                                break

                # Try matching based on email
                matchGHUser(userResults, lambda ghUser, person: equalsIgnoreCase(ghUser.email, contributorEmail))
                if person.name is not None:
                    # Try matching based on username
                    matchGHUser(self.githubDB.searchGithubUsers(person.name + ' in:login'), lambda ghUser, person: equalsIgnoreCase(ghUser.login, person.name))
                # Try matching based on displayName
                matchGHUser(self.githubDB.searchGithubUsers(person.displayName + ' in:fullname'), lambda ghUser, person: equalsIgnoreCase(ghUser.name, person.displayName))

            # TODO: assumes one github account per person
            if ghMatchedUser is None:
                ghLogin = None
                ghProfileCompany = None
                ghProfileLocation = None
            else:
                ghLogin = ghMatchedUser.login
                ghProfileCompany = ghMatchedUser.company
                ghProfileLocation = ghMatchedUser.location

            contributor = Contributor(ghLogin=ghLogin, ghProfileCompany=ghProfileCompany,
                                      ghProfileLocation=ghProfileLocation)
            self.session.add(contributor)
            log.info("Added new contributor (email=%s, login=%s, displayName=%s)", contributorEmail, NO_USERNAME if person.name is None else person.name, person.displayName)

        # Find out if this account is stored already
        # TODO: evaluate whether the change to match email instead of username impacts results relative to v1.0
        contributorAccount = self.session.query(ContributorAccount).filter(
            ContributorAccount.contributor == contributor, ContributorAccount.username == person.emailAddress,
            ContributorAccount.service == service).first()
        if contributorAccount is None:
            # Persist new account

            # Parse email domain
            domainMatch = EMAIL_DOMAIN_REGEX.search(contributorEmail)
            domain = domainMatch.group(1) if domainMatch is not None else None

            if domain is not None:
                # special cases: some domains can not be evaluated
                if domain == 'apache.org' or domain.endswith('.local') or domain.endswith('.(none)') or domain.endswith('.internal'):
                    usingPersonalEmail = None
                else:
                    # Find out if using a personal email address
                    usingPersonalEmail = domain in VOLUNTEER_DOMAINS
                    if not usingPersonalEmail:
                        usingPersonalEmail = isEmailDomainAdmin(self.session, contributorEmail, domain, person.displayName)
            else:
                log.warning('Unable to parse domain in email %s. No assumption will be made about domain.', contributorEmail)
                usingPersonalEmail = None

            log.debug("Adding new ContributorAccount for %s on %s", person.emailAddress, service)
            contributorAccount = ContributorAccount(contributor=contributor, username=NO_USERNAME if person.name is None else person.name, service=service,
                                                    displayName=person.displayName, email=contributorEmail,
                                                    domain=domain, hasCommercialEmail=not usingPersonalEmail)
            self.session.add(contributorAccount)

        # Persist this AccountProject if not exits
        accountProject = self.session.query(AccountProject).filter(
            AccountProject.account == contributorAccount,
            func.lower(AccountProject.project) == func.lower(project)).first()
        if accountProject is None:
            # compute stats for this account on this project

            # get employer from LinkedIn
            LinkedInEmployer = self.getLinkedInEmployer(person.displayName, project)

            # Find out if they have a domain from a company that is possibly contributing
            # TODO: check if '!=' does what I think it does
            rows = self.session.query(CompanyProject, Company.domain).join(Company).filter(
                func.lower(CompanyProject.project) == func.lower(project), Company.domain != '')
            log.debug('%s rows from query %s', rows.count(), rows)
            hasRelatedCompanyEmail = False
            for row in rows:
                if contributorEmail.lower().endswith(row.domain.lower()):
                    hasRelatedCompanyEmail = True
                    break

            # Find out if they work at a company that is possibly contributing
            rows = self.session.query(CompanyProject, Company.name).join(Company).filter(
                func.lower(CompanyProject.project) == func.lower(project), Company.name != '')
            log.debug('%s rows from query %s', rows.count(), rows)
            hasRelatedEmployer = False
            for row in rows:
                if contributor.ghProfileCompany is not None and row.name.lower() == contributor.ghProfileCompany.lower() or LinkedInEmployer is not None and row.name.lower() == LinkedInEmployer.lower():
                    hasRelatedEmployer = True
                    break

            # Get list of related org logins (used for the next two sections)
            relatedorgrows = self.session.query(CompanyProject, Company.ghlogin).join(Company).filter(
                func.lower(CompanyProject.project) == func.lower(project))
            relatedOrgLogins = [orgrow.ghlogin for orgrow in relatedorgrows]

            # Find out if their github account is a member of an organization that is possibly contributing
            isRelatedOrgMember = False
            if contributor.ghLogin is not None:
                orgusers = aliased(self.ghtorrentusers)
                rows = self.ghtorrentsession.query(self.ghtorrentorganization_members,
                                                   orgusers.c.login.label('orglogin')).join(self.ghtorrentusers,
                                                   self.ghtorrentorganization_members.c.user_id == self.ghtorrentusers.c.id).join(
                    orgusers, self.ghtorrentorganization_members.c.org_id == orgusers.c.id).filter(
                    self.ghtorrentusers.c.login == contributor.ghLogin)
                # check if any of those orgs are a possibly contributing org
                for row in rows:
                    if row.orglogin in relatedOrgLogins:
                        isRelatedOrgMember = True
                        break

            # Find out if they committed to a related project
            def getRelatedProjectID(orgLogin, projectName):
                return self.ghtorrentsession.query(self.ghtorrentprojects.c.id).join(self.ghtorrentusers, self.ghtorrentprojects.c.owner_id == self.ghtorrentusers.c.id).filter(
                    func.lower(self.ghtorrentprojects.c.name) == func.lower(projectName), self.ghtorrentusers.c.login == orgLogin)

            isRelatedProjectCommitter = False
            for relatedOrgLogin in relatedOrgLogins:
                subq = self.ghtorrentsession.query(self.ghtorrentproject_commits,
                                                   self.ghtorrentcommits.c.committer_id).join(
                    self.ghtorrentcommits, self.ghtorrentproject_commits.c.commit_id == self.ghtorrentcommits.c.id).filter(
                    self.ghtorrentproject_commits.c.project_id == getRelatedProjectID(relatedOrgLogin,
                                                                                      project)).subquery(
                    'distinct_committers')
                committerRows = self.ghtorrentsession.query(subq.c.committer_id.distinct(),
                                                            self.ghtorrentusers.c.login).join(self.ghtorrentusers,
                                                                                             subq.alias(
                                                            'distinct_committers').c.committer_id == self.ghtorrentusers.c.id)
                for committer in committerRows:
                    potentialUser2 = self.githubDB.getGithubUserForLogin(committer.login, self.session)
                    if not isinstance(potentialUser2, NullObject) and potentialUser2.name == person.displayName:
                        isRelatedProjectCommitter = True
                        break

            # count (non)business hour commits
            # TODO: there could be multiple rows returned?
            BHCommitCount = 0
            NonBHCommitCount = 0
            # match email on git
            row = gitDB.session.query(gitDB.people).filter(gitDB.people.c.email == contributorEmail).first()
            if row is None:
                # match name on git
                row = gitDB.session.query(gitDB.people).filter(
                    gitDB.people.c.name == person.displayName).first()
            if row is not None:
                log.debug('Matched %s on git log.', person.displayName)
                # Analyze commits authored within the window
                rows = gitDB.session.query(gitDB.log).filter(gitDB.log.c.author_id == row.id)
                for row in rows:
                    dt = pytz.utc.localize(row.author_date)  # datetime object
                    if dt > startDate and dt < endDate:
                        # Was this done during typical business hours?
                        if dt.hour > 10 and dt.hour < 16:
                            BHCommitCount += 1
                        else:
                            NonBHCommitCount += 1

            # If we have not seen commits from this email to this project, record it now
            if self.session.query(EmailProjectCommitCount).filter(EmailProjectCommitCount.email == contributorEmail, EmailProjectCommitCount.project == project).count() == 0:
                self.session.add(EmailProjectCommitCount(email=contributorEmail, project=project, commitcount=BHCommitCount + NonBHCommitCount))

            log.debug("Adding new AccountProject for %s account %s on project %s", contributorAccount.service,
                      contributorAccount.username, project)
            accountProject = AccountProject(account=contributorAccount, project=project,
                                            LinkedInEmployer=LinkedInEmployer,
                                            hasRelatedCompanyEmail=hasRelatedCompanyEmail, issuesReported=0,
                                            issuesResolved=0, hasRelatedEmployer=hasRelatedEmployer,
                                            isRelatedOrgMember=isRelatedOrgMember,
                                            isRelatedProjectCommitter=isRelatedProjectCommitter,
                                            BHCommitCount=BHCommitCount, NonBHCommitCount=NonBHCommitCount)
            self.session.add(accountProject)

        return accountProject

    def getLinkedInEmployer(self, displayName, project):
        # Try to get LinkedIn information from the Google cache
        gCacheRow = self.session.query(GoogleCache).filter(GoogleCache.displayName == displayName,
                                                           GoogleCache.project == project).first()
        if gCacheRow is None and self.googleSearchEnabled:
            # Get LinkedIn page from Google Search
            searchResults = None
            searchTerm = '{} {}'.format(displayName, project)
            try:
                searchResults = self.customSearch.list(q=searchTerm, cx=LINKEDIN_SEARCH_ID).execute()
                resultCount = int(searchResults['searchInformation']['totalResults'])
                LinkedInPage = None
                for i in range(min(resultCount, MAX_SEARCH_RESULT_SCAN)):
                    resultLink = searchResults['items'][i]['link']
                    if 'linkedin.com/in/' in resultLink or ('linkedin.com/pub/' in resultLink and 'linkedin.com/pub/dir/' not in resultLink):
                        LinkedInPage = searchResults['items'][i]['link']
                        break

                # Add this new LinkedInPage to the Google search cache table
                gCacheRow = GoogleCache(displayName=displayName, project=project,
                                        LinkedInPage=LinkedInPage,
                                        currentEmployer=None)
                self.session.add(gCacheRow)
            except HttpError as e:
                if e.resp['status'] == '403':
                    log.warning('Google search rate limit exceeded. Disabling Google search.')
                    self.googleSearchEnabled = False
                else:
                    log.error('Unexpected HttpError while executing Google search "%s"', searchTerm)
            except Exception as e:
                log.error('Failed to get LinkedIn URL. Error: %s', e)
                log.debug(searchResults)
        # Get employer from GoogleCache row, if we can.
        if gCacheRow is not None and gCacheRow.currentEmployer is None and canGetEmployers and gCacheRow.LinkedInPage is not None:
            log.debug("Getting  employer of %s through LinkedIn URL %s", gCacheRow.displayName,
                      gCacheRow.LinkedInPage)
            # get employer from LinkedIn URL using external algorithm
            try:
                gCacheRow.currentEmployer = getEmployer(gCacheRow.LinkedInPage)
                log.info('%s contributor %s is employed by %s', project, displayName, gCacheRow.currentEmployer)
            except Exception as e:
                log.info('Could not find employer of contributor %s in project %s using LinkedIn. Reason: %s',
                         displayName,
                         project, e)
        return None if gCacheRow is None else gCacheRow.currentEmployer

    def persistOrganizations(self, contributor):
        # get fresh github user object
        potentialUser = self.gh.user(contributor.ghLogin)
        if not isinstance(potentialUser, NullObject):
            ghUser = self.githubDB.refreshGithubUser(potentialUser)
            organizations = ghUser.organizations()
            for organization in organizations:
                org = self.githubDB.refreshGithubUser(organization)
                githubOrganization = self.session.query(GithubOrganization).filter(GithubOrganization.login == org.login).first()
                if githubOrganization is None:
                    githubOrganization = GithubOrganization(login=org.login, company=org.company, email=org.email, name=org.name)
                    self.session.add(githubOrganization)
                contributorOrganization = self.session.query(ContributorOrganization).filter(ContributorOrganization.contributor == contributor, ContributorOrganization.githuborganization == githubOrganization).first()
                if contributorOrganization is None:
                    self.session.add(ContributorOrganization(
                        contributor=contributor, githuborganization=githubOrganization
                    ))
