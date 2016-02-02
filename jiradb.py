import time
import logging
import re
import getpass
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, Table, VARCHAR, MetaData, asc, func
from subprocess import call
import os
from datetime import datetime, MAXYEAR, MINYEAR

from github3.null import NullObject
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, aliased
from sqlalchemy.orm import sessionmaker
from jira import JIRA
from jira.exceptions import JIRAError
import pythonwhois
from github3 import GitHub, login
from apiclient.errors import HttpError
import pytz
from requests.exceptions import ConnectionError

GHUSERS_EXTENDED_TABLE = 'ghusers_extended'

DATE_FORMAT = '%Y-%m-%d'
JIRA_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f%z'

log = logging.getLogger('jiradb')

try:
    from getEmployer import getEmployer

    canGetEmployers = True
except ImportError:
    log.warning('No mechanism available to get employer names.')
    canGetEmployers = False

VOLUNTEER_DOMAINS = ["hotmail.com", "apache.org", "yahoo.com", "gmail.com", "aol.com", "outlook.com", "live.com",
                     "mac.com", "icloud.com", "me.com", "yandex.com", "mail.com"]
EMAIL_DOMAIN_REGEX = re.compile('.+@(\S+)')
SCHEMA_REGEX = re.compile('.+/([^/?]+)\?*[^/]*')

LINKEDIN_SEARCH_ID = '008656707069871259401:vpdorsx4z_o'


def getArguments():
    # Parse script arguments. Returns a dict.
    import argparse
    parser = argparse.ArgumentParser(description='Mine ASF JIRA data.')
    parser.add_argument('-c', '--cached', dest='cached', action='store_true', help='Mines data from the caching DB')
    parser.add_argument('--dbstring', action='store', default='sqlite:///sqlite.db',
                        help='The output database connection string')
    parser.add_argument('--gkeyfile', action='store',
                        help='File that contains a Google Custom Search API key enciphered by simple-crypt. If not specified, a cache of search results will be used instead.')
    parser.add_argument('--ghtoken', help='A github authentication token')
    parser.add_argument('--ghusersextendeddbstring', action='store',
                        help='DB connection string for database containing the dump of users_data_aggregated_gender.csv as table ' + GHUSERS_EXTENDED_TABLE)
    parser.add_argument('--ghtorrentdbstring', action='store',
                        help='The connection string for a ghtorrent database', required=True)
    parser.add_argument('--ghscanlimit', type=int, default=10, action='store',
                        help='Maximum number of results to analyze per Github search')
    parser.add_argument('--gitdbuser', default=getpass.getuser(),
                        help='Username for MySQL server containing cvsanaly databases for all projects', )
    parser.add_argument('--gitdbpass', help='Password for MySQL server containing cvsanaly databases for all projects')
    parser.add_argument('--gitdbhostname', default='localhost',
                        help='Hostname for MySQL server containing cvsanaly databases for all projects')
    parser.add_argument('--startdate', help='Persist only data points occurring after this date')
    parser.add_argument('--enddate', help='Persist only data points occurring before this date')
    parser.add_argument('projects', nargs='+', help='Name of an ASF project (case sensitive)')
    return vars(parser.parse_args())


Base = declarative_base()


class Issue(Base):
    __table__ = Table('issues', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('reporter_id', Integer, ForeignKey("contributors.id"), nullable=True),
                      Column('resolver_id', Integer, ForeignKey("contributors.id"), nullable=True),
                      Column('isResolved', Boolean, nullable=False),
                      Column('originalPriority', String(16), nullable=True),
                      Column('currentPriority', String(16), nullable=True),
                      Column('project', String(16), nullable=False)
                      )
    reporter = relationship("Contributor", foreign_keys=[__table__.c.reporter_id])
    resolver = relationship("Contributor", foreign_keys=[__table__.c.resolver_id])


class IssueAssignment(Base):
    __table__ = Table('issueassignments', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('project', String(16), nullable=False),
                      Column('assigner_id', Integer, ForeignKey("contributors.id")),
                      Column('assignee_id', Integer, ForeignKey("contributors.id")),
                      Column('count', Integer, nullable=False),
                      Column('countInWindow', Integer, nullable=False)
                      )
    assigner = relationship("Contributor", foreign_keys=[__table__.c.assigner_id])
    assignee = relationship("Contributor", foreign_keys=[__table__.c.assignee_id])


class Contributor(Base):
    __table__ = Table('contributors', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('LinkedInPage', String(128), nullable=True),
                      Column('employer', String(128), nullable=True),
                      Column('ghLogin', String(64), nullable=True),
                      Column('ghProfileCompany', VARCHAR(), nullable=True),
                      Column('ghProfileLocation', VARCHAR(), nullable=True)
                      )


class ContributorAccount(Base):
    __table__ = Table('contributoraccounts', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('contributors_id', Integer, ForeignKey("contributors.id"), nullable=False),
                      Column('username', String(64)),
                      Column('service', String(8)),
                      Column('displayName', String(64), nullable=True),
                      Column('email', String(64)),
                      Column('hasCommercialEmail', Boolean, nullable=True)
                      )
    contributor = relationship("Contributor")


class AccountProject(Base):
    __table__ = Table('accountprojects', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('contributoraccounts_id', Integer, ForeignKey("contributoraccounts.id"), nullable=False),
                      Column('project', String(16)),
                      Column('hasRelatedCompanyEmail', Boolean, nullable=False),
                      Column('issuesReported', Integer, nullable=False),
                      Column('issuesResolved', Integer, nullable=False),
                      Column('hasRelatedEmployer', Boolean, nullable=False),
                      Column('isRelatedOrgMember', Boolean, nullable=False),
                      Column('isRelatedProjectCommitter', Boolean, nullable=False),
                      Column('BHCommitCount', Integer, nullable=True),
                      Column('NonBHCommitCount', Integer, nullable=True)
                      )
    account = relationship("ContributorAccount")


class Company(Base):
    __table__ = Table('companies', Base.metadata,
                      Column('ghlogin', VARCHAR(), primary_key=True),
                      Column('name', VARCHAR(), nullable=True),
                      Column('domain', VARCHAR(), nullable=True)
                      )


class CompanyProject(Base):
    __table__ = Table('companyprojects', Base.metadata,
                      Column('company_ghlogin', VARCHAR(), ForeignKey("companies.ghlogin"), primary_key=True),
                      Column('project', VARCHAR(), nullable=False)
                      )
    company = relationship("Company")


class MockPerson(object):
    """Represents a JIRA user object. Construct this object when username, displayName, and emailAddress are known, but the JIRA user object is not available."""

    def __init__(self, username, displayName, emailAddress):
        self.name = username
        self.displayName = displayName
        self.emailAddress = emailAddress


class GoogleCache(Base):
    __table__ = Table('googlecache', Base.metadata,
                      Column('email', String(64), primary_key=True),
                      Column('LinkedInPage', String(128))
                      )


class GitDB(object):
    def __init__(self, project, gitdbuser, gitdbpass, gitdbhostname):
        projectLower = project.lower()
        schema = projectLower + '_git'
        self.engine = create_engine(
            'mysql+mysqlconnector://{}:{}@{}/{}'.format(gitdbuser, gitdbpass, gitdbhostname, schema))
        try:
            self.engine.connect()
        except ProgrammingError:
            log.info('Database %s not found. Attemting to clone project repo...', schema)
            call(['git', 'clone', 'git@github.com:apache/' + projectLower + '.git'])
            os.chdir(projectLower)
            log.info('Creating database %s...', schema)
            call(['mysql', '-u', gitdbuser, '--password=' + gitdbpass, '-e',
                  'create database ' + schema + ';'])
            log.info('Populating database %s using cvsanaly...', schema)
            call(['cvsanaly2', '--db-user', gitdbuser, '--db-password', gitdbpass, '--db-database', schema,
                  '--db-hostname', gitdbhostname])
            os.chdir(os.pardir)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        metadata = MetaData(self.engine)
        self.log = Table('scmlog', metadata, autoload_with=self.engine, schema=schema)
        self.people = Table('people', metadata, autoload_with=self.engine, schema=schema)


class JIRADB(object):
    # noinspection PyUnusedLocal
    def __init__(self, ghtoken, ghusersextendeddbstring, ghtorrentdbstring, gitdbpass, dbstring='sqlite:///sqlite.db',
                 gkeyfile=None, ghscanlimit=10, startdate=None, enddate=None, gitdbuser=getpass.getuser(),
                 gitdbhostname='localhost', **unusedKwargs):
        """Initializes database connections/resources, and creates the necessary tables if they do not already exist."""
        self.dbstring = dbstring
        self.gkeyfile = gkeyfile
        self.ghtoken = ghtoken
        self.ghusersextendeddbstring = ghusersextendeddbstring
        self.ghtorrentdbstring = ghtorrentdbstring
        self.ghscanlimit = ghscanlimit
        self.gitdbuser = gitdbuser
        self.gitdbpass = gitdbpass
        self.gitdbhostname = gitdbhostname
        self.jira = JIRA('https://issues.apache.org/jira')

        # Output DB connection
        self.engine = create_engine(self.dbstring)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        Base.metadata.create_all(self.engine)

        # DB connection for ghtorrent
        self.ghtorrentengine = create_engine(self.ghtorrentdbstring)
        GHTorrentSession = sessionmaker(bind=self.ghtorrentengine)
        self.ghtorrentsession = GHTorrentSession()
        self.ghtorrentmetadata = MetaData(self.ghtorrentengine)
        ghtorrentschema = SCHEMA_REGEX.search(self.ghtorrentdbstring).group(1)
        self.ghtorrentprojects = Table('projects', self.ghtorrentmetadata, autoload_with=self.ghtorrentengine,
                                       schema=ghtorrentschema)
        self.ghtorrentusers = Table('users', self.ghtorrentmetadata, autoload_with=self.ghtorrentengine,
                                    schema=ghtorrentschema)
        self.ghtorrentorganization_members = Table('organization_members', self.ghtorrentmetadata,
                                                   autoload_with=self.ghtorrentengine, schema=ghtorrentschema)
        self.ghtorrentproject_commits = Table('project_commits', self.ghtorrentmetadata,
                                              autoload_with=self.ghtorrentengine, schema=ghtorrentschema)
        self.ghtorrentcommits = Table('commits', self.ghtorrentmetadata, autoload_with=self.ghtorrentengine,
                                      schema=ghtorrentschema)

        self.startDate = pytz.utc.localize(
            datetime(MINYEAR, 1, 1) if startdate is None else datetime.strptime(startdate, DATE_FORMAT))
        self.endDate = pytz.utc.localize(
            datetime(MAXYEAR, 1, 1) if enddate is None else datetime.strptime(enddate, DATE_FORMAT))

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
        if self.ghusersextendeddbstring is not None:
            # Reflect Github account data table
            ghusersextendeddbengine = create_engine(self.ghusersextendeddbstring)
            self.ghusersextended = Table(GHUSERS_EXTENDED_TABLE, MetaData(ghusersextendeddbengine),
                                         autoload_with=ghusersextendeddbengine)
            GHUsersExtendedSession = sessionmaker(bind=ghusersextendeddbengine)
            self.ghusersextendedsession = GHUsersExtendedSession()

        # Get handle to Github API
        if self.ghtoken is not None and self.ghtoken != '':
            self.gh = login(token=self.ghtoken)
        else:
            log.warning('Using unauthenticated access to Github API. This will result in severe rate limiting.')
            self.gh = GitHub()
        if self.gitdbpass is None:
            self.gitdbpass = getpass.getpass('Enter password for MySQL server containing cvsanaly dumps:')

    def persistIssues(self, projectList):
        """Replace the DB data with fresh data"""
        Base.metadata.create_all(self.engine)
        excludedProjects = []
        for project in projectList:
            # Delete existing entries for this project related to contribution activity
            for table in [IssueAssignment, AccountProject, Issue]:
                log.info("deleted %d entries for project %s",
                         self.session.query(table).filter(func.lower(table.project) == func.lower(project)).delete(
                             synchronize_session='fetch'), project)

            # Delete accounts that have no projects
            log.info("deleted %d orphaned accounts", self.session.query(ContributorAccount).filter(
                ~ContributorAccount.id.in_(
                    self.session.query(AccountProject.contributoraccounts_id.distinct()))).delete(
                synchronize_session='fetch'))

            # Delete contributors that have no accounts
            log.info("deleted %d orphaned contributors", self.session.query(Contributor).filter(
                ~Contributor.id.in_(self.session.query(ContributorAccount.contributors_id.distinct()))).delete(
                synchronize_session='fetch'))

            apacheProjectCreationDate = self.ghtorrentsession.query(
                self.ghtorrentprojects.c.created_at.label('project_creation_date')).join(self.ghtorrentusers).filter(
                self.ghtorrentusers.c.login == 'apache',
                self.ghtorrentprojects.c.name == project).first().project_creation_date
            # TODO: may fail to find creation date
            log.info('Scanning ghtorrent to find out which companies may be working on this project...')
            rows = self.ghtorrentsession.query(self.ghtorrentprojects).join(self.ghtorrentusers).add_columns(
                self.ghtorrentusers.c.login, self.ghtorrentusers.c.name.label('company_name'),
                self.ghtorrentusers.c.email).filter(self.ghtorrentusers.c.type == 'ORG',
                                                    self.ghtorrentprojects.c.name == project,
                                                    self.ghtorrentprojects.c.created_at < apacheProjectCreationDate).order_by(
                asc(self.ghtorrentprojects.c.created_at))
            for row in rows:
                # Store Company if not seen
                if self.session.query(Company).filter(Company.ghlogin == row.login).count() == 0:
                    newCompany = Company(ghlogin=row.login, name=row.company_name,
                                         domain=None if row.email is None else EMAIL_DOMAIN_REGEX.search(
                                             row.email).group(1))
                    self.session.add(newCompany)
                    newCompanyProject = CompanyProject(company=newCompany, project=project)
                    self.session.add(newCompanyProject)

            log.info("Scanning project %s...", project)
            scanStartTime = time.time()
            try:
                issuePool = self.jira.search_issues('project = ' + project, maxResults=False, expand='changelog')
            except JIRAError:
                log.error('Failed to find project %s on JIRA', project)
                excludedProjects.append(project)
                continue
            log.info('Parsed %d issues in %.2f seconds', len(issuePool), time.time() - scanStartTime)
            # Get DB containing git data for this project
            gitDB = GitDB(project, self.gitdbuser, self.gitdbpass, self.gitdbhostname)
            log.info("Persisting issues...")
            for issue in issuePool:
                # Check if issue was created in the specified time window
                creationDate = datetime.strptime(issue.fields.created, JIRA_DATE_FORMAT)
                if self.endDate is not None and creationDate > self.endDate:
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
                        if isResolved and item.field == 'status' and item.toString == 'Resolved' and eventDate > self.startDate and eventDate < self.endDate:
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
                if resolverJiraObject is not None or creationDate > self.startDate:
                    # This issue was reported and/or resolved in the window
                    reporter = None
                    if creationDate > self.startDate:
                        if issue.fields.reporter is None:
                            log.warning('Issue %s was reported by an anonymous user', issue.key)
                        else:
                            reporter = self.persistContributor(issue.fields.reporter, project, "jira", gitDB)
                            reporterAccountProject = self.session.query(AccountProject).join(ContributorAccount).filter(
                                (ContributorAccount.username == issue.fields.reporter.name) & (
                                ContributorAccount.service == "jira") & (AccountProject.project == project)).first()
                            reporterAccountProject.issuesReported += 1
                    resolver = None
                    if resolverJiraObject is not None:
                        resolver = self.persistContributor(resolverJiraObject, project, "jira", gitDB)
                        resolverAccountProject = self.session.query(AccountProject).join(ContributorAccount).filter(
                            (ContributorAccount.username == resolverJiraObject.name) & (
                            ContributorAccount.service == "jira") & (AccountProject.project == project)).first()
                        resolverAccountProject.issuesResolved += 1

                    # Persist issue
                    newIssue = Issue(reporter=reporter, resolver=resolver, isResolved=isResolved,
                                     currentPriority=currentPriority,
                                     originalPriority=originalPriority,
                                     project=issue.fields.project.key)
                    self.session.add(newIssue)

            log.info('Persisting git contributors...')
            rows = gitDB.session.query(gitDB.people, self.ghtorrentusers.c.login).join(self.ghtorrentusers,
                                                                                       gitDB.people.c.email == self.ghtorrentusers.c.email)
            for row in rows:
                self.persistContributor(MockPerson(row.login, row.name, row.email), project, "git", gitDB)

            for issue in issuePool:
                for event in issue.changelog.histories:
                    eventDate = datetime.strptime(event.created, JIRA_DATE_FORMAT)
                    for item in event.items:
                        # TODO: do we care when contributors clear the assignee field (i.e. item.to = None)?
                        if item.field == 'assignee' and item.to is not None:
                            # Check if the assignee is a known contributor (may be same as assigner)
                            contributorList = [c for c in
                                               self.session.query(Contributor).join(ContributorAccount).filter(
                                                   ContributorAccount.service == "jira",
                                                   ContributorAccount.username == item.to)]
                            assert len(contributorList) < 2, "Too many Contributors returned for username " + item.to
                            if len(contributorList) == 1:
                                # Have they assigned to this person before?
                                # TODO: possible that event.author could raise AtrributeError if author is anonymous?
                                assigner = self.persistContributor(event.author, project, "jira", gitDB)
                                assignee = contributorList[0]
                                issueAssignment = self.session.query(IssueAssignment).filter(
                                    IssueAssignment.project == project,
                                    IssueAssignment.assigner == assigner,
                                    IssueAssignment.assignee == assignee).first()
                                if issueAssignment is None:
                                    issueAssignment = IssueAssignment(project=project, assigner=assigner,
                                                                      assignee=assignee,
                                                                      count=0, countInWindow=0)
                                # Increment count of times this assigner assigned to this assignee
                                issueAssignment.count += 1
                                if eventDate > self.startDate and eventDate < self.endDate:
                                    # Increment count of times this assigner assigned to this assignee within the window
                                    issueAssignment.countInWindow += 1
                                self.session.add(issueAssignment)
                            else:
                                log.warning('%s assigned %s to unknown contributor %s. Ignoring.', event.author,
                                            issue.key,
                                            item.to)

            self.session.commit()
            log.info("Refreshed DB for project %s", project)
        log.info('Finished persisting projects. %s projects were excluded: %s', len(excludedProjects), excludedProjects)

    def persistContributor(self, person, project, service, gitDB):
        """Persist the contributor to the DB unless they are already there. Returns the Contributor object."""
        contributorEmail = person.emailAddress
        # Convert email format to standard format
        contributorEmail = contributorEmail.replace(" dot ", ".").replace(" at ", "@")
        # Find out if there is a contributor with an account that has the same email or (the same username and the same project) or (the same name and the same project)
        contributor = self.session.query(Contributor).join(ContributorAccount).join(AccountProject).filter(
            (ContributorAccount.email == contributorEmail) | (
                (ContributorAccount.username == person.name) & (
                func.lower(AccountProject.project) == func.lower(project))) | (
                (ContributorAccount.displayName == person.displayName) & (
                func.lower(AccountProject.project) == func.lower(project)))).first()
        # TODO: it may be good to rank matchings based on what matched (e.g. displayName-only match is low ranking)

        if contributor is None:
            # Persist new entry to contributors table
            # TODO: We only search for LinkedIn page based on the first displayName we get for this contributor. Should search for each displayName encountered.
            LinkedInPage = None
            if self.gkeyfile is None:
                # Try to get LinkedInPage from the cached table
                row = self.session.query(GoogleCache).filter(
                    GoogleCache.email == contributorEmail).first()
                if row is not None:
                    LinkedInPage = row.LinkedInPage
            if (LinkedInPage is None or LinkedInPage == '') and self.googleSearchEnabled:
                # Get LinkedIn page from Google Search
                searchResults = None
                searchTerm = '{} {}'.format(person.displayName, project)
                try:
                    searchResults = self.customSearch.list(q=searchTerm, cx=LINKEDIN_SEARCH_ID).execute()
                    LinkedInPage = searchResults['items'][0]['link'] if searchResults['searchInformation'][
                                                                            'totalResults'] != '0' and (
                                                                            'linkedin.com/in/' in
                                                                            searchResults['items'][0][
                                                                                'link'] or 'linkedin.com/pub/' in
                                                                            searchResults['items'][0]['link']) else None

                    # Add this new LinkedInPage to the Google search cache table
                    self.session.add(GoogleCache(email=contributorEmail, LinkedInPage=LinkedInPage))
                except HttpError as e:
                    if e.resp['status'] == '403':
                        log.warning('Google search rate limit exceeded. Disabling Google search.')
                        self.googleSearchEnabled = False
                    else:
                        log.error('Unexpected HttpError while executing Google search "%s"', searchTerm)
                except Exception as e:
                    log.error('Failed to get LinkedIn URL. Error: %s', e)
                    log.debug(searchResults)
            employer = None
            if LinkedInPage is not None and canGetEmployers:
                try:
                    employer = getEmployer(LinkedInPage)
                except Exception as e:
                    log.info('Could not find employer of %s (%s) using LinkedIn. Reason: %s', person.displayName,
                             contributorEmail, e)

            # Try to get information from Github profile
            def waitForRateLimit(resourceType):
                """resourceType can be 'search' or 'core'."""
                try:
                    rateLimitInfo = self.gh.rate_limit()['resources']
                    while rateLimitInfo[resourceType]['remaining'] < (1 if resourceType == 'search' else 12):
                        waitTime = max(1, rateLimitInfo[resourceType]['reset'] - time.time())
                        log.warning('Waiting %s seconds for Github rate limit...', waitTime)
                        time.sleep(waitTime)
                        rateLimitInfo = self.gh.rate_limit()['resources']
                except ConnectionError as e:
                    log.error("Connection error while querying GitHub rate limit. Retrying...")
                    waitForRateLimit(resourceType)

            ghMatchedUser = None
            if self.ghusersextendeddbstring is not None:
                # Attempt to use offline GHTorrent db for a quick Github username match
                rows = self.ghusersextendedsession.query(self.ghusersextended).filter(
                    self.ghusersextended.c.email == contributorEmail)
                for ghAccount in rows:
                    waitForRateLimit('core')
                    potentialUser = self.gh.user(ghAccount.login)
                    if not isinstance(potentialUser, NullObject):
                        # valid GitHub username
                        ghMatchedUser = potentialUser.refresh(True)
                        log.debug('Matched email %s to GitHub user %s', contributorEmail, ghMatchedUser.name)
                        break

            if ghMatchedUser is None:
                # Search email prefix on github
                waitForRateLimit('search')
                userResults = self.gh.search_users(contributorEmail.split('@')[0] + ' in:email')
                if userResults.total_count > self.ghscanlimit:
                    # Too many results to scan through. Add full name to search.
                    waitForRateLimit('search')
                    userResults = self.gh.search_users(
                        contributorEmail.split('@')[0] + ' in:email ' + person.displayName + ' in:name')
                    if userResults.total_count > self.ghscanlimit:
                        # Still too many results. Add username to search.
                        waitForRateLimit('search')
                        userResults = self.gh.search_users(contributorEmail.split('@')[
                                                               0] + ' in:email ' + person.displayName + ' in:name ' + person.name + ' in:login')
                # Scan search results for an exact email match
                userIndex = 0
                for ghUserResult in userResults:
                    userIndex += 1
                    waitForRateLimit('core')
                    ghUser = ghUserResult.user.refresh(True)
                    if ghUser.email.lower() == contributorEmail.lower():
                        # Found exact match for this email
                        ghMatchedUser = ghUser
                        break
                    elif userIndex >= self.ghscanlimit:
                        break
            if ghMatchedUser is None:
                # Try to find them based on username
                userIndex = 0
                waitForRateLimit('search')
                userResults = self.gh.search_users(person.name + ' in:login')
                for ghUserResult in userResults:
                    userIndex += 1
                    waitForRateLimit('core')
                    ghUser = ghUserResult.user.refresh(True)
                    if ghUser.login.lower() == person.name.lower():
                        # Found an account with the same username
                        ghMatchedUser = ghUser
                        break
                    elif userIndex >= self.ghscanlimit:
                        break
            if ghMatchedUser is None:
                # Try to find them based on real name
                userIndex = 0
                waitForRateLimit('search')
                userResults = self.gh.search_users(person.displayName + ' in:fullname')
                for ghUserResult in userResults:
                    userIndex += 1
                    waitForRateLimit('core')
                    ghUser = ghUserResult.user.refresh(True)
                    if ghUser.name.lower() == person.displayName.lower():
                        # Found a person with the same name
                        ghMatchedUser = ghUser
                        break
                    elif userIndex >= self.ghscanlimit:
                        break

            # TODO: assumes one github account per person
            if ghMatchedUser is None:
                ghLogin = None
                ghProfileCompany = None
                ghProfileLocation = None
            else:
                ghLogin = ghMatchedUser.login
                ghProfileCompany = ghMatchedUser.company
                ghProfileLocation = ghMatchedUser.location

            log.debug("New contributor %s %s %s", contributorEmail, person.name, person.displayName)
            contributor = Contributor(LinkedInPage=LinkedInPage, employer=employer, ghLogin=ghLogin,
                                      ghProfileCompany=ghProfileCompany,
                                      ghProfileLocation=ghProfileLocation,
                                      )
            self.session.add(contributor)

        # Find out if this account is stored already
        contributorAccount = self.session.query(ContributorAccount).filter(
            ContributorAccount.contributor == contributor, ContributorAccount.username == person.name,
            ContributorAccount.service == service).first()
        if contributorAccount is None:
            # Persist new account

            # Find out if using a personal email address
            usingPersonalEmail = False
            for volunteerDomain in VOLUNTEER_DOMAINS:
                if volunteerDomain in contributorEmail:
                    usingPersonalEmail = True
            if not usingPersonalEmail:
                # Check for personal domain
                domain = EMAIL_DOMAIN_REGEX.search(contributorEmail).group(1)
                try:
                    whoisInfo = pythonwhois.get_whois(domain)
                    # Also check if they are using the WHOIS obfuscator "whoisproxy"
                    usingPersonalEmail = whoisInfo['contacts'] is not None and whoisInfo['contacts'][
                                                                                   'admin'] is not None and 'admin' in \
                                                                                                            whoisInfo[
                                                                                                                'contacts'] and (
                                             'name' in whoisInfo['contacts']['admin'] and
                                             whoisInfo['contacts']['admin']['name'] is not None and
                                             whoisInfo['contacts']['admin'][
                                                 'name'].lower() == person.displayName.lower() or 'email' in
                                             whoisInfo['contacts']['admin'] and whoisInfo['contacts']['admin'][
                                                 'email'] is not None and 'whoisproxy' in
                                             whoisInfo['contacts']['admin']['email'])
                except pythonwhois.shared.WhoisException as e:
                    log.warning('Error in WHOIS query for %s: %s. Assuming non-commercial domain.', domain, e)
                    # we assume that a corporate domain would have been more reliable than this
                    usingPersonalEmail = True
                except ConnectionResetError as e:
                    # this is probably a rate limit or IP ban, which is typically something only corporations do
                    log.warning('Error in WHOIS query for %s: %s. Assuming commercial domain.', domain, e)
                except UnicodeDecodeError as e:
                    log.warning(
                        'UnicodeDecodeError in WHOIS query for %s: %s. No assumption will be made about domain.',
                        domain, e)
                    usingPersonalEmail = None
                except Exception as e:
                    log.warning('Unexpected error in WHOIS query for %s: %s. No assumption will be made about domain.',
                                domain, e)
                    usingPersonalEmail = None

            log.debug("Adding new ContributorAccount for %s on %s", person.name, service)
            contributorAccount = ContributorAccount(contributor=contributor, username=person.name, service=service,
                                                    displayName=person.displayName, email=contributorEmail,
                                                    hasCommercialEmail=not usingPersonalEmail)
            self.session.add(contributorAccount)
            # If this email is commercial, set hasCommercialEmail=True
            contributor.hasCommercialEmail = True
            self.session.add(contributor)

        # Persist this AccountProject if not exits
        accountProject = self.session.query(AccountProject).filter(
            AccountProject.account == contributorAccount,
            func.lower(AccountProject.project) == func.lower(project)).first()
        if accountProject is None:
            # compute stats for this account on this project

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
                if contributor.ghProfileCompany is not None and row.name.lower() == contributor.ghProfileCompany.lower() or contributor.employer is not None and row.name.lower() == contributor.employer.lower():
                    hasRelatedEmployer = True
                    break

            # Get list of related org logins (used for the next two sections)
            relatedorgrows = self.session.query(CompanyProject, Company.ghlogin).join(Company).filter(
                CompanyProject.project == project)
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
                return self.ghtorrentsession.query(self.ghtorrentprojects.c.id).join(self.ghtorrentusers).filter(
                    self.ghtorrentprojects.c.name == projectName, self.ghtorrentusers.c.login == orgLogin)

            isRelatedProjectCommitter = False
            for relatedOrgLogin in relatedOrgLogins:
                subq = self.ghtorrentsession.query(self.ghtorrentproject_commits,
                                                   self.ghtorrentcommits.c.committer_id).join(
                    self.ghtorrentcommits).filter(
                    self.ghtorrentproject_commits.c.project_id == getRelatedProjectID(relatedOrgLogin,
                                                                                      project)).subquery(
                    'distinct_committers')
                committerRows = self.ghtorrentsession.query(subq.c.committer_id.distinct(),
                                                            self.ghtorrentusers.c.name).join(self.ghtorrentusers,
                                                                                             subq.alias(
                                                                                                 'distinct_committers').c.committer_id == self.ghtorrentusers.c.id)
                if person.displayName in [committer.name for committer in committerRows]:
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
                # Analyze commits within the window
                rows = gitDB.session.query(gitDB.log).filter(gitDB.log.c.author_id == row.id)
                for row in rows:
                    dt = pytz.utc.localize(row.author_date)  # datetime object
                    if dt > self.startDate and dt < self.endDate:
                        # Was this done during typical business hours?
                        if dt.hour > 10 and dt.hour < 16:
                            BHCommitCount += 1
                        else:
                            NonBHCommitCount += 1

            self.session.add(AccountProject(account=contributorAccount, project=project,
                                            hasRelatedCompanyEmail=hasRelatedCompanyEmail, issuesReported=0,
                                            issuesResolved=0, hasRelatedEmployer=hasRelatedEmployer,
                                            isRelatedOrgMember=isRelatedOrgMember,
                                            isRelatedProjectCommitter=isRelatedProjectCommitter,
                                            BHCommitCount=BHCommitCount, NonBHCommitCount=NonBHCommitCount))

        return contributor

    def getContributors(self):
        return self.session.query(Contributor)

    def getVolunteers(self):
        self.getContributors().filter_by(hasCommercialEmail=True)


if __name__ == "__main__":
    log.setLevel(logging.INFO)
    # Add console log handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(message)s'))
    log.addHandler(ch)
    # Add file log handler
    fh = logging.FileHandler('jiradb.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('[%(levelname)s @ %(asctime)s]: %(message)s'))
    log.addHandler(fh)

    args = getArguments()
    jiradb = JIRADB(**args)
    jiradb.persistIssues(args['projects'])
