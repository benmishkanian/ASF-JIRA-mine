import getpass
import logging
import os
import re
import time
from datetime import datetime, MAXYEAR, MINYEAR
from enum import Enum
from subprocess import call

import pythonwhois
import pytz
from apiclient.errors import HttpError
from github3 import GitHub, login
from github3.exceptions import UnprocessableEntity
from github3.null import NullObject
from jira import JIRA
from jira.exceptions import JIRAError
from requests.exceptions import ConnectionError
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, Table, VARCHAR, MetaData, asc, func
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, aliased
from sqlalchemy.orm import sessionmaker

GHUSERS_EXTENDED_TABLE = 'ghusers_extended'

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
WHOIS_OBFUSCATORS = ["domainnameproxyservice.com", "whoisproxy.org", "1and1-private-registration.com",
                     "proxy.dreamhost.com", "domainsbyproxy.com", "whoisprotectservice.com", "whoisguard.com",
                     "whoisprivacyprotect.com", "contactprivacy.com", "privacyprotect.org", "privacyguardian.org",
                     "domainprivacygroup.com", "privacy@1and1.com", "networksolutionsprivateregistration.com",
                     "YinSiBaoHu.AliYun.com", "protecteddomainservices.com"]

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


def equalsIgnoreCase(s1, s2):
    if s1 is None:
        return s2 is None
    if s2 is None:
        return s1 is None
    return s1.lower() == s2.lower()


Base = declarative_base()


class Issue(Base):
    __table__ = Table('issues', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('reporter_id', Integer, ForeignKey("contributoraccounts.id"), nullable=True),
                      Column('resolver_id', Integer, ForeignKey("contributoraccounts.id"), nullable=True),
                      Column('isResolved', Boolean, nullable=False),
                      Column('originalPriority', String(16), nullable=True),
                      Column('currentPriority', String(16), nullable=True),
                      Column('project', String(16), nullable=False)
                      )
    reporter = relationship("ContributorAccount", foreign_keys=[__table__.c.reporter_id])
    resolver = relationship("ContributorAccount", foreign_keys=[__table__.c.resolver_id])


class IssueAssignment(Base):
    __table__ = Table('issueassignments', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('project', String(16), nullable=False),
                      Column('assigner_id', Integer, ForeignKey("contributoraccounts.id")),
                      Column('assignee_id', Integer, ForeignKey("contributoraccounts.id")),
                      Column('count', Integer, nullable=False),
                      Column('countInWindow', Integer, nullable=False)
                      )
    assigner = relationship("ContributorAccount", foreign_keys=[__table__.c.assigner_id])
    assignee = relationship("ContributorAccount", foreign_keys=[__table__.c.assignee_id])


class Contributor(Base):
    __table__ = Table('contributors', Base.metadata,
                      Column('id', Integer, primary_key=True),
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
                      Column('domain', VARCHAR()),
                      Column('hasCommercialEmail', Boolean, nullable=True)
                      )
    contributor = relationship("Contributor")


class AccountProject(Base):
    __table__ = Table('accountprojects', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('contributoraccounts_id', Integer, ForeignKey("contributoraccounts.id"), nullable=False),
                      Column('project', String(16)),
                      Column('LinkedInEmployer', String(128)),
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


class EmailProjectCommitCount(Base):
    __table__ = Table('emailprojectcommitcounts', Base.metadata,
                      Column('email', String(64), primary_key=True),
                      Column('project', String(16), primary_key=True),
                      Column('commitcount', Integer, nullable=False)
                      )


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


class ContributorOrganization(Base):
    __table__ = Table('contributororganizations', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('contributors_id', Integer, ForeignKey("contributors.id"), nullable=False),
                      Column('githuborganizations_id', VARCHAR(), ForeignKey("githuborganizations.login"), nullable=False)
                      )
    contributor = relationship("Contributor")
    githuborganization = relationship("GithubOrganization")


class GithubOrganization(Base):
    __table__ = Table('githuborganizations', Base.metadata,
                      Column('login', VARCHAR(), primary_key=True),
                      Column('company', VARCHAR()),
                      Column('email', VARCHAR()),
                      Column('name', VARCHAR())
                      )


class MockPerson(object):
    """Represents a JIRA user object. Construct this object when username, displayName, and emailAddress are known, but the JIRA user object is not available."""

    def __init__(self, username, displayName, emailAddress):
        self.name = username
        self.displayName = displayName
        self.emailAddress = emailAddress


class GoogleCache(Base):
    __table__ = Table('googlecache', Base.metadata,
                      Column('displayName', String(64), primary_key=True),
                      Column('project', String(16), primary_key=True),
                      Column('LinkedInPage', String(128)),
                      Column('currentEmployer', String(128))
                      )


class WhoisError(Enum):
    NO_ERR = 0
    NO_CONTACT_INFO = 1
    CONFIGURATION_ERR = 2
    CONNECTION_RESET_ERR = 3
    UNICODE_DECODE_ERR = 4
    UNKNOWN_ERR = 5


class WhoisCache(Base):
    __table__ = Table('whoiscache', Base.metadata,
                      Column('domain', VARCHAR(), primary_key=True),
                      Column('adminName', VARCHAR(), nullable=True),
                      Column('adminEmail', VARCHAR(), nullable=True),
                      Column('error', Integer, nullable=False)
                      )


def TableReflector(engine, schema):
    metadata = MetaData(engine)
    def reflectTable(tableName):
        nonlocal engine, metadata, schema
        return Table(tableName, metadata, autoload_with=engine, schema=schema)
    return reflectTable


class GitDB(object):
    def __init__(self, project, gitdbuser, gitdbpass, gitdbhostname):
        self.projectLower = project.lower()
        schema = self.projectLower + '_git'
        self.engine = create_engine(
            'mysql+mysqlconnector://{}:{}@{}/{}'.format(gitdbuser, gitdbpass, gitdbhostname, schema))
        try:
            self.engine.connect()
        except ProgrammingError:
            log.info('Database %s not found. Attempting to clone project repo...', schema)
            call(['git', 'clone', 'git@github.com:apache/' + self.projectLower + '.git'])
            os.chdir(self.projectLower)
            log.info('Creating database %s...', schema)
            call(['mysql', '-u', gitdbuser, '--password=' + gitdbpass, '-e',
                  'create database `' + schema + '`;'])
            log.info('Populating database %s using cvsanaly...', schema)
            call(['cvsanaly2', '--db-user', gitdbuser, '--db-password', gitdbpass, '--db-database', schema,
                  '--db-hostname', gitdbhostname])
            os.chdir(os.pardir)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        gitdbTable = TableReflector(self.engine, schema)
        self.log = gitdbTable('scmlog')
        self.people = gitdbTable('people')
        self.gitdbuser = gitdbuser
        self.gitdbpass = gitdbpass
        self.schema = schema
        self.gitdbhostname = gitdbhostname

    def update(self):
        self.session.close()
        self.engine.dispose()
        os.chdir(self.projectLower)
        log.info('updating git log for project %s', self.projectLower)
        call(['git', 'pull'])
        log.info('repopulating git DB...')
        call(['mysql', '-u', self.gitdbuser, '--password=' + self.gitdbpass, '-e',
              'drop database `' + self.schema + '`;'])
        call(['mysql', '-u', self.gitdbuser, '--password=' + self.gitdbpass, '-e',
              'create database `' + self.schema + '`;'])
        call(['cvsanaly2', '--db-user', self.gitdbuser, '--db-password', self.gitdbpass, '--db-database', self.schema,
              '--db-hostname', self.gitdbhostname])
        os.chdir(os.pardir)
        log.info('reconnecting to git DB...')
        self.engine = create_engine(
            'mysql+mysqlconnector://{}:{}@{}/{}'.format(self.gitdbuser, self.gitdbpass, self.gitdbhostname, self.schema))
        self.engine.connect()
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        gitdbTable = TableReflector(self.engine, self.schema)
        self.log = gitdbTable('scmlog')
        self.people = gitdbTable('people')


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
        ghtorrentengine = create_engine(self.ghtorrentdbstring)
        GHTorrentSession = sessionmaker(bind=ghtorrentengine)
        self.ghtorrentsession = GHTorrentSession()
        ghtTable = TableReflector(ghtorrentengine, SCHEMA_REGEX.search(self.ghtorrentdbstring).group(1))
        self.ghtorrentprojects = ghtTable('projects')
        self.ghtorrentusers = ghtTable('users')
        self.ghtorrentorganization_members = ghtTable('organization_members')
        self.ghtorrentproject_commits = ghtTable('project_commits')
        self.ghtorrentcommits = ghtTable('commits')

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

    def getTopContributors(self, project: str, requiredCommitCoverage: float):
        """
        Make a list of the top contributors for this project in terms of commit count. We keep appending contributors
        until at least requiredCommitCoverage percent of the commits are covered by a contributor in the list.

        :param project: name of the project
        :param requiredCommitCoverage: percentage of commits in project that must have been authored by a contributor in the list
        :return: a minimal list of the top contributors
        """
        assert 0 <= requiredCommitCoverage <= 1
        requiredCommitCount = requiredCommitCoverage * self.session.query(func.sum(EmailProjectCommitCount.commitcount)).filter(EmailProjectCommitCount.project == project).first()[0]
        coveredCommitCount = 0
        topContributors = []
        # Get the list of contributors, ordered by commit count, ascending
        subq = self.session.query(Contributor.id, ContributorAccount.email, EmailProjectCommitCount.commitcount).join(
            ContributorAccount).join(EmailProjectCommitCount,
                                     EmailProjectCommitCount.email == ContributorAccount.email).filter(EmailProjectCommitCount.project == project).distinct().subquery()
        subq2 = self.session.query(subq.c.id, func.sum(subq.c.commitcount).label('commitcount')).group_by(subq.c.id).subquery()
        contributorCommits = self.session.query(subq2).order_by(asc('commitcount')).all()
        # Append to topContributors until we have sufficient commit coverage
        while coveredCommitCount < requiredCommitCount:
            contributorCommitTuple = contributorCommits.pop()
            topContributors.append(contributorCommitTuple[0])
            coveredCommitCount = coveredCommitCount + contributorCommitTuple[1]
        log.info('%d contributors authored at least %f fraction of the commits in %s', len(topContributors), requiredCommitCoverage, project)
        return topContributors

    def getTopContributorCount(self, projects, requiredProjectCommitCoverage):
        """
        Get the minimum number of contributors required to provide commit coverage over all projects.

        :param projects: the projects to cover
        :param requiredProjectCommitCoverage: fraction of commits in each project that must be covered
        :return: the number of contributors required
        """
        requiredContributorCount = 0
        for project in projects:
            requiredContributorCount = requiredContributorCount + len(self.getTopContributors(project, requiredProjectCommitCoverage))
        return requiredContributorCount

    def searchGithubUsers(self, query):
        self.waitForRateLimit('search')
        return self.gh.search_users(query)

    def refreshGithubUser(self, ghUserObject):
        self.waitForRateLimit('core')
        return ghUserObject.refresh(True)

    def deleteRows(self, table, *filterArgs):
        return self.session.query(table).filter(*filterArgs).delete(synchronize_session='fetch')

    def hasNoChildren(self, parentTable, childTable, idColumn):
        """Returns a filter clause for the condition where parentTable.id is not referenced by any childTable row."""
        return ~(self.session.query(childTable).filter(idColumn == parentTable.id).exists())

    def deleteUnusedEntries(self, table, *childTableIDTuples):
        """childTableIDTuples should each be a tuple of the form (<childTableName>, <idColumn>)."""
        return self.deleteRows(table, *[self.hasNoChildren(table, childTuple[0], childTuple[1]) for childTuple in childTableIDTuples])

    def persistIssues(self, projectList):
        """Replace the DB data with fresh data"""
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
            rows = self.ghtorrentsession.query(self.ghtorrentprojects).join(self.ghtorrentusers, self.ghtorrentprojects.c.owner_id == self.ghtorrentusers.c.id).add_columns(
                self.ghtorrentusers.c.login, self.ghtorrentusers.c.name.label('company_name'),
                self.ghtorrentusers.c.email).filter(self.ghtorrentusers.c.type == 'ORG',
                                                    self.ghtorrentprojects.c.name == project,
                                                    self.ghtorrentprojects.c.created_at < apacheProjectCreationDate).order_by(
                asc(self.ghtorrentprojects.c.created_at))
            if rows.count() == 0:
                log.error('Failed to find any pre-Apache repos for project %s', project)
                excludedProjects.append(project)
                continue
            for row in rows:
                # Store Company if not seen
                if self.session.query(Company).filter(Company.ghlogin == row.login).count() == 0:
                    companyDomain = None
                    if row.email is not None:
                        companyDomainMatch = EMAIL_DOMAIN_REGEX.search(row.email)
                        if companyDomainMatch is not None:
                            companyDomain = companyDomainMatch.group(1)
                    newCompany = Company(ghlogin=row.login, name=row.company_name, domain=companyDomain)
                    self.session.add(newCompany)
                    newCompanyProject = CompanyProject(company=newCompany, project=project)
                    self.session.add(newCompanyProject)

            # Delete existing entries for this project related to contribution activity
            for table in [Issue, IssueAssignment, AccountProject, EmailProjectCommitCount]:
                log.info("deleted %d entries for project %s",
                         self.deleteRows(table, func.lower(table.project) == func.lower(project)), project)

            # Delete accounts that have no projects and no issues and no issue assignments
            log.info("deleted %d unused accounts", self.deleteUnusedEntries(ContributorAccount,
                                                                            (AccountProject, AccountProject.contributoraccounts_id),
                                                                            (Issue, Issue.reporter_id),
                                                                            (Issue, Issue.resolver_id),
                                                                            (IssueAssignment, IssueAssignment.assigner_id),
                                                                            (IssueAssignment, IssueAssignment.assignee_id)))

            # Delete contributors that have no accounts
            log.info("deleted %d unused contributors", self.deleteUnusedEntries(Contributor,
                                                                                (ContributorAccount, ContributorAccount.contributors_id)))

            log.info("Scanning project %s...", project)
            scanStartTime = time.time()
            try:
                JQLQuery = 'project = "{0}" AND created < "{1}" AND (created > "{2}" OR resolved < "{1}")'\
                    .format(project, self.endDate.strftime(JQL_TIME_FORMAT), self.startDate.strftime(JQL_TIME_FORMAT))
                log.debug('JQL Query: %s', JQLQuery)
                issuePool = self.jira.search_issues(JQLQuery, maxResults=False, expand='changelog')
            except JIRAError:
                log.error('Failed to find project %s on JIRA', project)
                excludedProjects.append(project)
                continue
            log.info('Parsed %d issues in %.2f seconds', len(issuePool), time.time() - scanStartTime)

            # Get DB containing git data for this project
            gitDB = self.getGitDB(project)

            # Verify that there are enough commits
            if gitDB.session.query(gitDB.log).filter(gitDB.log.c.author_date > self.startDate.strftime(CVSANALY_TIME_FORMAT),
                                                     gitDB.log.c.author_date < self.endDate.strftime(CVSANALY_TIME_FORMAT)).count() < MIN_COMMITS:
                log.warn('Project %s had less than %s commits in the given time window and will be excluded', project, MIN_COMMITS)
                excludedProjects.append(project)
                continue

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
                    reporterAccountProject = None
                    if creationDate > self.startDate:
                        if issue.fields.reporter is None:
                            log.warning('Issue %s was reported by an anonymous user', issue.key)
                        else:
                            reporterAccountProject = self.persistContributor(issue.fields.reporter, project, "jira",
                                                                             gitDB)
                            reporterAccountProject.issuesReported += 1
                    resolverAccountProject = None
                    if resolverJiraObject is not None:
                        resolverAccountProject = self.persistContributor(resolverJiraObject, project, "jira", gitDB)
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
                                assignerAccountProject = self.persistContributor(event.author, project, "jira", gitDB)
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
        self.session.commit()
        log.info('Finished persisting projects. %s projects were excluded: %s', len(excludedProjects), excludedProjects)

    def getGitDB(self, project):
        return GitDB(project, self.gitdbuser, self.gitdbpass, self.gitdbhostname)

    def waitForRateLimit(self, resourceType):
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
            self.waitForRateLimit(resourceType)

    def persistContributor(self, person, project, service, gitDB):
        """Persist the contributor to the DB unless they are already there. Returns the Contributor object."""
        contributorEmail = person.emailAddress
        # Convert email format to standard format
        contributorEmail = contributorEmail.replace(" dot ", ".").replace(" at ", "@")
        if len(contributorEmail) > 64:
            log.warn("Truncating the following email to 64 characters: %s", contributorEmail)
            contributorEmail = contributorEmail[:64]
        # Find out if there is a contributor with an account that has the same email or (the same username on the same service)
        if contributorEmail == 'dev-null@apache.org':
            # We can't match using this anonymous email. Check username and service only.
            contributor = self.session.query(Contributor).join(ContributorAccount).filter(
                (ContributorAccount.username == person.name) & (
                    ContributorAccount.service == service)).first()
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
            log.debug('Could not merge contributor given username %s, displayName %s, service %s, project %s. A new contributor object will be created.',
                     person.name, person.displayName, service, project)

            # Try to get information from Github profile
            ghMatchedUser = None
            if self.ghusersextendeddbstring is not None:
                # Attempt to use offline GHTorrent db for a quick Github username match
                rows = self.ghusersextendedsession.query(self.ghusersextended).filter(
                    self.ghusersextended.c.email == contributorEmail)
                for ghAccount in rows:
                    try:
                        potentialUser = self.gh.user(ghAccount.login)
                    except ConnectionError:
                        log.error("github query failed when attempting to verify username %s", ghAccount.login)
                        potentialUser = NullObject()
                    if not isinstance(potentialUser, NullObject):
                        # valid GitHub username
                        ghMatchedUser = self.refreshGithubUser(potentialUser)
                        log.debug('Matched email %s to GitHub user %s', contributorEmail, ghMatchedUser.name)
                        break

            if ghMatchedUser is None:
                # Search email prefix on github
                userResults = self.searchGithubUsers(contributorEmail.split('@')[0] + ' in:email')
                if userResults.total_count > self.ghscanlimit:
                    # Too many results to scan through. Add full name to search.
                    userResults = self.searchGithubUsers(
                        contributorEmail.split('@')[0] + ' in:email ' + person.displayName + ' in:name')
                    if userResults.total_count > self.ghscanlimit:
                        # Still too many results. Add username to search.
                        userResults = self.searchGithubUsers(contributorEmail.split('@')[
                                                               0] + ' in:email ' + person.displayName + ' in:name ' + person.name + ' in:login')

                def matchGHUser(userResults, verificationFunction):
                    nonlocal ghMatchedUser
                    if ghMatchedUser is None:
                        userIndex = 0
                        while ghMatchedUser is None and userIndex < self.ghscanlimit:
                            try:
                                ghUserResult = userResults.next()
                                userIndex += 1
                                ghUser = self.refreshGithubUser(ghUserResult.user)
                                if verificationFunction(ghUser, person):
                                    ghMatchedUser = ghUser
                            except StopIteration:
                                break
                            except UnprocessableEntity as e:
                                log.error("Aborting search for user %s due to GitHub API error: %s", person.name, e.message)
                                break

                # Try matching based on email
                matchGHUser(userResults, lambda ghUser, person: equalsIgnoreCase(ghUser.email, contributorEmail))
                # Try matching based on username
                matchGHUser(self.searchGithubUsers(person.name + ' in:login'), lambda ghUser, person: equalsIgnoreCase(ghUser.login, person.name))
                # Try matching based on displayName
                matchGHUser(self.searchGithubUsers(person.displayName + ' in:fullname'), lambda ghUser, person: equalsIgnoreCase(ghUser.name, person.displayName))

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
            contributor = Contributor(ghLogin=ghLogin,
                                      ghProfileCompany=ghProfileCompany,
                                      ghProfileLocation=ghProfileLocation)
            self.session.add(contributor)

        # Find out if this account is stored already
        contributorAccount = self.session.query(ContributorAccount).filter(
            ContributorAccount.contributor == contributor, ContributorAccount.username == person.name,
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
                        # Check for personal domain
                        usingPersonalEmail = None
                        # Try to get domain info from cache
                        whoisCacheRow = self.session.query(WhoisCache).filter(WhoisCache.domain == domain).first()
                        if whoisCacheRow is None:
                            # Run a WHOIS query
                            adminEmail = None
                            adminName = None
                            try:
                                whoisInfo = pythonwhois.get_whois(domain)

                                if whoisInfo['contacts'] is not None and whoisInfo['contacts']['admin'] is not None and 'admin' in \
                                        whoisInfo['contacts']:
                                    adminEmail = whoisInfo['contacts']['admin']['email'] if 'email' in whoisInfo['contacts']['admin'] else None
                                    adminName = whoisInfo['contacts']['admin']['name'] if 'name' in whoisInfo['contacts']['admin'] else None
                                    errorEnum = WhoisError.NO_ERR
                                else:
                                    errorEnum = WhoisError.NO_CONTACT_INFO
                            except pythonwhois.shared.WhoisException as e:
                                log.warning('Error in WHOIS query for %s: %s. Assuming non-commercial domain.', domain, e)
                                # we assume that a corporate domain would have been more reliable than this
                                errorEnum = WhoisError.CONFIGURATION_ERR
                            except ConnectionResetError as e:
                                # this is probably a rate limit or IP ban, which is typically something only corporations do
                                log.warning('Error in WHOIS query for %s: %s. Assuming commercial domain.', domain, e)
                                errorEnum = WhoisError.CONNECTION_RESET_ERR
                            except UnicodeDecodeError as e:
                                log.warning(
                                    'UnicodeDecodeError in WHOIS query for %s: %s. No assumption will be made about domain.',
                                    domain, e)
                                errorEnum = WhoisError.UNICODE_DECODE_ERR
                            except Exception as e:
                                log.warning('Unexpected error in WHOIS query for %s: %s. No assumption will be made about domain.',
                                            domain, e)
                                errorEnum = WhoisError.UNKNOWN_ERR
                            whoisCacheRow = WhoisCache(domain=domain, adminName=adminName, adminEmail=adminEmail, error=errorEnum.value)
                            self.session.add(whoisCacheRow)

                        if whoisCacheRow.error == WhoisError.CONFIGURATION_ERR.value:
                            usingPersonalEmail = True
                        elif whoisCacheRow.error == WhoisError.CONNECTION_RESET_ERR.value:
                            usingPersonalEmail = False
                        elif whoisCacheRow.error == WhoisError.NO_ERR.value:
                            # Check for an identity match, or whether they are using the WHOIS obfuscator "whoisproxy"
                            # Check if they are using a WHOIS obfuscation service
                            for obfuscator in WHOIS_OBFUSCATORS:
                                if contributorEmail.endswith(obfuscator):
                                    usingPersonalEmail = True
                                    break
                            if not usingPersonalEmail:
                                # Check if they own their email domain
                                usingPersonalEmail = equalsIgnoreCase(whoisCacheRow.adminName,
                                                                      person.displayName) or equalsIgnoreCase(
                                    whoisCacheRow.adminEmail, contributorEmail)
                        else:
                            usingPersonalEmail = None
            else:
                log.warn('Unable to parse domain in email %s. No assumption will be made about domain.', contributorEmail)
                usingPersonalEmail = None

            log.debug("Adding new ContributorAccount for %s on %s", person.name, service)
            contributorAccount = ContributorAccount(contributor=contributor, username=person.name, service=service,
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
                # Analyze commits authored within the window
                rows = gitDB.session.query(gitDB.log).filter(gitDB.log.c.author_id == row.id)
                for row in rows:
                    dt = pytz.utc.localize(row.author_date)  # datetime object
                    if dt > self.startDate and dt < self.endDate:
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

    def getContributors(self):
        return self.session.query(Contributor)

    def getVolunteers(self):
        self.getContributors().filter_by(hasCommercialEmail=True)

    def getAccountProjectRows(self, project):
        return self.session.query(ContributorAccount).join(AccountProject).filter(AccountProject.project == project)

    def persistOrganizations(self, contributor):
        # get fresh github user object
        potentialUser = self.gh.user(contributor.ghLogin)
        if not isinstance(potentialUser, NullObject):
            ghUser = self.refreshGithubUser(potentialUser)
            organizations = ghUser.organizations()
            for organization in organizations:
                org = self.refreshGithubUser(organization)
                githubOrganization = self.session.query(GithubOrganization).filter(GithubOrganization.login == org.login).first()
                if githubOrganization is None:
                    githubOrganization = GithubOrganization(login=org.login, company=org.company, email=org.email, name=org.name)
                    self.session.add(githubOrganization)
                contributorOrganization = self.session.query(ContributorOrganization).filter(ContributorOrganization.contributor == contributor, ContributorOrganization.githuborganization == githubOrganization).first()
                if contributorOrganization is None:
                    self.session.add(ContributorOrganization(
                        contributor=contributor, githuborganization=githubOrganization
                    ))

if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
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
    # Add error file log handler
    efh = logging.FileHandler('errors.log')
    efh.setLevel(logging.ERROR)
    efh.setFormatter(logging.Formatter('[%(levelname)s @ %(asctime)s]: %(message)s'))
    log.addHandler(efh)

    args = getArguments()
    jiradb = JIRADB(**args)
    jiradb.persistIssues(args['projects'])
