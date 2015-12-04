import time
import logging
import re
import getpass
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, Table, VARCHAR, MetaData, asc

from github3.null import NullObject
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from jira import JIRA
import pythonwhois
from github3 import GitHub, login
from apiclient.errors import HttpError

log = logging.getLogger('jiradb')

try:
    from getEmployer import getEmployer

    canGetEmployers = True
except ImportError:
    log.warn('No mechanism available to get employer names.')
    canGetEmployers = False

VOLUNTEER_DOMAINS = ["hotmail.com", "apache.org", "yahoo.com", "gmail.com", "aol.com", "outlook.com", "live.com",
                     "mac.com", "icloud.com", "me.com", "yandex.com", "mail.com"]
EMAIL_DOMAIN_REGEX = re.compile('.+@(\S+)')
LINKEDIN_SEARCH_ID = '008656707069871259401:vpdorsx4z_o'


def getArguments():
    # Parse script arguments
    import argparse
    parser = argparse.ArgumentParser(description='Mine ASF JIRA data.')
    parser.add_argument('-c', '--cached', dest='cached', action='store_true', help='Mines data from the caching DB')
    parser.add_argument('--dbstring', dest='dbstring', action='store', default='sqlite:///sqlite.db',
                        help='The database connection string')
    parser.add_argument('--mysqldbstring', action='store',
                        help='The connection string for a MySQL database containing a cvsanaly dump', required=True)
    parser.add_argument('--gkeyfile', dest='gkeyfile', action='store',
                        help='File that contains a Google Custom Search API key enciphered by simple-crypt')
    parser.add_argument('--cachedtable', dest='cachedtable', action='store',
                        help='Table containing cached Google Search data')
    parser.add_argument('--ghcache', action='store',
                        help='Table containing cached Github account data')
    parser.add_argument('--ghtorrentdbstring', action='store',
                        help='The connection string for a ghtorrent database', required=True)
    parser.add_argument('--ghscanlimit', type=int, default=10, action='store',
                        help='Maximum number of results to analyze per Github search')
    parser.add_argument('projects', nargs='+', help='Name of an ASF project (case sensitive)')
    return parser.parse_args()


args = getArguments()
mainEngine = create_engine(args.dbstring)
Base = declarative_base(mainEngine)


class Issue(Base):
    __table__ = Table('issues', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('reporter_id', Integer, ForeignKey("contributors.id"), nullable=False),
                      Column('resolver_id', Integer, ForeignKey("contributors.id"), nullable=True),
                      Column('isResolved', Boolean, nullable=False),
                      Column('originalPriority', String(16), nullable=False),
                      Column('currentPriority', String(16), nullable=False),
                      Column('project', String(16), nullable=False)
                      )
    reporter = relationship("Contributor", foreign_keys=[__table__.c.reporter_id])
    resolver = relationship("Contributor", foreign_keys=[__table__.c.resolver_id])


class Contributor(Base):
    __table__ = Table('contributors', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('username', String(64), nullable=False),
                      Column('displayName', String(64), nullable=False),
                      Column('email', String(64), nullable=False),
                      Column('hasFreeEmail', Boolean, nullable=True),
                      Column('hasRelatedCompanyEmail', Boolean, nullable=False),
                      Column('issuesReported', Integer, nullable=False),
                      Column('issuesResolved', Integer, nullable=False),
                      Column('assignedToCommercialCount', Integer, nullable=False),
                      Column('LinkedInPage', String(128), nullable=True),
                      Column('employer', String(128), nullable=True),
                      Column('ghProfileCompany', VARCHAR(), nullable=True),
                      Column('ghProfileLocation', VARCHAR(), nullable=True),
                      Column('BHCommitCount', Integer, nullable=True),
                      Column('NonBHCommitCount', Integer, nullable=True)
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


class JIRADB(object):
    def __init__(self, engine):
        """Initializes a connection to the database, and creates the necessary tables if they do not already exist."""
        # Main DB connection
        self.engine = engine
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        Base.metadata.create_all(self.engine)

        # MySQL connection for cvsanaly
        self.mysqlengine = create_engine(args.mysqldbstring)
        MySQLSession = sessionmaker(bind=self.mysqlengine)
        self.mysqlsession = MySQLSession()
        self.mysqlmetadata = MetaData(self.mysqlengine)
        self.gitlog = Table('scmlog', self.mysqlmetadata, autoload_with=self.mysqlengine)
        self.gitpeople = Table('people', self.mysqlmetadata, autoload_with=self.mysqlengine)

        # DB connection for ghtorrent
        self.ghtorrentengine = create_engine(args.ghtorrentdbstring)
        GHTorrentSession = sessionmaker(bind=self.ghtorrentengine)
        self.ghtorrentsession = GHTorrentSession()
        self.ghtorrentmetadata = MetaData(self.ghtorrentengine)
        self.ghtorrentprojects = Table('projects', self.ghtorrentmetadata, autoload_with=self.ghtorrentengine)
        self.ghtorrentusers = Table('users', self.ghtorrentmetadata, autoload_with=self.ghtorrentengine)

        if args.cachedtable is not None:
            # Use the data in the cached table
            self.cachedContributors = Table(args.cachedtable, Base.metadata, autoload_with=self.engine)
        if args.gkeyfile is not None:
            # Enable Google Search
            self.googleSearchEnabled = True
            from simplecrypt import decrypt
            from apiclient.discovery import build
            gpass = getpass.getpass('Enter Google Search key password:')
            with open(args.gkeyfile, 'rb') as gkeyfilereader:
                ciphertext = gkeyfilereader.read()
            searchService = build('customsearch', 'v1', developerKey=decrypt(gpass, ciphertext))
            self.customSearch = searchService.cse()
        if args.ghcache is not None:
            # Reflect Github account data table
            self.ghcache = Table(args.ghcache, Base.metadata, autoload_with=self.engine)
        # Get handle to Github API
        tok = getpass.getpass('Enter Github token:')
        if tok != '':
            self.gh = login(token=tok)
        else:
            log.warn('Using unauthenticated access to Github API. This will result in severe rate limiting.')
            self.gh = GitHub()

    def persistIssues(self, projectList):
        """Replace the DB data with fresh data"""
        # Refresh declarative schema
        Base.metadata.drop_all(self.engine, tables=[Issue.__table__, Contributor.__table__])
        Base.metadata.create_all(self.engine)
        for project in projectList:
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
            jira = JIRA('https://issues.apache.org/jira')
            issuePool = jira.search_issues('project = ' + project, maxResults=False, expand='changelog')
            log.info('Parsed %d issues in %.2f seconds', len(issuePool), time.time() - scanStartTime)
            log.info("Persisting issues...")
            for issue in issuePool:
                # Get current priority
                currentPriority = issue.fields.priority.name
                # Get reporter
                reporter = self.persistContributor(issue.fields.reporter, project)
                reporter.issuesReported += 1
                # Scan changelog
                resolver = None
                foundOriginalPriority = False
                originalPriority = currentPriority
                isResolved = issue.fields.status.name == 'Resolved'
                for event in issue.changelog.histories:
                    for item in event.items:
                        if isResolved and item.field == 'status' and item.toString == 'Resolved':
                            # Get most recent resolver
                            try:
                                resolverJiraObject = event.author
                            except AttributeError:
                                log.warn('Issue %s was resolved by an anonymous user', issue.key)
                        elif not foundOriginalPriority and item.field == 'priority':
                            # Get original priority
                            originalPriority = item.fromString
                            foundOriginalPriority = True
                if isResolved:
                    assert resolverJiraObject is not None, "Failed to get resolver for resolved issue " + issue
                    resolver = self.persistContributor(resolverJiraObject, project)
                    resolver.issuesResolved += 1
                # Persist issue
                newIssue = Issue(reporter=reporter, resolver=resolver, isResolved=isResolved,
                                 currentPriority=currentPriority,
                                 originalPriority=originalPriority,
                                 project=issue.fields.project.key)
                self.session.add(newIssue)
            for issue in issuePool:
                for event in issue.changelog.histories:
                    for item in event.items:
                        if item.field == 'assignee':
                            # Did they assign to a known commercial dev?
                            contributorList = [c for c in
                                               self.session.query(Contributor).filter(item.to == Contributor.username)]
                            assert len(contributorList) < 2, "Too many Contributors returned for username " + item.to
                            # TODO: Use more than just the hasFreeEmail feature to determine volunteer status
                            if len(contributorList) == 1 and not contributorList[0].hasFreeEmail:
                                # Increment count of times this assigner assigned to a commercial dev
                                # TODO: is it possible that event.author could raise AtrributeError if the author is anonymous?
                                assigner = self.persistContributor(event.author, project)
                                assigner.assignedToCommercialCount += 1
            self.session.commit()
            log.info("Refreshed DB for project %s", project)

    def persistContributor(self, person, project):
        """Persist the contributor to the DB unless they are already there. Returns the Contributor object."""
        contributorEmail = person.emailAddress
        # Convert email format to standard format
        contributorEmail = contributorEmail.replace(" dot ", ".").replace(" at ", "@")
        contributorList = [c for c in self.session.query(Contributor).filter(Contributor.email == contributorEmail)]
        if len(contributorList) == 0:
            LinkedInPage = None
            if args.cachedtable is not None:
                # Try to get LinkedInPage from the cached table
                row = self.session.query(self.cachedContributors).filter(
                    self.cachedContributors.c.email == contributorEmail).first()
                if row is not None:
                    LinkedInPage = row.LinkedInPage
            if (LinkedInPage is None or LinkedInPage == '') and self.googleSearchEnabled:
                # Get LinkedIn page from Google Search
                searchResults = None
                try:
                    searchTerm = '{} {}'.format(person.displayName, project)
                    searchResults = self.customSearch.list(q=searchTerm, cx=LINKEDIN_SEARCH_ID).execute()
                    LinkedInPage = searchResults['items'][0]['link'] if searchResults['searchInformation'][
                                                                            'totalResults'] != '0' and (
                                                                            'linkedin.com/in/' in
                                                                            searchResults['items'][0][
                                                                                'link'] or 'linkedin.com/pub/' in
                                                                            searchResults['items'][0]['link']) else None
                    if args.cachedtable is not None:
                        # Add this new LinkedInPage to the Google search cache table
                        result = self.engine.execute(self.cachedContributors.insert(), email=contributorEmail,
                                                     LinkedInPage=LinkedInPage)
                        result.close()
                except HttpError as e:
                    if e.resp['status'] == '403':
                        log.warn('Google search rate limit exceeded. Disabling Google search.')
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
                rateLimitInfo = self.gh.rate_limit()['resources']
                while rateLimitInfo[resourceType]['remaining'] < (1 if resourceType == 'search' else 12):
                    waitTime = max(1, rateLimitInfo[resourceType]['reset'] - time.time())
                    log.warn('Waiting %s seconds for Github rate limit...', waitTime)
                    time.sleep(waitTime)
                    rateLimitInfo = self.gh.rate_limit()['resources']

            waitForRateLimit('search')
            userResults = self.gh.search_users(contributorEmail.split('@')[0] + ' in:email')
            if userResults.total_count > args.ghscanlimit:
                # Too many results to scan through. Add full name to search.
                waitForRateLimit('search')
                userResults = self.gh.search_users(
                    contributorEmail.split('@')[0] + ' in:email ' + person.displayName + ' in:name')
                if userResults.total_count > args.ghscanlimit:
                    # Still too many results. Add username to search.
                    waitForRateLimit('search')
                    userResults = self.gh.search_users(contributorEmail.split('@')[
                                                           0] + ' in:email ' + person.displayName + ' in:name ' + person.name + ' in:login')

            ghMatchedUser = None
            if args.ghcache is not None:
                # Attempt to use offline GHTorrent db for a quick Github username match
                rows = self.session.query(self.ghcache).filter(self.ghcache.c.email == contributorEmail)
                for ghAccount in rows:
                    waitForRateLimit('core')
                    potentialUser = self.gh.user(ghAccount.login)
                    if not isinstance(potentialUser, NullObject):
                        # valid GitHub username
                        ghMatchedUser = potentialUser.refresh(True)
                        log.debug('Matched email %s to GitHub user %s', contributorEmail, ghMatchedUser.name)
                        break
            if ghMatchedUser is None:
                # Search for an email match
                userIndex = 0
                for ghUserResult in userResults:
                    userIndex += 1
                    waitForRateLimit('core')
                    ghUser = ghUserResult.user.refresh(True)
                    if ghUser.email.lower() == contributorEmail.lower():
                        # Found exact match for this email
                        ghMatchedUser = ghUser
                        break
                    elif userIndex >= args.ghscanlimit:
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
                    elif userIndex >= args.ghscanlimit:
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
                    elif userIndex >= args.ghscanlimit:
                        break
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
                                                                          'admin'] is not None and 'admin' in whoisInfo[
                        'contacts'] and (
                                             'name' in whoisInfo['contacts']['admin'] and
                                             whoisInfo['contacts']['admin']['name'] is not None and
                                             whoisInfo['contacts']['admin'][
                                                 'name'].lower() == person.displayName.lower() or 'email' in
                                             whoisInfo['contacts']['admin'] and whoisInfo['contacts']['admin'][
                                    'email'] is not None and 'whoisproxy' in whoisInfo['contacts']['admin']['email'])
                except pythonwhois.shared.WhoisException as e:
                    log.warn('Error in WHOIS query for %s: %s. Assuming non-commercial domain.', domain, e)
                    # we assume that a corporate domain would have been more reliable than this
                    usingPersonalEmail = True
                except ConnectionResetError as e:
                    # this is probably a rate limit or IP ban, which is typically something only corporations do
                    log.warn('Error in WHOIS query for %s: %s. Assuming commercial domain.', domain, e)
                except UnicodeDecodeError as e:
                    log.warn('UnicodeDecodeError in WHOIS query for %s: %s. No assumption will be made about domain.',
                             domain, e)
                    usingPersonalEmail = None
                except Exception as e:
                    log.warn('Unexpected error in WHOIS query for %s: %s. No assumption will be made about domain.',
                             domain, e)
                    usingPersonalEmail = None

            # TODO: there could be multiple rows returned?
            BHCommitCount = 0
            NonBHCommitCount = 0
            # match email on git
            row = self.mysqlsession.query(self.gitpeople).filter(self.gitpeople.c.email == contributorEmail).first()
            if row is None:
                # match name on git
                row = self.mysqlsession.query(self.gitpeople).filter(
                    self.gitpeople.c.name == person.displayName).first()
            if row is not None:
                log.debug('Matched %s on git log.', person.displayName)
                # Find out when they do most of their commits
                rows = self.mysqlsession.query(self.gitlog).filter(self.gitlog.c.author_id == row.id)
                for row in rows:
                    t = row.author_date
                    if t.hour > 10 and t.hour < 16:
                        BHCommitCount += 1
                    else:
                        NonBHCommitCount += 1

            # Find out if they have a domain from a company that is possibly contributing
            rows = self.session.query(CompanyProject, Company.domain).join(Company).filter(
                CompanyProject.project == project, Company.domain != '')
            hasRelatedCompanyEmail = False
            for row in rows:
                if contributorEmail.lower().endswith(row.domain.lower()):
                    hasRelatedCompanyEmail = True
                    break

            contributor = Contributor(username=person.name, displayName=person.displayName, email=contributorEmail,
                                      hasFreeEmail=usingPersonalEmail, hasRelatedCompanyEmail=hasRelatedCompanyEmail,
                                      issuesReported=0, issuesResolved=0, assignedToCommercialCount=0,
                                      LinkedInPage=LinkedInPage, employer=employer,
                                      ghProfileCompany=None if ghMatchedUser is None else ghMatchedUser.company,
                                      ghProfileLocation=None if ghMatchedUser is None else ghMatchedUser.location,
                                      BHCommitCount=BHCommitCount, NonBHCommitCount=NonBHCommitCount)
            self.session.add(contributor)
        elif len(contributorList) == 1:
            contributor = contributorList[0]
        else:
            raise RuntimeError("Too many Contributors returned for this email.")
        return contributor

    def getContributors(self):
        return self.session.query(Contributor)

    def getVolunteers(self):
        self.getContributors().filter_by(hasFreeEmail=True)


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

    jiradb = JIRADB(mainEngine)
    jiradb.persistIssues(args.projects)
