import time
import logging
import re
import getpass
import code

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from jira import JIRA
import pythonwhois
from github3 import GitHub, login

log = logging.getLogger('jiradb')

try:
    from getEmployer import getEmployer

    canGetEmployers = True
except ImportError:
    log.warn('No mechanism available to get employer names.')
    canGetEmployers = False

Base = declarative_base()
VOLUNTEER_DOMAINS = ["hotmail.com", "apache.org", "yahoo.com", "gmail.com", "aol.com", "outlook.com", "live.com",
                     "mac.com", "icloud.com", "me.com", "yandex.com", "mail.com"]
EMAIL_DOMAIN_REGEX = re.compile('.+@(\S+)')
LINKEDIN_SEARCH_ID = '008656707069871259401:vpdorsx4z_o'


class Issue(Base):
    __table__ = Table('issues', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('reporter_id', Integer, ForeignKey("contributors.id"), nullable=False),
                      Column('resolver_id', Integer, ForeignKey("contributors.id"), nullable=True),
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
                      Column('issuesReported', Integer, nullable=False),
                      Column('issuesResolved', Integer, nullable=False),
                      Column('assignedToCommercialCount', Integer, nullable=False),
                      Column('LinkedInPage', String(128), nullable=True),
                      Column('employer', String(128), nullable=True),
                      Column('ghProfileCompany', String(64), nullable=True),
                      Column('ghProfileLocation', String(64), nullable=True)
                      )


class JIRADB(object):
    def __init__(self, dbstring):
        """Initializes a connection to the database, and creates the necessary tables if they do not already exist."""
        self.engine = create_engine(dbstring)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        Base.metadata.create_all(self.engine)
        if args.cachedtable is not None:
            # Use the data in the cached table
            self.cachedContributors = Table(args.cachedtable, Base.metadata, autoload_with=self.engine)
        if args.gkeyfile is not None:
            # Enable Google Search
            from simplecrypt import decrypt
            from apiclient.discovery import build
            gpass = getpass.getpass('Enter Google Search key password:')
            with open(args.gkeyfile, 'rb') as gkeyfilereader:
                ciphertext = gkeyfilereader.read()
            searchService = build('customsearch', 'v1', developerKey=decrypt(gpass, ciphertext))
            self.customSearch = searchService.cse()
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
                            except Exception as e:
                                log.error('Encountered error when scanning for issue resolvers: %s', e)
                                code.interact(local=locals())
                        elif not foundOriginalPriority and item.field == 'priority':
                            # Get original priority
                            originalPriority = item.fromString
                            foundOriginalPriority = True
                if isResolved:
                    assert resolverJiraObject is not None, "Failed to get resolver for resolved issue " + issue
                    resolver = self.persistContributor(resolverJiraObject, project)
                    resolver.issuesResolved += 1
                # Persist issue
                newIssue = Issue(reporter=reporter, resolver=resolver, currentPriority=currentPriority,
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
            if (LinkedInPage is None or LinkedInPage == '') and args.gkeyfile is not None:
                # Get LinkedIn page from Google Search
                searchResults = None
                try:
                    searchResults = self.customSearch.list(q='{} {}'.format(person.displayName, project),
                                                           cx=LINKEDIN_SEARCH_ID).execute()
                    LinkedInPage = searchResults['items'][0]['link'] if searchResults['searchInformation'][
                                                                            'totalResults'] != '0' and (
                                                                            'linkedin.com/in/' in
                                                                            searchResults['items'][0][
                                                                                'link'] or 'linkedin.com/pub/' in
                                                                            searchResults['items'][0]['link']) else None
                    if args.cachedtable is not None:
                        # Add this new LinkedInPage to the Google search cache table
                        result = self.engine.execute(self.cachedContributors.insert, email=contributorEmail,
                                                     LinkedInPage=LinkedInPage)
                        result.close()
                except Exception as e:
                    log.error('Failed to get LinkedIn URL. Error: %s', e)
                    log.debug(searchResults)
            employer = None
            if LinkedInPage is not None and canGetEmployers:
                try:
                    employer = getEmployer(LinkedInPage)
                except Exception as e:
                    log.warn('Failed to get employer of %s (%s). Reason: %s', person.displayName, contributorEmail, e)
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
            contributor = Contributor(username=person.name, displayName=person.displayName, email=contributorEmail,
                                      hasFreeEmail=usingPersonalEmail,
                                      issuesReported=0, issuesResolved=0, assignedToCommercialCount=0,
                                      LinkedInPage=LinkedInPage, employer=employer,
                                      ghProfileCompany=None if ghMatchedUser is None else ghMatchedUser.company,
                                      ghProfileLocation=None if ghMatchedUser is None else ghMatchedUser.location)
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


def getArguments():
    # Parse script arguments
    import argparse
    parser = argparse.ArgumentParser(description='Mine ASF JIRA data.')
    parser.add_argument('-c', '--cached', dest='cached', action='store_true', help='Mines data from the caching DB')
    parser.add_argument('--dbstring', dest='dbstring', action='store', default='sqlite:///sqlite.db',
                        help='The database connection string')
    parser.add_argument('--gkeyfile', dest='gkeyfile', action='store',
                        help='File that contains a Google Custom Search API key enciphered by simple-crypt')
    parser.add_argument('--cachedtable', dest='cachedtable', action='store',
                        help='Table containing cached Google Search data')
    parser.add_argument('--ghscanlimit', type=int, default=10, action='store',
                        help='Maximum number of results to analyze per Github search')
    parser.add_argument('projects', nargs='+', help='Name of an ASF project (case sensitive)')
    return parser.parse_args()


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
    jiradb = JIRADB(dbstring=args.dbstring)
    jiradb.persistIssues(args.projects)
