import time
import logging
import re

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from jira import JIRA
import pythonwhois

log = logging.getLogger('jiradb')
Base = declarative_base()
VOLUNTEER_DOMAINS = ["hotmail.com", "apache.org", "yahoo.com", "gmail.com", "aol.com", "outlook.com", "live.com",
                     "mac.com", "icloud.com", "me.com", "yandex.com", "mail.com"]
EMAIL_DOMAIN_REGEX = re.compile('.+@(\S+)')
LINKEDIN_SEARCH_ID = '008656707069871259401:vpdorsx4z_o'


class Issue(Base):
    __tablename__ = 'issues'

    id = Column(Integer, primary_key=True)
    reporter_id = Column(Integer, ForeignKey("contributors.id"), nullable=False)
    reporter = relationship("Contributor", foreign_keys=[reporter_id])
    resolver_id = Column(Integer, ForeignKey("contributors.id"), nullable=True)
    resolver = relationship("Contributor", foreign_keys=[resolver_id])
    originalPriority = Column(String(16), nullable=False)
    currentPriority = Column(String(16), nullable=False)
    project = Column(String(16), nullable=False)


class Contributor(Base):
    __tablename__ = 'contributors'

    id = Column(Integer, primary_key=True)
    username = Column(String(64), nullable=False)
    displayName = Column(String(64), nullable=False)
    email = Column(String(64), nullable=False)
    isVolunteer = Column(Boolean, nullable=True)
    issuesReported = Column(Integer, nullable=False)
    issuesResolved = Column(Integer, nullable=False)
    assignedToCommercialCount = Column(Integer, nullable=False)
    LinkedInPage = Column(String(128), nullable=True)


class JIRADB(object):
    def __init__(self, dbstring):
        """Initializes a connection to the database, and creates the necessary tables if they do not already exist."""
        self.engine = create_engine(dbstring)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        Base.metadata.create_all(self.engine)
        if args.gkeyfile is not None:
            from simplecrypt import decrypt
            import getpass
            from apiclient.discovery import build
            gpass = getpass.getpass('Enter Google Search key password:')
            with open(args.gkeyfile, 'rb') as gkeyfilereader:
                ciphertext = gkeyfilereader.read()
            searchService = build('customsearch', 'v1', developerKey=decrypt(gpass, ciphertext))
            self.customSearch = searchService.cse()

    def persistIssues(self, projectList):
        """Replace the DB data with fresh data"""
        # Refresh declarative schema
        Base.metadata.drop_all(self.engine)
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
                            resolverJiraObject = event.author
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
                            if len(contributorList) == 1 and not contributorList[0].isVolunteer:
                                # Increment count of times this assigner assigned to a commercial dev
                                assigner = self.persistContributor(event.author, project)
                                assigner.assignedToCommercialCount += 1
            self.session.commit()
            log.info("Refreshed DB for project %s", project)

    def persistContributor(self, person, project):
        contributorEmail = person.emailAddress
        """Persist the contributor to the DB unless they are already there. Returns the Contributor object."""
        # Convert email format to standard format
        contributorEmail = contributorEmail.replace(" dot ", ".").replace(" at ", "@")
        contributorList = [c for c in self.session.query(Contributor).filter(Contributor.email == contributorEmail)]
        if len(contributorList) == 0:
            LinkedInPage = None
            if args.gkeyfile is not None:
                # Get LinkedIn page
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
                except Exception as e:
                    log.error('Failed to get LinkedIn URL. Error: %s', e)
                    log.debug(searchResults)
            # Find out if volunteer
            volunteer = False
            for volunteerDomain in VOLUNTEER_DOMAINS:
                if volunteerDomain in contributorEmail:
                    volunteer = True
            if not volunteer:
                # Check for personal domain
                domain = EMAIL_DOMAIN_REGEX.search(contributorEmail).group(1)
                try:
                    whoisInfo = pythonwhois.get_whois(domain)
                    volunteer = whoisInfo['contacts'] is not None and whoisInfo['contacts'][
                                                                          'admin'] is not None and 'admin' in whoisInfo[
                        'contacts'] and 'name' in whoisInfo['contacts']['admin'] and whoisInfo['contacts']['admin'][
                                                                                         'name'] is not None and \
                                (whoisInfo['contacts']['admin'][
                                     'name'].lower() == person.displayName.lower() or 'whoisproxy' in
                                 whoisInfo['contacts']['admin']['email'])
                except pythonwhois.shared.WhoisException as e:
                    log.warn('Error in WHOIS query for %s: %s. Assuming non-commercial domain.', domain, e)
                    # we assume that a corporate domain would have been more reliable than this
                    volunteer = True
                except ConnectionResetError as e:
                    log.warn('Error in WHOIS query for %s: %s. Assuming commercial domain.', domain, e)
            contributor = Contributor(username=person.name, displayName=person.displayName, email=contributorEmail,
                                      isVolunteer=volunteer,
                                      issuesReported=0, issuesResolved=0, assignedToCommercialCount=0,
                                      LinkedInPage=LinkedInPage)
            self.session.add(contributor)
        elif len(contributorList) == 1:
            contributor = contributorList[0]
        else:
            raise RuntimeError("Too many Contributors returned for this email.")
        return contributor

    def getContributors(self):
        return self.session.query(Contributor)

    def getVolunteers(self):
        self.getContributors().filter_by(isVolunteer=True)


def getArguments():
    # Parse script arguments
    import argparse
    parser = argparse.ArgumentParser(description='Mine ASF JIRA data.')
    parser.add_argument('-c', '--cached', dest='cached', action='store_true', help='Mines data from the caching DB')
    parser.add_argument('--dbstring', dest='dbstring', action='store', default='sqlite:///sqlite.db',
                        help='The database connection string')
    parser.add_argument('--gkeyfile', dest='gkeyfile', action='store', required=False,
                        help='File that contains a Google Custom Search API key enciphered by simple-crypt')
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
