import time
import logging

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from jira import JIRA

log = logging.getLogger('jiradb')
Base = declarative_base()
VOLUNTEER_DOMAINS = ["hotmail.com", "apache.org", "yahoo.com", "gmail.com", "aol.com", "outlook.com", "live.com",
                     "mac.com", "icloud.com", "me.com", "yandex.com", "mail.com"]


class Issue(Base):
    __tablename__ = 'issues'

    id = Column(Integer, primary_key=True)
    reporter_id = Column(Integer, ForeignKey("contributors.id"), nullable=False)
    reporter = relationship("Contributor", foreign_keys=[reporter_id])
    resolver_id = Column(Integer, ForeignKey("contributors.id"), nullable=True)
    resolver = relationship("Contributor", foreign_keys=[resolver_id])
    currentPriority = Column(String(16), nullable=False)


class Contributor(Base):
    __tablename__ = 'contributors'

    id = Column(Integer, primary_key=True)
    email = Column(String(64))
    isVolunteer = Column(Boolean, nullable=True)
    issuesReported = Column(Integer, nullable=False)
    issuesResolved = Column(Integer, nullable=False)


class JIRADB(object):
    def __init__(self, dbstring='sqlite:///sqlite.db'):
        """Initializes a connection to the database, and creates the necessary tables if they do not already exist."""
        self.engine = create_engine(dbstring)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        Base.metadata.create_all(self.engine)

    def persistIssues(self, project):
        """Replace the DB data with fresh data"""
        # Refresh declarative schema
        Base.metadata.drop_all(self.engine)
        Base.metadata.create_all(self.engine)
        log.info("Scanning project %s...", project)
        scanStartTime = time.time()
        jira = JIRA('https://issues.apache.org/jira')
        issuePool = jira.search_issues('project = ' + project, maxResults=False, expand='changelog')
        log.info('Parsed %d issues in %.2f seconds', len(issuePool), time.time() - scanStartTime)
        log.info("Persisting issues...")
        for issue in issuePool:
            # Get reporter
            reporterEmail = issue.fields.reporter.emailAddress
            reporter = self.persistContributor(reporterEmail)
            reporter.issuesReported += 1
            # Get resolver
            resolver = None
            if issue.fields.status.name == 'Resolved':
                # Get most recent resolver
                for event in issue.changelog.histories:
                    for item in event.items:
                        if item.field == 'status' and item.toString == 'Resolved':
                            resolverEmail = event.author.emailAddress
                assert resolverEmail is not None, "Failed to get email of resolver for resolved issue " + issue
                resolver = self.persistContributor(resolverEmail)
                resolver.issuesResolved += 1
            # Get priority
            currentPriority = issue.fields.priority.name
            # Persist issue with this Contributor
            newIssue = Issue(reporter=reporter, resolver=resolver, currentPriority=currentPriority)
            self.session.add(newIssue)
        self.session.commit()
        log.info("Refreshed DB for project %s", project)

    def persistContributor(self, contributorEmail):
        """Persist the contributor to the DB unless they are already there. Returns the Contributor object."""
        # Convert email format to standard format
        contributorEmail = contributorEmail.replace(" dot ", ".").replace(" at ", "@")
        contributorList = [c for c in self.session.query(Contributor).filter(Contributor.email == contributorEmail)]
        if len(contributorList) == 0:
            # Find out if volunteer
            volunteer = False
            for domain in VOLUNTEER_DOMAINS:
                if domain in contributorEmail:
                    volunteer = True
            contributor = Contributor(email=contributorEmail, isVolunteer=volunteer, issuesReported=0, issuesResolved=0)
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

    # Parse script arguments
    import argparse

    parser = argparse.ArgumentParser(description='Mine ASF JIRA data.')
    parser.add_argument('--dbstring', dest='dbstring', action='store', default='sqlite:///sqlite.db',
                        help='The database connection string')
    args = parser.parse_args()

    project = "Helix"
    jiradb = JIRADB(dbstring=args.dbstring)
    jiradb.persistIssues(project)
