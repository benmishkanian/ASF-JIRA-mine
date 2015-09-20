import time
import logging

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from jira import JIRA

log = logging.getLogger('jiradb')
Base = declarative_base()
VOLUNTEER_DOMAINS = ["hotmail dot com", "apache dot org", "yahoo dot com", "gmail dot com", "aol dot com",
                     "outlook dot com", "live dot com", "mac dot com", "icloud dot com", "me dot com", "yandex dot com",
                     "mail dot com"]


class Issue(Base):
    __tablename__ = 'issues'

    id = Column(Integer, primary_key=True)
    reporter_id = Column(Integer, ForeignKey("contributors.id"), nullable=False)
    reporter = relationship("Contributor", foreign_keys=[reporter_id])
    resolver_id = Column(Integer, ForeignKey("contributors.id"), nullable=True)
    resolver = relationship("Contributor", foreign_keys=[resolver_id])


class Contributor(Base):
    __tablename__ = 'contributors'

    id = Column(Integer, primary_key=True)
    email = Column(String(64))
    isVolunteer = Column(Boolean, nullable=True)
    issuesReported = Column(Integer, nullable=False)
    issuesResolved = Column(Integer, nullable=False)


class JIRADB(object):
    def __init__(self, project, erase=False):
        """Initializes a connection to the database, and creates the necessary tables if they do not already exist."""
        engine = create_engine('sqlite:///sqlite.db')
        Session = sessionmaker(bind=engine)
        self.session = Session()
        if erase:
            jira = JIRA('https://issues.apache.org/jira')
            log.info("Scanning project %s...", project)
            scanStartTime = time.time()
            issuePool = jira.search_issues('project = ' + project, maxResults=False, expand='changelog')
            log.info('Parsed %d issues in %.2f seconds', len(issuePool), time.time() - scanStartTime)
            Base.metadata.drop_all(engine)
            Base.metadata.create_all(engine)
            self.persistIssues(issuePool)
        else:
            Base.metadata.create_all(engine)
        log.info("Loaded DB for project %s", project)

    def persistIssues(self, issuePool):
        """Persist the JIRA issues in issuePool to the database."""
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
            # Persist issue with this Contributor
            newIssue = Issue(reporter=reporter, resolver=resolver)
            self.session.add(newIssue)
        self.session.commit()

    def persistContributor(self, contributorEmail):
        """Persist the contributor to the DB unless they are already there. Returns the Contributor object."""
        contributorList = [c for c in self.session.query(Contributor).filter(Contributor.email == contributorEmail)]
        if len(contributorList) == 0:
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
    project = "Helix"
    jiradb = JIRADB(project, erase=True)
