from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy.orm import sessionmaker
from config import SQL_USER, SQL_PW, SQL_HOST, SQL_DB

Base = declarative_base()
VOLUNTEER_DOMAINS = ["hotmail dot com", "apache dot org", "yahoo dot com", "gmail dot com", "aol dot com", "outlook dot com", "live dot com", "mac dot com", "icloud dot com", "me dot com", "yandex dot com", "mail dot com"]

class Issue(Base):
    __tablename__ = 'issues'

    id = Column(Integer, primary_key=True)
    reporter_id = Column(Integer, ForeignKey("contributors.id"), nullable=False)
    reporter = relationship("Contributor")

class Contributor(Base):
    __tablename__ = 'contributors'

    id = Column(Integer, primary_key=True)
    email = Column(String(64))
    isVolunteer = Column(Boolean, nullable=True)
    issuesReported = Column(Integer, nullable=False)

class JIRADB(object):
    def __init__(self):
        engine = create_engine('mysql+mysqlconnector://' + SQL_USER + ':' + SQL_PW + '@' + SQL_HOST + '/' + SQL_DB)
        Session = sessionmaker(bind=engine)
        self.session = Session()
        Base.metadata.create_all(engine)

    def persistIssues(self, issuePool):
        print("Persisting issues...", end='', flush=True)
        for issue in issuePool:
            # If contributor is not stored, store them.
            thisemail = issue.fields.reporter.emailAddress
            contributorList = [c for c in self.session.query(Contributor).filter(Contributor.email == thisemail)]
            if len(contributorList) == 0:
                volunteer = False
                for domain in VOLUNTEER_DOMAINS:
                    if domain in thisemail:
                        volunteer = True
                reporter = Contributor(email=thisemail, isVolunteer=volunteer, issuesReported=1)
                self.session.add(reporter)
            elif len(contributorList) == 1:
                reporter = contributorList[0]
                reporter.issuesReported += 1
            else:
                raise RuntimeError("Too many Contributors returned for this email.")
            # Persist issue with this Contributor
            newIssue = Issue(reporter=reporter)
            self.session.add(newIssue)
        self.session.commit()
        print("Done")
