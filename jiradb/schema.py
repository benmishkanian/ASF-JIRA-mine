from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, Table, VARCHAR
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

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
                      Column('ghProfileCompany', VARCHAR(200), nullable=True),
                      Column('ghProfileLocation', VARCHAR(200), nullable=True)
                      )


class ContributorAccount(Base):
    __table__ = Table('contributoraccounts', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('contributors_id', Integer, ForeignKey("contributors.id"), nullable=False),
                      Column('username', String(64)),
                      Column('service', String(8)),
                      Column('displayName', String(64), nullable=True),
                      Column('email', String(64)),
                      Column('domain', VARCHAR(200)),
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


class ContributorCompany(Base):
    __table__ = Table('contributorcompanies', Base.metadata,
                      Column('contributors_id', Integer, ForeignKey("contributors.id"), primary_key=True),
                      Column('company', String(128))
                      )
    contributor = relationship("Contributor")


class EmailProjectCommitCount(Base):
    __table__ = Table('emailprojectcommitcounts', Base.metadata,
                      Column('email', String(64), primary_key=True),
                      Column('project', String(16), primary_key=True),
                      Column('commitcount', Integer, nullable=False)
                      )


class Company(Base):
    __table__ = Table('companies', Base.metadata,
                      Column('ghlogin', VARCHAR(200), primary_key=True),
                      Column('name', VARCHAR(200), nullable=True),
                      Column('domain', VARCHAR(200), nullable=True)
                      )


class CompanyProject(Base):
    __table__ = Table('companyprojects', Base.metadata,
                      Column('company_ghlogin', VARCHAR(200), ForeignKey("companies.ghlogin"), primary_key=True),
                      Column('project', VARCHAR(200), nullable=False)
                      )
    company = relationship("Company")


class ContributorOrganization(Base):
    __table__ = Table('contributororganizations', Base.metadata,
                      Column('id', Integer, primary_key=True),
                      Column('contributors_id', Integer, ForeignKey("contributors.id"), nullable=False),
                      Column('githuborganizations_id', VARCHAR(200), ForeignKey("githuborganizations.login"), nullable=False)
                      )
    contributor = relationship("Contributor")
    githuborganization = relationship("GithubOrganization")


class GithubOrganization(Base):
    __table__ = Table('githuborganizations', Base.metadata,
                      Column('login', VARCHAR(200), primary_key=True),
                      Column('company', VARCHAR(200)),
                      Column('email', VARCHAR(200)),
                      Column('name', VARCHAR(200))
                      )


class GoogleCache(Base):
    __table__ = Table('googlecache', Base.metadata,
                      Column('displayName', String(64), primary_key=True),
                      Column('project', String(16), primary_key=True),
                      Column('LinkedInPage', String(128)),
                      Column('currentEmployer', String(128))
                      )


class CompanyProjectEdge(Base):
    __table__ = Table('companyprojectedges', Base.metadata,
                      Column('company', String(128), primary_key=True),
                      Column('project', String(32), primary_key=True),
                      Column('commits', Integer)
                      )


class WhoisCache(Base):
    __table__ = Table('whoiscache', Base.metadata,
                      Column('domain', VARCHAR(200), primary_key=True),
                      Column('adminName', VARCHAR(200), nullable=True),
                      Column('adminEmail', VARCHAR(200), nullable=True),
                      Column('error', Integer, nullable=False)
                      )


class GitHubUserCache(Base):
    __table__ = Table('githubusercache', Base.metadata,
                      Column('login', VARCHAR(255), primary_key=True),
                      Column('name', VARCHAR(255)),
                      Column('email', VARCHAR(255)),
                      Column('company', VARCHAR(255)),
                      Column('location', VARCHAR(255)),
                      Column('fake', Boolean, default=False)
                      )
