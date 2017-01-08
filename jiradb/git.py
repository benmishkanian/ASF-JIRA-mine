import os
from subprocess import call

import logging
from git import Repo
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import Table
from sqlalchemy import VARCHAR
from sqlalchemy import and_
from sqlalchemy import create_engine
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

log = logging.getLogger(__name__)


class GitDB(object):
    def __init__(self, project, engine, metadata, session, gitCloningDir):
        """
        :param project: The project whose git log should be parsed
        :param engine: A sqlalchemy engine
        :param session: A sqlalchemy session to use for storing git log data
        :param gitCloningDir: A directory to use for cloning the project
        """
        self.projectLower = project.lower()
        tableName = self.projectLower + '_git'
        peopleTableName = tableName + '_people'
        self.log = Table(tableName, metadata,
                         Column('id', Integer, primary_key=True),
                         Column('author_date', DateTime),
                         Column('author_id', Integer, ForeignKey(peopleTableName + '.id'), nullable=False)
                         )
        self.people = Table(peopleTableName, metadata,
                            Column('id', Integer, primary_key=True),
                            Column('email', VARCHAR()),
                            Column('name', VARCHAR())
                            )
        # create table if not exists
        self.log.create(engine, checkfirst=True)
        self.people.create(engine, checkfirst=True)
        # if no rows, load rows using git log
        rowCount = session.query(self.log).count()
        log.info('%d rows in table %s', rowCount, tableName)
        if rowCount == 0:
            log.info('No rows in table %s. Attempting to clone project repo...', tableName)
            oldDir = os.curdir
            os.chdir(gitCloningDir)
            call(['git', 'clone', 'https://github.com/apache/' + self.projectLower + '.git'])
            log.info('Populating table %s using gitpython...', tableName)
            repo = Repo(self.projectLower)
            assert not repo.bare
            commits = list(repo.iter_commits('master'))
            conn = engine.connect()
            for commit in commits:
                # persist user if not seen before
                peopleRows = conn.execute(select([self.people]).where(and_(self.people.c.email == str(commit.author.email), self.people.c.name == str(commit.author.name))))
                personRow = peopleRows.fetchone()
                if personRow is None:
                    insertionResult = conn.execute(self.people.insert().values(email=str(commit.author.email), name=str(commit.author.name)))
                    personId = insertionResult.inserted_primary_key[0]
                else:
                    personId = personRow['id']
                # persist commit
                conn.execute(self.log.insert().values(author_date=commit.authored_datetime, author_id=personId))
            os.chdir(oldDir)
        self.session = session

    def update(self):
        # TODO: method needs updating
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