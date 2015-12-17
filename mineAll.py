from sqlalchemy import create_engine, Table, MetaData
import argparse
from subprocess import call

from sqlalchemy.orm import sessionmaker

parser = argparse.ArgumentParser(description='Mine ASF project data.')
parser.add_argument('--ghtorrentdbstring', action='store',
                    help='The connection string for a ghtorrent database', required=True)
ghtdb = parser.parse_args().ghtorrentdbstring

engine = create_engine(ghtdb)
Session = sessionmaker(bind=engine)
session = Session()
metadata = MetaData(engine)
projects = Table('projects', metadata, autoload_with=engine)
users = Table('users', metadata, autoload_with=engine)

projectNames = [''.join(tuple) for tuple in
                session.query(projects.c.name).join(users).filter('apache' == users.c.login).all()]

with open('template.sh', 'r') as template:
    fulltemplate = template.read()
    cmd = fulltemplate[:-1] if fulltemplate.endswith('\n') else fulltemplate  # exclude \n
    for projectName in projectNames:
        call(['createdb', '-O', 'bmishkan', '-T', 'asfmine', projectName])
        call(cmd.replace('<PROJECT_NAME>', projectName).split(' '))
