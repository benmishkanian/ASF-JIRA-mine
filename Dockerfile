FROM ubuntu:trusty
RUN apt-get update
RUN apt-get install -y curl python3 git
RUN curl -O -L http://dev.mysql.com/get/Downloads/Connector-Python/mysql-connector-python-2.0.5.tar.gz
RUN tar -zxf mysql-connector-python-2.0.5.tar.gz
WORKDIR /mysql-connector-python-2.0.5
RUN python3 ./setup.py install
RUN curl -O -L https://bootstrap.pypa.io/get-pip.py
RUN python3 get-pip.py
RUN pip3 install -I jira==1.0.3
RUN pip3 install pythonwhois pytz google-api-python-client-py3 github3.py==0.9.6 SQLAlchemy GitPython
ADD jiradb/ /vagrant/jiradb/
ADD tests/ /vagrant/tests/
