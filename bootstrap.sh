#!/usr/bin/env bash
sudo apt-get update
sudo apt-get install make
sudo apt-get -y install git
sudo debconf-set-selections <<< 'mysql-server mysql-server/root_password password'
sudo debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password'
sudo apt-get -y install mysql-server
sudo mysqld &
mysql -u root -e "create database helix_git"
mysqladmin -u root shutdown
wget http://dev.mysql.com/get/Downloads/Connector-Python/mysql-connector-python-2.0.5.tar.gz
tar -zxf mysql-connector-python-2.0.5.tar.gz
cd mysql-connector-python-2.0.5/
sudo python3 setup.py install
cd ..
wget https://www.python.org/ftp/python/3.4.6/Python-3.4.6rc1.tgz
tar -zxf Python-3.4.6rc1.tgz
cd Python-3.4.6rc1
./configure
make
make test
sudo make install
wget https://bootstrap.pypa.io/get-pip.py
sudo python3 get-pip.py
sudo pip3 install -I jira==1.0.3
sudo pip3 install pythonwhois pytz google-api-python-client-py3 github3.py SQLAlchemy GitPython
