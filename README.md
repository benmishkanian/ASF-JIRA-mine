# ASF-JIRA-mine
Mining JIRA and git for Apache projects to learn about contribution patterns

## Introduction
This project contains scripts that mine publicly available contributor data for ASF projects. The Python scripts mine 
the data of individual project contributors and store it in a database. The database can then be analyzed to learn
about how ASF contributors and their employers contribute to ASF. The R scripts contain some examples of such analysis.
The thesis directory contains a paper describing an experiment run using v1.0 of these scripts, which provided some
interesting findings about organizational collaboration in ASF.

## Dependencies
To use this, you either need access to [GHTorrent MySQL endpoint](http://ghtorrent.org/mysql.html) or have
a [GHTorrent MySQL database dump](http://ghtorrent.org/downloads.html). Using the endpoint will save you from having to 
download a 50GB+ database, but it makes the scripts run slower due to remote querying.

There are several other dependencies, but if you use [Vagrant](https://www.vagrantup.com/), the provisioning script
will handle all of them for you. If you do not want to use Vagrant, refer to the Vagrantfile to see all the 
dependencies. (Note: The Vagrantfile assumes that you are using GHTorrent MySQL endpoint, so it looks for your private 
key at ~/.ssh/id_rsa to use for setting up the tunnel to this endpoint. If your private key is named something else, you
have to change this line.)

## Usage
The easiest way to run this is to use [Vagrant](https://www.vagrantup.com/):

    vagrant up
    
You can then use the Python scripts within the VM by doing `vagrant ssh`. The VM already has a Python interpreter at /usr/local/bin/python3.
The local database is populated by creating and using a JIRADB object, defined in `jiradb.database`. The examples directory contains some example scripts that show how to do this.
The unit test testDatabase.py provides another example.

### Database requirements
A writable database is required to construct a JIRADB. The DB connection string is specified through the required parameter
`dbstring`. If you are not using Vagrant, ensure that any database you use is configured to collate characters using collation 'utf8_general_ci'.

### Specifying database connections
By default, the JIRADB writes to a local sqlite database **sqlite.db**. You can specify a custom database connection
string with the `dbstring` parameter. The proper formatting for this argument depends on your DBMS. [See this link for 
documentation on the connection strings.](http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls)

Note that the Vagrantfile sets up a MySQL database that can be connected to using the following dbstring:

    mysql+mysqlconnector://root:@127.0.0.1/helix_git
    
The JIRADB constructor also requires a connection string for the GHTorrent DB, which has no default. You can pass the following argument for `ghtorrentdbstring` to use the GHTorrent MySQL endpoint (after your SSH tunnel is set up):

    mysql+mysqlconnector://ght:@127.0.0.1:3307/ghtorrent

## Supported Environments
Version 1.0 of this software was tested using PostgreSQL on Linux Ubuntu. For a short period after that release, further testing was
done using MySQL on Windows 10. All testing after that point was done on the VM described in the Vagrantfile. Although the code is written in a platform-independent manner, these environments
are the ones that are most likely to work out of the box. Please submit a pull request if you have a fix to support
a different environment.