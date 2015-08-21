# ASF-JIRA-mine
Mining Apache JIRA to learn how volunteers and paid developers differ in their use of JIRA

## Dependencies
- jira-python
- pylab
- sqlalchemy
- mysql-connector
- MySQL database

## Usage
Run mine.py to collect some data from Apache JIRA.

### Using MySQL to cache data
In order to avoid repeatedly downloading JIRA data, you can set up a MySQL database to cache it. Create a file called config.py and define the following variables:
```
SQL_USER
SQL_PW
SQL_HOST
SQL_DB
```
To enable cached mode, use the command line option -c or --cached.
