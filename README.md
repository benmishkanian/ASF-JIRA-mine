# ASF-JIRA-mine
Mining JIRA and git for Apache projects to learn about contribution patterns

## Dependencies
- Python 3.3
- Python packages:
  - jira-python
  - pytz
  - git
  - mysql.connector
  - sqlalchemy
  - github3.py
  - pythonwhois
  - requests
- GHTorrent database
- git

## Usage
Run `jiradb.py --dbstring <db_connection_string> <projects...>` to do a full analysis of the given projects and store 
the results in the database.
If you want more fine-grained control over the mining, you can construct a JIRADB object and call the methods directly.
Alternatively, you can run `mine.py` for some simple analysis.
After the database is populated, you can use functions in `analyzeData.R` to do analysis.

### Data caching for mine.py
When mine.py is run, all the downloaded JIRA data is stored in a local SQLite db. If you want to perform queries against
this cached data instead of downloading new data every time, use the command line flag **-c** or **--cached**.

### Database requirements
A writable database is required to use jiradb.py. The DB connection string is specified through the required option
`--dbstring`. Make sure that any database you use is configured to collate characters using collation 'utf8_general_ci'.

### Using other databases
By default, the scripts write to a local sqlite database **sqlite.db**. You can specify a custom database connection
string with the **--dbstring** option. The proper formatting for this argument depends on your DBMS. [See this link for 
documentation on the connection strings.](http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls)

## Supported Environments
Version 1.0 of this software was tested using PostgreSQL on Linux Ubuntu. After that release, all further testing was
done using MySQL on Windows 10. Although the code is written in a platform-independent manner, these two configurations
are the ones that are most likely to work out of the box. Please submit a pull request if you have a fix to support
a different configuration.