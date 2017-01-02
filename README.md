# ASF-JIRA-mine
Mining JIRA and git for Apache projects to learn about contribution patterns

## Dependencies
- Python 3.3
- jira-python
- pytz
- cvsanaly
  - NOTE: this software seems to not support Windows
- mysql.connector
- sqlalchemy
- github3.py
- pythonwhois
- requests
- GHTorrent database

## Usage
Run `jiradb.py <projects...>` to do a full analysis of the given projects and store the results in the database.
If you want more fine-grained control over the mining, you can construct a JIRADB object and call the methods directly.
Alternatively, you can run `mine.py` for some simple analysis.
After the database is populated, you can use functions in `analyzeData.R` to do analysis.

### Data caching for mine.py
When mine.py is run, all the downloaded JIRA data is stored in a local SQLite db. If you want to perform queries against
this cached data instead of downloading new data every time, use the command line flag **-c** or **--cached**.

### Using other databases
By default, the scripts write to a local sqlite database **sqlite.db**. You can specify a custom database connection
string with the **--dbstring** option. The proper formatting for this argument depends on your DBMS. [See this link for 
documentation on the connection strings.](http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls)
