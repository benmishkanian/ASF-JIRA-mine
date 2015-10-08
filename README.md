# ASF-JIRA-mine
Mining Apache JIRA to learn how volunteers and paid developers differ in their use of JIRA

## Dependencies
- Python 3.3
- jira-python
- pylab
- sqlalchemy

## Usage
Run mine.py to analyze some data from Apache JIRA. Alternatively, run jiradb.py to refresh the local database for
offline analysis.

### Data caching
When the script is run, all the downloaded JIRA data is stored in a local SQLite db. If you want to perform queries on
this cached data instead of downloading new data every time, use the command line flag **-c** or **--cached**.

### Using other databases
By default, the scripts write to a local sqlite database **sqlite.db**. You can specify a custom database connection\
string with the **--dbstring** option.
