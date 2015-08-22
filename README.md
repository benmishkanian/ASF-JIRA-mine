# ASF-JIRA-mine
Mining Apache JIRA to learn how volunteers and paid developers differ in their use of JIRA

## Dependencies
- Python 3
- jira-python
- pylab
- sqlalchemy

## Usage
Run mine.py to collect some data from Apache JIRA.

### Data caching
When the script is run, all the downloaded JIRA data is stored in a local SQLite db. If you want to perform queries on
this cached data instead of downloading new data every time, use the command line option -c or --cached.
