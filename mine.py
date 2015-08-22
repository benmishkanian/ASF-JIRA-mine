import re
import time
import argparse

from jira import JIRA
import pylab as P

from jiradb import JIRADB

VOLUNTEER_DOMAINS = ["hotmail dot com", "apache dot org", "yahoo dot com", "gmail dot com", "aol dot com",
                     "outlook dot com", "live dot com", "mac dot com", "icloud dot com", "me dot com", "yandex dot com",
                     "mail dot com"]


def getDomains(emailList):
    """Prints to domains.txt the domain names of the emails of a dictionary of Contributors"""
    emailRegex = re.compile('.+at\s+(\S+\s+dot.+)')
    domainHash = dict()
    discardedEmailCount = 0
    # Iterate through Contributors' emails
    for email in emailList:
        matches = emailRegex.search(email)
        if matches is None:
            print("Warning: email address \'" + email + "\' does not match the expected format, and will be ignored")
            discardedEmailCount += 1
        else:
            # Hash this domain if not already hashed
            domain = matches.group(1)
            if domain not in domainHash:
                domainHash[domain] = True
    print("Domain scan complete. Results:")
    print(str(len(emailList)) + " unique email addresses successfully hashed (" + str(
        discardedEmailCount) + " discarded)")
    print(str(len(domainHash)) + " unique domains hashed")
    # Write domains to file
    domainFile = open('domains.txt', 'w')
    for domain in iter(domainHash):
        domainFile.write(str(domain) + '\n')
    print("Domain list has been written to domains.txt")


def getIssues(project):
    """Get a list of all issues in a project. This can take a long time, and requires internet access."""
    print("Scanning project " + project + "...")
    scanStartTime = time.time()
    issuePool = jira.search_issues('project = ' + project, maxResults=False)
    print('Parsed ' + str(len(issuePool)) + ' issues in ' + str(round(time.time() - scanStartTime, 2)) + ' seconds')
    return issuePool


def reportsHistogram(isVolunteer):
    P.figure()
    """Show a histogram of number of issues reported per person in this class of developers."""
    contributorsInClass = contributors.filter_by(isVolunteer=isVolunteer)
    contributorClassString = "volunteers" if isVolunteer else "employees"
    print("Generating histogram for " + str(contributorsInClass.count()) + " " + contributorClassString)
    P.hist([contributor.issuesReported for contributor in contributorsInClass], histtype='bar', rwidth=0.8)
    P.title(project + ": Histogram of issues reported for " + contributorClassString)
    P.xlabel("Issues Reported")
    P.ylabel("Frequency")


# Parse script arguments
parser = argparse.ArgumentParser(description='Mine ASF JIRA data.')
parser.add_argument('-c', '--cached', dest='cached', action='store_true', help='Mines data from the caching DB')
args = parser.parse_args()

jira = JIRA('https://issues.apache.org/jira')
project = "Helix"

if args.cached:
    # Get cached data from DB
    jiradb = JIRADB()
else:
    # Get fresh data from API, and store in DB
    issuePool = getIssues(project)
    jiradb = JIRADB(erase=True)
    jiradb.persistIssues(issuePool)

# Write list of domain names of contributors to domains.txt
contributors = jiradb.getContributors()
getDomains([contributor.email for contributor in contributors])

# Show histograms for reporters
reportsHistogram(True)
reportsHistogram(False)
P.show()