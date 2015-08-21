import re
import time

from jira import JIRA
import numpy as np
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
    issuePool = jira.search_issues('project = ' + project, maxResults=100)
    print('Parsed ' + str(len(issuePool)) + ' issues in ' + str(round(time.time() - scanStartTime, 2)) + ' seconds')
    return issuePool


def reportsHistogram(devClass, reporters):
    """Get a histogram of number of issues reported per person in this class of developers."""
    volunteerIssuesReported = []
    for reporter in reporters.values():
        if reporter.getIsVolunteer():
            print(reporter.issuesReported)
            volunteerIssuesReported.append(reporter.issuesReported)
    print(np.histogram(volunteerIssuesReported))


jira = JIRA('https://issues.apache.org/jira')
project = "Helix"
REFRESH_DB = False

if REFRESH_DB:
    issuePool = getIssues(project)
    jiradb = JIRADB(erase=True)
    jiradb.persistIssues(issuePool)
else:
    jiradb = JIRADB()
contributors = jiradb.getContributors()
getDomains([contributor.email for contributor in contributors])
volunteers = contributors.filter_by(isVolunteer=True)
print("Generating histogram for " + str(volunteers.count()) + " volunteers")
P.hist([volunteer.issuesReported for volunteer in volunteers], histtype='bar', rwidth=0.8)
P.title(project + ": Histogram of issues reported for volunteers")
P.xlabel("Issues Reported")
P.ylabel("Frequency")
P.figure()

employees = contributors.filter_by(isVolunteer=False)
print("Generating histogram for " + str(employees.count()) + " employees")
P.hist([employee.issuesReported for employee in employees], histtype='bar', rwidth=0.8)
P.title(project + ": Histogram of issues reported for employees")
P.xlabel("Issues Reported")
P.ylabel("Frequency")
P.show()
