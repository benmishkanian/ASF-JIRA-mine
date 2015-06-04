from jira import JIRA
import re
import time
import numpy as np

VOLUNTEER_DOMAINS = ["hotmail dot com", "apache dot org", "yahoo dot com", "gmail dot com", "aol dot com", "outlook dot com", "live dot com", "mac dot com", "icloud dot com", "me dot com", "yandex dot com", "mail dot com"]


class Contributor(object):
    """A person who is involved in ASF Jira in any way"""
    def __init__(self, person):
        self.person = person
        self.email = person.emailAddress
        self.isVolunteer = None

    def getIsVolunteer(self):
        """Returns True if the email address is hosted by one of the popular free email providers.
        This value is cached."""
        if self.isVolunteer is None:
            for domain in VOLUNTEER_DOMAINS:
                if domain in self.email:
                    self.isVolunteer = True
            if self.isVolunteer is None:
                # Failed to find a volunteer domain in this Contributor's email.
                self.isVolunteer = False
        return self.isVolunteer


class Reporter(Contributor):
    """An issue reporter"""
    def __init__(self, person, issuesReported = None):
        super().__init__(person)
        self.issuesReported = 0 if issuesReported is None else issuesReported


def indexReporters(issuePool):
    """Returns a dictionary of Reporters indexed by email address"""
    reporterHash = dict()
    for issue in issuePool:
        JIRAreporter = issue.fields.reporter
        # Hash this reporter if not already hashed
        if JIRAreporter.emailAddress not in reporterHash:
            reporterHash[JIRAreporter.emailAddress] = Reporter(JIRAreporter, issuesReported=1)
        # Otherwise, increment issues reported
        else:
            reporterHash[JIRAreporter.emailAddress].issuesReported += 1
    print("Hashed " + str(len(reporterHash)) + " reporters.")
    return reporterHash


def getDomains(contributors):
    """Prints to domains.txt the domain names of the emails of a dictionary of Contributors"""
    emailRegex = re.compile('.+at\s+(\S+\s+dot.+)')
    domainHash = dict()
    discardedEmailCount = 0
    # Iterate through Contributors' emails
    for email in iter(contributors):
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
    print(str(len(contributors)) + " unique email addresses successfully hashed (" + str(discardedEmailCount) + " discarded)")
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


def reportsHistogram(devClass, reporters):
    """Get a histogram of number of issues reported per person in this class of developers"""
    volunteerIssuesReported = []
    for reporter in reporters.values():
        if reporter.getIsVolunteer():
            print(reporter.issuesReported)
            volunteerIssuesReported.append(reporter.issuesReported)
    print(np.histogram(volunteerIssuesReported))

jira = JIRA('https://issues.apache.org/jira')
project = "Helix"
issuePool = getIssues(project)
reporters = indexReporters(issuePool)
getDomains(reporters)
