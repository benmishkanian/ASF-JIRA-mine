import re
import argparse
from enum import Enum

import pylab as P

from jiradb import JIRADB


class ContributionType(Enum):
    REPORT = 0
    RESOLVE = 1


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


def drawContributionHistogram(contributionType, isVolunteer):
    P.figure()
    """Show a histogram of contributionType per person in this class of developers."""
    contributorsInClass = contributors.filter_by(isVolunteer=isVolunteer)
    contributorClassString = "volunteers" if isVolunteer else "employees"
    print("Generating histogram for " + str(contributorsInClass.count()) + " " + contributorClassString)
    if contributionType == ContributionType.REPORT:
        P.hist([contributor.issuesReported for contributor in contributorsInClass], rwidth=0.8)
        contributionTypeString = "reported"
    elif contributionType == ContributionType.RESOLVE:
        P.hist([contributor.issuesResolved for contributor in contributorsInClass], rwidth=0.8)
        contributionTypeString = "resolved"
    else:
        raise RuntimeError("Unknown contribution type '{}'".format(contributionType))
    P.title("{}: Histogram of issues {} for {}".format(project, contributionTypeString, contributorClassString))
    P.xlabel("Issues {}".format(contributionTypeString))
    P.ylabel("Frequency")


# Parse script arguments
parser = argparse.ArgumentParser(description='Mine ASF JIRA data.')
parser.add_argument('-c', '--cached', dest='cached', action='store_true', help='Mines data from the caching DB')
parser.add_argument('--dbstring', dest='dbstring', action='store', default='sqlite:///sqlite.db', help='The database connection string')
args = parser.parse_args()

project = "Helix"

jiradb = JIRADB(dbstring=args.dbstring)
if not args.cached:
    print("Refreshing JIRA database...", end='', flush=True)
    jiradb.persistIssues(project)
    print("Done")

# Write list of domain names of contributors to domains.txt
contributors = jiradb.getContributors()
getDomains([contributor.email for contributor in contributors])

# Draw histograms for reporters
drawContributionHistogram(ContributionType.REPORT, True)
drawContributionHistogram(ContributionType.REPORT, False)

# Draw histograms for resolvers
drawContributionHistogram(ContributionType.RESOLVE, True)
drawContributionHistogram(ContributionType.RESOLVE, False)

# Show histograms
P.show()
