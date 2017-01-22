import re
from enum import Enum

import pylab as P

from jiradb.database import JIRADB, Contributor
from examples.argumentParser import getArguments


class ContributionType(Enum):
    REPORT = 0
    RESOLVE = 1


def getDomains(emailList):
    """Prints to domains.txt the domain names of the emails of a dictionary of Contributors"""
    emailRegex = re.compile('.+@(\S+)')
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


def drawContributionHistogram(project, contributionType, isVolunteer):
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


args = getArguments()

jiradb = JIRADB(dbstring=args['dbstring'])
if not args.cached:
    print("Refreshing JIRA database...", end='', flush=True)
    jiradb.populate(args.projects, args.startdate, args.enddate)
    print("Done")

# Write list of domain names of contributors to domains.txt
contributors = jiradb.session.query(Contributor)
getDomains([contributor.email for contributor in contributors])

for project in args.projects:
    # Draw histograms for reporters
    drawContributionHistogram(project, ContributionType.REPORT, True)
    drawContributionHistogram(project, ContributionType.REPORT, False)

    # Draw histograms for resolvers
    drawContributionHistogram(project, ContributionType.RESOLVE, True)
    drawContributionHistogram(project, ContributionType.RESOLVE, False)

# Show histograms
P.show()
