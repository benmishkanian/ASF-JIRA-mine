import logging

import time
from github3.null import NullObject


log = logging.getLogger(__name__)


class GitHubDB(object):
    def __init__(self, api):
        self.gh = api

    def waitForRateLimit(self, resourceType):
        """resourceType can be 'search' or 'core'."""
        try:
            rateLimitInfo = self.gh.rate_limit()['resources']
            while rateLimitInfo[resourceType]['remaining'] < (1 if resourceType == 'search' else 12):
                waitTime = max(1, rateLimitInfo[resourceType]['reset'] - time.time())
                log.warning('Waiting %s seconds for Github rate limit...', waitTime)
                time.sleep(waitTime)
                rateLimitInfo = self.gh.rate_limit()['resources']
        except ConnectionError as e:
            log.error("Connection error while querying GitHub rate limit. Retrying...")
            self.waitForRateLimit(resourceType)

    def refreshGithubUser(self, ghUserObject):
        self.waitForRateLimit('core')
        return ghUserObject.refresh(True)

    def getGithubUserForLogin(self, login):
        """Uses the Github API to find the user for the given username. Returns NullObject if the user was not found for any reason."""
        try:
            potentialUser = self.gh.user(login)
            if potentialUser is None:
                return NullObject()
            return self.refreshGithubUser(potentialUser)
        except ConnectionError:
            log.error("github query failed when attempting to verify username %s", login)
            return NullObject()

    def searchGithubUsers(self, query):
        self.waitForRateLimit('search')
        return self.gh.search_users(query)
