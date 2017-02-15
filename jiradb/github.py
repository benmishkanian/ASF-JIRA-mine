import logging

import time

from github3 import login, GitHub
from github3.null import NullObject

from .schema import GitHubUserCache

log = logging.getLogger(__name__)


class GitHubDB(object):
    def __init__(self, ghtoken):
        # Get handle to Github API
        if ghtoken is not None and ghtoken != '':
            self.gh = login(token=ghtoken)
        else:
            log.warning('Using unauthenticated access to Github API. This will result in severe rate limiting.')
            self.gh = GitHub()

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

    def getGithubUserForLogin(self, login, session):
        """Uses the Github API to find the user for the given username. Returns NullObject if the user was not found for any reason."""
        # Try to use cached result to avoid hitting rate limit
        cachedUser = session.query(GitHubUserCache).filter(GitHubUserCache.login == login).first()
        if cachedUser is not None:
            return cachedUser if not cachedUser.fake else NullObject()
        log.debug('Querying GutHub API for login %s', login)
        try:
            self.waitForRateLimit('core')
            potentialUser = self.gh.user(login)
            if potentialUser is None:
                # store login as fake
                session.add(GitHubUserCache(login=login, fake=True))
                return NullObject()
            actualUser = self.refreshGithubUser(potentialUser)
            if isinstance(potentialUser, NullObject):
                # store login as fake
                session.add(GitHubUserCache(login=login, fake=True))
            else:
                # cache user
                session.add(GitHubUserCache(login=login, name=actualUser.name, email=actualUser.email, company=actualUser.company, location=actualUser.location))
            return actualUser
        except ConnectionError:
            log.error("github query failed when attempting to verify username %s", login)
            return NullObject()

    def searchGithubUsers(self, query):
        self.waitForRateLimit('search')
        return self.gh.search_users(query)
