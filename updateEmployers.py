from jiradb import *


def waitForSearchQuota(jiradb):
    if not jiradb.googleSearchEnabled:
        jiradb.session.commit()
        log.warn('Exhausted search quota. Waiting a day...')
        time.sleep(60 * 60 * 24)
        jiradb.googleSearchEnabled = True


if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    # Add console log handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(message)s'))
    log.addHandler(ch)
    # Add file log handler
    fh = logging.FileHandler('updateEmployers.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('[%(levelname)s @ %(asctime)s]: %(message)s'))
    log.addHandler(fh)
    # Add error file log handler
    efh = logging.FileHandler('updateEmployersErrors.log')
    efh.setLevel(logging.ERROR)
    efh.setFormatter(logging.Formatter('[%(levelname)s @ %(asctime)s]: %(message)s'))
    log.addHandler(efh)

    args = getArguments()
    jiradb = JIRADB(**args)
    projectList = args['projects']
    for project in projectList:
        log.info('Updating employers for contributors to project ' + project)
        accountProjectRows = jiradb.getImportantAccounts(project, 0.80)
        for accountProjectRow in accountProjectRows:
            log.debug('Updating employer of ' + accountProjectRow.displayName)
            # update googlecache rows
            time.sleep(10)
            jiradb.getLinkedInEmployer(accountProjectRow.displayName, project)
            waitForSearchQuota(jiradb)
        # flush DB
        jiradb.session.commit()
    log.info('Done updating employers for all contributors for all projects')
