from jiradb import *

if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    # Add console log handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(message)s'))
    log.addHandler(ch)
    # Add file log handler
    fh = logging.FileHandler('buildNetwork.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('[%(levelname)s @ %(asctime)s]: %(message)s'))
    log.addHandler(fh)
    # Add error file log handler
    efh = logging.FileHandler('buildNetworkErrors.log')
    efh.setLevel(logging.ERROR)
    efh.setFormatter(logging.Formatter('[%(levelname)s @ %(asctime)s]: %(message)s'))
    log.addHandler(efh)

    args = getArguments()
    jiradb = JIRADB(**args)
    projectList = args['projects']
    missedCommitsDict = jiradb.buildCompanyProjectNetwork(projectList, 0.80)
    for key in missedCommitsDict:
        log.info('%s/%s commits were missed in project %s', missedCommitsDict[key][0], missedCommitsDict[key][1], key)
