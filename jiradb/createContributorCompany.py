from jiradb.database import *

if __name__ == "__main__":
    log.setLevel(logging.DEBUG)
    # Add console log handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(message)s'))
    log.addHandler(ch)
    # Add file log handler
    fh = logging.FileHandler('buildContributorCompany.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('[%(levelname)s @ %(asctime)s]: %(message)s'))
    log.addHandler(fh)
    # Add error file log handler
    efh = logging.FileHandler('buildContributorCompanyErrors.log')
    efh.setLevel(logging.ERROR)
    efh.setFormatter(logging.Formatter('[%(levelname)s @ %(asctime)s]: %(message)s'))
    log.addHandler(efh)

    args = getArguments()
    jiradb = JIRADB(**args)
    projectList = args['projects']
    jiradb.buildContributorCompanyTable(projectList, 0.80)
    log.info('Done updating contributorcompanies for all contributors for all projects')
