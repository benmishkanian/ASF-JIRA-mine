import pythonwhois

from ._internal_utils import equalsIgnoreCase
from jiradb.database import WhoisError, log, WHOIS_OBFUSCATORS
from jiradb.schema import WhoisCache


def isEmailDomainAdmin(session, contributorEmail, domain, contributorName):
    """
    Checks if the given contributor is the administrator of the domain of their email address. Note that this
    algorithm is not foolproof--there may be false positives or false negatives.

    :param session: the database session
    :param contributorName: the contributor's real name
    :param contributorEmail: the contributor's email address
    :param domain: the domain name to check
    :return: true if the contributor owns the domain of this email address, false if they seem not to, and None if the query failed.
    """
    # Check for personal domain
    usingPersonalEmail = None
    # Try to get domain info from cache
    whoisCacheRow = session.query(WhoisCache).filter(WhoisCache.domain == domain).first()
    if whoisCacheRow is None:
        # Run a WHOIS query
        adminEmail = None
        adminName = None
        try:
            whoisInfo = pythonwhois.get_whois(domain)

            if whoisInfo['contacts'] is not None and whoisInfo['contacts']['admin'] is not None and 'admin' in \
                    whoisInfo['contacts']:
                adminEmail = whoisInfo['contacts']['admin']['email'] if 'email' in whoisInfo['contacts'][
                    'admin'] else None
                adminName = whoisInfo['contacts']['admin']['name'] if 'name' in whoisInfo['contacts'][
                    'admin'] else None
                errorEnum = WhoisError.NO_ERR
            else:
                errorEnum = WhoisError.NO_CONTACT_INFO
        except pythonwhois.shared.WhoisException as e:
            log.warning('Error in WHOIS query for %s: %s. Assuming non-commercial domain.', domain, e)
            # we assume that a corporate domain would have been more reliable than this
            errorEnum = WhoisError.CONFIGURATION_ERR
        except ConnectionResetError as e:
            # this is probably a rate limit or IP ban, which is typically something only corporations do
            log.warning('Error in WHOIS query for %s: %s. Assuming commercial domain.', domain, e)
            errorEnum = WhoisError.CONNECTION_RESET_ERR
        except UnicodeDecodeError as e:
            log.warning(
                'UnicodeDecodeError in WHOIS query for %s: %s. No assumption will be made about domain.',
                domain, e)
            errorEnum = WhoisError.UNICODE_DECODE_ERR
        except Exception as e:
            log.warning('Unexpected error in WHOIS query for %s: %s. No assumption will be made about domain.',
                        domain, e)
            errorEnum = WhoisError.UNKNOWN_ERR
        whoisCacheRow = WhoisCache(domain=domain, adminName=adminName, adminEmail=adminEmail, error=errorEnum.value)
        session.add(whoisCacheRow)
    if whoisCacheRow.error == WhoisError.CONFIGURATION_ERR.value:
        usingPersonalEmail = True
    elif whoisCacheRow.error == WhoisError.CONNECTION_RESET_ERR.value:
        usingPersonalEmail = False
    elif whoisCacheRow.error == WhoisError.NO_ERR.value:
        # Check for an identity match, or whether they are using the WHOIS obfuscator "whoisproxy"
        # Check if they are using a WHOIS obfuscation service
        for obfuscator in WHOIS_OBFUSCATORS:
            if contributorEmail.endswith(obfuscator):
                usingPersonalEmail = True
                break
        if not usingPersonalEmail:
            # Check if they own their email domain
            usingPersonalEmail = equalsIgnoreCase(whoisCacheRow.adminName,
                                                  contributorName) or equalsIgnoreCase(
                whoisCacheRow.adminEmail, contributorEmail)
    else:
        usingPersonalEmail = None
    return usingPersonalEmail
