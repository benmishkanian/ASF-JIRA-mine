"""
jiradb._internal_utils
~~~~~~~~~~~~~~

Provides utility functions that are used internally by jiradb modules.
"""


def equalsIgnoreCase(s1, s2):
    if s1 is None:
        return s2 is None
    if s2 is None:
        return s1 is None
    return s1.lower() == s2.lower()