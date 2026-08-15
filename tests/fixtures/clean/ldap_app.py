# tests/fixtures/clean/ldap_app.py - true-negative (safe equivalent) fixture
# for modules/sast/rules/ldap.rules (tests/suites/sast.sh), one snippet per
# rule id in tests/fixtures/vuln/ldap_app.py, in the same order.  This file is
# also walked by the whole-tree gate test (scan.sh sast --fail-on high
# --fail-on-new against tests/fixtures/clean), so nothing below may trip any
# shipped rule, LDAP-specific or language-agnostic, at any severity a linked
# pack assigns.
#
# The prose below describes each hazard rather than spelling it: the pattern
# engine has no comment awareness at all, so a comment quoting an unescaped
# filter would be a match, and this file would be a false positive against
# itself.

import ldap
from ldap.filter import filter_format

BASE = "ou=users,dc=example,dc=com"


def find_user(conn, username):
    # A fixed filter template whose one value is bound through python-ldap's
    # own escaping helper, so a metacharacter in the supplied value cannot
    # change the filter's structure.
    query = filter_format("(uid=%s)", [username])
    return conn.search_s(BASE, ldap.SCOPE_SUBTREE, query)


def bind_user(conn, username, credential):
    # The account's distinguished name is read back from the entry the escaped
    # search above returned, rather than assembled from the supplied value.
    entries = find_user(conn, username)
    dn = entries[0][0]
    return conn.simple_bind_s(dn, credential)
