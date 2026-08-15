# tests/fixtures/vuln/ldap_app.py - true-positive fixture for
# modules/sast/rules/ldap.rules (tests/suites/sast.sh), the python-ldap shapes.
# One snippet per rule id this file covers, kept well apart so no rule's
# context window leaks into a neighbouring snippet.

import ldap

BASE = "ou=users,dc=example,dc=com"


def find_user(conn, username):
    query = "(uid=" + username + ")"
    return conn.search_s(BASE, ldap.SCOPE_SUBTREE, query)


def bind_user(conn, username, credential):
    dn = "cn=" + username + ",ou=users,dc=example,dc=com"
    return conn.simple_bind_s(dn, credential)
