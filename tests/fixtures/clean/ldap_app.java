// tests/fixtures/clean/ldap_app.java - true-negative (safe equivalent) fixture
// for modules/sast/rules/ldap.rules (tests/suites/sast.sh), one snippet per
// rule id in tests/fixtures/vuln/ldap_app.java, in the same order.  This file
// is also walked by the whole-tree gate test (scan.sh sast --fail-on high
// --fail-on-new against tests/fixtures/clean), so nothing below may trip any
// shipped rule, LDAP-specific or language-agnostic, at any severity a linked
// pack assigns.
//
// The prose below describes each hazard rather than spelling it: the pattern
// engine has no comment awareness at all, so a comment quoting an unescaped
// filter would be a match, and this file would be a false positive against
// itself.

import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

class LdapApp {

  NamingEnumeration<SearchResult> findUser(DirContext ctx, String username) throws Exception {
    // Every metacharacter in the supplied value is escaped on the same
    // expression that builds the filter, so the value can only ever be
    // compared as data.
    String filter = "(&(objectClass=person)(uid=" + escapeLDAPSearchFilter(username) + "))";
    return ctx.search("ou=users,dc=example,dc=com", filter, new SearchControls());
  }

  Object lookupUser(DirContext ctx, String username) throws Exception {
    // The entry's distinguished name comes back from the escaped search above
    // rather than being assembled from the supplied value.
    SearchResult entry = findUser(ctx, username).next();
    return ctx.lookup(entry.getNameInNamespace());
  }
}
