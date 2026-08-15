// tests/fixtures/vuln/ldap_app.java - true-positive fixture for
// modules/sast/rules/ldap.rules (tests/suites/sast.sh), the JNDI shapes.  One
// snippet per rule id this file covers, kept well apart so no rule's context
// window leaks into a neighbouring snippet.

import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

class LdapApp {

  NamingEnumeration<SearchResult> findUser(DirContext ctx, String username) throws Exception {
    String filter = "(&(objectClass=person)(uid=" + username + "))";
    return ctx.search("ou=users,dc=example,dc=com", filter, new SearchControls());
  }

  Object lookupUser(DirContext ctx, String username) throws Exception {
    String dn = "cn=" + username + ",ou=users,dc=example,dc=com";
    return ctx.lookup(dn);
  }
}
