// tests/fixtures/clean/ldap_app.js - true-negative (safe equivalent) fixture
// for modules/sast/rules/ldap.rules (tests/suites/sast.sh), one snippet per
// rule id in tests/fixtures/vuln/ldap_app.js, in the same order.  This file is
// also walked by the whole-tree gate test (scan.sh sast --fail-on high
// --fail-on-new against tests/fixtures/clean), so nothing below may trip any
// shipped rule, LDAP-specific or language-agnostic, at any severity a linked
// pack assigns.
//
// The prose below describes each hazard rather than spelling it: the pattern
// engine has no comment awareness at all, so a comment quoting an unescaped
// filter would be a match, and this file would be a false positive against
// itself.

const ldap = require('ldapjs');
const ldapEscape = require('ldap-escape');

function searchByFilter(client, req) {
  // The filter is a fixed expression owned by this application, and the one
  // value interpolated into it is escaped on the same expression, so the
  // caller supplies a value rather than a filter.
  const filter = ldapEscape.filter`(uid=${req.query.user})`;
  return client.search('ou=users,dc=example,dc=com', { filter: filter, scope: 'sub' });
}
