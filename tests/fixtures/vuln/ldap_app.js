// tests/fixtures/vuln/ldap_app.js - true-positive fixture for
// modules/sast/rules/ldap.rules (tests/suites/sast.sh), the ldapjs shapes.
// One snippet per rule id this file covers, kept well apart so no rule's
// context window leaks into a neighbouring snippet.

const ldap = require('ldapjs');

function searchByFilter(client, req) {
  return client.search('ou=users,dc=example,dc=com', { filter: req.query.filter, scope: 'sub' });
}
