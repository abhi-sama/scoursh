// tests/fixtures/clean/nosql_app.js - true-negative (safe equivalent) fixture
// for modules/sast/rules/nosql.rules (tests/suites/sast.sh), one snippet per
// rule id in tests/fixtures/vuln/nosql_app.js, in the same order.  This file
// is also walked by the whole-tree gate test (scan.sh sast --fail-on high
// --fail-on-new against tests/fixtures/clean), so nothing below may trip any
// shipped rule, NoSQL-specific or language-agnostic, at any severity a linked
// pack assigns.
//
// The prose below describes each hazard rather than spelling it: the pattern
// engine has no comment awareness at all, so a comment quoting the dangerous
// operator would be a match, and this file would be a false positive against
// itself.

const { MongoClient } = require('mongodb');

function searchByName(coll, req) {
  // An ordinary equality match on a field, so no part of the supplied value
  // is handed to the server as an expression to evaluate.
  const name = String(req.query.name);
  const filter = { name: name };
  return coll.find(filter);
}

function activeAccounts(coll) {
  // Expressed entirely with the aggregation pipeline's own comparison
  // operators, so the server never runs JavaScript on this application's
  // behalf.
  return coll.aggregate([{ $match: { $expr: { $eq: ['$status', 'active'] } } }]);
}

function login(coll, req) {
  // Both values are coerced to strings before they reach the query document,
  // so a supplied object cannot smuggle an operator into the filter.
  const username = String(req.body.username);
  const password = String(req.body.password);
  return coll.findOne({ username: username, password: password });
}

function filterFromRawQuery(coll, raw) {
  // The filter is assembled as a document with a bound value, rather than as
  // query text that is concatenated and then parsed back into a document.
  return coll.find({ owner: String(raw) });
}
