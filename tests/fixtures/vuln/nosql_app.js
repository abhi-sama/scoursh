// tests/fixtures/vuln/nosql_app.js - true-positive fixture for
// modules/sast/rules/nosql.rules (tests/suites/sast.sh), the MongoDB Node
// driver / Mongoose shapes.  Mirrors tests/fixtures/vuln/app.js's shape: one
// snippet per rule id this file covers, kept well apart so no rule's context
// window leaks into a neighbouring snippet.
//
// Nothing here may reach a rule owned by another pack: this file is walked by
// every shipped SAST pack, not only by nosql.rules.

const { MongoClient } = require('mongodb');

function searchByName(coll, req) {
  const filter = { $where: "this.name == '" + req.query.name + "'" };
  return coll.find(filter);
}

function activeAccounts(coll) {
  return coll.aggregate([{ $match: { $expr: { $function: { body: 'function (s) { return s; }', args: ['$status'], lang: 'js' } } } }]);
}

function login(coll, req) {
  return coll.findOne({ username: req.body.username, password: req.body.password });
}

function filterFromRawQuery(coll, raw) {
  const filter = JSON.parse('{"owner": "' + raw + '"}');
  return coll.find(filter);
}
