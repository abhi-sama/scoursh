// tests/fixtures/clean/nosql_app.java - true-negative (safe equivalent)
// fixture for modules/sast/rules/nosql.rules (tests/suites/sast.sh), one
// snippet per rule id in tests/fixtures/vuln/nosql_app.java, in the same
// order.  This file is also walked by the whole-tree gate test (scan.sh sast
// --fail-on high --fail-on-new against tests/fixtures/clean), so nothing below
// may trip any shipped rule, NoSQL-specific or language-agnostic, at any
// severity a linked pack assigns.
//
// The prose below describes each hazard rather than spelling it: the pattern
// engine has no comment awareness at all, so a comment quoting the dangerous
// operator would be a match, and this file would be a false positive against
// itself.

import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import org.bson.Document;

class NoSqlApp {

  Document findByOwner(MongoCollection<Document> coll, String owner) {
    // The filter is assembled from the driver's own builders with the value
    // bound as data, never as query text that is concatenated and parsed.
    return coll.find(Filters.eq("owner", owner)).first();
  }

  Document findByName(MongoCollection<Document> coll, String name) {
    // An ordinary equality match on a field, so no part of the supplied value
    // is handed to the server as an expression to evaluate.
    return coll.find(Filters.eq("name", name)).first();
  }
}
