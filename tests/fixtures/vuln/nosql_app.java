// tests/fixtures/vuln/nosql_app.java - true-positive fixture for
// modules/sast/rules/nosql.rules (tests/suites/sast.sh), the MongoDB Java
// driver shapes.  One snippet per rule id this file covers, kept well apart so
// no rule's context window leaks into a neighbouring snippet.

import com.mongodb.client.MongoCollection;
import org.bson.Document;

class NoSqlApp {

  Document findByOwner(MongoCollection<Document> coll, String owner) {
    Document filter = Document.parse("{ \"owner\": \"" + owner + "\" }");
    return coll.find(filter).first();
  }

  Document findByName(MongoCollection<Document> coll, String name) {
    Document filter = new Document("$where", "this.name == '" + name + "'");
    return coll.find(filter).first();
  }
}
