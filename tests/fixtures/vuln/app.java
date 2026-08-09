// tests/fixtures/vuln/app.java - true-positive fixture for
// modules/sast/rules/java.rules (tests/suites/sast.sh), one snippet per rule
// id. Mirrors tests/fixtures/vuln/app.js's shape: one combined file, snippets
// kept well apart so no rule's context-require/context-deny window (max 3
// lines here) leaks into a neighboring snippet.

import java.io.ObjectInputStream;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.springframework.expression.ExpressionParser;
import ognl.Ognl;

class App {

  void findUser(Statement stmt, String id) throws Exception {
    String query = "SELECT * FROM users WHERE id = " + id;
    ResultSet rs = stmt.executeQuery(query);
  }

  void parseUpload(byte[] userInput) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = dbf.newDocumentBuilder();
    builder.parse(new ByteArrayInputStream(userInput));
  }

  Object loadSession(byte[] blob) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(blob));
    return ois.readObject();
  }

  X509TrustManager trustAll() {
    return new X509TrustManager() {
      public void checkClientTrusted(X509Certificate[] chain, String authType) {}
      public void checkServerTrusted(X509Certificate[] chain, String authType) {}
      public X509Certificate[] getAcceptedIssuers() { return null; }
    };
  }

  HostnameVerifier allowAllHostnames() {
    return new HostnameVerifier() {
      public boolean verify(String hostname, SSLSession session) { return true; }
    };
  }

  Object evalSpel(ExpressionParser parser, String userExpression) {
    return parser.parseExpression(userExpression).getValue();
  }

  Object evalOgnl(String userExpression, Object root) throws Exception {
    return Ognl.getValue(userExpression, root);
  }
}
