// tests/fixtures/clean/app.java - true-negative (safe equivalent) fixture for
// modules/sast/rules/java.rules (tests/suites/sast.sh), one snippet per rule
// id in tests/fixtures/vuln/app.java, in the same order. This file is also
// walked by the whole-tree gate test (scan.sh sast --fail-on high
// --fail-on-new against tests/fixtures/clean), so nothing below may trip any
// shipped rule, Java-specific or language-agnostic, at any severity a linked
// pack assigns.

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.springframework.expression.ExpressionParser;
import com.fasterxml.jackson.databind.ObjectMapper;

class App {

  void findUser(Connection conn, String id) throws Exception {
    PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
    ps.setString(1, id);
    ResultSet rs = ps.executeQuery();
  }

  void parseUpload(byte[] userInput) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    DocumentBuilder builder = dbf.newDocumentBuilder();
    builder.parse(new ByteArrayInputStream(userInput));
  }

  Object loadSession(byte[] blob) throws Exception {
    return new ObjectMapper().readValue(blob, SessionData.class);
  }

  X509TrustManager trustAll(X509TrustManager defaultTrustManager) {
    return new X509TrustManager() {
      public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        defaultTrustManager.checkClientTrusted(chain, authType);
      }
      public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        defaultTrustManager.checkServerTrusted(chain, authType);
      }
      public X509Certificate[] getAcceptedIssuers() { return defaultTrustManager.getAcceptedIssuers(); }
    };
  }

  HostnameVerifier allowAllHostnames() {
    return new HostnameVerifier() {
      public boolean verify(String hostname, SSLSession session) {
        return HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session);
      }
    };
  }

  Object evalSpel(ExpressionParser parser) {
    return parser.parseExpression("#root.name").getValue();
  }

  Object evalOgnl(SomeBean root) {
    return root.getName();
  }
}
