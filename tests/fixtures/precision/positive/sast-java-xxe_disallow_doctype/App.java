class App { void f(String xml) { var factory = DocumentBuilderFactory.newInstance(); factory.newDocumentBuilder().parse(xml); } }
