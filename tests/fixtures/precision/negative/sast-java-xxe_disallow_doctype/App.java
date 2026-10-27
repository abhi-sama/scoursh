class App { void f() { var factory = DocumentBuilderFactory.newInstance();





factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); } }
