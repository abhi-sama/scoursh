class App { void f() { ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(new byte[0])); in.readObject(); } }
