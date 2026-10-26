class Streams { void f() { ObjectInputStream safe = new ObjectInputStream(new ByteArrayInputStream(new byte[0])); safe.readObject(); } }
