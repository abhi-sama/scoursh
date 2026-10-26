class App { void f(Socket s) { ObjectInputStream in = new ObjectInputStream(s.getInputStream()); in.readObject(); } }
