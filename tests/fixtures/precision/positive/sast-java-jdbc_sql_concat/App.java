class App { void f(Statement st,String user) { st.executeQuery("SELECT * FROM users WHERE name=" + user); } }
