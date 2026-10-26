class App { void f(Object root,HttpServletRequest req) { Ognl.getValue(req.getParameter("expr"), root); } }
