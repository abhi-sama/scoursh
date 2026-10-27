class App { void f(ExpressionParser parser,HttpServletRequest req) { String expression = req.getParameter("expr"); parser.parseExpression(expression); } }
