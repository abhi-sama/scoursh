env = jinja2.Environment(autoescape=False)
return env.from_string(request.args["html"]).render()
