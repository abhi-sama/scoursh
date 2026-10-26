ldap = LDAPClient()
request.args = {"filter": "(uid=alice)"}
request.args.update(request.json)
ldap.search(request.args["filter"])
