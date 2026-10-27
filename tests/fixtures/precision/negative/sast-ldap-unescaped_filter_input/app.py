ldap = LDAPClient()
request.args = {"filter": "(uid=alice)"}
ldap.search(request.args["filter"])
