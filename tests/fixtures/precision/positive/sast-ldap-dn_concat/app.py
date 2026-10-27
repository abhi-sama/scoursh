dn = "cn=" + request.args["user"]
ldap.bind(dn, password)
