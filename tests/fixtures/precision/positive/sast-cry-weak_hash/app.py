password_digest = hashlib.md5(request.form["password"].encode()).hexdigest()
