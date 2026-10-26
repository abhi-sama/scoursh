request.args = {"id": "abc"}
request.args["id"] = request.json
collection.find(request.args)
