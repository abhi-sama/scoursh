data = request.form.to_dict()
request.form = {"display_name": data.get("display_name", "")}
profile.update(**request.form)
