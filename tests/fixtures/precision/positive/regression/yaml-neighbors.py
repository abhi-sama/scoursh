safe = yaml.load(doc, Loader=yaml.SafeLoader); unsafe = yaml.load(request.data, Loader=yaml.Loader)
