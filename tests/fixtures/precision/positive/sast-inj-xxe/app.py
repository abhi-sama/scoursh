parser = etree.XMLParser(resolve_entities=True)
root = etree.fromstring(request.data, parser)
