import yaml
import ast


def handler(request):
    return ast.literal_eval(request.body)


def load(doc):
    return yaml.safe_load(doc)
