# tests/fixtures/vuln/nosql_app.py - true-positive fixture for
# modules/sast/rules/nosql.rules (tests/suites/sast.sh), the PyMongo shapes.
# One snippet per rule id this file covers, kept well apart so no rule's
# context window leaks into a neighbouring snippet.

import json


def search_by_name(coll, request):
    query = {"$where": "this.name == '" + request.args["name"] + "'"}
    return coll.find(query)


def top_sellers(coll):
    return coll.map_reduce(
        "function () { emit(this.region, this.total); }",
        "function (key, values) { return Array.sum(values); }",
        "results",
    )


def login(coll, request):
    return coll.find_one(request.json)


def filter_from_raw(coll, raw):
    query = json.loads('{"owner": "' + raw + '"}')
    return coll.find(query)
