# tests/fixtures/clean/nosql_app.py - true-negative (safe equivalent) fixture
# for modules/sast/rules/nosql.rules (tests/suites/sast.sh), one snippet per
# rule id in tests/fixtures/vuln/nosql_app.py, in the same order.  This file is
# also walked by the whole-tree gate test (scan.sh sast --fail-on high
# --fail-on-new against tests/fixtures/clean), so nothing below may trip any
# shipped rule, NoSQL-specific or language-agnostic, at any severity a linked
# pack assigns.
#
# The prose below describes each hazard rather than spelling it: the pattern
# engine has no comment awareness at all, so a comment quoting the dangerous
# operator would be a match, and this file would be a false positive against
# itself.


def search_by_name(coll, request):
    # An ordinary equality match on a field, with the supplied value coerced
    # to a string before it ever reaches the query document.
    name = str(request.args["name"])
    return coll.find({"name": name})


def top_sellers(coll):
    # Expressed with the aggregation pipeline's own accumulator operators, so
    # the server never runs JavaScript on this application's behalf.
    return coll.aggregate([{"$group": {"_id": "$region", "total": {"$sum": "$total"}}}])


def login(coll, request):
    # Both values are coerced to strings before they reach the query document,
    # so a supplied object cannot smuggle an operator into the filter.
    username = str(request.json.get("username", ""))
    password = str(request.json.get("password", ""))
    return coll.find_one({"username": username, "password": password})


def filter_from_raw(coll, raw):
    # The filter is assembled as a document with a bound value, rather than as
    # query text that is concatenated and then parsed back into a document.
    return coll.find({"owner": str(raw)})
