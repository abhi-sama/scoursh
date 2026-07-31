import yaml, os


def handler(request):
    # three byte-identical matches of one check in one file: the occurrence
    # discriminator (docs/FOUNDATION.md tension 5) has to tell them apart
    a = eval(request.body)
    b = eval(request.body)
    c = eval(request.body)
    return a, b, c


# two DIFFERENT secrets in one file must produce two distinct fingerprints and
# two distinct redaction digests
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12"
aws_secret_access_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def load(doc):
    return yaml.load(doc)
