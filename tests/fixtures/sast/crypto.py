# tests/fixtures/sast/crypto.py - true-positive fixture for
# modules/sast/rules/crypto.rules (tests/suites/sast.sh).

import hashlib


def weak_hash(data):
    return hashlib.md5(data).hexdigest()


CIPHER_MODE = "AES/ECB/PKCS5Padding"

iv = "0123456789abcdef0123456789abcdef"

session = requests.Session()
session.verify = False

# Math.random() near a "token" mention within the default context-window: 3.
def make_token():
    return Math.random()
