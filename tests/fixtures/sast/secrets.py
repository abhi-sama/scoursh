# tests/fixtures/sast/secrets.py - true-positive fixture for
# modules/sast/rules/secrets.rules (tests/suites/sast.sh).

AWS_KEY = "AKIAABCDEFGHIJKLMNOP"

PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvPEMBODYMARKERONEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END RSA PRIVATE KEY-----
"""

api_key = "sk_live_9f8e7d6c5b4a3f2e1d0c9b8a"

password = "correcthorsebattery"

# A placeholder value: the context-deny (context-window: 0) must suppress
# this one, proving F4's same-line-intent discipline works as designed.
password = "CHANGEME_PLACEHOLDER"

session_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYE_juyQlOzk"
