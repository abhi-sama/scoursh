# Django dotted paths and enums.
TOKEN_MODEL = "authtoken.Token"  # [[N12]]
PUSH_CREDENTIALS = "aggregator.utils.push_credentials"  # [[N13]]
CLIENT_SECRET_BASIC = "client_secret_basic"  # [[N14]]
ACCOUNT_RATE_LIMITS = {"change_password": "5/m/user"}  # [[N15]]
FORM_CLASSES = {'change_password': 'allauth.account.forms.ChangePasswordForm'}  # [[N16]]
SECRET_KEY = "k3y-Tr0ub4dor3xK-s3cr3tT0kenV4lue"  # [[P02]]
