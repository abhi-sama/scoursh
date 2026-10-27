# Calls, attribute references, subscripts, keyword arguments, classes and
# constants assigned to credential-named variables: none is a literal.
class SignupForm(forms.Form):
    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)  # [[N17]]


def login(request):
    password = request.POST.get("password")  # [[N18]]
    secret_manager_client = secretmanager_v1.SecretManagerServiceClient()  # [[N19]]
    search_tokens = re.findall(r"\w+", text)  # [[N20]]
    token_generator = EmailAwarePasswordResetTokenGenerator  # [[N21]]
    id_token_issuer = ID_TOKEN_ISSUER  # [[N22]]
    credential = form.cleaned_data["credential"]  # [[N23]]
    secret = settings.SECRET_KEY  # [[N43]]
    return authenticate(
        token=instance,  # [[N24]]
        password=pf.read(),  # [[N25]]
    )


class TokenSerializer:
    access_token = serializers.CharField(read_only=True)  # [[Q01]]
    token: Optional[str] = None  # [[Q02]]
