// Synthetic source references, including multiline function arguments.
export function connect(
  password = readPassword(), // [[N201]]
  apiKey = getApiKey(), // [[N202]]
) {
  const {
    password = initialPassword, // [[N203]]
    token = sessionToken, // [[N204]]
  } = options;
  const auth = {
    password: credentials.password, // [[N205]]
    apiKey: credentialProvider(), // [[N206]]
  };
  return auth;
}
// Fake planted positive: an issued-looking literal must still be detected.
export const API_KEY = "sk_live_!scoursh_synthetic_canary_42"; // [[P201]]
