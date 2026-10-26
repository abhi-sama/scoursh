// Synthetic JavaScript object and argument references.
export function configure(
  password = suppliedPassword, // [[N301]]
  token = readToken(), // [[N302]]
) {
  return {
    password: formPassword, // [[N303]]
    token: session.accessToken, // [[N304]]
    apiKey: settings.apiKey, // [[N305]]
  };
}
const token = `Bearer ${session.token}`; // [[N306]]
