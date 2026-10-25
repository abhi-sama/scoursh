// Synthetic JSX props and destructuring defaults.
export function Form({
  password = initialPassword, // [[N401]]
  token = defaultToken, // [[N402]]
}) {
  return <CredentialInput
    password={password} // [[N403]]
    type="password" // [[N404]]
    token={token} // [[N405]]
  />;
}
