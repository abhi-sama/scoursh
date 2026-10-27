// Synthetic React/Next-style controls; no live credentials.
export function Login({ pwd, session, t, onSubmit, initialPassword }) {
  const apiKey = process.env.SERVICE_KEY; // [[N101]]
  const headers = { Authorization: `Bearer ${t}` }; // [[N102]]
  const request = {
    password: initialPassword, // [[N103]]
    token: session.token, // [[N104]]
  };
  return <form onSubmit={onSubmit}>
    <input type="password" /> {/* [[N105]] */}
    <CredentialInput
      password={pwd} // [[N106]]
      token={session.token} // [[N107]]
      headers={{ Authorization: `Bearer ${t}` }} // [[N108]]
    />
  </form>;
}
