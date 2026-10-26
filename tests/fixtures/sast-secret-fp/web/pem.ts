// PEM helpers that name a header but carry no key material.
const PKCS8_HEADER = "-----BEGIN PRIVATE KEY-----"; // [[N10]]
export const isPem = (pem: string) => pem.includes("-----BEGIN RSA PRIVATE KEY-----"); // [[N11]]
