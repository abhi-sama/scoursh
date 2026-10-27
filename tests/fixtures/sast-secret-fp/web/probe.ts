// Real credentials on lines that also carry a URL, an arrow function, a
// negative number or a boolean: the line-wide guards used to drop all four.
const a = new Client({ apiKey: "s3cr3tT0kenV4lue0000", baseURL: "https://api.vendor.invalid/v1" }); // [[R01]]
export const handler = async () => fetch(url, { headers: { "x-api-key": "s3cr3tT0kenV4lue0000" } }); // [[R02]]
const c = { password: "Tr0ub4dor3xK", retries: -1 }; // [[R03]]
const d = { token: "s3cr3tT0kenV4lue0000", enabled: true }; // [[R04]]
const e = { password: "Tr0ub4dor3xK" }; // [[P01]]
