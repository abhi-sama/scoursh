for (const key in source) {
  if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
  target[key] = source[key];
}
