# Unquoted assignment source controls

These synthetic JavaScript, TypeScript and JSX files model React/Next source
references, object properties, destructuring, function defaults and template
expressions. They are scanner inputs, not an application to build or execute.

N-tagged lines contain no literal credential. The P-tagged TypeScript literal
is fake, authenticates nothing, and must still be caught by the generic API
key rule. Its provider prefix is followed by an invalid provider character so
it cannot be mistaken for an issued credential by a repository secret gate. `sast-secrets-source` scans this tree through the real CLI alongside
the existing assignment-form matrix; it also exercises module extensions.
