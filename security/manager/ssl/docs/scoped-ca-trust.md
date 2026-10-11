# Domain-scoped CA trust

In Certificate Manager, edit a CA certificate and enable **Trust this CA only
for the listed domains** to limit that CA to specific TLS hostnames. Enter one
hostname or wildcard per line. A hostname such as `api.example.com` matches
only that hostname. A wildcard such as `*.example.com` matches one label, for
example `api.example.com`, but not `example.com` or `a.api.example.com`.

Names must be ASCII DNS names. Internationalized names must use their
ASCII-compatible encoding (A-label). Wildcards are allowed only at the start
of a name. Empty labels, trailing dots, ports, and other wildcard positions
are rejected.

Firefox stores policies in the string preference
`security.certificate_scoped_ca.policies`. Each line has a SHA-256 certificate
fingerprint followed by `=` and a comma-separated list of host rules:

```text
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef=api.example.com,*.internal.example
```

The fingerprint binds the rule to the exact CA certificate. Invalid or
duplicate rules for a valid fingerprint disable that scoped CA entry. The
Certificate Manager removes the CA's general TLS trust when scoped trust is
enabled, so missing or unreadable policy data cannot grant that CA general
trust. The CA is actively distrusted outside its configured domains.

Scoped trust only changes whether the selected CA can act as a trust anchor
for a matching hostname. Firefox still verifies the chain signatures,
hostname, certificate validity, key usage, revocation status, and other TLS
security requirements. Other certificates continue through the normal
verifier and trust store.
