# Domain-scoped CA trust

In Certificate Manager, edit a CA certificate and enable **Trust this CA only
for the listed domains** to restrict its TLS trust to hostname patterns. Enter
one regular expression per line. Each expression is matched case-insensitively
against the entire hostname. For example, this matches any hostname ending in
`.ir`:

```regex
(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ir
```

## GitHub sitelist feed

The browser downloads and installs the Kogitsune CA sitelist automatically on
first startup in a clean profile, without general website trust. The main
application menu has a **Domain-scoped CA certificates** panel with the active
CA status and a shortcut to manage certificates or add another scoped CA. A failed initial
download is retried hourly while the browser is running. The Authorities tab
also has a manual import action; its review dialog shows the certificate
fingerprint and rules before installation. Automatic refresh checks the feed
daily. The last downloaded manifest is cached in
the profile at `security/kogitsune-sitelist.json`; the last valid local policy
remains active if a refresh fails. Use **Stop automatic updates** in the CA
trust dialog to keep the current patterns and manage them locally.

The feed is JSON with version 1, one PEM certificate, its SHA-256 fingerprint,
an exact-hostname allow list, and optional hostname regular expressions:

```json
{
  "version": 1,
  "certificateFingerprintSHA256": "lowercase SHA-256 hex",
  "certificatePEM": "-----BEGIN CERTIFICATE-----...",
  "hostnames": ["service.example.com"],
  "hostnamePatterns": ["pattern per entry"]
}
```

Hostnames are exact DNS names. Entries in `hostnamePatterns` are matched as
case-insensitive regular expressions against the entire hostname. A hostname is
allowed when it matches either list; both lists may be empty only if the feed
also supplies at least one entry in the other list.

The browser pins the expected fingerprint so a feed update cannot silently
replace the CA certificate. The feed can update its hostname patterns, which
changes the domains covered by this CA's trust.

Firefox stores manual policies in the string preference
`security.certificate_scoped_ca.policies`. Each line contains a SHA-256
certificate fingerprint followed by `=` and one regular expression:

```text
0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef=api\\.example\\.com
```

Malformed policies do not grant trust. Scoped trust only changes whether the
selected CA can act as a trust anchor for a matching hostname. Firefox still
checks chain signatures, hostname, certificate validity, key usage, revocation
status, and other TLS requirements. Other certificates continue through the
normal verifier and trust store.
