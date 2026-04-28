# Security Policy

Security is our top priority for `@hushboxapp/crypto`. If you find a security vulnerability, we'd appreciate it if you'd tell us about it right away.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately through [GitHub Security Advisories](https://github.com/hushboxapp/crypto-ts/security/advisories/new).

When reporting, please include:
- A description of the vulnerability.
- Steps to reproduce the issue.
- Potential impact.

We will acknowledge your report within 48 hours and work with you to resolve it.

## Supported Versions

Only the latest stable version of `@hushboxapp/crypto` is supported for security updates.

| Version | Supported |
| ------- | --------- |
| < 1.0.0 | No        |
| >= 1.0.0| Yes       |

## Our Commitment

We are committed to:
- Acknowledging security reports promptly.
- Investigating issues and providing a fix in a timely manner.
- Crediting researchers (with their permission) for their discoveries.

## Threat Model

`@hushboxapp/crypto` is a client-side library. The threat model assumes the
library runs in a browser or Node.js process whose memory and code path the
caller trusts; it does not protect against an attacker with execution access
to that environment.

### In scope

- **Confidentiality and integrity of ciphertext at rest or in transit.**
  Plaintext is encrypted under AES-GCM (256-bit) with random 12-byte IVs.
  An attacker who holds only the ciphertext, salt, and IV cannot recover
  plaintext or forge a tag without one of the protector passwords.
- **Authenticated parameter binding.** As of the v3 envelope, the
  threshold (`t`), hashing algorithm name, and Argon2id parameters
  (`iterations`, `memorySize`, `parallelism`, `hashLength`) are bound to
  every protector via AES-GCM additional authenticated data. Tampering
  with any of these fields in a serialized `EncryptedKey` causes
  decryption to fail.
- **Provider allowlisting on decode.** `EncryptedKey.decode` rejects
  envelopes that name an encryption, sharing, or hashing provider not in
  the configured allowlist, preventing attacker-chosen downgrade to a
  weaker scheme.
- **Multi-password reconstruction.** Shamir's Secret Sharing over
  GF(2^8) requires at least `t` of `n` correct passwords to reconstruct
  the master key. Sub-threshold attempts fail at the AES-GCM tag check.
- **Key material lifecycle.** `Key.dispose()` zeros the underlying
  `Uint8Array` and refuses further use. Callers should dispose keys as
  soon as they are no longer needed.

### Out of scope

- **Compromised host or runtime.** Memory dumps, malicious browser
  extensions, hostile JavaScript executing in the same realm, or a
  compromised Node.js process. Anything with execution access can read
  plaintext while it is in use.
- **Weak passwords.** Argon2id raises the cost of guessing but cannot
  rescue passwords with insufficient entropy. Callers are responsible
  for password policy and any rate limiting at the application layer.
- **Side-channel attacks.** The vendored Shamir core (see
  `src/sharing/shamir-core.ts`) contains constant-table lookups but
  branches on zero operands in field multiplication and division,
  leaking byte values via timing. The leak is benign in our flows
  because shares are wrapped in AES-GCM with AAD before persistence; a
  network attacker observes only ciphertext. Argon2id timing is
  similarly unprotected. A local timing-side-channel attacker has
  stronger primitives available.
- **Forward secrecy** beyond what AES-GCM provides. There is no key
  rotation primitive; rotating a master key requires re-encrypting the
  payload.
- **Denial of service via crafted inputs.** The library bounds `n` and
  `t` to `[2, 255]` and rejects empty secrets, but does not police
  caller-supplied Argon2id parameters or payload sizes. Callers should
  cap these at the application layer.

## Verifying Releases

Releases from v1.0.2 onward are published with
[npm provenance](https://docs.npmjs.com/generating-provenance-statements)
and signed by the npm registry. To verify:

```bash
npm audit signatures
```

This confirms the installed version of `@hushboxapp/crypto` was
published from this repository's `release-please` workflow and that the
tarball matches the registry signature. The provenance attestation is
also queryable directly at
`https://registry.npmjs.org/-/npm/v1/attestations/@hushboxapp/crypto@<version>`
and recorded in the public Sigstore transparency log.

## Hardening Guidance for Callers

- Tune Argon2id parameters to the strongest values the target device
  can sustain. The library's defaults favor desktop browsers; mobile
  devices or constrained Node.js environments may need lower values.
- Enforce password policy before passing passwords to `Key.encrypt`.
- Call `Key.dispose()` immediately after the master key has done its
  work. Avoid retaining decrypted keys in long-lived module state.
- Pin the encryption, sharing, and hashing allowlists when calling
  `EncryptedKey.decode` if your application does not need provider
  flexibility, narrowing the post-deployment attack surface.
