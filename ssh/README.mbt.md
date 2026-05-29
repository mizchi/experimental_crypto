# mizchi/ssh

> **Status: experimental.** Built to fill a gap in the MoonBit ecosystem;
> not production-grade. The implementation has not been independently
> audited. If you use it, review the source yourself — the author
> disclaims all liability. Prefer a vetted library where one exists.

This package is a conservative SSHSIG-style subset for git-signing flows.
It does not claim OpenSSH compatibility.

Supported surface:

- SSHSIG armor encode/decode with strict boundary checks.
- Ed25519, ECDSA P-256/P-384, and RSA SHA-2 signature verification.
- OpenSSH user certificates embedded in SSHSIG, when validated through a
  caller-trusted `cert-authority` CA key in `allowed_signers`.
- `allowed_signers` lookup for principals, glob principals, and
  `namespaces="..."` constraints.
- Time-aware `allowed_signers` verification via
  `verify_with_allowed_signers_at`, with `valid-after` / `valid-before`
  and certificate validity windows evaluated against caller-supplied Unix time.

Fail-closed surface:

- `cert-authority` entries are rejected by the plain
  `verify_with_allowed_signers` API because certificate validity requires an
  explicit verification time.
- SSH certificates with unsupported key types, non-user certificate type,
  untrusted CA keys, unknown critical options, malformed option/extension
  sequences, invalid CA signatures, or principal/time mismatches are rejected.
- The plain `verify_with_allowed_signers` API rejects entries carrying
  `valid-after` / `valid-before`; use the explicit time-aware API instead.
- Unknown or duplicate `allowed_signers` options are rejected rather than
  ignored.
