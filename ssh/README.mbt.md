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
- `allowed_signers` lookup for principals, glob principals, and
  `namespaces="..."` constraints.

Fail-closed surface:

- `cert-authority` entries are rejected because SSH certificates are not
  implemented.
- `valid-after` / `valid-before` entries are rejected because verification is
  not time-aware.
- Unknown or duplicate `allowed_signers` options are rejected rather than
  ignored.
