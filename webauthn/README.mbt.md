# webauthn

> **EXPERIMENTAL — not production-grade. Audit before use. No warranty.**

Pure-MoonBit **verification** for WebAuthn (W3C Level 2) / FIDO2 — the
verify-side composition of the workspace: CBOR (`cose_cbor`), the COSE_Key and
authenticatorData formats, the EC/EdDSA verifiers (`p256` / `p384` /
`ed25519`), and `pkix` / `pkix_verify` for attestation certificates.

## Status

- **Assertion** (`verify_assertion`): verifies the credential signature over
  `authenticatorData || clientDataHash`.
- **Attestation** (`verify_attestation`): parses the attestationObject and
  verifies the statement for `packed` (x5c and self-attestation), `fido-u2f`,
  and `none`. Returns the credential to register plus the x5c trust path.
- **authenticatorData** (`parse_authenticator_data`): rpIdHash, flags
  (UP / UV / AT), signCount, and the attested credential data (aaguid,
  credentialId, COSE_Key).
- **COSE_Key** (`parse_cose_key`): ES256 (P-256), ES384 (P-384), EdDSA
  (Ed25519). RS256 (e.g. Windows Hello) is not yet supported.
- **clientDataJSON** (`verify_client_data`): binds `type`, `challenge`, and
  `origin` (anti-phishing / anti-replay).

Verified against real Yubico python-fido2 test vectors: a `fido-u2f` and a
`packed` attestation that cryptographically verify (and are rejected when the
clientDataHash is tampered), plus authenticatorData / COSE_Key parsing and a
self-consistent ES256 assertion.

Certificate-chain trust (x5c → a trusted root / FIDO Metadata Service) is the
caller's job, as with TLS: `verify_attestation` returns the `trust_path` for
`pkix_verify`. Not yet implemented: RS256 credential keys, the `tpm`,
`android-key`, `android-safetynet`, and `apple` attestation formats, and
extension processing.
