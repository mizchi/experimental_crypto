# mizchi/pgp> **Status: experimental.** Built to fill a gap in the MoonBit ecosystem;
> not production-grade. The implementation has not been independently
> audited. If you use it, review the source yourself — the author
> disclaims all liability. Prefer a vetted library where one exists.

`parse_pubkey_armor` extracts the primary public key material from a
`PUBLIC KEY BLOCK`; it is not an OpenPGP trust-management API. It does not
evaluate User ID self-signatures, revocations, trust signatures, or subkey
binding signatures. Ambiguous transferable-key envelopes such as multiple
primary keys, leading non-key packets, or unsupported packet types are rejected
before any key material is returned.

Sign-side external interop is intentionally narrow: v4 Ed25519 exports a
minimal transferable public key verified by `gpg --verify`, and v6 Ed25519
exports a minimal RFC 9580 key plus Direct Key self-signature verified by
Sequoia `sq verify`.
