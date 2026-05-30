# mizchi/ed25519

> **Status: experimental.** Built to fill a gap in the MoonBit ecosystem;
> not production-grade. The implementation has not been independently
> audited. If you use it, review the source yourself — the author
> disclaims all liability. Prefer a vetted library where one exists.


Ed25519 (RFC 8032 §5.1) signature scheme over Edwards Curve25519.

## Memory hygiene

`PrivateKey::sign` makes a best-effort attempt to zero
seed-derived intermediates before returning: the SHA-512(seed)
hash, the 32-byte signing prefix, and the two SHA-512 outputs
`r_hash` / `k_hash` are overwritten in their `FixedArray[Byte]`
backing storage.

Several sign-side secrets are **not** fully wipe-able from MoonBit:

- Internal heap allocated while reducing `a_scalar`, `r`, `k`, and
  `S` with `crypto_bigint.Uint`. The visible limb arrays are wiped
  on a best-effort basis, but intermediate copies may live behind
  the GC.
- The SHA-512 working state reachable through the (now
  out-of-scope) `SHA512::new()` contexts. The arrays are
  GC-managed and reclaimed at the GC's discretion.

This is best-effort only — MoonBit gives no guarantee against
compiler dead-store elimination, and the GC may have already
relocated copies before the wipe runs.

## Security Disclaimer ⚠️

This implementation of these cryptographic algorithms is provided without any
security endorsement or professional certification. The experimental_crypto
project should be considered:

- An educational reference implementation
- Experimental cryptography software
- Not reviewed by third-party security experts
