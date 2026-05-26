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

Several sign-side secrets are **not** wipe-able from MoonBit:

- `a_scalar`, `r`, `k`, and any internal heap allocated by
  `BigInt` arithmetic — `BigInt` exposes no programmatic clear
  and may live as immutable boxed words behind the GC.
- The SHA-512 working state reachable through the (now
  out-of-scope) `SHA512::new()` contexts. The arrays are
  GC-managed and reclaimed at the GC's discretion.

This is best-effort only — MoonBit gives no guarantee against
compiler dead-store elimination, and the GC may have already
relocated copies before the wipe runs.
