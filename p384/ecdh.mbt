// ECDH (elliptic-curve Diffie-Hellman) key agreement on P-384 / secp384r1.
//
// Key-exchange counterpart to the ECDSA sign/verify in this package; the
// primitive TLS ECDHE and ECDH-ES (JWE) over P-384 are built on.

///|
/// Compute the ECDH shared secret `d · peer` and return its X coordinate as a
/// 48-byte big-endian field element (SEC 1 §3.3.1 / RFC 5903 §3.1).
///
/// Input validation: `peer` is guaranteed on-curve and non-identity because a
/// `PublicKey` is only constructible via `from_uncompressed` / `from_spki_der`,
/// both of which reject off-curve and malformed encodings. P-384 has cofactor
/// 1, so `d · peer` is never the identity for `d ∈ [1, n)` (enforced by
/// `PrivateKey::from_bytes`). This is the invalid-curve-attack guard, enforced
/// at the type boundary rather than here.
///
/// Side-channel note: uses the fixed-iteration complete-addition field ladder
/// (same path as base-point multiplication in signing), so the secret scalar is
/// processed without secret-dependent branches. Not yet externally validated as
/// constant-time; see `docs/CONSTANT_TIME.md`.
pub fn PrivateKey::ecdh(self : PrivateKey, peer : PublicKey) -> Bytes {
  let shared = fe384_point_to_affine(
    fe384_scalar_mult_fixed_complete(
      self.d,
      fe384_point_from_affine(peer.point),
    ),
  )
  shared.x.to_octets(length=48)
}
