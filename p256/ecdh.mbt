// ECDH (elliptic-curve Diffie-Hellman) key agreement on P-256 / secp256r1.
//
// This is the key-exchange counterpart to the ECDSA sign/verify already in
// this package. It is the primitive TLS ECDHE, ECDH-ES (JWE), WebPush
// (RFC 8291) and the Web Crypto `ECDH` algorithm are built on.

///|
/// Compute the ECDH shared secret `d · peer` and return its X coordinate as a
/// 32-byte big-endian field element (SEC 1 §3.3.1 / RFC 5903 §3.1: the shared
/// secret is the x-coordinate of the common point).
///
/// Input validation: `peer` is guaranteed to be a valid, on-curve, non-identity
/// point because a `PublicKey` can only be constructed via
/// `from_uncompressed` / `from_spki_der`, both of which reject off-curve and
/// malformed encodings. P-256 has cofactor 1, so there are no small-subgroup
/// points to screen, and `d · peer` is never the identity for `d ∈ [1, n)`
/// (enforced by `PrivateKey::from_bytes`). This is the check that defeats
/// invalid-curve attacks, and it lives at the type boundary rather than here.
///
/// Side-channel note: this uses the fixed-iteration complete-addition Montgomery
/// ladder — the same path as base-point multiplication in signing — so the
/// secret scalar is processed without secret-dependent branches. It is not yet
/// backed by external leakage measurement; see `docs/CONSTANT_TIME.md`.
pub fn PrivateKey::ecdh(self : PrivateKey, peer : PublicKey) -> Bytes {
  let shared = fe_mont_point_to_affine(
    fe_mont_scalar_mult_fixed_complete(
      self.d,
      fe_mont_point_from_affine(peer.point),
    ),
  )
  shared.x.to_octets(length=32)
}
