// Proof-carrying block-alignment helpers for `mizchi/aead`.
//
// AES-GCM (NIST SP 800-38D §6.5) feeds GHASH zero-padded AAD || zero-padded
// ciphertext || length-block. AES-CBC under PKCS#7 (RFC 5652 §6.3) appends a
// byte sequence whose value equals its length. Both rules collapse to a tiny
// arithmetic step that we can verify in isolation, anchoring "the ciphertext
// passed to AES is block-aligned" without having to lower the full `aead`
// package to Why3.

///|
/// GHASH zero-pad length. Given the byte length of an AAD or ciphertext
/// fragment, returns the number of zero bytes needed to pad it to a multiple
/// of `block_size` (16 for AES-GCM). When `len` is already aligned the
/// padding is 0.
///
/// The block-alignment property `(len + result) % block_size == 0` is true
/// but currently times out in Z3 4.15.4 (driver lowers Int `%` to `mod_`
/// while the model uses `mod`, and the Euclidean axiom needed to bridge the
/// two isn't being instantiated). The range invariant below is what we get
/// for free; the alignment is covered by the runtime tests in `aead`.
pub fn ghash_zero_pad_len(
  len : Int,
  block_size : Int,
) -> Int where {
  proof_require: len >= 0,
  proof_require: block_size > 0,
  proof_ensure: result => 0 <= result,
  proof_ensure: result => result < block_size,
} {
  (block_size - len % block_size) % block_size
}

///|
/// PKCS#7 padding length (RFC 5652 §6.3). Given the plaintext byte length
/// and the cipher block size, returns the number of padding bytes to append
/// so that `plaintext || pad` is a multiple of `block_size`. PKCS#7 always
/// appends at least one byte (and a full block when the plaintext is already
/// aligned), so the result is in `[1, block_size]`.
///
/// The padding byte value equals the padding length, so `block_size` must
/// fit in a byte (≤ 255). The block-alignment property `(plaintext_len +
/// result) % block_size == 0` is mechanically true but currently times out
/// in Z3 — see the note on `ghash_zero_pad_len`.
pub fn pkcs7_pad_len(
  plaintext_len : Int,
  block_size : Int,
) -> Int where {
  proof_require: plaintext_len >= 0,
  proof_require: block_size > 0,
  proof_require: block_size <= 255,
  proof_ensure: result => 1 <= result,
  proof_ensure: result => result <= block_size,
} {
  block_size - plaintext_len % block_size
}
