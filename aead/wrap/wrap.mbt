// Proof-carrying primitives for `mizchi/aead`.
//
// AES-GCM (NIST SP 800-38D §6.5) feeds GHASH zero-padded AAD || zero-padded
// ciphertext || length-block. AES-CBC under PKCS#7 (RFC 5652 §6.3) appends a
// byte sequence whose value equals its length. Both rules collapse to a tiny
// arithmetic step that we can verify in isolation, anchoring "the ciphertext
// passed to AES is block-aligned" without having to lower the full `aead`
// package to Why3.
//
// FIPS 197 §5.1 fixes the AES round count and key-expansion word count as a
// function of the key length; getting either wrong silently produces a
// different cipher, so the table is pinned down here too.

///|
/// GHASH zero-pad length. Given the byte length of an AAD or ciphertext
/// fragment, returns the number of zero bytes needed to pad it to a multiple
/// of `block_size` (16 for AES-GCM). When `len` is already aligned the
/// padding is 0.
pub fn ghash_zero_pad_len(
  len : Int,
  block_size : Int,
) -> Int where {
  proof_require: len >= 0,
  proof_require: block_size > 0,
  proof_ensure: result => result == ghash_zero_pad_len_logic(len, block_size),
  proof_ensure: result => aead_block_aligned(len, block_size, result),
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
/// fit in a byte (≤ 255).
pub fn pkcs7_pad_len(
  plaintext_len : Int,
  block_size : Int,
) -> Int where {
  proof_require: plaintext_len >= 0,
  proof_require: block_size > 0,
  proof_require: block_size <= 255,
  proof_ensure: result => result == pkcs7_pad_len_logic(plaintext_len, block_size),
  proof_ensure: result => aead_block_aligned(plaintext_len, block_size, result),
  proof_ensure: result => 1 <= result,
  proof_ensure: result => result <= block_size,
} {
  block_size - plaintext_len % block_size
}

///|
/// AES round count `Nr` (FIPS 197 §5.1 Table 4):
///   AES-128 → Nr = 10, AES-192 → Nr = 12, AES-256 → Nr = 14.
/// Anchors the key-schedule loop bound `for i in 0..<(Nr+1)` and the
/// round-key array size `(Nr+1) * 4` 32-bit words. Getting `Nr` wrong by
/// one would silently produce a different cipher, so the table is pinned.
pub fn aes_round_count(
  key_bits : Int,
) -> Int where {
  proof_require: aes_keysize_valid(key_bits),
  proof_ensure: result => result == aes_round_count_logic(key_bits),
} {
  if key_bits == 128 {
    10
  } else if key_bits == 192 {
    12
  } else {
    14
  }
}

///|
/// AES key-schedule word count `Nk` (FIPS 197 §5.2):
///   AES-128 → Nk = 4, AES-192 → Nk = 6, AES-256 → Nk = 8.
/// `Nk` is the number of 32-bit words in the cipher key and the first
/// `Nk` indices the key-expansion loop copies verbatim before deriving
/// the rest of the round keys.
pub fn aes_key_word_count(
  key_bits : Int,
) -> Int where {
  proof_require: aes_keysize_valid(key_bits),
  proof_ensure: result => result == aes_key_word_count_logic(key_bits),
} {
  if key_bits == 128 {
    4
  } else if key_bits == 192 {
    6
  } else {
    8
  }
}
