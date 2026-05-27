// Proof-carrying PBKDF2 block-count helper for `mizchi/scrypt`.
//
// scrypt (RFC 7914 §2) sandwiches the memory-hard ROMix between two
// PBKDF2-HMAC-SHA256 calls:
//   step 1:  B = PBKDF2(P, S,    1, p * 128 * r)
//   step 4:  DK = PBKDF2(P, B', 1, dkLen)
// Both call sites depend on the same `⌈out_len / hLen⌉` block count we
// already anchored in `pbkdf2/wrap`, but expressing it again here keeps
// the scrypt-side contract local: a future refactor of pbkdf2's proof
// can't silently widen the scrypt invariant without also touching this
// file.

///|
/// Number of PBKDF2-HMAC-SHA256 blocks the final scrypt step emits for
/// the requested derived-key length. Identical shape to
/// `mizchi/pbkdf2/wrap.pbkdf2_block_count` — this entry exists so the
/// scrypt-side spec stays self-contained.
pub fn scrypt_pbkdf_blocks(
  dk_len : Int,
  h_len : Int,
) -> Int where {
  proof_require: dk_len > 0,
  proof_require: h_len > 0,
  proof_require: dk_len <= 2147483647 - h_len,
  proof_ensure: result => 1 <= result,
  proof_ensure: result => (result - 1) * h_len < dk_len,
  proof_ensure: result => dk_len <= result * h_len,
} {
  (dk_len + h_len - 1) / h_len
}
