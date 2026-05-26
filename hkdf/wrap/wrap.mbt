// Proof-carrying block-count helper for `mizchi/hkdf`.
//
// RFC 5869 §2.3 caps HKDF-Expand output at `L ≤ 255 * HashLen`, because the
// expand step concatenates `T(1) || T(2) || … || T(N)` with `N = ⌈L/HashLen⌉`
// and the counter byte that feeds each `T(i)` is one byte wide. This helper
// pins down the exact relationship between `L`, `HashLen`, and the block
// count `N` so the security-relevant cap survives any refactoring of the
// expand loop.

///|
/// Number of HMAC blocks HKDF-Expand emits for the requested output length.
/// Equivalent to `⌈L / hash_len⌉`. The RFC 5869 cap requires `L ≤ 255 *
/// hash_len`, and the helper rejects anything outside that range; callers
/// in `mizchi/hkdf` perform the same check before invoking this.
pub fn hkdf_block_count(
  l : Int,
  hash_len : Int,
) -> Int where {
  proof_require: l > 0,
  proof_require: hash_len > 0,
  proof_require: l <= 255 * hash_len,
  proof_ensure: result => 1 <= result,
  proof_ensure: result => result <= 255,
  proof_ensure: result => (result - 1) * hash_len < l,
  proof_ensure: result => l <= result * hash_len,
} {
  (l + hash_len - 1) / hash_len
}
