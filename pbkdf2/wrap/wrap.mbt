// Proof-carrying block-count helper for `mizchi/pbkdf2`.
//
// RFC 8018 §5.2 defines PBKDF2 output as `T_1 || T_2 || … || T_l`, where
// `l = ⌈dkLen / hLen⌉` and the RFC caps `dkLen ≤ (2^32 - 1) · hLen` so the
// big-endian counter `INT(i)` fed into PRF(P, S || INT(i)) fits in 32 bits.
// In MoonBit's 32-bit `Int` we cannot literally write `(2^32 - 1) · hLen`,
// so this helper anchors the equivalent invariant up to `Int.max` and the
// caller (`mizchi/pbkdf2`) keeps the original RFC check.
//
// This is the PBKDF2 analogue of `mizchi/hkdf/wrap.hkdf_block_count`; the
// internal arithmetic is the same `⌈x/y⌉` pattern, but the input range
// and counter-width cap differ.

///|
/// Number of HMAC blocks PBKDF2 emits for the requested derived-key length.
/// Equivalent to `⌈dkLen / hLen⌉`. The result indexes the loop variable
/// `i ∈ [1, l]` in RFC 8018 §5.2 step 2, so its lower bound is 1 (whenever
/// `dkLen > 0`, which the caller already enforces).
pub fn pbkdf2_block_count(
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

///|
/// Total scratch-buffer size (bytes) PBKDF2's inner loop must allocate
/// to hold the full block-aligned output before the final truncation
/// step crops it back to `dk_len`. By construction this equals
/// `pbkdf2_block_count(dk_len, h_len) * h_len` — the proof anchors that
/// equivalence inline since `moon prove`'s logic body cannot call the
/// sister helper directly.
///
/// Anchors the caller-side allocation contract: `pbkdf2.derive` would
/// silently overflow or under-allocate if these two helpers ever drifted
/// out of sync.
pub fn pbkdf2_total_output_bytes(
  dk_len : Int,
  h_len : Int,
) -> Int where {
  proof_require: dk_len > 0,
  proof_require: h_len > 0,
  proof_require: dk_len <= 2147483647 - h_len,
  proof_ensure: result => dk_len <= result,
  proof_ensure: result => result < dk_len + h_len,
  proof_ensure: result => result % h_len == 0,
  proof_ensure: result => result == ((dk_len + h_len - 1) / h_len) * h_len,
} {
  ((dk_len + h_len - 1) / h_len) * h_len
}
