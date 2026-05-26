// Proof-carrying base64 line-wrap helper for `mizchi/pem`. RFC 7468 §3
// requires that strict-mode PEM emit no line longer than 64 base64
// characters. This package isolates the arithmetic step of the wrap loop
// so `moon prove` can discharge the line-cap invariant without having to
// lower the full `pem` package (which uses `Array` in `PemBlock.headers`
// and is therefore out of scope for the current Why3 frontend).

///|
/// RFC 7468 §3 strict-mode base64 line cap.
pub let pem_strict_line_max : Int = 64

///|
/// Decide how many base64 characters to emit on the next line when wrapping
/// a strict-mode PEM body. Returns `min(remaining, cap)`. This is the inner
/// step of `pem.encode`'s wrap loop. Proving this function once anchors:
///
///   * the RFC 7468 §3 invariant that no emitted line exceeds `cap`
///   * the loop's progress condition (when `cap > 0` and `remaining > 0`,
///     at least one byte is consumed per iteration so the loop terminates)
pub fn pem_next_chunk_len(
  remaining : Int,
  cap : Int,
) -> Int where {
  proof_require: remaining >= 0,
  proof_require: cap > 0,
  proof_ensure: result => 0 <= result,
  proof_ensure: result => result <= remaining,
  proof_ensure: result => result <= cap,
  proof_ensure: result => result == remaining || result == cap,
  proof_ensure: result => remaining == 0 || result > 0,
} {
  if remaining <= cap {
    remaining
  } else {
    cap
  }
}
