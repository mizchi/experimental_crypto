// Proof-carrying chunk-length helper for `mizchi/getrandom`.
//
// OS-level CSPRNG syscalls cap the per-call request size:
//   Linux getrandom(2): 256 bytes for blocking, 1 page otherwise (RFC-ish
//                       reading of `man 2 getrandom` — kernel may return
//                       short).
//   macOS / *BSD arc4random_buf: 4096 bytes per call.
//   Windows BCryptGenRandom: ~ 2^31 bytes (practically unlimited).
//
// The loop that fills a longer buffer reduces by `min(remaining, cap)`
// each iteration. Proving the inner step anchors:
//   * no read overruns the OS cap
//   * the loop terminates whenever `cap > 0` and `remaining > 0`
// without having to bring any Bytes / syscall types into Why3.
//
// Structurally identical to `mizchi/pem/wrap.pem_next_chunk_len`; the
// duplicate exists so the getrandom-side contract stays self-contained.

///|
/// Decide how many bytes to request from the OS CSPRNG on the next
/// syscall, given the remaining gap and the backend cap. Returns
/// `min(remaining, cap)`.
pub fn getrandom_chunk_len(
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
