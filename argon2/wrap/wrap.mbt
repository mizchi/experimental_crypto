// Proof-carrying segment-length helper for `mizchi/argon2`.
//
// Argon2 (RFC 9106 §3.2) lays out memory as a `lanes × 4-segments` grid
// and fills it column-major. Each segment holds `segment_length` blocks
// where:
//
//   segment_length = floor(m_cost / (4 * lanes))
//   m' = 4 * lanes * segment_length   (the actual memory used; may be
//                                      slightly less than m_cost)
//
// The RFC requires `m_cost >= 8 * lanes` so every segment holds at
// least two blocks (the second-block-onwards rule of the indexing
// function presumes this). Proving the closed form pins down:
//
//   * segment_length >= 2  (matches the indexing function's assumption)
//   * 4 * lanes * segment_length <= m_cost  (no overrun of caller's m_cost)
//   * 4 * lanes * (segment_length + 1) > m_cost  (segment_length is floor)
//
// SYNC_POINTS = 4 is hard-coded by §3.4 and not parametrised.

///|
/// Number of memory blocks in each of the four segments per lane.
/// `m_cost` is in KiB blocks (1 KiB = one Argon2 block), `lanes` is the
/// parallelism degree.
pub fn argon2_segment_length(
  m_cost : Int,
  lanes : Int,
) -> Int where {
  proof_require: lanes >= 1,
  proof_require: lanes <= 16777215,
  proof_require: m_cost >= 8 * lanes,
  proof_require: m_cost <= 1073741824,
  proof_ensure: result => result >= 2,
  proof_ensure: result => 4 * lanes * result <= m_cost,
  proof_ensure: result => 4 * lanes * (result + 1) > m_cost,
} {
  m_cost / (4 * lanes)
}
