// Proof-carrying DER length-prefix size helper for `mizchi/asn1`.
//
// X.690 §8.1.3 says the length octets are either:
//   * short form (one octet, value 0..127), or
//   * long form (a leading 0x80 | n with n in 1..126, then n octets of
//     length, big-endian, with no leading zeros).
//
// In practice DER blobs we care about top out well under 2^31, so we cap
// the prefix at 5 bytes (1 leader + 4 length octets). Proving the byte
// count is monotone and stays within `[1, 5]` anchors the worst-case
// allocation size every `write_length` caller relies on.

///|
/// Number of octets `write_length` emits for a given length value.
///   n < 2^7  → 1   (short form)
///   n < 2^8  → 2   (0x81 + 1 byte)
///   n < 2^16 → 3   (0x82 + 2 bytes)
///   n < 2^24 → 4   (0x83 + 3 bytes)
///   n ≤ 2^31 - 1 → 5  (0x84 + 4 bytes)
pub fn der_length_prefix_size(
  n : Int,
) -> Int where {
  proof_require: n >= 0,
  proof_require: n <= 2147483647,
  proof_ensure: result => 1 <= result,
  proof_ensure: result => result <= 5,
  proof_ensure: result => n >= 128 || result == 1,
  proof_ensure: result => n < 128 || n >= 256 || result == 2,
  proof_ensure: result => n < 256 || n >= 65536 || result == 3,
  proof_ensure: result => n < 65536 || n >= 16777216 || result == 4,
  proof_ensure: result => n < 16777216 || result == 5,
} {
  if n < 128 {
    1
  } else if n < 256 {
    2
  } else if n < 65536 {
    3
  } else if n < 16777216 {
    4
  } else {
    5
  }
}
