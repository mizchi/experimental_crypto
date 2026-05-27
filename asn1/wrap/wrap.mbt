// Proof-carrying DER byte-count helpers for `mizchi/asn1`.
//
// X.690 §8.1.3 says the length octets are either:
//   * short form (one octet, value 0..127), or
//   * long form (a leading 0x80 | n with n in 1..126, then n octets of
//     length, big-endian, with no leading zeros).
//
// X.690 §8.19 says each OID sub-identifier (arc) is encoded as a
// base-128 varint: 7 bits per byte, MSB=1 on continuation, MSB=0 on the
// last byte, no leading zeros.
//
// Both rules fix the byte count as a step function of the value, and in
// practice the values we care about stay below 2^31, so the byte count
// fits in `[1, 5]` for both. Proving the step function anchors the
// worst-case allocation size every `write_length` / OID encoder caller
// relies on.

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

///|
/// Number of base-128 varint octets `write_oid` emits for a single OID arc.
///   arc < 2^7  → 1
///   arc < 2^14 → 2
///   arc < 2^21 → 3
///   arc < 2^28 → 4
///   arc ≤ 2^31 - 1 → 5
/// Used by the OID encoder to size its scratch buffer before serialising
/// each sub-identifier (X.690 §8.19).
pub fn der_oid_arc_byte_count(
  arc : Int,
) -> Int where {
  proof_require: arc >= 0,
  proof_require: arc <= 2147483647,
  proof_ensure: result => 1 <= result,
  proof_ensure: result => result <= 5,
  proof_ensure: result => arc >= 128 || result == 1,
  proof_ensure: result => arc < 128 || arc >= 16384 || result == 2,
  proof_ensure: result => arc < 16384 || arc >= 2097152 || result == 3,
  proof_ensure: result => arc < 2097152 || arc >= 268435456 || result == 4,
  proof_ensure: result => arc < 268435456 || result == 5,
} {
  if arc < 128 {
    1
  } else if arc < 16384 {
    2
  } else if arc < 2097152 {
    3
  } else if arc < 268435456 {
    4
  } else {
    5
  }
}
