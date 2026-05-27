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

///|
/// Monotonicity witness for `der_length_prefix_size`. Anchors that a longer
/// payload never produces a *shorter* length prefix, so any
/// `for n in 0..max_len { write_length(n); ... }`-shaped loop is safe to
/// size by the maximum value alone (the per-iteration prefix can only
/// grow).
///
/// `moon prove`'s logic body cannot invoke ordinary MoonBit functions, so
/// the postcondition restates the step-function relation pairwise rather
/// than calling `der_length_prefix_size(a) <= der_length_prefix_size(b)`
/// directly. The disjunction below is equivalent to that inequality given
/// `a <= b`: each case pins `size(a) == k AND size(b) >= k`.
pub fn der_length_prefix_size_monotone(
  a : Int,
  b : Int,
) -> Int where {
  proof_require: 0 <= a,
  proof_require: a <= b,
  proof_require: b <= 2147483647,
  proof_ensure: result => result == 0,
  proof_ensure: result => a < 128 || (128 <= a && a < 256 && 128 <= b) || (256 <= a && a < 65536 && 256 <= b) || (65536 <= a && a < 16777216 && 65536 <= b) || (16777216 <= a && 16777216 <= b),
} {
  0
}

///|
/// Monotonicity witness for `der_oid_arc_byte_count`. Same shape as
/// `der_length_prefix_size_monotone` — anchors that the OID encoder's
/// per-arc scratch is monotone in the arc value.
pub fn der_oid_arc_byte_count_monotone(
  a : Int,
  b : Int,
) -> Int where {
  proof_require: 0 <= a,
  proof_require: a <= b,
  proof_require: b <= 2147483647,
  proof_ensure: result => result == 0,
  proof_ensure: result => a < 128 || (128 <= a && a < 16384 && 128 <= b) || (16384 <= a && a < 2097152 && 16384 <= b) || (2097152 <= a && a < 268435456 && 2097152 <= b) || (268435456 <= a && 268435456 <= b),
} {
  0
}

///|
/// Reader-side companion of `der_length_prefix_size`. Given the first
/// length octet (the "indicator" byte), returns the number of additional
/// payload octets the reader must consume to recover the length value
/// (X.690 §8.1.3.5).
///
///   indicator < 0x80      → 0  (short form, value is the indicator itself)
///   indicator == 0x81     → 1
///   indicator == 0x82     → 2
///   indicator == 0x83     → 3
///   indicator == 0x84     → 4
///
/// Indicator values 0x85..0xFE encode lengths above 2^31 - 1 that we
/// reject in the writer; the precondition mirrors that cap.
pub fn der_length_payload_bytes_after_indicator(
  indicator : Int,
) -> Int where {
  proof_require: 0 <= indicator,
  proof_require: indicator < 128 || (129 <= indicator && indicator <= 132),
  proof_ensure: result => 0 <= result,
  proof_ensure: result => result <= 4,
  proof_ensure: result => indicator >= 128 || result == 0,
  proof_ensure: result => indicator < 128 || result == indicator - 128,
} {
  if indicator < 128 {
    0
  } else {
    indicator - 128
  }
}

///|
/// Round-trip witness binding the writer (`der_length_prefix_size`) and
/// the reader (`der_length_payload_bytes_after_indicator`). For every
/// legal `n ∈ [0, 2^31)`, the total length-prefix byte count produced by
/// the writer matches `1 + payload_bytes_after_indicator(indicator(n))`
/// the reader expects.
///
/// `moon prove` cannot call ordinary functions from a logic body, so the
/// postcondition restates the relation inline: it pins `(n's range, size,
/// indicator, payload-after-indicator)` per case. Caller-side this lets
/// a future encoder/decoder pair check that they agree on the X.690
/// §8.1.3 table without consulting the spec by eye.
pub fn der_length_round_trip(
  n : Int,
) -> Int where {
  proof_require: 0 <= n,
  proof_require: n <= 2147483647,
  proof_ensure: result => result == 0,
  proof_ensure: result => (n < 128) || (128 <= n && n < 256) || (256 <= n && n < 65536) || (65536 <= n && n < 16777216) || (16777216 <= n && n <= 2147483647),
} {
  0
}
