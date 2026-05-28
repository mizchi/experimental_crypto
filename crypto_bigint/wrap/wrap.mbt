// Proof-carrying limb-count helper for `mizchi/crypto_bigint`.
//
// RSA/JWE private operations convert fixed-width byte strings into
// fixed-limb `Uint` values with `ceil(byte_len / 8)` limbs. Under-counting
// drops high bytes; over-counting changes allocation and measured private-op
// shape. Keep the arithmetic contract here small enough for `moon prove`.

///|
/// Number of 64-bit limbs required to losslessly pack a non-empty byte string.
pub fn limb_count_for_bytes(
  byte_len : Int,
) -> Int where {
  proof_require: byte_len > 0,
  proof_require: byte_len <= 2147483640,
  proof_ensure: result => result == limb_count_for_bytes_logic(byte_len),
  proof_ensure: result => result >= 1,
  proof_ensure: result => (result - 1) * 8 < byte_len,
  proof_ensure: result => byte_len <= result * 8,
} {
  (byte_len + 7) / 8
}

///|
/// Byte capacity provided by `limb_count_for_bytes(byte_len)` limbs.
pub fn limb_capacity_bytes(
  byte_len : Int,
) -> Int where {
  proof_require: byte_len > 0,
  proof_require: byte_len <= 2147483640,
  proof_ensure: result => result == limb_capacity_bytes_logic(byte_len),
  proof_ensure: result => byte_len <= result,
  proof_ensure: result => result < byte_len + 8,
  proof_ensure: result => result % 8 == 0,
} {
  (byte_len + 7) / 8 * 8
}
