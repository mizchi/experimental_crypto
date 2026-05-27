// Proof-carrying digit-modulus helper for `mizchi/totp`.
//
// RFC 4226 §5.3 (HOTP) reduces the 31-bit dynamic truncation `bin` modulo
// `10^digits` to produce the final OTP. RFC 6238 (TOTP) inherits the same
// rule. The accepted digit counts are 6, 7, and 8 (the RFC publishes test
// vectors for all three). Getting the modulus wrong by a single factor of
// 10 silently turns a 6-digit OTP into a 5-digit OTP — exactly the kind of
// off-by-one a table check catches.

///|
/// Modulus `10^digits` for HOTP / TOTP code reduction. Domain restricted
/// to the three RFC-supported widths.
pub fn totp_digit_modulus(
  digits : Int,
) -> Int where {
  proof_require: digits == 6 || digits == 7 || digits == 8,
  proof_ensure: result => result >= 1000000,
  proof_ensure: result => result <= 100000000,
  proof_ensure: result => digits != 6 || result == 1000000,
  proof_ensure: result => digits != 7 || result == 10000000,
  proof_ensure: result => digits != 8 || result == 100000000,
} {
  if digits == 6 {
    1000000
  } else if digits == 7 {
    10000000
  } else {
    100000000
  }
}
