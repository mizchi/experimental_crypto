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

///|
/// RFC 6238 §4.2 time-step counter using `Int` for proofability:
/// `T = floor((now - T0) / step)`.
pub fn totp_time_bucket(
  now_seconds : Int,
  step_seconds : Int,
  t0 : Int,
) -> Int where {
  proof_require: step_seconds > 0,
  proof_require: now_seconds >= t0,
  proof_ensure: result => result >= 0,
  proof_ensure: result => result * step_seconds <= now_seconds - t0,
  proof_ensure: result => now_seconds - t0 < (result + 1) * step_seconds,
} {
  (now_seconds - t0) / step_seconds
}

///|
/// Monotonicity witness for `totp_time_bucket`: later accepted times cannot
/// map to an earlier TOTP counter when `step_seconds > 0`.
pub fn totp_time_bucket_delta(
  earlier_seconds : Int,
  later_seconds : Int,
  step_seconds : Int,
  t0 : Int,
) -> Int where {
  proof_require: step_seconds > 0,
  proof_require: t0 <= earlier_seconds,
  proof_require: earlier_seconds <= later_seconds,
  proof_ensure: result => result >= 0,
} {
  (later_seconds - t0) / step_seconds - (earlier_seconds - t0) / step_seconds
}
