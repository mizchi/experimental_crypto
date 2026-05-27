// Proof-carrying SHA padding-length helpers for `mizchi/hash`.
//
// FIPS 180-4 §5.1 fixes the SHA-2 message-padding rule:
//
//   pad = 0x80 || zeros || big-endian length
//
// For SHA-256 the block size is 64 bytes and the trailing length field is
// 64 bits (8 bytes); for SHA-512 the block size is 128 bytes and the
// length is 128 bits (16 bytes). The padded message length must be a
// multiple of the block size — every SHA-2 caller in the workspace
// (HMAC, HKDF, PBKDF2, JWT, ECDSA-with-SHA, …) relies on this invariant
// when sizing scratch buffers and counting compression-function calls.
//
// Each helper returns the number of pad bytes (0x80 byte + zero pad +
// length field) appended to a message of `msg_bytes` bytes.

///|
/// SHA-256 padding length. `pad_len = total_pad_bytes` such that
/// `(msg_bytes + pad_len)` is divisible by 64.
///
/// The 9-byte minimum is `0x80 || 8-byte length`; the 72-byte maximum
/// occurs when `msg_bytes mod 64 == 56`, which forces an extra block.
pub fn sha256_pad_len(
  msg_bytes : Int,
) -> Int where {
  proof_require: 0 <= msg_bytes,
  proof_ensure: result => 9 <= result,
  proof_ensure: result => result <= 72,
  proof_ensure: result => (msg_bytes + result) % 64 == 0,
} {
  let r = msg_bytes % 64
  if r < 56 {
    64 - r
  } else {
    128 - r
  }
}

///|
/// SHA-512 padding length. `pad_len = total_pad_bytes` such that
/// `(msg_bytes + pad_len)` is divisible by 128.
///
/// The 17-byte minimum is `0x80 || 16-byte length`; the 144-byte maximum
/// occurs when `msg_bytes mod 128 == 112`, forcing an extra block.
pub fn sha512_pad_len(
  msg_bytes : Int,
) -> Int where {
  proof_require: 0 <= msg_bytes,
  proof_ensure: result => 17 <= result,
  proof_ensure: result => result <= 144,
  proof_ensure: result => (msg_bytes + result) % 128 == 0,
} {
  let r = msg_bytes % 128
  if r < 112 {
    128 - r
  } else {
    256 - r
  }
}
