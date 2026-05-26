// SHA-384 (FIPS 180-4) — SHA-512 inner loop with a different IV and a 48-byte
// truncated output. Self-contained, NOT constant-time.

///|
let sha384_h0 : FixedArray[UInt64] = [
  0xcbbb9d5dc1059ed8UL, 0x629a292a367cd507UL, 0x9159015a3070dd17UL, 0x152fecd8f70e5939UL,
  0x67332667ffc00b31UL, 0x8eb44a8768581511UL, 0xdb0c2e0d64f98fa7UL, 0x47b5481dbefa4fa4UL,
]

///|
/// SHA-384 of `data`. Returns the 48-byte digest.
pub fn sha384(data : Bytes) -> Bytes {
  let state = FixedArray::make(8, 0UL)
  for i = 0; i < 8; i = i + 1 {
    state[i] = sha384_h0[i]
  }
  sha512_core_hash(data, state)
  // SHA-384 output = first 6 state words (48 bytes).
  let out = FixedArray::make(48, b'\x00')
  for i = 0; i < 6; i = i + 1 {
    u64_to_u8be(state[i], out, i * 8)
  }
  Bytes::makei(48, fn(j) { out[j] })
}
