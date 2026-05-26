// ChaCha20 stream cipher (RFC 8439 §2.3).
//
// Self-contained implementation: no dependency on moonbitlang/x/crypto.
// The block function is hand-unrolled — each of the 10 double-rounds expands
// to 8 inlined quarter-rounds (16 ops each), so the inner loop body is
// roughly 128 32-bit operations and `chacha20_block` contains no internal
// function calls.
//
// State layout (16 × UInt32):
//   s0..s3   : constants "expand 32-byte k"
//   s4..s11  : key (little-endian 32-bit words)
//   s12      : block counter
//   s13..s15 : nonce (little-endian 32-bit words)
//
// This is not constant-time. Same caveat as the rest of the aead package.

///|
fn load_le_u32(b : Bytes, off : Int) -> UInt {
  b[off].to_uint() |
  (b[off + 1].to_uint() << 8) |
  (b[off + 2].to_uint() << 16) |
  (b[off + 3].to_uint() << 24)
}

///|
fn rotl_u32(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
/// Generate one 64-byte ChaCha20 keystream block.
///
/// The double-round is fully inlined: 8 quarter-rounds (4 column + 4 diagonal)
/// per iteration, looped 10 times. No `fn` call overhead inside the loop body.
fn chacha20_block(
  key : Bytes,
  nonce : Bytes,
  counter : UInt,
  out : FixedArray[Byte],
  out_off : Int,
) -> Unit {
  // Initial state.
  let i0 : UInt = 0x61707865U
  let i1 : UInt = 0x3320646eU
  let i2 : UInt = 0x79622d32U
  let i3 : UInt = 0x6b206574U
  let i4 = load_le_u32(key, 0)
  let i5 = load_le_u32(key, 4)
  let i6 = load_le_u32(key, 8)
  let i7 = load_le_u32(key, 12)
  let i8 = load_le_u32(key, 16)
  let i9 = load_le_u32(key, 20)
  let i10 = load_le_u32(key, 24)
  let i11 = load_le_u32(key, 28)
  let i12 = counter
  let i13 = load_le_u32(nonce, 0)
  let i14 = load_le_u32(nonce, 4)
  let i15 = load_le_u32(nonce, 8)

  // Working state.
  let mut s0 = i0
  let mut s1 = i1
  let mut s2 = i2
  let mut s3 = i3
  let mut s4 = i4
  let mut s5 = i5
  let mut s6 = i6
  let mut s7 = i7
  let mut s8 = i8
  let mut s9 = i9
  let mut s10 = i10
  let mut s11 = i11
  let mut s12 = i12
  let mut s13 = i13
  let mut s14 = i14
  let mut s15 = i15

  // 10 double-rounds (20 rounds total). Each iteration: 4 column QRs + 4
  // diagonal QRs, fully inlined for no call overhead.
  for _round in 0..<10 {
    // Column round.
    // QR(0, 4, 8, 12)
    s0 = s0 + s4
    s12 = rotl_u32(s12 ^ s0, 16)
    s8 = s8 + s12
    s4 = rotl_u32(s4 ^ s8, 12)
    s0 = s0 + s4
    s12 = rotl_u32(s12 ^ s0, 8)
    s8 = s8 + s12
    s4 = rotl_u32(s4 ^ s8, 7)
    // QR(1, 5, 9, 13)
    s1 = s1 + s5
    s13 = rotl_u32(s13 ^ s1, 16)
    s9 = s9 + s13
    s5 = rotl_u32(s5 ^ s9, 12)
    s1 = s1 + s5
    s13 = rotl_u32(s13 ^ s1, 8)
    s9 = s9 + s13
    s5 = rotl_u32(s5 ^ s9, 7)
    // QR(2, 6, 10, 14)
    s2 = s2 + s6
    s14 = rotl_u32(s14 ^ s2, 16)
    s10 = s10 + s14
    s6 = rotl_u32(s6 ^ s10, 12)
    s2 = s2 + s6
    s14 = rotl_u32(s14 ^ s2, 8)
    s10 = s10 + s14
    s6 = rotl_u32(s6 ^ s10, 7)
    // QR(3, 7, 11, 15)
    s3 = s3 + s7
    s15 = rotl_u32(s15 ^ s3, 16)
    s11 = s11 + s15
    s7 = rotl_u32(s7 ^ s11, 12)
    s3 = s3 + s7
    s15 = rotl_u32(s15 ^ s3, 8)
    s11 = s11 + s15
    s7 = rotl_u32(s7 ^ s11, 7)
    // Diagonal round.
    // QR(0, 5, 10, 15)
    s0 = s0 + s5
    s15 = rotl_u32(s15 ^ s0, 16)
    s10 = s10 + s15
    s5 = rotl_u32(s5 ^ s10, 12)
    s0 = s0 + s5
    s15 = rotl_u32(s15 ^ s0, 8)
    s10 = s10 + s15
    s5 = rotl_u32(s5 ^ s10, 7)
    // QR(1, 6, 11, 12)
    s1 = s1 + s6
    s12 = rotl_u32(s12 ^ s1, 16)
    s11 = s11 + s12
    s6 = rotl_u32(s6 ^ s11, 12)
    s1 = s1 + s6
    s12 = rotl_u32(s12 ^ s1, 8)
    s11 = s11 + s12
    s6 = rotl_u32(s6 ^ s11, 7)
    // QR(2, 7, 8, 13)
    s2 = s2 + s7
    s13 = rotl_u32(s13 ^ s2, 16)
    s8 = s8 + s13
    s7 = rotl_u32(s7 ^ s8, 12)
    s2 = s2 + s7
    s13 = rotl_u32(s13 ^ s2, 8)
    s8 = s8 + s13
    s7 = rotl_u32(s7 ^ s8, 7)
    // QR(3, 4, 9, 14)
    s3 = s3 + s4
    s14 = rotl_u32(s14 ^ s3, 16)
    s9 = s9 + s14
    s4 = rotl_u32(s4 ^ s9, 12)
    s3 = s3 + s4
    s14 = rotl_u32(s14 ^ s3, 8)
    s9 = s9 + s14
    s4 = rotl_u32(s4 ^ s9, 7)
  }

  // Add initial state.
  let w0 = s0 + i0
  let w1 = s1 + i1
  let w2 = s2 + i2
  let w3 = s3 + i3
  let w4 = s4 + i4
  let w5 = s5 + i5
  let w6 = s6 + i6
  let w7 = s7 + i7
  let w8 = s8 + i8
  let w9 = s9 + i9
  let w10 = s10 + i10
  let w11 = s11 + i11
  let w12 = s12 + i12
  let w13 = s13 + i13
  let w14 = s14 + i14
  let w15 = s15 + i15

  // Serialize little-endian into out[out_off..out_off+64].
  store_le_u32(out, out_off + 0, w0)
  store_le_u32(out, out_off + 4, w1)
  store_le_u32(out, out_off + 8, w2)
  store_le_u32(out, out_off + 12, w3)
  store_le_u32(out, out_off + 16, w4)
  store_le_u32(out, out_off + 20, w5)
  store_le_u32(out, out_off + 24, w6)
  store_le_u32(out, out_off + 28, w7)
  store_le_u32(out, out_off + 32, w8)
  store_le_u32(out, out_off + 36, w9)
  store_le_u32(out, out_off + 40, w10)
  store_le_u32(out, out_off + 44, w11)
  store_le_u32(out, out_off + 48, w12)
  store_le_u32(out, out_off + 52, w13)
  store_le_u32(out, out_off + 56, w14)
  store_le_u32(out, out_off + 60, w15)
}

///|
fn store_le_u32(out : FixedArray[Byte], off : Int, w : UInt) -> Unit {
  out[off + 0] = (w & 0xffU).reinterpret_as_int().to_byte()
  out[off + 1] = ((w >> 8) & 0xffU).reinterpret_as_int().to_byte()
  out[off + 2] = ((w >> 16) & 0xffU).reinterpret_as_int().to_byte()
  out[off + 3] = ((w >> 24) & 0xffU).reinterpret_as_int().to_byte()
}

///|
/// XOR `data` against the ChaCha20 keystream produced from
/// (key, nonce, counter). counter increments per 64-byte block.
fn chacha20_xor_inner(
  key : Bytes,
  nonce : Bytes,
  counter : UInt,
  data : Bytes,
) -> Bytes {
  let n = data.length()
  if n == 0 {
    return b""
  }
  let out = FixedArray::make(n, b'\x00')
  let mut off = 0
  let mut ctr = counter
  // Scratch keystream buffer (64 bytes per block).
  let ks = FixedArray::make(64, b'\x00')
  while off < n {
    chacha20_block(key, nonce, ctr, ks, 0)
    let remaining = n - off
    let take = if remaining >= 64 { 64 } else { remaining }
    for i in 0..<take {
      let d = data[off + i].to_int()
      let k = ks[i].to_int()
      out[off + i] = (d ^ k).to_byte()
    }
    off = off + take
    ctr = ctr + 1U
  }
  let result = Bytes::makei(n, fn(i) { out[i] })
  // Best-effort wipe of the scratch keystream buffer. The last block's
  // keystream is key/nonce-derived secret material; zero it before the
  // FixedArray becomes GC-reachable garbage. Best-effort because the
  // compiler may elide as dead-store and GC may have already relocated
  // earlier copies. See security_review2.md finding 18.
  for i in 0..<64 {
    ks[i] = b'\x00'
  }
  result
}

///|
/// Generate the first 32-byte ChaCha20 keystream block into a FixedArray.
/// Used by Poly1305 one-time key generation so the caller can wipe the
/// secret after tag computation (see review #2 finding 7).
fn chacha20_first32_fa(key : Bytes, nonce : Bytes) -> FixedArray[Byte] {
  let ks = FixedArray::make(64, b'\x00')
  chacha20_block(key, nonce, 0U, ks, 0)
  let out = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    out[i] = ks[i]
  }
  // Wipe the local 64-byte scratch (bytes 32..63 are also keystream of the
  // counter=0 block and are never used by Poly1305).
  for i in 0..<64 {
    ks[i] = b'\x00'
  }
  out
}

///|
/// HChaCha20 sub-key derivation (RFC draft-irtf-cfrg-xchacha §2.2).
///
/// Run the 20-round ChaCha20 permutation with the 16-byte input replacing
/// the counter + nonce words at state[12..16]. Unlike `chacha20_block` the
/// initial state is NOT added at the end. The output sub-key is
/// `state[0..4] || state[12..16]` as little-endian bytes (32 bytes total).
///
/// `key` must be 32 bytes; `nonce16` must be 16 bytes. Callers are expected
/// to enforce lengths.
pub fn hchacha20(key : Bytes, nonce16 : Bytes) -> Bytes {
  // Initial state.
  let i0 : UInt = 0x61707865U
  let i1 : UInt = 0x3320646eU
  let i2 : UInt = 0x79622d32U
  let i3 : UInt = 0x6b206574U
  let i4 = load_le_u32(key, 0)
  let i5 = load_le_u32(key, 4)
  let i6 = load_le_u32(key, 8)
  let i7 = load_le_u32(key, 12)
  let i8 = load_le_u32(key, 16)
  let i9 = load_le_u32(key, 20)
  let i10 = load_le_u32(key, 24)
  let i11 = load_le_u32(key, 28)
  let i12 = load_le_u32(nonce16, 0)
  let i13 = load_le_u32(nonce16, 4)
  let i14 = load_le_u32(nonce16, 8)
  let i15 = load_le_u32(nonce16, 12)

  // Working state.
  let mut s0 = i0
  let mut s1 = i1
  let mut s2 = i2
  let mut s3 = i3
  let mut s4 = i4
  let mut s5 = i5
  let mut s6 = i6
  let mut s7 = i7
  let mut s8 = i8
  let mut s9 = i9
  let mut s10 = i10
  let mut s11 = i11
  let mut s12 = i12
  let mut s13 = i13
  let mut s14 = i14
  let mut s15 = i15

  // 10 double-rounds (20 rounds total).
  for _round in 0..<10 {
    // Column round.
    s0 = s0 + s4
    s12 = rotl_u32(s12 ^ s0, 16)
    s8 = s8 + s12
    s4 = rotl_u32(s4 ^ s8, 12)
    s0 = s0 + s4
    s12 = rotl_u32(s12 ^ s0, 8)
    s8 = s8 + s12
    s4 = rotl_u32(s4 ^ s8, 7)
    s1 = s1 + s5
    s13 = rotl_u32(s13 ^ s1, 16)
    s9 = s9 + s13
    s5 = rotl_u32(s5 ^ s9, 12)
    s1 = s1 + s5
    s13 = rotl_u32(s13 ^ s1, 8)
    s9 = s9 + s13
    s5 = rotl_u32(s5 ^ s9, 7)
    s2 = s2 + s6
    s14 = rotl_u32(s14 ^ s2, 16)
    s10 = s10 + s14
    s6 = rotl_u32(s6 ^ s10, 12)
    s2 = s2 + s6
    s14 = rotl_u32(s14 ^ s2, 8)
    s10 = s10 + s14
    s6 = rotl_u32(s6 ^ s10, 7)
    s3 = s3 + s7
    s15 = rotl_u32(s15 ^ s3, 16)
    s11 = s11 + s15
    s7 = rotl_u32(s7 ^ s11, 12)
    s3 = s3 + s7
    s15 = rotl_u32(s15 ^ s3, 8)
    s11 = s11 + s15
    s7 = rotl_u32(s7 ^ s11, 7)
    // Diagonal round.
    s0 = s0 + s5
    s15 = rotl_u32(s15 ^ s0, 16)
    s10 = s10 + s15
    s5 = rotl_u32(s5 ^ s10, 12)
    s0 = s0 + s5
    s15 = rotl_u32(s15 ^ s0, 8)
    s10 = s10 + s15
    s5 = rotl_u32(s5 ^ s10, 7)
    s1 = s1 + s6
    s12 = rotl_u32(s12 ^ s1, 16)
    s11 = s11 + s12
    s6 = rotl_u32(s6 ^ s11, 12)
    s1 = s1 + s6
    s12 = rotl_u32(s12 ^ s1, 8)
    s11 = s11 + s12
    s6 = rotl_u32(s6 ^ s11, 7)
    s2 = s2 + s7
    s13 = rotl_u32(s13 ^ s2, 16)
    s8 = s8 + s13
    s7 = rotl_u32(s7 ^ s8, 12)
    s2 = s2 + s7
    s13 = rotl_u32(s13 ^ s2, 8)
    s8 = s8 + s13
    s7 = rotl_u32(s7 ^ s8, 7)
    s3 = s3 + s4
    s14 = rotl_u32(s14 ^ s3, 16)
    s9 = s9 + s14
    s4 = rotl_u32(s4 ^ s9, 12)
    s3 = s3 + s4
    s14 = rotl_u32(s14 ^ s3, 8)
    s9 = s9 + s14
    s4 = rotl_u32(s4 ^ s9, 7)
  }

  // Output = state[0..4] || state[12..16] LE bytes (no initial-state add).
  let out = FixedArray::make(32, b'\x00')
  store_le_u32(out, 0, s0)
  store_le_u32(out, 4, s1)
  store_le_u32(out, 8, s2)
  store_le_u32(out, 12, s3)
  store_le_u32(out, 16, s12)
  store_le_u32(out, 20, s13)
  store_le_u32(out, 24, s14)
  store_le_u32(out, 28, s15)
  let result = Bytes::makei(32, fn(i) { out[i] })
  // Best-effort wipe of the local sub-key buffer.
  for i in 0..<32 {
    out[i] = b'\x00'
  }
  result
}
