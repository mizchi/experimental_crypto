// RIPEMD-160 (ISO/IEC 10118-3:2004). 160-bit (20-byte) hash, little-endian
// 32-bit word stream, 512-bit (64-byte) block.
//
// Used here primarily to support BIP-32 / Bitcoin "HASH160" =
// RIPEMD-160(SHA-256(.)). Self-contained, NOT constant-time.
//
// Reference: H. Dobbertin, A. Bosselaers, B. Preneel, "RIPEMD-160: A
// Strengthened Version of RIPEMD" (1996), Annex B of ISO/IEC 10118-3.

///|
let ripemd160_h0 : FixedArray[UInt] = [
  0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U, 0xc3d2e1f0U,
]

///|
let ripemd160_r_l : FixedArray[Int] = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3,
  12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10,
  14, 1, 3, 8, 11, 6, 15, 13,
]

///|
let ripemd160_r_r : FixedArray[Int] = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10,
  14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7,
  6, 2, 13, 14, 0, 3, 9, 11,
]

///|
let ripemd160_s_l : FixedArray[Int] = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7,
  15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5,
  12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11,
  6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
]

///|
let ripemd160_s_r : FixedArray[Int] = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9,
  11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13,
  7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12,
  5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
]

///|
fn rol32(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
// Round functions f_j (j = 0..79). They are grouped in 16-round blocks:
//   j ∈ [0,15]  : f(x,y,z) = x ^ y ^ z
//   j ∈ [16,31] : f(x,y,z) = (x ∧ y) ∨ (¬x ∧ z)
//   j ∈ [32,47] : f(x,y,z) = (x ∨ ¬y) ^ z
//   j ∈ [48,63] : f(x,y,z) = (x ∧ z) ∨ (y ∧ ¬z)
//   j ∈ [64,79] : f(x,y,z) = x ^ (y ∨ ¬z)
fn ripemd160_f(j : Int, x : UInt, y : UInt, z : UInt) -> UInt {
  if j < 16 {
    x ^ y ^ z
  } else if j < 32 {
    (x & y) | (x.lnot() & z)
  } else if j < 48 {
    (x | y.lnot()) ^ z
  } else if j < 64 {
    (x & z) | (y & z.lnot())
  } else {
    x ^ (y | z.lnot())
  }
}

///|
// K_l (left line): j ∈ {0..15,16..31,32..47,48..63,64..79} →
//   0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E
fn ripemd160_k_l(j : Int) -> UInt {
  if j < 16 {
    0x00000000U
  } else if j < 32 {
    0x5a827999U
  } else if j < 48 {
    0x6ed9eba1U
  } else if j < 64 {
    0x8f1bbcdcU
  } else {
    0xa953fd4eU
  }
}

///|
// K_r (right line): inverse order of the constants above:
//   0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000
fn ripemd160_k_r(j : Int) -> UInt {
  if j < 16 {
    0x50a28be6U
  } else if j < 32 {
    0x5c4dd124U
  } else if j < 48 {
    0x6d703ef3U
  } else if j < 64 {
    0x7a6d76e9U
  } else {
    0x00000000U
  }
}

///|
// Compress one 64-byte block (msg_w[0..16] in little-endian) into state.
fn ripemd160_compress(state : FixedArray[UInt], w : FixedArray[UInt]) -> Unit {
  let mut al = state[0]
  let mut bl = state[1]
  let mut cl = state[2]
  let mut dl = state[3]
  let mut el = state[4]
  let mut ar = state[0]
  let mut br = state[1]
  let mut cr = state[2]
  let mut dr = state[3]
  let mut er = state[4]
  for j = 0; j < 80; j = j + 1 {
    // Left line.
    let t_l = rol32(
        al + ripemd160_f(j, bl, cl, dl) + w[ripemd160_r_l[j]] + ripemd160_k_l(j),
        ripemd160_s_l[j],
      ) +
      el
    al = el
    el = dl
    dl = rol32(cl, 10)
    cl = bl
    bl = t_l
    // Right line. f index is inverted: f(79 - j).
    let t_r = rol32(
        ar +
        ripemd160_f(79 - j, br, cr, dr) +
        w[ripemd160_r_r[j]] +
        ripemd160_k_r(j),
        ripemd160_s_r[j],
      ) +
      er
    ar = er
    er = dr
    dr = rol32(cr, 10)
    cr = br
    br = t_r
  }
  let h0 = state[0]
  let h1 = state[1]
  let h2 = state[2]
  let h3 = state[3]
  let h4 = state[4]
  state[0] = h1 + cl + dr
  state[1] = h2 + dl + er
  state[2] = h3 + el + ar
  state[3] = h4 + al + br
  state[4] = h0 + bl + cr
}

///|
// Load 16 little-endian 32-bit words from `block[offset..offset+64]`.
fn ripemd160_load_block(
  block : FixedArray[Byte],
  offset : Int,
  w : FixedArray[UInt],
) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    let p = offset + i * 4
    let b0 = block[p].to_uint()
    let b1 = block[p + 1].to_uint()
    let b2 = block[p + 2].to_uint()
    let b3 = block[p + 3].to_uint()
    w[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
  }
}

///|
/// RIPEMD-160 of `data`. Returns the 20-byte digest.
pub fn ripemd160(data : Bytes) -> Bytes {
  let state = FixedArray::make(5, 0U)
  for i = 0; i < 5; i = i + 1 {
    state[i] = ripemd160_h0[i]
  }
  let n = data.length()
  let w = FixedArray::make(16, 0U)
  let block = FixedArray::make(64, b'\x00')
  let mut offset = 0
  while offset + 64 <= n {
    for i = 0; i < 64; i = i + 1 {
      block[i] = data[offset + i]
    }
    ripemd160_load_block(block, 0, w)
    ripemd160_compress(state, w)
    offset += 64
  }
  // Tail + 0x80 + 64-bit length (little-endian bits), possibly spanning two
  // blocks if tail_len + 9 > 64.
  let tail_len = n - offset
  for i = 0; i < 64; i = i + 1 {
    block[i] = b'\x00'
  }
  for i = 0; i < tail_len; i = i + 1 {
    block[i] = data[offset + i]
  }
  block[tail_len] = b'\x80'
  let total_bits = n.to_uint64() * 8UL
  if tail_len + 1 + 8 <= 64 {
    // length in last 8 bytes, little-endian
    block[56] = total_bits.to_byte()
    block[57] = (total_bits >> 8).to_byte()
    block[58] = (total_bits >> 16).to_byte()
    block[59] = (total_bits >> 24).to_byte()
    block[60] = (total_bits >> 32).to_byte()
    block[61] = (total_bits >> 40).to_byte()
    block[62] = (total_bits >> 48).to_byte()
    block[63] = (total_bits >> 56).to_byte()
    ripemd160_load_block(block, 0, w)
    ripemd160_compress(state, w)
  } else {
    ripemd160_load_block(block, 0, w)
    ripemd160_compress(state, w)
    for i = 0; i < 64; i = i + 1 {
      block[i] = b'\x00'
    }
    block[56] = total_bits.to_byte()
    block[57] = (total_bits >> 8).to_byte()
    block[58] = (total_bits >> 16).to_byte()
    block[59] = (total_bits >> 24).to_byte()
    block[60] = (total_bits >> 32).to_byte()
    block[61] = (total_bits >> 40).to_byte()
    block[62] = (total_bits >> 48).to_byte()
    block[63] = (total_bits >> 56).to_byte()
    ripemd160_load_block(block, 0, w)
    ripemd160_compress(state, w)
  }
  // Output 5 LE-32 words = 20 bytes.
  let out = FixedArray::make(20, b'\x00')
  for i = 0; i < 5; i = i + 1 {
    let v = state[i]
    out[i * 4] = v.to_byte()
    out[i * 4 + 1] = (v >> 8).to_byte()
    out[i * 4 + 2] = (v >> 16).to_byte()
    out[i * 4 + 3] = (v >> 24).to_byte()
  }
  Bytes::makei(20, fn(j) { out[j] })
}

///|
/// Bitcoin / BIP-32 "HASH160": RIPEMD-160(SHA-256(data)). Returns 20 bytes.
pub fn hash160(data : Bytes) -> Bytes {
  ripemd160(sha256(data))
}
