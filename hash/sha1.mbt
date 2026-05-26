// SHA-1 (FIPS 180-4 §6.1). Self-contained, NOT constant-time.
//
// 32-bit big-endian words, 512-bit block, 160-bit (20-byte) digest.
//
// Provided here only because OCSP responders (RFC 6960) and a non-trivial
// fraction of legacy X.509 / CRL deployments still use SHA-1 for CertID
// issuerNameHash / issuerKeyHash. NOT recommended for signing.

///|
let sha1_h0 : FixedArray[UInt] = [
  0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
]

///|
fn sha1_rotl(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
fn sha1_compress(state : FixedArray[UInt], w : FixedArray[UInt]) -> Unit {
  // Message schedule expansion: w[16..79]
  for i = 16; i < 80; i = i + 1 {
    let v = w.unsafe_get(i - 3) ^
      w.unsafe_get(i - 8) ^
      w.unsafe_get(i - 14) ^
      w.unsafe_get(i - 16)
    w.unsafe_set(i, sha1_rotl(v, 1))
  }
  let mut a = state.unsafe_get(0)
  let mut b = state.unsafe_get(1)
  let mut c = state.unsafe_get(2)
  let mut d = state.unsafe_get(3)
  let mut e = state.unsafe_get(4)
  for i = 0; i < 80; i = i + 1 {
    let (f, k) = if i < 20 {
      ((b & c) | (b.lnot() & d), 0x5a827999U)
    } else if i < 40 {
      (b ^ c ^ d, 0x6ed9eba1U)
    } else if i < 60 {
      ((b & c) | (b & d) | (c & d), 0x8f1bbcdcU)
    } else {
      (b ^ c ^ d, 0xca62c1d6U)
    }
    let t = sha1_rotl(a, 5) + f + e + k + w.unsafe_get(i)
    e = d
    d = c
    c = sha1_rotl(b, 30)
    b = a
    a = t
  }
  state.unsafe_set(0, state.unsafe_get(0) + a)
  state.unsafe_set(1, state.unsafe_get(1) + b)
  state.unsafe_set(2, state.unsafe_get(2) + c)
  state.unsafe_set(3, state.unsafe_get(3) + d)
  state.unsafe_set(4, state.unsafe_get(4) + e)
}

///|
fn sha1_load_block_be(
  block : FixedArray[Byte],
  offset : Int,
  w : FixedArray[UInt],
) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    let p = offset + i * 4
    let b0 = block.unsafe_get(p).to_uint()
    let b1 = block.unsafe_get(p + 1).to_uint()
    let b2 = block.unsafe_get(p + 2).to_uint()
    let b3 = block.unsafe_get(p + 3).to_uint()
    w.unsafe_set(i, (b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
  }
}

///|
/// SHA-1 of `data`. Returns the 20-byte digest.
pub fn sha1(data : Bytes) -> Bytes {
  let state = FixedArray::make(5, 0U)
  for i = 0; i < 5; i = i + 1 {
    state.unsafe_set(i, sha1_h0.unsafe_get(i))
  }
  let n = data.length()
  let w = FixedArray::make(80, 0U)
  let block = FixedArray::make(64, b'\x00')
  let mut offset = 0
  while offset + 64 <= n {
    for i = 0; i < 16; i = i + 1 {
      let p = offset + i * 4
      let b0 = data[p].to_uint()
      let b1 = data[p + 1].to_uint()
      let b2 = data[p + 2].to_uint()
      let b3 = data[p + 3].to_uint()
      w.unsafe_set(i, (b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }
    sha1_compress(state, w)
    offset += 64
  }
  // Final tail + padding.
  let tail_len = n - offset
  for i = 0; i < tail_len; i = i + 1 {
    block.unsafe_set(i, data[offset + i])
  }
  let total_bits = n.to_uint64() * 8UL
  let buf = FixedArray::make(128, b'\x00')
  for i = 0; i < tail_len; i = i + 1 {
    buf.unsafe_set(i, block.unsafe_get(i))
  }
  buf.unsafe_set(tail_len, b'\x80')
  let pad_end = if tail_len + 1 + 8 <= 64 { 64 } else { 128 }
  buf.unsafe_set(pad_end - 8, (total_bits >> 56).to_byte())
  buf.unsafe_set(pad_end - 7, (total_bits >> 48).to_byte())
  buf.unsafe_set(pad_end - 6, (total_bits >> 40).to_byte())
  buf.unsafe_set(pad_end - 5, (total_bits >> 32).to_byte())
  buf.unsafe_set(pad_end - 4, (total_bits >> 24).to_byte())
  buf.unsafe_set(pad_end - 3, (total_bits >> 16).to_byte())
  buf.unsafe_set(pad_end - 2, (total_bits >> 8).to_byte())
  buf.unsafe_set(pad_end - 1, total_bits.to_byte())
  sha1_load_block_be(buf, 0, w)
  sha1_compress(state, w)
  if pad_end == 128 {
    sha1_load_block_be(buf, 64, w)
    sha1_compress(state, w)
  }
  let out = FixedArray::make(20, b'\x00')
  for i = 0; i < 5; i = i + 1 {
    let v = state.unsafe_get(i)
    out.unsafe_set(i * 4, (v >> 24).to_byte())
    out.unsafe_set(i * 4 + 1, (v >> 16).to_byte())
    out.unsafe_set(i * 4 + 2, (v >> 8).to_byte())
    out.unsafe_set(i * 4 + 3, v.to_byte())
  }
  Bytes::makei(20, fn(j) { out.unsafe_get(j) })
}
