// SHA-256 (FIPS 180-4) — small self-impl used only to compute the
// message digest required by PKCS#1 v1.5 signature verification.
//
// This is the third copy in the workspace (pbkdf2/jwt also hand-roll
// SHA-256 to keep their PRF / HMAC ipad/opad fast paths inline). When
// a shared `mizchi/hash` module exists we will collapse them.

///|
let sha256_h0 : FixedArray[UInt] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
  0x5be0cd19,
]

///|
let sha256_k : FixedArray[UInt] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
  0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
  0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
  0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
  0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
  0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
]

///|
fn rotr(x : UInt, n : Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

///|
fn sha256_compress(state : FixedArray[UInt], w : FixedArray[UInt]) -> Unit {
  for i = 16; i < 64; i = i + 1 {
    let w15 = w.unsafe_get(i - 15)
    let w2 = w.unsafe_get(i - 2)
    let s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >> 3)
    let s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >> 10)
    w.unsafe_set(i, w.unsafe_get(i - 16) + s0 + w.unsafe_get(i - 7) + s1)
  }
  let mut a = state.unsafe_get(0)
  let mut b = state.unsafe_get(1)
  let mut c = state.unsafe_get(2)
  let mut d = state.unsafe_get(3)
  let mut e = state.unsafe_get(4)
  let mut f = state.unsafe_get(5)
  let mut g = state.unsafe_get(6)
  let mut h = state.unsafe_get(7)
  for i = 0; i < 64; i = i + 1 {
    let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
    let ch = (e & f) ^ (e.lnot() & g)
    let t1 = h + s1 + ch + sha256_k.unsafe_get(i) + w.unsafe_get(i)
    let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
    let mj = (a & b) ^ (a & c) ^ (b & c)
    let t2 = s0 + mj
    h = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
  }
  state.unsafe_set(0, state.unsafe_get(0) + a)
  state.unsafe_set(1, state.unsafe_get(1) + b)
  state.unsafe_set(2, state.unsafe_get(2) + c)
  state.unsafe_set(3, state.unsafe_get(3) + d)
  state.unsafe_set(4, state.unsafe_get(4) + e)
  state.unsafe_set(5, state.unsafe_get(5) + f)
  state.unsafe_set(6, state.unsafe_get(6) + g)
  state.unsafe_set(7, state.unsafe_get(7) + h)
}

///|
fn load_block_be(
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
// Hash `data` and return a 32-byte digest.
fn sha256(data : Bytes) -> Bytes {
  let state = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    state.unsafe_set(i, sha256_h0.unsafe_get(i))
  }
  let n = data.length()
  let w = FixedArray::make(64, 0U)
  // Consume full 64-byte blocks first.
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
    sha256_compress(state, w)
    offset += 64
  }
  // Pad the tail. Worst case: tail + 0x80 + 8 length bytes spans 2 blocks.
  let tail_len = n - offset
  let buf = FixedArray::make(128, b'\x00')
  for i = 0; i < tail_len; i = i + 1 {
    buf.unsafe_set(i, data[offset + i])
  }
  buf.unsafe_set(tail_len, b'\x80')
  let pad_end = if tail_len + 1 + 8 <= 64 { 64 } else { 128 }
  let total_bits = n.to_uint64() * 8UL
  buf.unsafe_set(pad_end - 8, (total_bits >> 56).to_byte())
  buf.unsafe_set(pad_end - 7, (total_bits >> 48).to_byte())
  buf.unsafe_set(pad_end - 6, (total_bits >> 40).to_byte())
  buf.unsafe_set(pad_end - 5, (total_bits >> 32).to_byte())
  buf.unsafe_set(pad_end - 4, (total_bits >> 24).to_byte())
  buf.unsafe_set(pad_end - 3, (total_bits >> 16).to_byte())
  buf.unsafe_set(pad_end - 2, (total_bits >> 8).to_byte())
  buf.unsafe_set(pad_end - 1, total_bits.to_byte())
  load_block_be(buf, 0, w)
  sha256_compress(state, w)
  if pad_end == 128 {
    load_block_be(buf, 64, w)
    sha256_compress(state, w)
  }
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    let v = state.unsafe_get(i)
    out.unsafe_set(i * 4, (v >> 24).to_byte())
    out.unsafe_set(i * 4 + 1, (v >> 16).to_byte())
    out.unsafe_set(i * 4 + 2, (v >> 8).to_byte())
    out.unsafe_set(i * 4 + 3, v.to_byte())
  }
  Bytes::makei(32, fn(j) { out.unsafe_get(j) })
}
