// SHA-512 (FIPS 180-4). Self-contained, NOT constant-time.
//
// Big-endian 64-bit words, 1024-bit (128-byte) block, 512-bit (64-byte) digest.
// SHA-384 reuses the inner block-processing routine with a different IV and
// a 48-byte truncated output; both live in this package.

///|
let sha512_h0 : FixedArray[UInt64] = [
  0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
  0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
]

///|
let sha512_k : FixedArray[UInt64] = [
  0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
  0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
  0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
  0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
  0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
  0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
  0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
  0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
  0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
  0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
  0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
  0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
  0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
  0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
  0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
  0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
  0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
  0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
  0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
  0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
]

///|
fn rotr64(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
fn u8_to_u64be(x : FixedArray[Byte], i : Int) -> UInt64 {
  let b0 = x[i].to_uint64()
  let b1 = x[i + 1].to_uint64()
  let b2 = x[i + 2].to_uint64()
  let b3 = x[i + 3].to_uint64()
  let b4 = x[i + 4].to_uint64()
  let b5 = x[i + 5].to_uint64()
  let b6 = x[i + 6].to_uint64()
  let b7 = x[i + 7].to_uint64()
  (b0 << 56) |
  (b1 << 48) |
  (b2 << 40) |
  (b3 << 32) |
  (b4 << 24) |
  (b5 << 16) |
  (b6 << 8) |
  b7
}

///|
fn u64_to_u8be(x : UInt64, buf : FixedArray[Byte], offset : Int) -> Unit {
  buf[offset + 0] = (x >> 56).to_byte()
  buf[offset + 1] = (x >> 48).to_byte()
  buf[offset + 2] = (x >> 40).to_byte()
  buf[offset + 3] = (x >> 32).to_byte()
  buf[offset + 4] = (x >> 24).to_byte()
  buf[offset + 5] = (x >> 16).to_byte()
  buf[offset + 6] = (x >> 8).to_byte()
  buf[offset + 7] = x.to_byte()
}

///|
fn sha512_transform(data : FixedArray[Byte], reg : FixedArray[UInt64]) -> Unit {
  let w = FixedArray::make(80, 0UL)
  for i = 0; i < 16; i = i + 1 {
    w[i] = u8_to_u64be(data, 8 * i)
  }
  for i = 16; i < 80; i = i + 1 {
    let s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
    let s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1
  }
  let mut a = reg[0]
  let mut b = reg[1]
  let mut c = reg[2]
  let mut d = reg[3]
  let mut e = reg[4]
  let mut f = reg[5]
  let mut g = reg[6]
  let mut h = reg[7]
  for i = 0; i < 80; i = i + 1 {
    let big_s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
    let ch = (e & f) ^ (e.lnot() & g)
    let t1 = h + big_s1 + ch + sha512_k[i] + w[i]
    let big_s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let t2 = big_s0 + maj
    h = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
  }
  reg[0] = reg[0] + a
  reg[1] = reg[1] + b
  reg[2] = reg[2] + c
  reg[3] = reg[3] + d
  reg[4] = reg[4] + e
  reg[5] = reg[5] + f
  reg[6] = reg[6] + g
  reg[7] = reg[7] + h
}

///|
// Process `data` into the supplied state register. Used by both sha512 (with
// the standard IV) and sha384 (with the SHA-384 IV).
fn sha512_core_hash(data : Bytes, state : FixedArray[UInt64]) -> Unit {
  let n = data.length()
  let block = FixedArray::make(128, b'\x00')
  let mut offset = 0
  while offset + 128 <= n {
    for i = 0; i < 128; i = i + 1 {
      block[i] = data[offset + i]
    }
    sha512_transform(block, state)
    offset += 128
  }
  // Tail + 0x80 + 128-bit length, possibly spanning 2 blocks.
  let tail_len = n - offset
  for i = 0; i < 128; i = i + 1 {
    block[i] = b'\x00'
  }
  for i = 0; i < tail_len; i = i + 1 {
    block[i] = data[offset + i]
  }
  block[tail_len] = b'\x80'
  let pad_end = if tail_len + 1 + 16 <= 128 { 128 } else { 256 }
  if pad_end == 128 {
    // 128-bit BE length in the high 16 bytes; total bits fit in 64-bit lo.
    let total_bits_lo = n.to_uint64() * 8UL
    u64_to_u8be(0UL, block, 112)
    u64_to_u8be(total_bits_lo, block, 120)
    sha512_transform(block, state)
  } else {
    sha512_transform(block, state)
    for i = 0; i < 128; i = i + 1 {
      block[i] = b'\x00'
    }
    let total_bits_lo = n.to_uint64() * 8UL
    u64_to_u8be(0UL, block, 112)
    u64_to_u8be(total_bits_lo, block, 120)
    sha512_transform(block, state)
  }
}

///|
/// SHA-512 of `data`. Returns the 64-byte digest.
pub fn sha512(data : Bytes) -> Bytes {
  let state = FixedArray::make(8, 0UL)
  for i = 0; i < 8; i = i + 1 {
    state[i] = sha512_h0[i]
  }
  sha512_core_hash(data, state)
  let out = FixedArray::make(64, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    u64_to_u8be(state[i], out, i * 8)
  }
  Bytes::makei(64, fn(j) { out[j] })
}
