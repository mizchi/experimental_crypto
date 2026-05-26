// SHA-384 (FIPS 180-4) — SHA-512 inner loop with a different IV and a 48-byte
// truncated output. Self-contained, NOT constant-time. Used internally by
// p384 verify.
//
// Big-endian 64-bit words, 1024-bit (128-byte) block, 384-bit (48-byte) digest.

///|
priv struct SHA384 {
  reg : FixedArray[UInt64]
  mut len : UInt64
  mut len_hi : UInt64
  buf : FixedArray[Byte]
  mut buf_index : Int
}

///|
fn SHA384::new() -> SHA384 {
  // FIPS 180-4 §5.3.4 initial hash values for SHA-384.
  {
    reg: [
      0xcbbb9d5dc1059ed8UL, 0x629a292a367cd507UL, 0x9159015a3070dd17UL, 0x152fecd8f70e5939UL,
      0x67332667ffc00b31UL, 0x8eb44a8768581511UL, 0xdb0c2e0d64f98fa7UL, 0x47b5481dbefa4fa4UL,
    ],
    len: 0UL,
    len_hi: 0UL,
    buf: FixedArray::make(128, b'\x00'),
    buf_index: 0,
  }
}

///|
let sha384_k : FixedArray[UInt64] = [
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
fn rotr64_(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
fn u8_to_u64be_(x : FixedArray[Byte], i : Int) -> UInt64 {
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
fn u64_to_u8be_(x : UInt64, buf : FixedArray[Byte], offset : Int) -> Unit {
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
fn SHA384::transform(data : FixedArray[Byte], reg : FixedArray[UInt64]) -> Unit {
  let w = FixedArray::make(80, 0UL)
  for i = 0; i < 16; i = i + 1 {
    w[i] = u8_to_u64be_(data, 8 * i)
  }
  for i = 16; i < 80; i = i + 1 {
    let s0 = rotr64_(w[i - 15], 1) ^ rotr64_(w[i - 15], 8) ^ (w[i - 15] >> 7)
    let s1 = rotr64_(w[i - 2], 19) ^ rotr64_(w[i - 2], 61) ^ (w[i - 2] >> 6)
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
    let big_s1 = rotr64_(e, 14) ^ rotr64_(e, 18) ^ rotr64_(e, 41)
    let ch = (e & f) ^ (e.lnot() & g)
    let t1 = h + big_s1 + ch + sha384_k[i] + w[i]
    let big_s0 = rotr64_(a, 28) ^ rotr64_(a, 34) ^ rotr64_(a, 39)
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
fn SHA384::update_bytes(self : SHA384, data : Bytes) -> Unit {
  let mut offset = 0
  while offset < data.length() {
    let remaining = data.length() - offset
    let space = 128 - self.buf_index
    let n = if space <= remaining { space } else { remaining }
    for i = 0; i < n; i = i + 1 {
      self.buf[self.buf_index + i] = data[offset + i]
    }
    self.buf_index += n
    if self.buf_index == 128 {
      let old = self.len
      self.len = self.len + 1024UL
      if self.len < old {
        self.len_hi = self.len_hi + 1UL
      }
      SHA384::transform(self.buf, self.reg)
      self.buf_index = 0
    }
    offset += n
  }
}

///|
fn SHA384::finalize(self : SHA384) -> Bytes {
  let bits_in_buf = (self.buf_index * 8).to_uint64()
  let old = self.len
  let total_lo = self.len + bits_in_buf
  let mut total_hi = self.len_hi
  if total_lo < old {
    total_hi = total_hi + 1UL
  }
  let data = FixedArray::make(128, b'\x00')
  for i = 0; i < self.buf_index; i = i + 1 {
    data[i] = self.buf[i]
  }
  let mut cnt = self.buf_index
  data[cnt] = b'\x80'
  cnt = cnt + 1
  let reg = self.reg.copy()
  if cnt > 112 {
    SHA384::transform(data, reg)
    for i = 0; i < 128; i = i + 1 {
      data[i] = b'\x00'
    }
  }
  // 128-bit big-endian length
  u64_to_u8be_(total_hi, data, 112)
  u64_to_u8be_(total_lo, data, 120)
  SHA384::transform(data, reg)
  // SHA-384 output = first 6 words (48 bytes) of the SHA-512-style state.
  let out = FixedArray::make(48, b'\x00')
  for i = 0; i < 6; i = i + 1 {
    u64_to_u8be_(reg[i], out, i * 8)
  }
  Bytes::makei(48, fn(j) { out[j] })
}

///|
fn sha384(data : Bytes) -> Bytes {
  let ctx = SHA384::new()
  ctx.update_bytes(data)
  ctx.finalize()
}
