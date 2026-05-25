// RFC 7914 scrypt key derivation: PBKDF2-HMAC-SHA256 + ROMix + BlockMix +
// Salsa20/8. Memory-hard by construction; N=2^log_n controls the cost.

///|
pub(all) struct Params {
  log_n : Int // log2(N), 14..30 typical. N = 2^log_n
  r : Int // block size factor. usually 8
  p : Int // parallelization factor. usually 1
  dk_len : Int // derived key length in bytes
} derive(Eq, Show)

///|
/// Interactive baseline: log_n=15, r=8, p=1, dk_len=32.
pub fn Params::recommended_interactive() -> Params {
  { log_n: 15, r: 8, p: 1, dk_len: 32 }
}

///|
/// Sensitive baseline: log_n=20, r=8, p=1, dk_len=32.
pub fn Params::recommended_sensitive() -> Params {
  { log_n: 20, r: 8, p: 1, dk_len: 32 }
}

///|
pub suberror ScryptError {
  InvalidParams(String)
  OutputTooLong
  Pbkdf2Failure
} derive(Show)

///|
/// Derives a key of `params.dk_len` bytes from `password` and `salt` using
/// scrypt as specified in RFC 7914.
pub fn derive_key(
  params : Params,
  password : Bytes,
  salt : Bytes,
) -> Bytes raise ScryptError {
  validate_params(params)
  let n = 1 << params.log_n
  let r = params.r
  let p = params.p
  let dk_len = params.dk_len
  let block_size = 128 * r // bytes per ROMix block

  // Step 1: B = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r)
  let b_total = pbkdf2_call(password, salt, 1, p * block_size)

  // Step 2: for each of the p blocks, run ROMix in place.
  let blocks = FixedArray::make(p * block_size, b'\x00')
  for i in 0..<(p * block_size) {
    blocks[i] = b_total[i]
  }
  for i in 0..<p {
    let off = i * block_size
    let block = FixedArray::make(block_size, b'\x00')
    for j in 0..<block_size {
      block[j] = blocks[off + j]
    }
    let mixed = romix(block, n, r)
    for j in 0..<block_size {
      blocks[off + j] = mixed[j]
    }
  }
  // Step 3: DK = PBKDF2-HMAC-SHA256(password, B, 1, dk_len)
  let new_salt = Bytes::makei(p * block_size, fn(i) { blocks[i] })
  pbkdf2_call(password, new_salt, 1, dk_len)
}

///|
fn validate_params(params : Params) -> Unit raise ScryptError {
  if params.log_n < 1 || params.log_n > 30 {
    raise InvalidParams("log_n out of range")
  }
  if params.r < 1 {
    raise InvalidParams("r must be >= 1")
  }
  if params.p < 1 {
    raise InvalidParams("p must be >= 1")
  }
  if params.dk_len < 1 {
    raise InvalidParams("dk_len must be >= 1")
  }
  // RFC 7914 §6 constraint: p <= ((2^32 - 1) * 32) / (128 * r) but on 32-bit
  // Int we cannot even represent that.
}

///|
fn pbkdf2_call(
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dk_len : Int,
) -> Bytes raise ScryptError {
  @pbkdf2.pbkdf2(Sha256, password, salt, iterations, dk_len) catch {
    _ => raise Pbkdf2Failure
  }
}

// ─── ROMix ───────────────────────────────────────────────────────────────

///|
fn romix(b : FixedArray[Byte], n : Int, r : Int) -> FixedArray[Byte] {
  let block_size = 128 * r
  let v = FixedArray::make(n * block_size, b'\x00')
  let x = FixedArray::make(block_size, b'\x00')
  for i in 0..<block_size {
    x[i] = b[i]
  }
  // V[i] = X; X = BlockMix(X)
  for i in 0..<n {
    let off = i * block_size
    for j in 0..<block_size {
      v[off + j] = x[j]
    }
    let next = block_mix(x, r)
    for j in 0..<block_size {
      x[j] = next[j]
    }
  }
  // for N iterations: j = Integerify(X) mod N; X = BlockMix(X XOR V[j])
  for _ in 0..<n {
    let j = integerify(x, r) % n.to_uint64()
    let j_idx = j.to_int()
    let off = j_idx * block_size
    let xored = FixedArray::make(block_size, b'\x00')
    for k in 0..<block_size {
      xored[k] = (x[k].to_int() ^ v[off + k].to_int()).to_byte()
    }
    let next = block_mix(xored, r)
    for k in 0..<block_size {
      x[k] = next[k]
    }
  }
  x
}

///|
fn integerify(b : FixedArray[Byte], r : Int) -> UInt64 {
  // Last 64-byte block of B, treated as a little-endian unsigned integer.
  // For mod N we only need the low 64 bits.
  let off = (2 * r - 1) * 64
  let mut value : UInt64 = 0UL
  for i = 7; i >= 0; i = i - 1 {
    value = (value << 8) | b[off + i].to_uint64()
  }
  value
}

// ─── BlockMix ────────────────────────────────────────────────────────────

///|
fn block_mix(b : FixedArray[Byte], r : Int) -> FixedArray[Byte] {
  // B is 2r blocks of 64 bytes each.
  let block_count = 2 * r
  let x = FixedArray::make(64, b'\x00')
  for i in 0..<64 {
    x[i] = b[(block_count - 1) * 64 + i]
  }
  let y = FixedArray::make(block_count * 64, b'\x00')
  let tmp = FixedArray::make(64, b'\x00')
  for i in 0..<block_count {
    for k in 0..<64 {
      tmp[k] = (x[k].to_int() ^ b[i * 64 + k].to_int()).to_byte()
    }
    let mixed = salsa20_8(tmp)
    for k in 0..<64 {
      x[k] = mixed[k]
      y[i * 64 + k] = mixed[k]
    }
  }
  // Reorder: Y[0], Y[2], ..., Y[2r-2], Y[1], Y[3], ..., Y[2r-1]
  let out = FixedArray::make(block_count * 64, b'\x00')
  for i in 0..<r {
    for k in 0..<64 {
      out[i * 64 + k] = y[2 * i * 64 + k]
    }
    for k in 0..<64 {
      out[(r + i) * 64 + k] = y[(2 * i + 1) * 64 + k]
    }
  }
  out
}

// ─── Salsa20/8 core ──────────────────────────────────────────────────────

///|
fn salsa20_8(input : FixedArray[Byte]) -> FixedArray[Byte] {
  // 64-byte input → 64-byte output. 8 rounds = 4 double rounds.
  let x = FixedArray::make(16, 0U)
  for i in 0..<16 {
    let off = i * 4
    x[i] = input[off].to_uint() |
      (input[off + 1].to_uint() << 8) |
      (input[off + 2].to_uint() << 16) |
      (input[off + 3].to_uint() << 24)
  }
  let orig = FixedArray::make(16, 0U)
  for i in 0..<16 {
    orig[i] = x[i]
  }
  for _ in 0..<4 {
    // Column round
    x[4] = x[4] ^ rotl(x[0] + x[12], 7)
    x[8] = x[8] ^ rotl(x[4] + x[0], 9)
    x[12] = x[12] ^ rotl(x[8] + x[4], 13)
    x[0] = x[0] ^ rotl(x[12] + x[8], 18)
    x[9] = x[9] ^ rotl(x[5] + x[1], 7)
    x[13] = x[13] ^ rotl(x[9] + x[5], 9)
    x[1] = x[1] ^ rotl(x[13] + x[9], 13)
    x[5] = x[5] ^ rotl(x[1] + x[13], 18)
    x[14] = x[14] ^ rotl(x[10] + x[6], 7)
    x[2] = x[2] ^ rotl(x[14] + x[10], 9)
    x[6] = x[6] ^ rotl(x[2] + x[14], 13)
    x[10] = x[10] ^ rotl(x[6] + x[2], 18)
    x[3] = x[3] ^ rotl(x[15] + x[11], 7)
    x[7] = x[7] ^ rotl(x[3] + x[15], 9)
    x[11] = x[11] ^ rotl(x[7] + x[3], 13)
    x[15] = x[15] ^ rotl(x[11] + x[7], 18)
    // Row round
    x[1] = x[1] ^ rotl(x[0] + x[3], 7)
    x[2] = x[2] ^ rotl(x[1] + x[0], 9)
    x[3] = x[3] ^ rotl(x[2] + x[1], 13)
    x[0] = x[0] ^ rotl(x[3] + x[2], 18)
    x[6] = x[6] ^ rotl(x[5] + x[4], 7)
    x[7] = x[7] ^ rotl(x[6] + x[5], 9)
    x[4] = x[4] ^ rotl(x[7] + x[6], 13)
    x[5] = x[5] ^ rotl(x[4] + x[7], 18)
    x[11] = x[11] ^ rotl(x[10] + x[9], 7)
    x[8] = x[8] ^ rotl(x[11] + x[10], 9)
    x[9] = x[9] ^ rotl(x[8] + x[11], 13)
    x[10] = x[10] ^ rotl(x[9] + x[8], 18)
    x[12] = x[12] ^ rotl(x[15] + x[14], 7)
    x[13] = x[13] ^ rotl(x[12] + x[15], 9)
    x[14] = x[14] ^ rotl(x[13] + x[12], 13)
    x[15] = x[15] ^ rotl(x[14] + x[13], 18)
  }
  for i in 0..<16 {
    x[i] = x[i] + orig[i]
  }
  let out = FixedArray::make(64, b'\x00')
  for i in 0..<16 {
    out[i * 4] = (x[i] & 0xFFU).to_byte()
    out[i * 4 + 1] = ((x[i] >> 8) & 0xFFU).to_byte()
    out[i * 4 + 2] = ((x[i] >> 16) & 0xFFU).to_byte()
    out[i * 4 + 3] = ((x[i] >> 24) & 0xFFU).to_byte()
  }
  out
}

///|
fn rotl(v : UInt, n : Int) -> UInt {
  (v << n) | (v >> (32 - n))
}

// ─── stubs for PHC-encoded variants ──────────────────────────────────────

///|
pub fn hash_encoded(
  _params : Params,
  _password : Bytes,
  _salt : Bytes,
) -> String raise ScryptError {
  abort("todo: scrypt PHC encoder")
}

///|
pub fn verify_encoded(
  _encoded : String,
  _password : Bytes,
) -> Unit raise ScryptError {
  abort("todo: scrypt PHC verifier")
}
