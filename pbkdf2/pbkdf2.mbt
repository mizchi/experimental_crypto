// RFC 8018 PBKDF2 with PRF = HMAC-<hash>.
//
// Only SHA-256 is implemented today. The inner SHA-256 is hand-rolled so that
// HMAC's ipad / opad blocks can be pre-compressed once per pbkdf2 call and the
// resulting 8-word digest state can be reused as the starting point for every
// HMAC iteration. This halves the SHA-256 compression count (2 per HMAC instead
// of 4) on the hot path.

///|
pub(all) enum HashAlg {
  Sha1
  Sha256
  Sha384
  Sha512
} derive(Eq, Debug)

///|
pub suberror Pbkdf2Error {
  InvalidIterations
  OutputTooLong
  InvalidLength
  UnsupportedHash(HashAlg)
} derive(Debug)

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
// SHA-256 compression: mix one 64-byte block (msg_w[0..16]) into state in-place.
fn sha256_compress(state : FixedArray[UInt], w : FixedArray[UInt]) -> Unit {
  // w[0..16] already loaded by caller; expand to w[16..64].
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
// Load 64 bytes from `block` starting at `offset` into w[0..16] (big-endian).
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
// Compute SHA-256 of one 64-byte block, starting from given state.
// Returns nothing; mutates `state` in place.
fn sha256_one_block(state : FixedArray[UInt], block : FixedArray[Byte]) -> Unit {
  let w = FixedArray::make(64, 0U)
  load_block_be(block, 0, w)
  sha256_compress(state, w)
}

///|
// Finalize SHA-256 given a starting state and the tail message bytes
// (`tail[0..tail_len]`), where the *total* length being hashed is
// `prefix_bits + tail_len * 8` bits. `prefix_bits` is the number of bits
// already mixed into `state` via earlier compressions.
// `out` receives 32 bytes.
fn sha256_finalize_with_tail(
  state : FixedArray[UInt],
  tail : FixedArray[Byte],
  tail_len : Int,
  prefix_bits : UInt64,
  out : FixedArray[Byte],
) -> Unit {
  // SHA-256's length field is a 64-bit big-endian *bit* count, so the
  // total input must fit in 2^64 - 1 bits = 2^61 - 1 bytes (~2 EiB).
  // We don't enforce that explicitly because MoonBit's Bytes is Int-indexed
  // (~2 GiB max on current platforms), making it unreachable. If the platform
  // ever grows, prefix_bits + tail_len*8 above would silently wrap on UInt64
  // past 2^64 - 1 bits and emit a wrong length, breaking the digest.
  let total_bits = prefix_bits + tail_len.to_uint64() * 8UL
  let buf = FixedArray::make(128, b'\x00')
  // copy tail
  for i = 0; i < tail_len; i = i + 1 {
    buf.unsafe_set(i, tail.unsafe_get(i))
  }
  buf.unsafe_set(tail_len, b'\x80')
  // figure out how many blocks we need: payload + 0x80 + at-least-8-byte length must
  // fit in 64 bytes per block.
  let pad_end = if tail_len + 1 + 8 <= 64 { 64 } else { 128 }
  // length goes in last 8 bytes (big-endian)
  buf.unsafe_set(pad_end - 8, (total_bits >> 56).to_byte())
  buf.unsafe_set(pad_end - 7, (total_bits >> 48).to_byte())
  buf.unsafe_set(pad_end - 6, (total_bits >> 40).to_byte())
  buf.unsafe_set(pad_end - 5, (total_bits >> 32).to_byte())
  buf.unsafe_set(pad_end - 4, (total_bits >> 24).to_byte())
  buf.unsafe_set(pad_end - 3, (total_bits >> 16).to_byte())
  buf.unsafe_set(pad_end - 2, (total_bits >> 8).to_byte())
  buf.unsafe_set(pad_end - 1, total_bits.to_byte())
  let w = FixedArray::make(64, 0U)
  load_block_be(buf, 0, w)
  sha256_compress(state, w)
  if pad_end == 128 {
    load_block_be(buf, 64, w)
    sha256_compress(state, w)
  }
  // write big-endian state to out[0..32]
  for i = 0; i < 8; i = i + 1 {
    let v = state.unsafe_get(i)
    out.unsafe_set(i * 4, (v >> 24).to_byte())
    out.unsafe_set(i * 4 + 1, (v >> 16).to_byte())
    out.unsafe_set(i * 4 + 2, (v >> 8).to_byte())
    out.unsafe_set(i * 4 + 3, v.to_byte())
  }
}

///|
// Hash a Bytes input from scratch into `out` (32 bytes).
fn sha256_hash_bytes(data : Bytes, out : FixedArray[Byte]) -> Unit {
  let state = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    state.unsafe_set(i, sha256_h0.unsafe_get(i))
  }
  let n = data.length()
  let w = FixedArray::make(64, 0U)
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
    sha256_compress(state, w)
    offset += 64
  }
  let tail_len = n - offset
  for i = 0; i < tail_len; i = i + 1 {
    block.unsafe_set(i, data[offset + i])
  }
  sha256_finalize_with_tail(
    state,
    block,
    tail_len,
    offset.to_uint64() * 8UL,
    out,
  )
}

///|
// Precomputed HMAC-SHA256 context: the digest state after compressing
// the ipad and opad blocks once. Each HMAC iteration clones one of these
// states and adds only the message.
priv struct HmacSha256Ctx {
  inner_state : FixedArray[UInt] // state after compressing ipad (64 bytes)
  outer_state : FixedArray[UInt] // state after compressing opad (64 bytes)
}

///|
/// Best-effort zero of the precomputed HMAC state words. The two
/// `inner_state` / `outer_state` arrays are derived from the password
/// (via ipad/opad XOR + one SHA-256 compression); zeroing them shortens
/// the window during which an offline dictionary attacker with heap
/// read access could substitute them for the password's HMAC key. Best-
/// effort because MoonBit gives no guarantee against compiler dead-store
/// elimination or GC copies. See review #2 finding 8.
fn HmacSha256Ctx::clear(self : HmacSha256Ctx) -> Unit {
  for i in 0..<self.inner_state.length() {
    self.inner_state[i] = 0U
  }
  for i in 0..<self.outer_state.length() {
    self.outer_state[i] = 0U
  }
}

///|
fn hmac_sha256_init(key : Bytes) -> HmacSha256Ctx {
  let block_size = 64
  let padded = FixedArray::make(block_size, b'\x00')
  if key.length() > block_size {
    sha256_hash_bytes(key, padded) // hash fills first 32 bytes, rest stay 0
  } else {
    for i = 0; i < key.length(); i = i + 1 {
      padded.unsafe_set(i, key[i])
    }
  }
  let ipad = FixedArray::make(block_size, b'\x00')
  let opad = FixedArray::make(block_size, b'\x00')
  for i = 0; i < block_size; i = i + 1 {
    let k = padded.unsafe_get(i).to_int()
    ipad.unsafe_set(i, (k ^ 0x36).to_byte())
    opad.unsafe_set(i, (k ^ 0x5c).to_byte())
  }
  let inner_state = FixedArray::make(8, 0U)
  let outer_state = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    inner_state.unsafe_set(i, sha256_h0.unsafe_get(i))
    outer_state.unsafe_set(i, sha256_h0.unsafe_get(i))
  }
  sha256_one_block(inner_state, ipad)
  sha256_one_block(outer_state, opad)
  { inner_state, outer_state }
}

///|
// Compute HMAC-SHA256 of `msg` (length <= 64 bytes is enough for PBKDF2's
// inner loop, but the implementation handles arbitrary msg length).
// Result is written to `out` (32 bytes).
fn hmac_sha256_compute(
  ctx : HmacSha256Ctx,
  msg : FixedArray[Byte],
  msg_len : Int,
  out : FixedArray[Byte],
) -> Unit {
  // ---- inner: H(ipad || msg) ----
  let state = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    state.unsafe_set(i, ctx.inner_state.unsafe_get(i))
  }
  // Consume full 64-byte blocks from msg first.
  let w = FixedArray::make(64, 0U)
  let mut offset = 0
  while offset + 64 <= msg_len {
    load_block_be(msg, offset, w)
    sha256_compress(state, w)
    offset += 64
  }
  let tail_len = msg_len - offset
  let tail = FixedArray::make(64, b'\x00')
  for i = 0; i < tail_len; i = i + 1 {
    tail.unsafe_set(i, msg.unsafe_get(offset + i))
  }
  // prefix_bits accounts for ipad block (64 bytes = 512 bits) + full msg blocks
  let prefix_bits = 512UL + offset.to_uint64() * 8UL
  let inner_hash = FixedArray::make(32, b'\x00')
  sha256_finalize_with_tail(state, tail, tail_len, prefix_bits, inner_hash)

  // ---- outer: H(opad || inner_hash) ----
  let state2 = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    state2.unsafe_set(i, ctx.outer_state.unsafe_get(i))
  }
  // inner_hash is 32 bytes, fits in one block; place in `tail`
  let tail2 = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    tail2.unsafe_set(i, inner_hash.unsafe_get(i))
  }
  sha256_finalize_with_tail(state2, tail2, 32, 512UL, out)
}

///|
pub fn pbkdf2(
  hash : HashAlg,
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dk_len : Int,
) -> Bytes raise Pbkdf2Error {
  if iterations < 1 {
    raise InvalidIterations
  }
  if dk_len < 0 {
    raise InvalidLength
  }
  // Cap dk_len well below the RFC 8018 bound of (2^32 - 1) * h_len to
  // avoid integer overflow on the `(dk_len + h_len - 1) / h_len * h_len`
  // allocation. 64 MiB is already absurd for a derived key.
  if dk_len > 64 * 1024 * 1024 {
    raise OutputTooLong
  }
  match hash {
    Sha256 => pbkdf2_sha256(password, salt, iterations, dk_len)
    _ => raise UnsupportedHash(hash)
  }
}

///|
fn pbkdf2_sha256(
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dk_len : Int,
) -> Bytes {
  let h_len = 32
  let num_blocks = (dk_len + h_len - 1) / h_len
  let ctx = hmac_sha256_init(password)
  let out = FixedArray::make(num_blocks * h_len, b'\x00')
  let salt_len = salt.length()
  // msg buffer for U_1 = HMAC(P, S || INT(i)). For subsequent iters msg is
  // the previous 32-byte tag, so 64 bytes is enough unless salt is huge.
  // We allocate max(salt_len + 4, 64) but reuse for the 32-byte tag case.
  let u1_msg_cap = if salt_len + 4 > 64 { salt_len + 4 } else { 64 }
  let u1_msg = FixedArray::make(u1_msg_cap, b'\x00')
  for i = 0; i < salt_len; i = i + 1 {
    u1_msg.unsafe_set(i, salt[i])
  }
  let u = FixedArray::make(32, b'\x00')
  let t = FixedArray::make(32, b'\x00')
  for blk = 1; blk <= num_blocks; blk = blk + 1 {
    // INT(blk) big-endian
    u1_msg.unsafe_set(salt_len, ((blk >> 24) & 0xff).to_byte())
    u1_msg.unsafe_set(salt_len + 1, ((blk >> 16) & 0xff).to_byte())
    u1_msg.unsafe_set(salt_len + 2, ((blk >> 8) & 0xff).to_byte())
    u1_msg.unsafe_set(salt_len + 3, (blk & 0xff).to_byte())
    // U_1
    hmac_sha256_compute(ctx, u1_msg, salt_len + 4, u)
    for i = 0; i < 32; i = i + 1 {
      t.unsafe_set(i, u.unsafe_get(i))
    }
    // U_2 .. U_c: msg is previous u (32 bytes)
    for _ in 1..<iterations {
      hmac_sha256_compute(ctx, u, 32, u)
      for i = 0; i < 32; i = i + 1 {
        t.unsafe_set(i, t.unsafe_get(i) ^ u.unsafe_get(i))
      }
    }
    // copy T into out[(blk-1)*32 .. blk*32]
    let base = (blk - 1) * h_len
    for i = 0; i < 32; i = i + 1 {
      out.unsafe_set(base + i, t.unsafe_get(i))
    }
  }
  let result = Bytes::makei(dk_len, fn(j) { out.unsafe_get(j) })
  // Best-effort wipe of password-derived intermediate state. See review #2
  // finding 8. The HMAC ctx holds the ipad/opad-compressed state words,
  // u/t hold the latest U_i / accumulated T (both PRF outputs under the
  // password's key), and the first salt_len+4 bytes of u1_msg hold the
  // final salt || INT(block) (non-secret but cheap to clear together).
  ctx.clear()
  for i in 0..<32 {
    u[i] = b'\x00'
    t[i] = b'\x00'
  }
  for i in 0..<u1_msg.length() {
    u1_msg[i] = b'\x00'
  }
  result
}
