// HMAC-SHA256 (RFC 2104). Built on top of the SHA-256 primitives in this
// package.
//
// We expose a `HmacSha256Ctx` so consumers that call HMAC repeatedly with the
// same key (PBKDF2, JWT verifying many tokens) can amortize the ipad/opad
// pre-compression. The one-shot `hmac_sha256(key, msg)` is the lazy form.

///|
pub struct HmacSha256Ctx {
  inner_state : FixedArray[UInt]
  outer_state : FixedArray[UInt]
}

///|
/// Initialise an HMAC-SHA256 context with `key`. The ipad/opad first blocks
/// are pre-compressed so each subsequent `compute` is two finalise passes
/// rather than four compressions.
pub fn hmac_sha256_init(key : Bytes) -> HmacSha256Ctx {
  let block_size = 64
  let padded = FixedArray::make(block_size, b'\x00')
  if key.length() > block_size {
    sha256_hash_bytes(key, padded) // fills first 32 bytes; tail stays zero
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
/// HMAC-SHA256 of `msg` under the pre-baked context. Returns a 32-byte tag.
pub fn hmac_sha256_compute(ctx : HmacSha256Ctx, msg : Bytes) -> Bytes {
  // ---- inner: H(ipad || msg) ----
  let state = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    state.unsafe_set(i, ctx.inner_state.unsafe_get(i))
  }
  let n = msg.length()
  let w = FixedArray::make(64, 0U)
  let block = FixedArray::make(64, b'\x00')
  let mut offset = 0
  while offset + 64 <= n {
    for i = 0; i < 16; i = i + 1 {
      let p = offset + i * 4
      let b0 = msg[p].to_uint()
      let b1 = msg[p + 1].to_uint()
      let b2 = msg[p + 2].to_uint()
      let b3 = msg[p + 3].to_uint()
      w.unsafe_set(i, (b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }
    sha256_compress(state, w)
    offset += 64
  }
  let tail_len = n - offset
  for i = 0; i < tail_len; i = i + 1 {
    block.unsafe_set(i, msg[offset + i])
  }
  let prefix_bits = 512UL + offset.to_uint64() * 8UL
  let inner_hash = FixedArray::make(32, b'\x00')
  sha256_finalize_with_tail(state, block, tail_len, prefix_bits, inner_hash)
  // ---- outer: H(opad || inner_hash) ----
  let state2 = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    state2.unsafe_set(i, ctx.outer_state.unsafe_get(i))
  }
  let tail2 = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    tail2.unsafe_set(i, inner_hash.unsafe_get(i))
  }
  let out = FixedArray::make(32, b'\x00')
  sha256_finalize_with_tail(state2, tail2, 32, 512UL, out)
  Bytes::makei(32, fn(j) { out.unsafe_get(j) })
}

///|
/// One-shot HMAC-SHA256 over `msg` under `key`. Equivalent to
/// `hmac_sha256_compute(hmac_sha256_init(key), msg)`.
pub fn hmac_sha256(key : Bytes, msg : Bytes) -> Bytes {
  let ctx = hmac_sha256_init(key)
  hmac_sha256_compute(ctx, msg)
}

///|
/// Constant-time byte-sequence equality. Returns true iff `a` and `b` have
/// the same length and the same contents. Time depends on max(|a|, |b|)
/// rather than the position of the first difference.
pub fn ct_eq(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    // Length is public for the MAC tags we compare here, so an early return
    // does not leak anything privileged.
    return false
  }
  let mut diff = 0
  for i = 0; i < a.length(); i = i + 1 {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}
