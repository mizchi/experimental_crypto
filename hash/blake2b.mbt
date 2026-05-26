// BLAKE2b (RFC 7693 §3.2). Self-contained, NOT constant-time.
//
// Little-endian 64-bit words, 1024-bit (128-byte) block, output 1..64 bytes.
// Supports keyed mode (MAC) with key length 0..64 bytes.
//
// This implementation is independent of the BLAKE2b copy embedded in
// `mizchi/argon2` (which is kept there because Argon2's H' / H0 paths feed it
// `FixedArray[Byte]` buffers under heavy tuning, and we don't want to perturb
// the bit-exact RFC 9106 vectors). The two implementations agree on test
// vectors but are not source-shared.

///|
pub suberror Blake2bError {
  InvalidOutputLength
  InvalidKeyLength
} derive(Debug)

///|
/// BLAKE2b IV (RFC 7693 §2.6).
let blake2b_iv : FixedArray[UInt64] = [
  0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL, 0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
  0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL, 0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL,
]

///|
/// BLAKE2b sigma message schedule (RFC 7693 §2.7).
let blake2b_sigma : FixedArray[FixedArray[Int]] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  // Final 2 rounds reuse sigma[0] and sigma[1] for total 12 rounds.
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
]

///|
/// Rotate-right 64-bit. Local copy — `sha512.mbt` defines a sibling but
/// MoonBit allows duplicate file-private names only when both are file-private;
/// using a local inline-form keeps this file standalone.
fn blake2b_rotr(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
/// Load 8 bytes little-endian as UInt64 from a Bytes-like buffer.
fn blake2b_load_u64_le(buf : FixedArray[Byte], o : Int) -> UInt64 {
  buf[o].to_uint64() |
  (buf[o + 1].to_uint64() << 8) |
  (buf[o + 2].to_uint64() << 16) |
  (buf[o + 3].to_uint64() << 24) |
  (buf[o + 4].to_uint64() << 32) |
  (buf[o + 5].to_uint64() << 40) |
  (buf[o + 6].to_uint64() << 48) |
  (buf[o + 7].to_uint64() << 56)
}

///|
/// One mixing G(a,b,c,d,x,y) per RFC 7693 §3.1.
fn blake2b_g(
  v : FixedArray[UInt64],
  a : Int,
  b : Int,
  c : Int,
  d : Int,
  x : UInt64,
  y : UInt64,
) -> Unit {
  v[a] = v[a] + v[b] + x
  v[d] = blake2b_rotr(v[d] ^ v[a], 32)
  v[c] = v[c] + v[d]
  v[b] = blake2b_rotr(v[b] ^ v[c], 24)
  v[a] = v[a] + v[b] + y
  v[d] = blake2b_rotr(v[d] ^ v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = blake2b_rotr(v[b] ^ v[c], 63)
}

///|
/// Compression function F (RFC 7693 §3.2).
///
/// `h` is the 8-word state, `block` is the 128-byte message block starting at
/// `block_offset`, `t_low` / `t_high` is the 128-bit byte counter, and `last`
/// indicates the final block (sets f0 = 0xFFFFFFFFFFFFFFFF).
fn blake2b_compress(
  h : FixedArray[UInt64],
  block : FixedArray[Byte],
  block_offset : Int,
  t_low : UInt64,
  t_high : UInt64,
  last : Bool,
) -> Unit {
  // Initialize local work vector v[0..16].
  let v = FixedArray::make(16, 0UL)
  for i in 0..<8 {
    v[i] = h[i]
    v[i + 8] = blake2b_iv[i]
  }
  v[12] = v[12] ^ t_low
  v[13] = v[13] ^ t_high
  if last {
    v[14] = v[14] ^ 0xFFFFFFFFFFFFFFFFUL
  }
  // Load message block as 16 little-endian u64 words.
  let m = FixedArray::make(16, 0UL)
  for i in 0..<16 {
    m[i] = blake2b_load_u64_le(block, block_offset + i * 8)
  }
  // 12 rounds.
  for r in 0..<12 {
    let s = blake2b_sigma[r]
    blake2b_g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
    blake2b_g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
    blake2b_g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
    blake2b_g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
    blake2b_g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
    blake2b_g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
    blake2b_g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
    blake2b_g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
  }
  // Finalize: h[i] ^= v[i] ^ v[i+8].
  for i in 0..<8 {
    h[i] = h[i] ^ v[i] ^ v[i + 8]
  }
}

///|
/// Internal core: arbitrary-length input → `out_len` bytes (1..64), with
/// optional `key` (length 0..64).
///
/// This expects validated inputs — callers must check ranges first.
fn blake2b_core(data : Bytes, key : Bytes, out_len : Int) -> Bytes {
  // Initialize state from IV; mix in parameter block low word.
  // Parameter block layout (RFC 7693 §2.5, sequential mode):
  //   byte 0: digest_length (1..64)
  //   byte 1: key_length    (0..64)
  //   byte 2: fanout        = 1
  //   byte 3: depth         = 1
  //   bytes 4..7: leaf_length (= 0)
  //   bytes 8..15: node_offset (= 0)
  //   bytes 16..17: node_depth (= 0) / inner_length (= 0)
  //   ... rest zero
  // The low 64 bits = 0x0101kkll where kk = key_len, ll = out_len. All other
  // parameter-block words are 0, so only h[0] gets XORed.
  let h = FixedArray::make(8, 0UL)
  for i in 0..<8 {
    h[i] = blake2b_iv[i]
  }
  let key_len = key.length()
  let p0 = 0x01010000UL | (key_len.to_uint64() << 8) | out_len.to_uint64()
  h[0] = h[0] ^ p0

  // Build buffer: if keyed, prepend key padded to 128 bytes (one full block).
  let input_len = data.length()
  let total_len = (if key_len > 0 { 128 } else { 0 }) + input_len
  // Even for empty input + no key we still need to process one zero block.
  let buf_len = if total_len == 0 {
    128
  } else if total_len % 128 == 0 {
    total_len
  } else {
    total_len + (128 - total_len % 128)
  }
  let buf = FixedArray::make(buf_len, b'\x00')
  if key_len > 0 {
    for i in 0..<key_len {
      buf[i] = key[i]
    }
  }
  let in_off = if key_len > 0 { 128 } else { 0 }
  for i in 0..<input_len {
    buf[in_off + i] = data[i]
  }

  // Process all but the last block as non-final, last block as final.
  let num_blocks = buf_len / 128
  let mut processed : UInt64 = 0UL
  for i in 0..<(num_blocks - 1) {
    processed = processed + 128UL
    blake2b_compress(h, buf, i * 128, processed, 0UL, false)
  }
  // Final block: counter = total bytes hashed (including key block when keyed).
  // We pass t_high = 0 because hash:blake2b inputs in practice are well under
  // 2^64 bytes; for streaming over hypothetical >2^64-byte inputs t_high must
  // be (total >> 64).
  let last_count : UInt64 = total_len.to_uint64()
  blake2b_compress(h, buf, (num_blocks - 1) * 128, last_count, 0UL, true)

  // Extract out_len little-endian bytes from h.
  let out = FixedArray::make(out_len, b'\x00')
  for i in 0..<out_len {
    let word_idx = i / 8
    let byte_idx = i % 8
    out[i] = ((h[word_idx] >> (byte_idx * 8)) & 0xFFUL).to_byte()
  }
  Bytes::makei(out_len, fn(j) { out[j] })
}

///|
/// BLAKE2b (RFC 7693). Output length 1..64 bytes.
///
/// One-shot: H = BLAKE2b(data, out_len)
pub fn blake2b(data : Bytes, out_len : Int) -> Bytes raise Blake2bError {
  if out_len < 1 || out_len > 64 {
    raise InvalidOutputLength
  }
  blake2b_core(data, b"", out_len)
}

///|
/// Keyed BLAKE2b (MAC mode). Key length 0..64.
pub fn blake2b_keyed(
  data : Bytes,
  key : Bytes,
  out_len : Int,
) -> Bytes raise Blake2bError {
  if out_len < 1 || out_len > 64 {
    raise InvalidOutputLength
  }
  if key.length() > 64 {
    raise InvalidKeyLength
  }
  blake2b_core(data, key, out_len)
}

///|
/// Convenience: BLAKE2b-256 = blake2b(data, 32).
pub fn blake2b_256(data : Bytes) -> Bytes {
  // out_len = 32 is in range, so the inner check cannot raise.
  blake2b_core(data, b"", 32)
}

///|
/// Convenience: BLAKE2b-512 = blake2b(data, 64).
pub fn blake2b_512(data : Bytes) -> Bytes {
  // out_len = 64 is in range, so the inner check cannot raise.
  blake2b_core(data, b"", 64)
}
