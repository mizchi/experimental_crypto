// AES-128/256-GCM (NIST SP 800-38D).
//
// The nonce ("IV" in the spec) is restricted to 12 bytes here, which is the
// most common case and what RFC 5116 / TLS / NIST recommend. For 12-byte
// nonces, the pre-counter block J0 = nonce || 0x00000001. The first AES
// counter block used for encryption is J0 with counter bumped to 2.
//
// Tag = AES_E(J0) XOR GHASH(AAD || pad16(AAD) || C || pad16(C)
//                            || len(AAD)*8 as 64-bit BE
//                            || len(C)*8   as 64-bit BE)
//
// GHASH is a polynomial hash over GF(2^128) with reduction polynomial
// f(x) = 1 + x + x^2 + x^7 + x^128. By the "bit-reversed" convention NIST
// uses, the multiplication-by-2 operation in this field corresponds to a
// right shift with XOR of 0xe1 in the high byte when bit 127 was set.

///|
/// 128-bit value as two big-endian UInt64 (hi, lo). The 128-bit input is
/// interpreted with the high byte at position 0 of the input bytes, then
/// "bit-reversed within each byte" implicitly handled by the right-shift
/// reduction. In practice: hi holds bytes[0..8] as a big-endian UInt64; lo
/// holds bytes[8..16] similarly.
fn be_load_u64(b : Bytes, off : Int) -> UInt64 {
  (b[off].to_uint64() << 56) |
  (b[off + 1].to_uint64() << 48) |
  (b[off + 2].to_uint64() << 40) |
  (b[off + 3].to_uint64() << 32) |
  (b[off + 4].to_uint64() << 24) |
  (b[off + 5].to_uint64() << 16) |
  (b[off + 6].to_uint64() << 8) |
  b[off + 7].to_uint64()
}

///|
fn be_load_u64_arr(buf : FixedArray[Byte], off : Int) -> UInt64 {
  (buf[off].to_uint64() << 56) |
  (buf[off + 1].to_uint64() << 48) |
  (buf[off + 2].to_uint64() << 40) |
  (buf[off + 3].to_uint64() << 32) |
  (buf[off + 4].to_uint64() << 24) |
  (buf[off + 5].to_uint64() << 16) |
  (buf[off + 6].to_uint64() << 8) |
  buf[off + 7].to_uint64()
}

///|
fn be_store_u64(out : FixedArray[Byte], off : Int, v : UInt64) -> Unit {
  out[off + 0] = ((v >> 56) & 0xFFUL).to_int().to_byte()
  out[off + 1] = ((v >> 48) & 0xFFUL).to_int().to_byte()
  out[off + 2] = ((v >> 40) & 0xFFUL).to_int().to_byte()
  out[off + 3] = ((v >> 32) & 0xFFUL).to_int().to_byte()
  out[off + 4] = ((v >> 24) & 0xFFUL).to_int().to_byte()
  out[off + 5] = ((v >> 16) & 0xFFUL).to_int().to_byte()
  out[off + 6] = ((v >> 8) & 0xFFUL).to_int().to_byte()
  out[off + 7] = (v & 0xFFUL).to_int().to_byte()
}

///|
/// GHASH multiplication X · H in GF(2^128). NIST SP 800-38D §6.3 Algorithm 1
/// (bit-by-bit). Inputs and outputs are 128-bit values as (hi, lo) where hi
/// holds the "leftmost" / most-significant bits.
///
/// Reduction polynomial: f(x) = 1 + x + x^2 + x^7 + x^128, encoded as
/// R = 0xe1 << 120 in the (hi, lo) representation.
fn gf128_mul(
  x_hi : UInt64,
  x_lo : UInt64,
  h_hi : UInt64,
  h_lo : UInt64,
) -> (UInt64, UInt64) {
  let mut z_hi : UInt64 = 0UL
  let mut z_lo : UInt64 = 0UL
  let mut v_hi = h_hi
  let mut v_lo = h_lo
  // Iterate over the 128 bits of x from MSB (hi bit 63) down to lo bit 0.
  for i in 0..<128 {
    let bit = if i < 64 {
      (x_hi >> (63 - i)) & 1UL
    } else {
      (x_lo >> (127 - i)) & 1UL
    }
    if bit == 1UL {
      z_hi = z_hi ^ v_hi
      z_lo = z_lo ^ v_lo
    }
    // V = V >> 1, with V XOR R if low bit was set (i.e., v_lo's bit 0).
    let v_low_bit = v_lo & 1UL
    v_lo = (v_lo >> 1) | (v_hi << 63)
    v_hi = v_hi >> 1
    if v_low_bit == 1UL {
      v_hi = v_hi ^ 0xe100000000000000UL
    }
  }
  (z_hi, z_lo)
}

///|
/// GHASH(H, A, C). Accepts arbitrary-length AAD and ciphertext.
/// Returns 16-byte tag value, packed as big-endian (hi, lo).
fn ghash(
  h_hi : UInt64,
  h_lo : UInt64,
  aad : Bytes,
  ct : Bytes,
) -> (UInt64, UInt64) {
  let mut y_hi : UInt64 = 0UL
  let mut y_lo : UInt64 = 0UL

  // Process AAD in 16-byte chunks (zero-pad the final partial block).
  let aad_len = aad.length()
  let mut i = 0
  while i < aad_len {
    let take = if aad_len - i >= 16 { 16 } else { aad_len - i }
    let buf = FixedArray::make(16, b'\x00')
    for j in 0..<take {
      buf[j] = aad[i + j]
    }
    let blk_hi = be_load_u64_arr(buf, 0)
    let blk_lo = be_load_u64_arr(buf, 8)
    y_hi = y_hi ^ blk_hi
    y_lo = y_lo ^ blk_lo
    let (nz_hi, nz_lo) = gf128_mul(y_hi, y_lo, h_hi, h_lo)
    y_hi = nz_hi
    y_lo = nz_lo
    i = i + take
  }

  // Process ciphertext.
  let ct_len = ct.length()
  i = 0
  while i < ct_len {
    let take = if ct_len - i >= 16 { 16 } else { ct_len - i }
    let buf = FixedArray::make(16, b'\x00')
    for j in 0..<take {
      buf[j] = ct[i + j]
    }
    let blk_hi = be_load_u64_arr(buf, 0)
    let blk_lo = be_load_u64_arr(buf, 8)
    y_hi = y_hi ^ blk_hi
    y_lo = y_lo ^ blk_lo
    let (nz_hi, nz_lo) = gf128_mul(y_hi, y_lo, h_hi, h_lo)
    y_hi = nz_hi
    y_lo = nz_lo
    i = i + take
  }

  // Final block: len(AAD)*8 || len(C)*8, each big-endian 64-bit.
  let aad_bits = aad_len.to_uint64() * 8UL
  let ct_bits = ct_len.to_uint64() * 8UL
  y_hi = y_hi ^ aad_bits
  y_lo = y_lo ^ ct_bits
  let (nz_hi, nz_lo) = gf128_mul(y_hi, y_lo, h_hi, h_lo)
  (nz_hi, nz_lo)
}

///|
/// Helper: AES-encrypt a 16-byte counter block represented as
/// (j0_hi, j0_lo). Returns 16 bytes.
fn aes_encrypt_counter(
  round_keys : FixedArray[Int],
  nr : Int,
  ctr_hi : UInt64,
  ctr_lo : UInt64,
) -> Bytes {
  let buf = FixedArray::make(16, b'\x00')
  be_store_u64(buf, 0, ctr_hi)
  be_store_u64(buf, 8, ctr_lo)
  let block = Bytes::makei(16, fn(i) { buf[i] })
  aes_encrypt_block(block, round_keys, nr)
}

///|
/// CTR-mode encryption / decryption (symmetric). `ctr0_hi/lo` is the initial
/// counter value (which is *not* used for the first block; the spec
/// increments before use). Returns ciphertext of the same length as input.
fn aes_ctr_xor(
  round_keys : FixedArray[Int],
  nr : Int,
  ctr_hi : UInt64,
  ctr_lo : UInt64,
  data : Bytes,
) -> Bytes {
  let n = data.length()
  if n == 0 {
    return b""
  }
  let out = FixedArray::make(n, b'\x00')
  let mut ctr = ctr_lo
  let hi = ctr_hi
  let mut i = 0
  while i < n {
    // inc32: increment the low 32 bits of the counter; high 96 stay.
    let ctr_low32 = (ctr + 1UL) & 0xFFFFFFFFUL
    ctr = (ctr & 0xFFFFFFFF00000000UL) | ctr_low32
    let keystream = aes_encrypt_counter(round_keys, nr, hi, ctr)
    let take = if n - i >= 16 { 16 } else { n - i }
    for j in 0..<take {
      out[i + j] = (data[i + j].to_int() ^ keystream[j].to_int()).to_byte()
    }
    i = i + take
  }
  Bytes::makei(n, fn(i) { out[i] })
}

///|
fn aes_gcm_seal(
  key_len : Int,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> (Bytes, Bytes) raise AeadError {
  if key.length() != key_len {
    raise InvalidKeySize(expected=key_len, got=key.length())
  }
  if nonce.length() != 12 {
    raise InvalidNonceSize(expected=12, got=nonce.length())
  }
  let (rk, nr) = aes_key_schedule(key)

  // H = AES_E(0^128)
  let zero16 = Bytes::makei(16, fn(_) { b'\x00' })
  let h_bytes = aes_encrypt_block(zero16, rk, nr)
  let h_hi = be_load_u64(h_bytes, 0)
  let h_lo = be_load_u64(h_bytes, 8)

  // J0 = nonce || 0x00000001  (96 + 32 = 128 bits, 12-byte nonce path)
  let j0_hi = (nonce[0].to_uint64() << 56) |
    (nonce[1].to_uint64() << 48) |
    (nonce[2].to_uint64() << 40) |
    (nonce[3].to_uint64() << 32) |
    (nonce[4].to_uint64() << 24) |
    (nonce[5].to_uint64() << 16) |
    (nonce[6].to_uint64() << 8) |
    nonce[7].to_uint64()
  let j0_lo = (nonce[8].to_uint64() << 56) |
    (nonce[9].to_uint64() << 48) |
    (nonce[10].to_uint64() << 40) |
    (nonce[11].to_uint64() << 32) |
    1UL

  // C = CTR_{INC32(J0)}(P)
  let ct = aes_ctr_xor(rk, nr, j0_hi, j0_lo, plaintext)

  // S = GHASH(H, A, C)
  let (s_hi, s_lo) = ghash(h_hi, h_lo, aad, ct)

  // T = MSB_t(E_K(J0) XOR S)
  let ej0 = aes_encrypt_counter(rk, nr, j0_hi, j0_lo)
  let ej0_hi = be_load_u64(ej0, 0)
  let ej0_lo = be_load_u64(ej0, 8)
  let tag_hi = ej0_hi ^ s_hi
  let tag_lo = ej0_lo ^ s_lo
  let tag_buf = FixedArray::make(16, b'\x00')
  be_store_u64(tag_buf, 0, tag_hi)
  be_store_u64(tag_buf, 8, tag_lo)
  let tag = Bytes::makei(16, fn(i) { tag_buf[i] })
  (ct, tag)
}

///|
fn aes_gcm_open(
  key_len : Int,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
) -> Bytes raise AeadError {
  if key.length() != key_len {
    raise InvalidKeySize(expected=key_len, got=key.length())
  }
  if nonce.length() != 12 {
    raise InvalidNonceSize(expected=12, got=nonce.length())
  }
  if tag.length() != 16 {
    raise AuthenticationFailed
  }
  let (rk, nr) = aes_key_schedule(key)
  let zero16 = Bytes::makei(16, fn(_) { b'\x00' })
  let h_bytes = aes_encrypt_block(zero16, rk, nr)
  let h_hi = be_load_u64(h_bytes, 0)
  let h_lo = be_load_u64(h_bytes, 8)
  let j0_hi = (nonce[0].to_uint64() << 56) |
    (nonce[1].to_uint64() << 48) |
    (nonce[2].to_uint64() << 40) |
    (nonce[3].to_uint64() << 32) |
    (nonce[4].to_uint64() << 24) |
    (nonce[5].to_uint64() << 16) |
    (nonce[6].to_uint64() << 8) |
    nonce[7].to_uint64()
  let j0_lo = (nonce[8].to_uint64() << 56) |
    (nonce[9].to_uint64() << 48) |
    (nonce[10].to_uint64() << 40) |
    (nonce[11].to_uint64() << 32) |
    1UL

  // S = GHASH(H, A, C)
  let (s_hi, s_lo) = ghash(h_hi, h_lo, aad, ciphertext)
  let ej0 = aes_encrypt_counter(rk, nr, j0_hi, j0_lo)
  let ej0_hi = be_load_u64(ej0, 0)
  let ej0_lo = be_load_u64(ej0, 8)
  let expected_tag_hi = ej0_hi ^ s_hi
  let expected_tag_lo = ej0_lo ^ s_lo
  let expected_tag_buf = FixedArray::make(16, b'\x00')
  be_store_u64(expected_tag_buf, 0, expected_tag_hi)
  be_store_u64(expected_tag_buf, 8, expected_tag_lo)
  let expected_tag = Bytes::makei(16, fn(i) { expected_tag_buf[i] })
  if !constant_time_eq(tag, expected_tag) {
    raise AuthenticationFailed
  }
  aes_ctr_xor(rk, nr, j0_hi, j0_lo, ciphertext)
}
