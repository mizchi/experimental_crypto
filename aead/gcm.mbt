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
/// 16-entry GHASH reduction-lookup table for the 4-bit Shoup method. Each
/// entry rem_4bit[i] (i in 0..15) is the 16-bit value of `i * x^{124}` mod
/// the GCM reduction polynomial, positioned so that `(rem_4bit[i] as u64)
/// << 48` is the XOR mask applied to z_hi when a bottom nibble `i` is
/// shifted out of z_lo.
let rem_4bit : FixedArray[UInt64] = [
  0x0000UL, 0x1c20UL, 0x3840UL, 0x2460UL, 0x7080UL, 0x6ca0UL, 0x48c0UL, 0x54e0UL,
  0xe100UL, 0xfd20UL, 0xd940UL, 0xc560UL, 0x9180UL, 0x8da0UL, 0xa9c0UL, 0xb5e0UL,
]

///|
/// Bit-reverse a 4-bit value (0..15). Used to lay out the 16-entry product
/// table so that the inner loop can index it by the raw nibble.
fn reverse_bits4(i : Int) -> Int {
  let i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
  ((i << 1) & 0xa) | ((i >> 1) & 0x5)
}

///|
/// Multiply a 128-bit (hi, lo) value by x in GF(2^128) using the NIST
/// bit-reversed convention: shift right by 1 with a conditional XOR of
/// R = 0xe1 << 56 into hi when the low bit of `lo` is set.
fn gf128_double(hi : UInt64, lo : UInt64) -> (UInt64, UInt64) {
  let msb_set = (lo & 1UL) == 1UL
  let new_lo = (lo >> 1) | (hi << 63)
  let new_hi = hi >> 1
  if msb_set {
    (new_hi ^ 0xe100000000000000UL, new_lo)
  } else {
    (new_hi, new_lo)
  }
}

///|
/// Build the 16-entry product table for H. The result is laid out as a
/// flat FixedArray[UInt64] of length 32 where entry i occupies indices
/// (2*i) for hi and (2*i + 1) for lo. The table is filled such that
/// `productTable[bitreverse4(i)] = i * H`, so during the multiply loop
/// we can look up `productTable[nibble]` directly.
fn build_ghash_table(h_hi : UInt64, h_lo : UInt64) -> FixedArray[UInt64] {
  let t = FixedArray::make(32, 0UL)
  // productTable[reverseBits(1)] = 1 * H
  let idx1 = reverse_bits4(1)
  t[idx1 * 2] = h_hi
  t[idx1 * 2 + 1] = h_lo
  // Fill even-index entries via doubling; odd via XOR with H.
  let mut i = 2
  while i < 16 {
    // productTable[reverseBits(i)] = double(productTable[reverseBits(i/2)])
    let prev = reverse_bits4(i / 2)
    let (d_hi, d_lo) = gf128_double(t[prev * 2], t[prev * 2 + 1])
    let cur = reverse_bits4(i)
    t[cur * 2] = d_hi
    t[cur * 2 + 1] = d_lo
    // productTable[reverseBits(i+1)] = productTable[reverseBits(i)] XOR H
    let nxt = reverse_bits4(i + 1)
    t[nxt * 2] = d_hi ^ h_hi
    t[nxt * 2 + 1] = d_lo ^ h_lo
    i = i + 2
  }
  t
}

///|
/// Multiply Y · H in GF(2^128) using the precomputed 4-bit table.
/// Returns (z_hi, z_lo) where the encoding matches gf128_mul's contract.
fn gf128_mul_table(
  table : FixedArray[UInt64],
  y_hi : UInt64,
  y_lo : UInt64,
) -> (UInt64, UInt64) {
  let mut z_hi : UInt64 = 0UL
  let mut z_lo : UInt64 = 0UL
  // First iteration consumes y_lo (bytes 8..15 = high-degree coefficients).
  let mut word = y_lo
  let mut j = 0
  while j < 16 {
    let msw = (z_lo & 0xfUL).to_int()
    z_lo = (z_lo >> 4) | (z_hi << 60)
    z_hi = z_hi >> 4
    z_hi = z_hi ^ (rem_4bit[msw] << 48)
    let nib = (word & 0xfUL).to_int()
    z_hi = z_hi ^ table[nib * 2]
    z_lo = z_lo ^ table[nib * 2 + 1]
    word = word >> 4
    j = j + 1
  }
  // Second iteration consumes y_hi (bytes 0..7 = low-degree coefficients).
  word = y_hi
  j = 0
  while j < 16 {
    let msw = (z_lo & 0xfUL).to_int()
    z_lo = (z_lo >> 4) | (z_hi << 60)
    z_hi = z_hi >> 4
    z_hi = z_hi ^ (rem_4bit[msw] << 48)
    let nib = (word & 0xfUL).to_int()
    z_hi = z_hi ^ table[nib * 2]
    z_lo = z_lo ^ table[nib * 2 + 1]
    word = word >> 4
    j = j + 1
  }
  (z_hi, z_lo)
}

///|
/// GHASH(H, A, C) using the 4-bit table-driven multiplication. Output
/// matches the previous bit-by-bit `ghash` function bit-for-bit.
fn ghash(
  h_hi : UInt64,
  h_lo : UInt64,
  aad : Bytes,
  ct : Bytes,
) -> (UInt64, UInt64) {
  let table = build_ghash_table(h_hi, h_lo)
  let mut y_hi : UInt64 = 0UL
  let mut y_lo : UInt64 = 0UL

  // Process AAD in 16-byte chunks (zero-pad the final partial block).
  let aad_len = aad.length()
  let mut i = 0
  while i + 16 <= aad_len {
    y_hi = y_hi ^ be_load_u64(aad, i)
    y_lo = y_lo ^ be_load_u64(aad, i + 8)
    let (nz_hi, nz_lo) = gf128_mul_table(table, y_hi, y_lo)
    y_hi = nz_hi
    y_lo = nz_lo
    i = i + 16
  }
  if i < aad_len {
    let take = aad_len - i
    let buf = FixedArray::make(16, b'\x00')
    for j in 0..<take {
      buf[j] = aad[i + j]
    }
    let blk_hi = be_load_u64_arr(buf, 0)
    let blk_lo = be_load_u64_arr(buf, 8)
    y_hi = y_hi ^ blk_hi
    y_lo = y_lo ^ blk_lo
    let (nz_hi, nz_lo) = gf128_mul_table(table, y_hi, y_lo)
    y_hi = nz_hi
    y_lo = nz_lo
  }

  // Process ciphertext.
  let ct_len = ct.length()
  i = 0
  while i + 16 <= ct_len {
    y_hi = y_hi ^ be_load_u64(ct, i)
    y_lo = y_lo ^ be_load_u64(ct, i + 8)
    let (nz_hi, nz_lo) = gf128_mul_table(table, y_hi, y_lo)
    y_hi = nz_hi
    y_lo = nz_lo
    i = i + 16
  }
  if i < ct_len {
    let take = ct_len - i
    let buf = FixedArray::make(16, b'\x00')
    for j in 0..<take {
      buf[j] = ct[i + j]
    }
    let blk_hi = be_load_u64_arr(buf, 0)
    let blk_lo = be_load_u64_arr(buf, 8)
    y_hi = y_hi ^ blk_hi
    y_lo = y_lo ^ blk_lo
    let (nz_hi, nz_lo) = gf128_mul_table(table, y_hi, y_lo)
    y_hi = nz_hi
    y_lo = nz_lo
  }

  // Final block: len(AAD)*8 || len(C)*8, each big-endian 64-bit.
  let aad_bits = aad_len.to_uint64() * 8UL
  let ct_bits = ct_len.to_uint64() * 8UL
  y_hi = y_hi ^ aad_bits
  y_lo = y_lo ^ ct_bits
  let (nz_hi, nz_lo) = gf128_mul_table(table, y_hi, y_lo)
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
  // Reuse two 16-byte scratch buffers across every block. The old code
  // allocated 3 Bytes per block (buf, block, keystream); for a 16 KiB
  // payload that meant 3072 short-lived allocations on the GCM hot path.
  let ctr_buf = FixedArray::make(16, b'\x00')
  let ks_buf = FixedArray::make(16, b'\x00')
  // hi 64 bits of J0 stay constant; write once.
  be_store_u64(ctr_buf, 0, ctr_hi)
  let mut ctr = ctr_lo
  let mut i = 0
  while i < n {
    // inc32: increment the low 32 bits of the counter; high 96 stay.
    let ctr_low32 = (ctr + 1UL) & 0xFFFFFFFFUL
    ctr = (ctr & 0xFFFFFFFF00000000UL) | ctr_low32
    be_store_u64(ctr_buf, 8, ctr)
    aes_encrypt_block_fa(ctr_buf, 0, round_keys, nr, ks_buf, 0)
    let take = if n - i >= 16 { 16 } else { n - i }
    for j in 0..<take {
      out[i + j] = (data[i + j].to_int() ^ ks_buf.unsafe_get(j).to_int()).to_byte()
    }
    i = i + take
  }
  Bytes::makei(n, fn(i) { out.unsafe_get(i) })
}

///|
fn check_aes_gcm_block_count(plaintext_len : Int) -> Unit raise AeadError {
  if plaintext_len < 0 {
    raise PlaintextTooLong
  }
  // 2^39 - 256 bits = 2^36 - 32 bytes
  let max_bytes : UInt64 = (1UL << 36) - 32UL
  if plaintext_len.to_uint64() > max_bytes {
    raise PlaintextTooLong
  }
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
  // NIST SP 800-38D §5.2.1.1: plaintext is bounded by 2^39 - 256 bits,
  // i.e. ~64 GiB per (key, IV). Past that, GHASH collision probability
  // grows beyond the security target. MoonBit Bytes is Int-indexed so
  // this is unreachable today, but the check future-proofs the API.
  check_aes_gcm_block_count(plaintext.length())
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
    raise InvalidTagSize(expected=16, got=tag.length())
  }
  // Same NIST SP 800-38D §5.2.1.1 bound on ciphertext as on plaintext.
  check_aes_gcm_block_count(ciphertext.length())
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
