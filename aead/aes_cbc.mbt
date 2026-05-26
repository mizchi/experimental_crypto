// AES-CBC (NIST SP 800-38A §6.2) — confidentiality-only block-cipher mode.
//
// This is NOT an AEAD. CBC alone provides no authentication; callers that
// need integrity MUST add a MAC (encrypt-then-MAC) or use a real AEAD
// (GCM / ChaCha20-Poly1305). The reason this exists in the aead module
// despite that is to serve PBES2 (PKCS#5 v2.1) decryption in
// `mizchi/pkcs8`, which has a fixed legacy ciphersuite. Do not reach for
// raw AES-CBC for new designs.
//
// Implementation notes:
// - Encryption reuses the existing T-table forward block cipher in aes.mbt.
// - Decryption needs the inverse cipher, so we build the inverse S-box and
//   the four inverse T-tables (Td0..Td3) once at module-load time. The
//   round-key schedule is the same as for encryption (the inverse cipher
//   walks round keys in reverse). The "Equivalent Inverse Cipher" (FIPS
//   197 §5.3.5) is used: the schedule is applied as-is and the round keys
//   for the middle rounds are pre-multiplied by InvMixColumns. We do that
//   on the fly during decryption rather than mutating the schedule, so
//   key expansion is shared with encrypt.
//
// Not constant-time (T-table lookups).

// ─── Public API ─────────────────────────────────────────────────────────

///|
/// Encrypt `plaintext` under AES-CBC with the given `key` and `iv`.
/// `plaintext` must already be a multiple of 16 bytes — this function does
/// NOT add PKCS#7 padding; the caller is responsible for that. Returns
/// `plaintext.length()` bytes of ciphertext.
///
/// Key length must be 16 or 32 bytes (AES-128 or AES-256). `iv` must be
/// 16 bytes.
pub fn aes_cbc_encrypt(
  key : Bytes,
  iv : Bytes,
  plaintext : Bytes,
) -> Bytes raise AeadError {
  if iv.length() != 16 {
    raise InvalidNonceSize(expected=16, got=iv.length())
  }
  if plaintext.length() % 16 != 0 {
    raise PlaintextTooLong
  }
  let (rk, nr) = aes_key_schedule(key)
  let n = plaintext.length()
  let out = FixedArray::make(n, b'\x00')
  let prev = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    prev[i] = iv[i]
  }
  let block = FixedArray::make(16, b'\x00')
  let mut off = 0
  while off < n {
    for i in 0..<16 {
      block[i] = (plaintext[off + i].to_int() ^ prev[i].to_int()).to_byte()
    }
    let block_bytes = Bytes::makei(16, fn(i) { block[i] })
    let enc = aes_encrypt_block(block_bytes, rk, nr)
    for i in 0..<16 {
      out[off + i] = enc[i]
      prev[i] = enc[i]
    }
    off = off + 16
  }
  Bytes::makei(n, fn(i) { out[i] })
}

///|
/// Decrypt `ciphertext` under AES-CBC with the given `key` and `iv`.
/// `ciphertext` must be a multiple of 16 bytes. This function does NOT
/// strip padding; the caller is responsible for that. Returns
/// `ciphertext.length()` bytes of plaintext.
///
/// Key length must be 16 or 32 bytes (AES-128 or AES-256). `iv` must be
/// 16 bytes.
pub fn aes_cbc_decrypt(
  key : Bytes,
  iv : Bytes,
  ciphertext : Bytes,
) -> Bytes raise AeadError {
  if iv.length() != 16 {
    raise InvalidNonceSize(expected=16, got=iv.length())
  }
  if ciphertext.length() % 16 != 0 {
    raise CiphertextTooShort
  }
  let (rk, nr) = aes_key_schedule(key)
  let n = ciphertext.length()
  let out = FixedArray::make(n, b'\x00')
  let prev = FixedArray::make(16, b'\x00')
  for i in 0..<16 {
    prev[i] = iv[i]
  }
  let block = FixedArray::make(16, b'\x00')
  let mut off = 0
  while off < n {
    for i in 0..<16 {
      block[i] = ciphertext[off + i]
    }
    let block_bytes = Bytes::makei(16, fn(i) { block[i] })
    let dec = aes_decrypt_block(block_bytes, rk, nr)
    for i in 0..<16 {
      out[off + i] = (dec[i].to_int() ^ prev[i].to_int()).to_byte()
      prev[i] = ciphertext[off + i]
    }
    off = off + 16
  }
  Bytes::makei(n, fn(i) { out[i] })
}

// ─── Inverse AES block cipher (Equivalent Inverse Cipher, FIPS 197 §5.3.5)

///|
/// AES inverse S-box (FIPS 197 §5.1.2, Figure 14).
let aes_inv_sbox : FixedArray[Int] = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
  0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
  0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c,
  0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
  0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68,
  0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
  0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8,
  0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13,
  0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
  0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
  0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
  0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33,
  0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
  0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53,
  0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
  0x55, 0x21, 0x0c, 0x7d,
]

///|
/// gmul: multiplication in GF(2^8) with the AES reduction polynomial.
fn gmul(a : Int, b : Int) -> Int {
  let mut p = 0
  let mut aa = a & 0xFF
  let mut bb = b & 0xFF
  for _ in 0..<8 {
    if (bb & 1) != 0 {
      p = p ^ aa
    }
    let hi = aa & 0x80
    aa = (aa << 1) & 0xFF
    if hi != 0 {
      aa = aa ^ 0x1B
    }
    bb = bb >> 1
  }
  p & 0xFF
}

///|
/// Build Td0: inverse T-table. Td0[s] is the InvMixColumns transform applied
/// to the column (InvSBox[s], 0, 0, 0). Packed as (r0 << 24 | r1 << 16 | r2 << 8 | r3).
/// InvMixColumns matrix: [0e 0b 0d 09; 09 0e 0b 0d; 0d 09 0e 0b; 0b 0d 09 0e].
fn build_td0() -> FixedArray[Int] {
  let t = FixedArray::make(256, 0)
  for s in 0..<256 {
    let v = aes_inv_sbox[s]
    let v9 = gmul(v, 0x09)
    let vb = gmul(v, 0x0b)
    let vd = gmul(v, 0x0d)
    let ve = gmul(v, 0x0e)
    t[s] = (ve << 24) | (v9 << 16) | (vd << 8) | vb
  }
  t
}

///|
fn build_td1(td0 : FixedArray[Int]) -> FixedArray[Int] {
  let t = FixedArray::make(256, 0)
  for s in 0..<256 {
    let w = td0[s]
    t[s] = (((w >> 8) & 0x00FFFFFF) | (w << 24)) & 0xFFFFFFFF
  }
  t
}

///|
fn build_td2(td0 : FixedArray[Int]) -> FixedArray[Int] {
  let t = FixedArray::make(256, 0)
  for s in 0..<256 {
    let w = td0[s]
    t[s] = (((w >> 16) & 0x0000FFFF) | (w << 16)) & 0xFFFFFFFF
  }
  t
}

///|
fn build_td3(td0 : FixedArray[Int]) -> FixedArray[Int] {
  let t = FixedArray::make(256, 0)
  for s in 0..<256 {
    let w = td0[s]
    t[s] = (((w >> 24) & 0x000000FF) | (w << 8)) & 0xFFFFFFFF
  }
  t
}

///|
let td0 : FixedArray[Int] = build_td0()

///|
let td1 : FixedArray[Int] = build_td1(td0)

///|
let td2 : FixedArray[Int] = build_td2(td0)

///|
let td3 : FixedArray[Int] = build_td3(td0)

///|
/// inv_mix_word: applies InvMixColumns to a single 32-bit column word.
/// Used to transform the encryption round keys for the equivalent inverse
/// cipher's middle rounds.
fn inv_mix_word(w : Int) -> Int {
  let b0 = (w >> 24) & 0xFF
  let b1 = (w >> 16) & 0xFF
  let b2 = (w >> 8) & 0xFF
  let b3 = w & 0xFF
  let r0 = gmul(b0, 0x0e) ^ gmul(b1, 0x0b) ^ gmul(b2, 0x0d) ^ gmul(b3, 0x09)
  let r1 = gmul(b0, 0x09) ^ gmul(b1, 0x0e) ^ gmul(b2, 0x0b) ^ gmul(b3, 0x0d)
  let r2 = gmul(b0, 0x0d) ^ gmul(b1, 0x09) ^ gmul(b2, 0x0e) ^ gmul(b3, 0x0b)
  let r3 = gmul(b0, 0x0b) ^ gmul(b1, 0x0d) ^ gmul(b2, 0x09) ^ gmul(b3, 0x0e)
  (r0 << 24) | (r1 << 16) | (r2 << 8) | r3
}

///|
/// AES inverse block cipher (Equivalent Inverse Cipher). Uses the same
/// round-key schedule as encryption but walks it in reverse and applies
/// InvMixColumns to each middle-round key word on the fly.
fn aes_decrypt_block(
  block : Bytes,
  round_keys : FixedArray[Int],
  nr : Int,
) -> Bytes {
  // Load state and XOR final-round key (round_keys[nr*4 .. nr*4+4]).
  let rk_last = nr * 4
  let mut s0 = (
      (block[0].to_int() << 24) |
      (block[1].to_int() << 16) |
      (block[2].to_int() << 8) |
      block[3].to_int()
    ) ^
    round_keys[rk_last]
  let mut s1 = (
      (block[4].to_int() << 24) |
      (block[5].to_int() << 16) |
      (block[6].to_int() << 8) |
      block[7].to_int()
    ) ^
    round_keys[rk_last + 1]
  let mut s2 = (
      (block[8].to_int() << 24) |
      (block[9].to_int() << 16) |
      (block[10].to_int() << 8) |
      block[11].to_int()
    ) ^
    round_keys[rk_last + 2]
  let mut s3 = (
      (block[12].to_int() << 24) |
      (block[13].to_int() << 16) |
      (block[14].to_int() << 8) |
      block[15].to_int()
    ) ^
    round_keys[rk_last + 3]

  // Main rounds nr-1 down to 1: inverse T-table.
  // Inverse ShiftRows reads from offsets (0, -1, -2, -3) per row
  // (equivalently (0, +3, +2, +1) mod 4 in column index).
  let mut round = nr - 1
  while round >= 1 {
    let rk_off = round * 4
    let t0 = td0[(s0 >> 24) & 0xFF] ^
      td1[(s3 >> 16) & 0xFF] ^
      td2[(s2 >> 8) & 0xFF] ^
      td3[s1 & 0xFF] ^
      inv_mix_word(round_keys[rk_off])
    let t1 = td0[(s1 >> 24) & 0xFF] ^
      td1[(s0 >> 16) & 0xFF] ^
      td2[(s3 >> 8) & 0xFF] ^
      td3[s2 & 0xFF] ^
      inv_mix_word(round_keys[rk_off + 1])
    let t2 = td0[(s2 >> 24) & 0xFF] ^
      td1[(s1 >> 16) & 0xFF] ^
      td2[(s0 >> 8) & 0xFF] ^
      td3[s3 & 0xFF] ^
      inv_mix_word(round_keys[rk_off + 2])
    let t3 = td0[(s3 >> 24) & 0xFF] ^
      td1[(s2 >> 16) & 0xFF] ^
      td2[(s1 >> 8) & 0xFF] ^
      td3[s0 & 0xFF] ^
      inv_mix_word(round_keys[rk_off + 3])
    s0 = t0
    s1 = t1
    s2 = t2
    s3 = t3
    round = round - 1
  }

  // First round (last to be applied to state): InvSubBytes + InvShiftRows
  // + AddRoundKey (no InvMixColumns).
  let f0 = (
      (aes_inv_sbox[(s0 >> 24) & 0xFF] << 24) |
      (aes_inv_sbox[(s3 >> 16) & 0xFF] << 16) |
      (aes_inv_sbox[(s2 >> 8) & 0xFF] << 8) |
      aes_inv_sbox[s1 & 0xFF]
    ) ^
    round_keys[0]
  let f1 = (
      (aes_inv_sbox[(s1 >> 24) & 0xFF] << 24) |
      (aes_inv_sbox[(s0 >> 16) & 0xFF] << 16) |
      (aes_inv_sbox[(s3 >> 8) & 0xFF] << 8) |
      aes_inv_sbox[s2 & 0xFF]
    ) ^
    round_keys[1]
  let f2 = (
      (aes_inv_sbox[(s2 >> 24) & 0xFF] << 24) |
      (aes_inv_sbox[(s1 >> 16) & 0xFF] << 16) |
      (aes_inv_sbox[(s0 >> 8) & 0xFF] << 8) |
      aes_inv_sbox[s3 & 0xFF]
    ) ^
    round_keys[2]
  let f3 = (
      (aes_inv_sbox[(s3 >> 24) & 0xFF] << 24) |
      (aes_inv_sbox[(s2 >> 16) & 0xFF] << 16) |
      (aes_inv_sbox[(s1 >> 8) & 0xFF] << 8) |
      aes_inv_sbox[s0 & 0xFF]
    ) ^
    round_keys[3]

  Bytes::makei(16, fn(i) {
    let col = i / 4
    let row = i % 4
    let w = match col {
      0 => f0
      1 => f1
      2 => f2
      _ => f3
    }
    ((w >> ((3 - row) * 8)) & 0xFF).to_byte()
  })
}
