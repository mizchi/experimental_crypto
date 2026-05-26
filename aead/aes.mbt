// AES-128 and AES-256 block cipher (FIPS 197). Encryption only — GCM does
// not need the inverse direction. This implementation uses the T-table
// (Te0..Te3) optimization: each main round becomes 16 table lookups + 16
// XORs over four 32-bit words, instead of per-byte SubBytes / ShiftRows /
// MixColumns. The final round still uses the raw S-box (no MixColumns).
//
// This is NOT constant-time: the table lookups leak key bits via cache
// timing. Do not use where side-channel resistance matters.

///|
/// AES forward S-box (FIPS 197 §5.1.1, Figure 7). 256 entries.
let aes_sbox : FixedArray[Int] = [
  // row 0
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
  0xab, 0x76,
  // row 1
   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c,
  0xa4, 0x72, 0xc0,
  // row 2
   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
  0xd8, 0x31, 0x15,
  // row 3
   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb,
  0x27, 0xb2, 0x75,
  // row 4
   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
  0xe3, 0x2f, 0x84,
  // row 5
   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a,
  0x4c, 0x58, 0xcf,
  // row 6
   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50,
  0x3c, 0x9f, 0xa8,
  // row 7
   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10,
  0xff, 0xf3, 0xd2,
  // row 8
   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64,
  0x5d, 0x19, 0x73,
  // row 9
   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde,
  0x5e, 0x0b, 0xdb,
  // row a
   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91,
  0x95, 0xe4, 0x79,
  // row b
   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65,
  0x7a, 0xae, 0x08,
  // row c
   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b,
  0xbd, 0x8b, 0x8a,
  // row d
   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86,
  0xc1, 0x1d, 0x9e,
  // row e
   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce,
  0x55, 0x28, 0xdf,
  // row f
   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
  0x54, 0xbb, 0x16,
]

///|
/// Round constants (FIPS 197 §5.2). rcon[i] = (rc(i), 0, 0, 0) where rc is
/// 2^(i-1) in GF(2^8) reduced by x^8 + x^4 + x^3 + x + 1.
let aes_rcon : FixedArray[Int] = [
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]

///|
/// Look up the S-box at byte position `b` (0..=255).
fn sbox(b : Int) -> Int {
  aes_sbox[b & 0xFF]
}

///|
/// xtime: multiplication by x (= 0x02) in GF(2^8) with reduction by
/// x^8 + x^4 + x^3 + x + 1.
fn xtime(b : Int) -> Int {
  let shifted = (b << 1) & 0xFF
  if (b & 0x80) != 0 {
    shifted ^ 0x1B
  } else {
    shifted
  }
}

///|
/// Build Te0: the 256-entry T-table where Te0[s] equals the MixColumns
/// transform applied to the column (SBox[s], 0, 0, 0). Words are packed
/// with row 0 in the high byte: word = (r0 << 24) | (r1 << 16) | (r2 << 8) | r3.
fn build_te0() -> FixedArray[Int] {
  let t = FixedArray::make(256, 0)
  for s in 0..<256 {
    let v = aes_sbox[s]
    let v2 = xtime(v)
    let v3 = v2 ^ v
    // MixColumns × (v, 0, 0, 0) = (2v, v, v, 3v)
    t[s] = (v2 << 24) | (v << 16) | (v << 8) | v3
  }
  t
}

///|
/// Te1[s] = rotate Te0[s] right by 8 bits. Corresponds to MixColumns ×
/// (0, SBox[s], 0, 0) = (3v, 2v, v, v).
fn build_te1(te0 : FixedArray[Int]) -> FixedArray[Int] {
  let t = FixedArray::make(256, 0)
  for s in 0..<256 {
    let w = te0[s]
    // rotate right 8: (w >> 8) | (w << 24), masked to 32 bits.
    t[s] = (((w >> 8) & 0x00FFFFFF) | (w << 24)) & 0xFFFFFFFF
  }
  t
}

///|
/// Te2[s] = rotate Te0[s] right by 16 bits. MixColumns × (0, 0, SBox[s], 0)
/// = (v, 3v, 2v, v).
fn build_te2(te0 : FixedArray[Int]) -> FixedArray[Int] {
  let t = FixedArray::make(256, 0)
  for s in 0..<256 {
    let w = te0[s]
    t[s] = (((w >> 16) & 0x0000FFFF) | (w << 16)) & 0xFFFFFFFF
  }
  t
}

///|
/// Te3[s] = rotate Te0[s] right by 24 bits. MixColumns × (0, 0, 0, SBox[s])
/// = (v, v, 3v, 2v).
fn build_te3(te0 : FixedArray[Int]) -> FixedArray[Int] {
  let t = FixedArray::make(256, 0)
  for s in 0..<256 {
    let w = te0[s]
    t[s] = (((w >> 24) & 0x000000FF) | (w << 8)) & 0xFFFFFFFF
  }
  t
}

///|
let te0 : FixedArray[Int] = build_te0()

///|
let te1 : FixedArray[Int] = build_te1(te0)

///|
let te2 : FixedArray[Int] = build_te2(te0)

///|
let te3 : FixedArray[Int] = build_te3(te0)

///|
/// AES key schedule. Returns Nr+1 round keys, each 16 bytes packed as 4 ×
/// UInt (column-major: column 0 is bytes 0..3 = (a0, a1, a2, a3)). Nr is 10
/// for AES-128 and 14 for AES-256.
fn aes_key_schedule(key : Bytes) -> (FixedArray[Int], Int) {
  let key_len = key.length()
  let (nk, nr) = match key_len {
    16 => (4, 10) // AES-128: 4 words of key, 10 rounds, 44 round-key words
    32 => (8, 14) // AES-256: 8 words of key, 14 rounds, 60 round-key words
    _ => abort("aes_key_schedule: bad key length")
  }
  let total_words = 4 * (nr + 1)
  // Each word is a 32-bit value stored as 4 bytes packed into an Int (we use
  // the bottom 32 bits). Index w[i] = round key word i.
  let w = FixedArray::make(total_words, 0)
  for i in 0..<nk {
    let b0 = key[i * 4].to_int()
    let b1 = key[i * 4 + 1].to_int()
    let b2 = key[i * 4 + 2].to_int()
    let b3 = key[i * 4 + 3].to_int()
    w[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
  }
  for i in nk..<total_words {
    let mut temp = w[i - 1]
    if i % nk == 0 {
      // RotWord then SubWord then XOR Rcon
      let r = ((temp << 8) & 0xFFFFFFFF) | ((temp >> 24) & 0xFF)
      let s0 = sbox((r >> 24) & 0xFF)
      let s1 = sbox((r >> 16) & 0xFF)
      let s2 = sbox((r >> 8) & 0xFF)
      let s3 = sbox(r & 0xFF)
      let sub = (s0 << 24) | (s1 << 16) | (s2 << 8) | s3
      let rc = aes_rcon[i / nk] << 24
      temp = sub ^ rc
    } else if nk > 6 && i % nk == 4 {
      // SubWord only (AES-256 every 4th word in the middle of a "block")
      let s0 = sbox((temp >> 24) & 0xFF)
      let s1 = sbox((temp >> 16) & 0xFF)
      let s2 = sbox((temp >> 8) & 0xFF)
      let s3 = sbox(temp & 0xFF)
      temp = (s0 << 24) | (s1 << 16) | (s2 << 8) | s3
    }
    w[i] = w[i - nk] ^ temp
  }
  (w, nr)
}

///|
/// AES block encryption (T-table). `block` is exactly 16 bytes;
/// `(round_keys, nr)` comes from `aes_key_schedule`. Output is 16 bytes.
///
/// State is held as 4 × 32-bit column words (Int). Each column c packs
/// state bytes as word_c = (s[0,c] << 24) | (s[1,c] << 16) | (s[2,c] << 8)
/// | s[3,c], i.e. row 0 of the column in the high byte.
///
/// One main round (with MixColumns):
///   new_col[j] = Te0[byte(col_j,    row=0)]
///              ^ Te1[byte(col_j+1, row=1)]
///              ^ Te2[byte(col_j+2, row=2)]
///              ^ Te3[byte(col_j+3, row=3)]
///              ^ rk[round*4 + j]
///
/// Final round (no MixColumns) uses the raw S-box with the same byte
/// permutation pattern.
fn aes_encrypt_block(
  block : Bytes,
  round_keys : FixedArray[Int],
  nr : Int,
) -> Bytes {
  // Load 4 column words from input, then XOR initial round key.
  let mut s0 = (
      (block[0].to_int() << 24) |
      (block[1].to_int() << 16) |
      (block[2].to_int() << 8) |
      block[3].to_int()
    ) ^
    round_keys[0]
  let mut s1 = (
      (block[4].to_int() << 24) |
      (block[5].to_int() << 16) |
      (block[6].to_int() << 8) |
      block[7].to_int()
    ) ^
    round_keys[1]
  let mut s2 = (
      (block[8].to_int() << 24) |
      (block[9].to_int() << 16) |
      (block[10].to_int() << 8) |
      block[11].to_int()
    ) ^
    round_keys[2]
  let mut s3 = (
      (block[12].to_int() << 24) |
      (block[13].to_int() << 16) |
      (block[14].to_int() << 8) |
      block[15].to_int()
    ) ^
    round_keys[3]

  // Main rounds 1..nr-1: T-table.
  let mut round = 1
  while round < nr {
    let rk_off = round * 4
    let t0 = te0[(s0 >> 24) & 0xFF] ^
      te1[(s1 >> 16) & 0xFF] ^
      te2[(s2 >> 8) & 0xFF] ^
      te3[s3 & 0xFF] ^
      round_keys[rk_off]
    let t1 = te0[(s1 >> 24) & 0xFF] ^
      te1[(s2 >> 16) & 0xFF] ^
      te2[(s3 >> 8) & 0xFF] ^
      te3[s0 & 0xFF] ^
      round_keys[rk_off + 1]
    let t2 = te0[(s2 >> 24) & 0xFF] ^
      te1[(s3 >> 16) & 0xFF] ^
      te2[(s0 >> 8) & 0xFF] ^
      te3[s1 & 0xFF] ^
      round_keys[rk_off + 2]
    let t3 = te0[(s3 >> 24) & 0xFF] ^
      te1[(s0 >> 16) & 0xFF] ^
      te2[(s1 >> 8) & 0xFF] ^
      te3[s2 & 0xFF] ^
      round_keys[rk_off + 3]
    s0 = t0
    s1 = t1
    s2 = t2
    s3 = t3
    round = round + 1
  }

  // Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns).
  let rk_off = nr * 4
  let f0 = (
      (aes_sbox[(s0 >> 24) & 0xFF] << 24) |
      (aes_sbox[(s1 >> 16) & 0xFF] << 16) |
      (aes_sbox[(s2 >> 8) & 0xFF] << 8) |
      aes_sbox[s3 & 0xFF]
    ) ^
    round_keys[rk_off]
  let f1 = (
      (aes_sbox[(s1 >> 24) & 0xFF] << 24) |
      (aes_sbox[(s2 >> 16) & 0xFF] << 16) |
      (aes_sbox[(s3 >> 8) & 0xFF] << 8) |
      aes_sbox[s0 & 0xFF]
    ) ^
    round_keys[rk_off + 1]
  let f2 = (
      (aes_sbox[(s2 >> 24) & 0xFF] << 24) |
      (aes_sbox[(s3 >> 16) & 0xFF] << 16) |
      (aes_sbox[(s0 >> 8) & 0xFF] << 8) |
      aes_sbox[s1 & 0xFF]
    ) ^
    round_keys[rk_off + 2]
  let f3 = (
      (aes_sbox[(s3 >> 24) & 0xFF] << 24) |
      (aes_sbox[(s0 >> 16) & 0xFF] << 16) |
      (aes_sbox[(s1 >> 8) & 0xFF] << 8) |
      aes_sbox[s2 & 0xFF]
    ) ^
    round_keys[rk_off + 3]

  // Pack the four column words back into 16 output bytes.
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

///|
/// Public test hook: encrypt one block under the given key. The key length
/// must be 16 or 32 bytes; the block must be 16 bytes.
fn aes_encrypt(key : Bytes, block : Bytes) -> Bytes {
  let (rk, nr) = aes_key_schedule(key)
  aes_encrypt_block(block, rk, nr)
}
