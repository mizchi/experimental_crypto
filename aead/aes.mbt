// AES-128 and AES-256 block cipher (FIPS 197). Encryption only — GCM does
// not need the inverse direction. This is a straightforward table-based
// implementation: it is NOT constant-time (the S-box lookup leaks key bits
// via cache timing).

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
/// AES block encryption. `block` is exactly 16 bytes; `(round_keys, nr)`
/// comes from `aes_key_schedule`. Output is 16 bytes.
fn aes_encrypt_block(
  block : Bytes,
  round_keys : FixedArray[Int],
  nr : Int,
) -> Bytes {
  // State is 4 columns of 4 bytes each. Use 16 mutable Ints in column-major
  // order: s[col*4 + row].
  let s = FixedArray::make(16, 0)
  for c in 0..<4 {
    for r in 0..<4 {
      s[c * 4 + r] = block[c * 4 + r].to_int() & 0xFF
    }
  }
  // AddRoundKey round 0
  add_round_key(s, round_keys, 0)
  // Main rounds 1..nr-1
  for round = 1; round < nr; round = round + 1 {
    sub_bytes(s)
    shift_rows(s)
    mix_columns(s)
    add_round_key(s, round_keys, round)
  }
  // Final round (no MixColumns)
  sub_bytes(s)
  shift_rows(s)
  add_round_key(s, round_keys, nr)
  Bytes::makei(16, fn(i) {
    let col = i / 4
    let row = i % 4
    s[col * 4 + row].to_byte()
  })
}

///|
fn add_round_key(
  s : FixedArray[Int],
  round_keys : FixedArray[Int],
  round : Int,
) -> Unit {
  // Each round key is 4 words = round_keys[round*4 .. round*4+3].
  // Word w packs bytes (a0 a1 a2 a3) with a0 in the high byte.
  for c in 0..<4 {
    let w = round_keys[round * 4 + c]
    s[c * 4 + 0] = s[c * 4 + 0] ^ ((w >> 24) & 0xFF)
    s[c * 4 + 1] = s[c * 4 + 1] ^ ((w >> 16) & 0xFF)
    s[c * 4 + 2] = s[c * 4 + 2] ^ ((w >> 8) & 0xFF)
    s[c * 4 + 3] = s[c * 4 + 3] ^ (w & 0xFF)
  }
}

///|
fn sub_bytes(s : FixedArray[Int]) -> Unit {
  for i in 0..<16 {
    s[i] = aes_sbox[s[i] & 0xFF]
  }
}

///|
fn shift_rows(s : FixedArray[Int]) -> Unit {
  // Row r is shifted left by r positions.
  // Row 0: no change (positions 0,4,8,12 — column*4 + 0)
  // Row 1: positions 1,5,9,13 ← shift left by 1
  // Row 2: positions 2,6,10,14 ← shift left by 2
  // Row 3: positions 3,7,11,15 ← shift left by 3
  let r1_0 = s[1]
  s[1] = s[5]
  s[5] = s[9]
  s[9] = s[13]
  s[13] = r1_0
  let r2_0 = s[2]
  let r2_1 = s[6]
  s[2] = s[10]
  s[6] = s[14]
  s[10] = r2_0
  s[14] = r2_1
  let r3_0 = s[3]
  let r3_1 = s[7]
  let r3_2 = s[11]
  s[3] = s[15]
  s[7] = r3_0
  s[11] = r3_1
  s[15] = r3_2
}

///|
fn mix_columns(s : FixedArray[Int]) -> Unit {
  for c in 0..<4 {
    let a0 = s[c * 4 + 0]
    let a1 = s[c * 4 + 1]
    let a2 = s[c * 4 + 2]
    let a3 = s[c * 4 + 3]
    let t = a0 ^ a1 ^ a2 ^ a3
    s[c * 4 + 0] = a0 ^ t ^ xtime(a0 ^ a1)
    s[c * 4 + 1] = a1 ^ t ^ xtime(a1 ^ a2)
    s[c * 4 + 2] = a2 ^ t ^ xtime(a2 ^ a3)
    s[c * 4 + 3] = a3 ^ t ^ xtime(a3 ^ a0)
  }
}

///|
/// Public test hook: encrypt one block under the given key. The key length
/// must be 16 or 32 bytes; the block must be 16 bytes.
fn aes_encrypt(key : Bytes, block : Bytes) -> Bytes {
  let (rk, nr) = aes_key_schedule(key)
  aes_encrypt_block(block, rk, nr)
}

