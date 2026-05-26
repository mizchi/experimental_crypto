// BIP-39 test vectors from the spec:
// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
//
// Each vector is (entropy hex, mnemonic, seed hex with passphrase="TREZOR").

///|
fn hex_to_bytes(s : String) -> Bytes {
  let n = s.length() / 2
  let arr = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble(s.code_unit_at(i * 2).to_int())
    let lo = hex_nibble(s.code_unit_at(i * 2 + 1).to_int())
    arr[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::makei(n, fn(i) { arr[i] })
}

///|
fn hex_nibble(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    0
  }
}

///|
fn bytes_to_hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    let by = b[i].to_int()
    let hi = (by >> 4) & 0xF
    let lo = by & 0xF
    buf.write_char(digits.code_unit_at(hi).to_int() |> Int::unsafe_to_char)
    buf.write_char(digits.code_unit_at(lo).to_int() |> Int::unsafe_to_char)
  }
  buf.to_string()
}

///|
test "entropy_to_mnemonic: all-zero 128-bit" {
  let entropy = hex_to_bytes("00000000000000000000000000000000")
  let m = entropy_to_mnemonic(entropy)
  @debug.assert_eq(
    m, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  )
}

///|
test "entropy_to_mnemonic: all-zero 256-bit" {
  let entropy = hex_to_bytes(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  let m = entropy_to_mnemonic(entropy)
  @debug.assert_eq(
    m, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
  )
}

///|
test "entropy_to_mnemonic: all-ones 256-bit" {
  // Per trezor vectors: 32-byte 0xFF entropy → "...zoo vote"
  let entropy = hex_to_bytes(
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  )
  let m = entropy_to_mnemonic(entropy)
  @debug.assert_eq(
    m, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
  )
}

///|
test "entropy_to_mnemonic: all-ones 128-bit" {
  // 16-byte 0xFF entropy → "...zoo wrong" (12 words).
  let entropy = hex_to_bytes("ffffffffffffffffffffffffffffffff")
  let m = entropy_to_mnemonic(entropy)
  @debug.assert_eq(m, "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
}

///|
test "entropy_to_mnemonic: trezor vector 0x80808080..." {
  // From trezor vectors, 128-bit entropy = 0x80808080808080808080808080808080
  // → "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
  let entropy = hex_to_bytes("80808080808080808080808080808080")
  let m = entropy_to_mnemonic(entropy)
  @debug.assert_eq(
    m, "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
  )
}

///|
test "mnemonic_to_entropy: round trip 128-bit" {
  let entropy = hex_to_bytes("0c1e24e5917779d297e14d45f14e1a1a")
  let m = entropy_to_mnemonic(entropy)
  let back = mnemonic_to_entropy(m)
  @debug.assert_eq(bytes_to_hex(back), bytes_to_hex(entropy))
}

///|
test "mnemonic_to_entropy: round trip 256-bit" {
  let entropy = hex_to_bytes(
    "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
  )
  let m = entropy_to_mnemonic(entropy)
  let back = mnemonic_to_entropy(m)
  @debug.assert_eq(bytes_to_hex(back), bytes_to_hex(entropy))
}

///|
test "mnemonic_to_entropy: rejects unknown word" {
  let m = "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  try mnemonic_to_entropy(m) catch {
    UnknownWord(_) => ()
    other => abort("expected UnknownWord, got " + repr(other))
  } noraise {
    other => abort("expected UnknownWord, got " + repr(other))
  }
}

///|
test "mnemonic_to_entropy: rejects bad checksum" {
  // Take a valid mnemonic and replace the last word with a different valid
  // word; checksum should fail with overwhelming probability.
  let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
  try mnemonic_to_entropy(m) catch {
    InvalidChecksum => ()
    other => abort("expected InvalidChecksum, got " + repr(other))
  } noraise {
    other => abort("expected InvalidChecksum, got " + repr(other))
  }
}

///|
test "mnemonic_to_entropy: rejects bad word count" {
  let m = "abandon abandon abandon" // only 3 words
  try mnemonic_to_entropy(m) catch {
    InvalidMnemonicWordCount(3) => ()
    other => abort("expected InvalidMnemonicWordCount, got " + repr(other))
  } noraise {
    other => abort("expected InvalidMnemonicWordCount, got " + repr(other))
  }
}

///|
test "mnemonic_to_seed: trezor vector 1 (128-bit all zero, TREZOR pass)" {
  let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  let seed = mnemonic_to_seed(m, passphrase="TREZOR")
  @debug.assert_eq(
    bytes_to_hex(seed),
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
  )
}

///|
test "mnemonic_to_seed: trezor vector 128-bit zoo wrong (TREZOR pass)" {
  let m = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
  let seed = mnemonic_to_seed(m, passphrase="TREZOR")
  @debug.assert_eq(
    bytes_to_hex(seed),
    "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
  )
}

///|
test "mnemonic_to_seed: trezor vector 256-bit zoo vote (TREZOR pass)" {
  let m = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
  let seed = mnemonic_to_seed(m, passphrase="TREZOR")
  @debug.assert_eq(
    bytes_to_hex(seed),
    "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
  )
}

///|
test "mnemonic_to_seed: trezor vector 128-bit 0x80*16 (TREZOR pass)" {
  let m = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
  let seed = mnemonic_to_seed(m, passphrase="TREZOR")
  @debug.assert_eq(
    bytes_to_hex(seed),
    "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
  )
}
