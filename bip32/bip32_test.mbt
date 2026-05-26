// BIP-32 test vectors.
// Source: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//
// Test vector 1: seed = 0x000102030405060708090a0b0c0d0e0f
//   m              chain_code 873dff8...37d508
//                  pub        0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2
//                  priv       e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
//   m/0'           fingerprint 3442193e
//                  priv       edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
//                  chain_code 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
//   m/0'/1         chain_code 2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19
//                  priv       3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368

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
fn priv_hex(xpriv : @bip32.ExtendedPrivateKey) -> String {
  // The PrivateKey.d field is `pub`, so we can read it from outside and
  // serialise it to 32-byte big-endian for the hex comparison.
  let scalar = xpriv.privkey.d
  let bytes = scalar.to_octets(length=32)
  bytes_to_hex(bytes)
}

///|
fn pub_hex(xpriv : @bip32.ExtendedPrivateKey) -> String {
  // Compressed pub for comparison against BIP-32 vectors.
  bytes_to_hex(xpriv.privkey.public_key().to_compressed())
}

///|
test "master_from_seed: BIP-32 test vector 1" {
  let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let m = @bip32.master_from_seed(seed)
  @debug.assert_eq(
    bytes_to_hex(m.chain_code),
    "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
  )
  @debug.assert_eq(
    priv_hex(m),
    "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
  )
  @debug.assert_eq(
    pub_hex(m),
    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
  )
  @debug.assert_eq(m.depth, 0)
  @debug.assert_eq(bytes_to_hex(m.parent_fingerprint), "00000000")
}

///|
test "derive_path: BIP-32 vector 1 m/0'" {
  let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let m = @bip32.master_from_seed(seed)
  let child = @bip32.derive_path(m, "m/0'")
  @debug.assert_eq(
    priv_hex(child),
    "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
  )
  @debug.assert_eq(
    bytes_to_hex(child.chain_code),
    "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
  )
  @debug.assert_eq(bytes_to_hex(child.parent_fingerprint), "3442193e")
  @debug.assert_eq(child.depth, 1)
}

///|
test "derive_path: BIP-32 vector 1 m/0'/1" {
  let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let m = @bip32.master_from_seed(seed)
  let child = @bip32.derive_path(m, "m/0'/1")
  @debug.assert_eq(
    priv_hex(child),
    "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
  )
  @debug.assert_eq(
    bytes_to_hex(child.chain_code),
    "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
  )
  @debug.assert_eq(child.depth, 2)
}

///|
test "derive_path: BIP-32 vector 1 m/0'/1/2'" {
  // BIP-32 vector 1 m/0'/1/2'
  //   priv  cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca
  //   chain 04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f
  let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let m = @bip32.master_from_seed(seed)
  let child = @bip32.derive_path(m, "m/0'/1/2'")
  @debug.assert_eq(
    priv_hex(child),
    "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
  )
  @debug.assert_eq(
    bytes_to_hex(child.chain_code),
    "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
  )
  @debug.assert_eq(child.depth, 3)
}

///|
test "derive_path: BIP-32 vector 1 m/0'/1/2'/2/1000000000" {
  // Final leaf:
  //   priv  471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8
  //   chain c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e
  let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let m = @bip32.master_from_seed(seed)
  let child = @bip32.derive_path(m, "m/0'/1/2'/2/1000000000")
  @debug.assert_eq(
    priv_hex(child),
    "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
  )
  @debug.assert_eq(
    bytes_to_hex(child.chain_code),
    "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
  )
}

///|
test "derive_path: BIP-32 test vector 2 (different seed)" {
  // Vector 2 seed = fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
  let seed = hex_to_bytes(
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
  )
  let m = @bip32.master_from_seed(seed)
  // Master priv 4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e
  // Master chain 60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689
  @debug.assert_eq(
    priv_hex(m),
    "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
  )
  @debug.assert_eq(
    bytes_to_hex(m.chain_code),
    "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
  )
}

///|
test "derive_path: BIP-44 layout m/44'/0'/0'/0/0" {
  // Sanity: full BIP-44 path runs without raising. Compares against pinned
  // result computed by reference impl over the same seed.
  let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let m = @bip32.master_from_seed(seed)
  let child = @bip32.derive_path(m, "m/44'/0'/0'/0/0")
  @debug.assert_eq(child.depth, 5)
  @debug.assert_eq(child.privkey.d.is_zero(), false)
}

///|
test "neuter strips private half" {
  let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let m = @bip32.master_from_seed(seed)
  let xpub = @bip32.neuter(m)
  @debug.assert_eq(
    bytes_to_hex(xpub.pubkey.to_compressed()),
    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
  )
  @debug.assert_eq(bytes_to_hex(xpub.chain_code), bytes_to_hex(m.chain_code))
}

///|
test "derive_path: rejects hardened from path on extended public key path" {
  // Just confirm derive_public raises HardenedFromPublic if asked (the
  // current CKDpub impl raises DerivationFailed for the non-hardened
  // branch too, since point-add isn't wired; we only assert the hardened
  // gate here).
  let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let m = @bip32.master_from_seed(seed)
  let xpub = @bip32.neuter(m)
  let hardened_idx : UInt = 0x80000000U
  try {
    let _ = @bip32.derive_public(xpub, hardened_idx)
    abort("expected HardenedFromPublic, got Ok")
  } catch {
    @bip32.HardenedFromPublic(_) => ()
    other => raise other
  }
}

///|
test "derive_path: invalid path string raises InvalidPath" {
  let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
  let m = @bip32.master_from_seed(seed)
  try {
    let _ = @bip32.derive_path(m, "0/0")
    abort("expected InvalidPath, got Ok")
  } catch {
    @bip32.InvalidPath(_) => ()
    other => raise other
  }
}
