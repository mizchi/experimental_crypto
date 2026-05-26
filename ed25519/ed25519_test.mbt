// Blackbox tests run against the package's public API. Use `@ed25519` to import.

///|
fn hex_to_bytes(s : String) -> Bytes {
  // Parse a lowercase hex string into Bytes. Length must be even.
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
test "RFC 8032 §7.1 TEST 1 (empty message)" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let expected_pk = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  // Canonical RFC 8032 §7.1 TEST 1 signature (64 bytes / 128 hex chars).
  // Cross-checked against Wycheproof tcId 80 (draft-josefsson-eddsa-ed25519-02
  // Test 1).
  let expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  assert_eq(bytes_to_hex(pk.to_bytes()), expected_pk)
  let sig = sk.sign(b"")
  assert_eq(bytes_to_hex(sig), expected_sig)
  assert_true(pk.verify(b"", sig))
}

///|
test "RFC 8032 §7.1 TEST 2 (one-byte message)" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let expected_pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
  let expected_sig = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  assert_eq(bytes_to_hex(pk.to_bytes()), expected_pk)
  let msg = hex_to_bytes("72")
  let sig = sk.sign(msg)
  assert_eq(bytes_to_hex(sig), expected_sig)
  assert_true(pk.verify(msg, sig))
}

///|
test "RFC 8032 §7.1 TEST 3 (two-byte message)" {
  let seed = hex_to_bytes(
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
  )
  let expected_pk = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
  let expected_sig = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  assert_eq(bytes_to_hex(pk.to_bytes()), expected_pk)
  let msg = hex_to_bytes("af82")
  let sig = sk.sign(msg)
  assert_eq(bytes_to_hex(sig), expected_sig)
  assert_true(pk.verify(msg, sig))
}

///|
test "verify rejects tampered signature" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let msg = hex_to_bytes("72")
  let sig = sk.sign(msg)
  // flip first byte of signature
  let bad_arr = FixedArray::make(64, b'\x00')
  for i = 0; i < 64; i = i + 1 {
    bad_arr[i] = sig[i]
  }
  bad_arr[0] = (bad_arr[0].to_int() ^ 0x01).to_byte()
  let bad_sig = Bytes::makei(64, fn(i) { bad_arr[i] })
  assert_false(pk.verify(msg, bad_sig))
}

///|
test "verify rejects tampered message" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let msg = hex_to_bytes("72")
  let sig = sk.sign(msg)
  let bad_msg = hex_to_bytes("73")
  assert_false(pk.verify(bad_msg, sig))
}

///|
test "verify rejects wrong-length signature" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  assert_false(pk.verify(b"hi", b"short"))
}

///|
test "PrivateKey::from_seed rejects wrong length" {
  let r : Result[@ed25519.PrivateKey, @ed25519.Ed25519Error] = try? @ed25519.PrivateKey::from_seed(
    b"\x00\x01\x02",
  )
  match r {
    Ok(_) => fail("expected error")
    Err(@ed25519.InvalidSeedLength(n)) => assert_eq(n, 3)
    Err(_) => fail("unexpected error")
  }
}

///|
test "PublicKey::from_bytes rejects wrong length" {
  let r : Result[@ed25519.PublicKey, @ed25519.Ed25519Error] = try? @ed25519.PublicKey::from_bytes(
    b"\x00\x01",
  )
  match r {
    Ok(_) => fail("expected error")
    Err(@ed25519.InvalidPublicKeyLength(n)) => assert_eq(n, 2)
    Err(_) => fail("unexpected error")
  }
}

///|
test "verify_strict raises on wrong-length signature" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let r : Result[Bool, @ed25519.Ed25519Error] = try? pk.verify_strict(
    b"hi", b"short",
  )
  match r {
    Ok(_) => fail("expected error")
    Err(@ed25519.InvalidSignatureLength(n)) => assert_eq(n, 5)
    Err(_) => fail("wrong error variant")
  }
}

///|
test "verify_strict accepts a valid signature" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let msg = hex_to_bytes("72")
  let sig = sk.sign(msg)
  assert_true(pk.verify_strict(msg, sig))
}

///|
test "PublicKey::from_bytes roundtrip and external verify" {
  let pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let sig_hex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
  let pk = @ed25519.PublicKey::from_bytes(hex_to_bytes(pk_hex))
  assert_eq(bytes_to_hex(pk.to_bytes()), pk_hex)
  assert_true(pk.verify(b"", hex_to_bytes(sig_hex)))
}

// -----------------------------------------------------------------------------
// Security attack tests
// -----------------------------------------------------------------------------

///|
test "ATTACK Ed25519 malleability: verify_strict must reject S >= L (non-canonical S)" {
  // RFC 8032 §5.1.7: "verifiers MUST verify ... that 0 <= s < L". Sign
  // anything and forge a copy whose S = S + L (still mod L, still a valid
  // ECDSA-equivalent but encoded non-canonically). The strict verifier must
  // reject the second copy.
  let sk_seed = Bytes::makei(32, fn(_) { b'\x42' })
  let sk = @ed25519.PrivateKey::from_seed(sk_seed)
  let pk = sk.public_key()
  let msg : Bytes = b"hello"
  let sig = sk.sign(msg)
  // L = 2^252 + 27742317777372353535851937790883648493 (little-endian).
  // Bytes BE high → low: 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  //                      14 de f9 de a2 f7 9c d6 58 12 63 1a 5c f5 d3 ed
  // Little-endian bytes: ed d3 f5 5c 1a 63 12 58 d6 9c f7 a2 de f9 de 14
  //                      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10
  let l_le : Bytes = b"\xed\xd3\xf5\x5c\x1a\x63\x12\x58\xd6\x9c\xf7\xa2\xde\xf9\xde\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"
  // forged_sig = R || (S + L) as little-endian 32-byte addition.
  let s_le = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    s_le[i] = sig[32 + i]
  }
  let mut carry = 0
  for i = 0; i < 32; i = i + 1 {
    let sum = s_le[i].to_int() + l_le[i].to_int() + carry
    s_le[i] = (sum & 0xff).to_byte()
    carry = sum >> 8
  }
  let forged = Bytes::makei(64, fn(i) {
    if i < 32 {
      sig[i]
    } else {
      s_le[i - 32]
    }
  })
  // The strict verifier MUST reject the forged signature.
  let raised = try {
    let _ = pk.verify_strict(msg, forged)
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}
