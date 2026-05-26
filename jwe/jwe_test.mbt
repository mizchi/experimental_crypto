// Blackbox tests for JWE (RFC 7516) compact serialization.

// ─── hex helper (matches the style used in rsa_test.mbt / aead_test.mbt) ──

///|
fn hex_nibble(c : Int) -> Int {
  if c >= '0'.to_int() && c <= '9'.to_int() {
    c - '0'.to_int()
  } else if c >= 'a'.to_int() && c <= 'f'.to_int() {
    c - 'a'.to_int() + 10
  } else if c >= 'A'.to_int() && c <= 'F'.to_int() {
    c - 'A'.to_int() + 10
  } else {
    abort("non-hex character in literal")
  }
}

///|
fn hex(s : String) -> Bytes {
  let bytes = @utf8.encode(s[:])
  let n = bytes.length()
  if n % 2 != 0 {
    abort("odd-length hex literal")
  }
  Bytes::makei(n / 2, fn(i) {
    let hi = hex_nibble(bytes[i * 2].to_int())
    let lo = hex_nibble(bytes[i * 2 + 1].to_int())
    ((hi << 4) | lo).to_byte()
  })
}

// ─── Fixture: RSA-2048 PKCS#1 key (same as rsa/rsa_test.mbt) ──────────────

///|
let rsa2048_priv_pkcs1_der : Bytes = hex(
  "308204a30201000282010100a48f36ef8cfe5dd94faba96b3abf276fde0e82f9ad0b9963955c933413bf300a4dda0287" +
  "48590762459ddb2a4c2b9ce04e4f2d8f37ea0a1379cc9076ea17a97bad91178d7983c9e15a7f30db77268d3be00d85b9" +
  "60db3396d24ac0bf229bbb242c72b2b4d4ae15abc51d72b372b0132e75cf92265cb5e97747e617a69a78384d99dd5136" +
  "7575953c16e32cc45c3fbb28fdbd0064228043e39721e3bf5ee496d3fb9ced6fd4d7a0daf98fb016cfe8da87484765f9" +
  "c35115f12e095585aba390cb27eb03900045575854e0100d19f32fac1981f6c286567c6387791e642a7941096c92e89e" +
  "cc5cf3c934a363c5ca63f633940ce37965bcfe8b86d7ef432f799c2702030100010282010029ab461ae495e887c57fcf" +
  "57a2b992afe607c0ac9e5fe88869e2d63782a48ff29c020f4fd8470af29c743b71fb75b3b4acbfa9e6b11ee74c453442" +
  "848a0451db4a790a00bdfb5c1c5f4103cb1ee1b933a729656a2a9776f9c2e840e4654c0fd83a1515216b1565d168096b" +
  "e8faaa9140db7e2320e9aafaa244a783e7a107be21a856466f50e3d697cc685e221164d83918b8cfd6f3653c9e7748cf" +
  "ade136ed267ebab8433f9a981fd6af49c4edc149aa281fead06947fe52381009a9e6d49d63f8eb1ff94f15170929f3eb" +
  "0d66a3ec72b0fb1f14d54792a9a5c48cb6310d60771a26344f00dcabc959bb5acc9583cd74a744aa3c079c1b7ed1c746" +
  "7aaa115ee102818100d05869008488dbe1b9afa5c851af7f44ca1fd11f2c31ab19b014c194b32a553338c29fba82a384" +
  "0b0735e8b30cba04ef54c0cc74752d2075f93907ba6ba0654f29872cf6fbe82808e6db11fcce997331417600d6298085" +
  "94085d00b21ed3608e65c2d04d212494aad6edd1383c63154d758fd3145ee3e9df1724b47da56d1a1702818100ca32ef" +
  "5ff51a550e7b5f6434f4d04a3d22a18aa89cd4d628c2b3dca129805f02360da47b5dce7cf14932f19bb4a5e368a06462" +
  "912aa755f05913b89f4af5053fb3ecf2fdac49f636a7be5aecdd62f9aaa8b0d61976b31214b534f9d15d5648d1207e34" +
  "78080f96fa1f2112058d22332916cd2266e15c2036aed2bdd9a19ea8710281803277a7ffb31affc03edd7857fcc97917" +
  "adaa655a9ab6f14e48a3ce7c79a5e07b86dd4619c4b95d2bdab44948cde5657a9fda0fec89d1c392302b8b5eb1e16988" +
  "f273470610e11c89837a3f72308d6524e249764c6a433298382a6717be75cf66cee990d18e1cb1526cbbb0b9618f52c2" +
  "af9e862fe2086d4757f0d133ba55a2430281810088174c421ba8438361ca4c99d004b952f8921dcf6aef5dcd456ee59a" +
  "9b624990256d7d3d835fcd7c613626a4142c6b292a7b26546a8f022aa8e9bb238bc1ea6c7bdf8994ef77407e7cdc843a" +
  "54af9f371c1f199b3de73cce2f409ebc29c43f72721a3f9a62628bcd815232dd05a6f5243cb288eb11d77ddf103fcb84" +
  "456192210281803ef388d592aa5e24b930ab2d434f20a41742cee683fca57a59e2bf57fd090e45158c10952e37392381" +
  "312f139a39c3ad9c947b52e21a18bce16e6b8c0ecfec7556e277b8d34734ca3e7b9a1d95408cd976eba53406eb95905b" +
  "a101317dc5c5fd5b21783244e1b8a8bdd5a3e2e4339fb43248e8cc61307ccd278280b058ad9be1",
)

///|
fn fixed_iv12() -> Bytes {
  hex("0102030405060708090a0b0c")
}

///|
fn fixed_cek32() -> Bytes {
  hex(
    "0001020304050607" +
    "08090a0b0c0d0e0f" +
    "1011121314151617" +
    "18191a1b1c1d1e1f",
  )
}

///|
fn fixed_cek16() -> Bytes {
  hex("000102030405060708090a0b0c0d0e0f")
}

///|
fn fixed_kek32() -> Bytes {
  hex(
    "ff" +
    "1f1e1d1c1b1a1918" +
    "1716151413121110" +
    "0f0e0d0c0b0a0908" +
    "07060504030201",
  )
}

///|
fn fixed_oaep_seed() -> Bytes {
  // 32 bytes, deterministic for tests only.
  hex(
    "aabbccddeeff0011" +
    "2233445566778899" +
    "aabbccddeeff0011" +
    "2233445566778899",
  )
}

// ─── Roundtrip: dir + A256GCM ─────────────────────────────────────────────

///|
test "jwe: dir + A256GCM roundtrip" {
  let cek = fixed_cek32()
  let iv = fixed_iv12()
  let plaintext : Bytes = b"hello jwe (dir+A256GCM)"
  let token = @jwe.encrypt(
    plaintext,
    @jwe.JweAlg::Dir,
    @jwe.JweEnc::A256gcm,
    @jwe.EncryptionKey::EncDir(cek~),
    iv~,
  )
  // Compact form has exactly 4 dots.
  inspect(token.split(".").to_array().length(), content="5")
  // Encrypted-key segment must be empty for dir.
  let parts = token.split(".").to_array()
  inspect(parts[1].to_string(), content="")
  let decoded = @jwe.decrypt(token, @jwe.DecryptionKey::DecDir(cek~))
  assert_eq(decoded, plaintext)
}

///|
test "jwe: dir + A128GCM roundtrip" {
  let cek = fixed_cek16()
  let iv = fixed_iv12()
  let plaintext : Bytes = b"hello jwe (dir+A128GCM)"
  let token = @jwe.encrypt(
    plaintext,
    @jwe.JweAlg::Dir,
    @jwe.JweEnc::A128gcm,
    @jwe.EncryptionKey::EncDir(cek~),
    iv~,
  )
  let decoded = @jwe.decrypt(token, @jwe.DecryptionKey::DecDir(cek~))
  assert_eq(decoded, plaintext)
}

// ─── Roundtrip: A256KW + A256GCM ──────────────────────────────────────────

///|
test "jwe: A256KW + A256GCM roundtrip" {
  let kek = fixed_kek32()
  let cek = fixed_cek32()
  let iv = fixed_iv12()
  let plaintext : Bytes = b"hello jwe (A256KW+A256GCM)"
  let token = @jwe.encrypt(
    plaintext,
    @jwe.JweAlg::A256kw,
    @jwe.JweEnc::A256gcm,
    @jwe.EncryptionKey::EncAes256Kw(kek~),
    cek~,
    iv~,
  )
  // Encrypted key for A256KW with 32-byte CEK is 40 bytes → base64url(40) = 54 chars.
  let parts = token.split(".").to_array()
  // Decode base64url length check would require redoing base64; just sanity-check
  // it's non-empty.
  assert_true(parts[1].length() > 0)
  let decoded = @jwe.decrypt(token, @jwe.DecryptionKey::DecAes256Kw(kek~))
  assert_eq(decoded, plaintext)
}

// ─── Roundtrip: RSA-OAEP-256 + A256GCM ────────────────────────────────────

///|
test "jwe: RSA-OAEP-256 + A256GCM roundtrip" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rsa2048_priv_pkcs1_der)
  let pk = sk.public_key()
  let cek = fixed_cek32()
  let iv = fixed_iv12()
  let plaintext : Bytes = b"hello jwe (RSA-OAEP-256+A256GCM)"
  let token = @jwe.encrypt(
    plaintext,
    @jwe.JweAlg::Rsa_oaep_256,
    @jwe.JweEnc::A256gcm,
    @jwe.EncryptionKey::EncRsa(pubkey=pk),
    cek~,
    iv~,
    oaep_seed=fixed_oaep_seed(),
  )
  let decoded = @jwe.decrypt(token, @jwe.DecryptionKey::DecRsa(privkey=sk))
  assert_eq(decoded, plaintext)
}

// ─── Tamper resistance ────────────────────────────────────────────────────

///|
test "jwe: tampered ciphertext fails AuthenticationFailed" {
  let cek = fixed_cek32()
  let iv = fixed_iv12()
  let plaintext : Bytes = b"sensitive payload"
  let token = @jwe.encrypt(
    plaintext,
    @jwe.JweAlg::Dir,
    @jwe.JweEnc::A256gcm,
    @jwe.EncryptionKey::EncDir(cek~),
    iv~,
  )
  // Flip one character in the ciphertext segment (4th of 5).
  let parts = token.split(".").to_array()
  let mut ct = parts[3].to_string()
  // Flip last character. base64url charset is [A-Za-z0-9-_]; just pick a
  // replacement that is definitely different from the current one.
  let last_idx = ct.length() - 1
  let last_view = ct[last_idx:]
  let last_str = last_view.to_string()
  let replacement = if last_str == "A" { "B" } else { "A" }
  ct = ct[:last_idx].to_string() + replacement
  let tampered = parts[0].to_string() +
    "." +
    parts[1].to_string() +
    "." +
    parts[2].to_string() +
    "." +
    ct +
    "." +
    parts[4].to_string()
  let raised = try {
    let _ = @jwe.decrypt(tampered, @jwe.DecryptionKey::DecDir(cek~))
    false
  } catch {
    @jwe.AuthenticationFailed => true
    _ => false
  }
  assert_true(raised)
}

///|
test "jwe: tampered header (AAD) fails AuthenticationFailed" {
  // RFC 7516 §5.1 step 14: the AAD is the ASCII bytes of the base64url-
  // encoded protected header. Modifying the header without re-deriving
  // anything else must break GCM authentication, since the tag is over
  // the original header bytes.
  let cek = fixed_cek32()
  let iv = fixed_iv12()
  let plaintext : Bytes = b"sensitive payload"
  let token = @jwe.encrypt(
    plaintext,
    @jwe.JweAlg::Dir,
    @jwe.JweEnc::A256gcm,
    @jwe.EncryptionKey::EncDir(cek~),
    iv~,
    extra_header={ "kid": Json::string("k1") },
  )
  // Build a *different* but well-formed header (kid="k2") and substitute it.
  // This must fail integrity: the GCM tag was computed over the original
  // base64url(header) bytes.
  let alt_header_json : Json = Json::object({
    "alg": Json::string("dir"),
    "enc": Json::string("A256GCM"),
    "kid": Json::string("k2"),
  })
  let alt_header_str = alt_header_json.stringify()
  // base64url-encode without padding, '+' → '-', '/' → '_'.
  let alt_b64_padded = @base64.encode(
    @utf8.encode(alt_header_str[:])[:],
    padding=false,
  )
  let alt_b64 = {
    let buf = StringBuilder::new()
    for c in alt_b64_padded {
      let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
      buf.write_char(c2)
    }
    buf.to_string()
  }
  let parts = token.split(".").to_array()
  let tampered = alt_b64 +
    "." +
    parts[1].to_string() +
    "." +
    parts[2].to_string() +
    "." +
    parts[3].to_string() +
    "." +
    parts[4].to_string()
  let raised = try {
    let _ = @jwe.decrypt(tampered, @jwe.DecryptionKey::DecDir(cek~))
    false
  } catch {
    @jwe.AuthenticationFailed => true
    _ => false
  }
  assert_true(raised)
}

///|
test "jwe: wrong KEK fails (A256KW unwrap mismatch)" {
  let real_kek = fixed_kek32()
  let cek = fixed_cek32()
  let iv = fixed_iv12()
  let plaintext : Bytes = b"hello"
  let token = @jwe.encrypt(
    plaintext,
    @jwe.JweAlg::A256kw,
    @jwe.JweEnc::A256gcm,
    @jwe.EncryptionKey::EncAes256Kw(kek=real_kek),
    cek~,
    iv~,
  )
  // Use a different KEK (flip the last byte).
  let wrong_kek = Bytes::makei(32, fn(i) {
    if i == 31 {
      (real_kek[i].to_int() ^ 1).to_byte()
    } else {
      real_kek[i]
    }
  })
  let raised = try {
    let _ = @jwe.decrypt(token, @jwe.DecryptionKey::DecAes256Kw(kek=wrong_kek))
    false
  } catch {
    @jwe.AuthenticationFailed => true
    // The unwrap might also produce a corrupt CEK that happens to fail the
    // subsequent GCM tag check; that also collapses to AuthenticationFailed.
    _ => false
  }
  assert_true(raised)
}

// ─── Sanity: header structure ─────────────────────────────────────────────

///|
test "jwe: produced header has alg + enc" {
  let cek = fixed_cek32()
  let iv = fixed_iv12()
  let token = @jwe.encrypt(
    b"x",
    @jwe.JweAlg::Dir,
    @jwe.JweEnc::A256gcm,
    @jwe.EncryptionKey::EncDir(cek~),
    iv~,
  )
  let parts = token.split(".").to_array()
  let header_b64 = parts[0].to_string()
  // Decode the header (it uses base64url without padding).
  let padded = {
    let buf = StringBuilder::new()
    for c in header_b64 {
      let c2 = if c == '-' { '+' } else if c == '_' { '/' } else { c }
      buf.write_char(c2)
    }
    let pad = (4 - header_b64.length() % 4) % 4
    for _ in 0..<pad {
      buf.write_char('=')
    }
    buf.to_string()
  }
  let header_bytes = @base64.decode(padded)
  let header_str = @utf8.decode(header_bytes[:])
  let parsed = @json.parse(header_str[:])
  match parsed {
    Object(m) => {
      assert_eq(m.get("alg"), Some(Json::string("dir")))
      assert_eq(m.get("enc"), Some(Json::string("A256GCM")))
    }
    _ => assert_true(false)
  }
}
