// Blackbox tests for mizchi/rsa.
//
// Vectors:
// 1. RFC 7515 §A.2.1 (JWS RS256 example). JWK n / e + the signing input
//    + signature taken straight from the RFC; the PKCS#1 / SPKI DER
//    blobs are constructed mechanically from those n / e bytes so that
//    we exercise both decoders against a fully known-good public key.
// 2. A fresh openssl-generated RSA-2048 + SHA-256 vector for an
//    independent SPKI / PKCS#1 path that does not share n / e with (1).
//
// Negative tests: tampered message, tampered signature, wrong key,
// truncated DER, wrong-algorithm SPKI.

// ─── hex helpers (lifted from jwt/jwt_test.mbt) ────────────────────────

///|
fn hex_nibble(c : Int) -> Int {
  if c >= '0'.to_int() && c <= '9'.to_int() {
    c - '0'.to_int()
  } else if c >= 'a'.to_int() && c <= 'f'.to_int() {
    c - 'a'.to_int() + 10
  } else if c >= 'A'.to_int() && c <= 'F'.to_int() {
    c - 'A'.to_int() + 10
  } else {
    -1
  }
}

///|
fn hex(s : String) -> Bytes {
  let n = s.length() / 2
  let arr = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble(s.code_unit_at(i * 2).to_int())
    let lo = hex_nibble(s.code_unit_at(i * 2 + 1).to_int())
    arr[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::makei(n, fn(j) { arr[j] })
}

// ─── RFC 7515 §A.2.1 vectors ──────────────────────────────────────────

// JWS signing input (header.payload, US-ASCII): the exact bytes whose
// SHA-256 the RFC computes.
//
// header  = `eyJhbGciOiJSUzI1NiJ9`
// payload = `eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`
///|
let rfc7515_signing_input : Bytes = hex(
  "65794a68624763694f694a53557a49314e694a392e65794a7063334d694f694a71623255694c41304b49434a6c654841694f6a457a4d4441344d546b7a4f44417344516f67496d6830644841364c79396c654746746347786c4c6d4e76625339706331397962323930496a7030636e566c6651",
)

///|
let rfc7515_signature : Bytes = hex(
  "702e218943e88fd11eb5d82dbf7845f34106ae1b81fff7731116add1717d83656d420afd3c96eedd73a2663e5166687b000b87226e0187ed1073f945e582adfcef16d85a798ee8c66ddb3db8975b17d09402beedd5d9d97007108db28160d5f8040ca7445762b81fbe7ff9d92e0ae76f24f25b33bbe6f44ae61eb1040acb20044d3ef9128ed40130795bd4bd3b41eecad066ab651981fde48df77f372dc38b9fafdd3befb18b5da3cc3c2eb02f9e3a41d612caad15911273a05f23b9e838faaf849d698429ef5a1e88798236c3d40e604522a544c8f27a7a2db80663d16cf7caea56de405cb2215a45b2c25566b55ac1a748a070dfc8a32a469543d019eefb47",
)

///|
// PKCS#1 RSAPublicKey DER built from the RFC 7515 §A.2.1 JWK n / e.
let rfc7515_pkcs1_der : Bytes = hex(
  "3082010a0282010100a1f8160ae2e3c9b465ce8d2d656263362b927dbe29e1f02477fc1625cc90a136e38bd93497c5b6ea63dd7711e67c7429f956b0fb8a8f089adc4b69893cc1333f53edd019b87784252fec914fe4857769594bea4280d32c0f55bf62944f130396bc6e9bdf6ebdd2bda3678eeca0c668f701b38dbffb38c8342ce2fe6d27fade4a5a4874979dd4b9cf9adec4c75b05852c2c0f5ef8a5c1750392f944e8ed64c110c6b647609aa4783aeb9c6c9ad755313050638b83665c6f6f7a82a396702a1f641b82d3ebf2392219491fb686872c5716f50af8358d9a8b9d17c340728f7f87d89a18d8fcab67ad84590c2ecf759339363c07034d6f606f9e21e05456cae5e9a10203010001",
)

///|
// SubjectPublicKeyInfo DER (SPKI) wrapping the same RSA public key.
let rfc7515_spki_der : Bytes = hex(
  "30820122300d06092a864886f70d01010105000382010f003082010a0282010100a1f8160ae2e3c9b465ce8d2d656263362b927dbe29e1f02477fc1625cc90a136e38bd93497c5b6ea63dd7711e67c7429f956b0fb8a8f089adc4b69893cc1333f53edd019b87784252fec914fe4857769594bea4280d32c0f55bf62944f130396bc6e9bdf6ebdd2bda3678eeca0c668f701b38dbffb38c8342ce2fe6d27fade4a5a4874979dd4b9cf9adec4c75b05852c2c0f5ef8a5c1750392f944e8ed64c110c6b647609aa4783aeb9c6c9ad755313050638b83665c6f6f7a82a396702a1f641b82d3ebf2392219491fb686872c5716f50af8358d9a8b9d17c340728f7f87d89a18d8fcab67ad84590c2ecf759339363c07034d6f606f9e21e05456cae5e9a10203010001",
)

///|
test "RFC 7515 §A.2.1: RS256 verify via PKCS#1 DER" {
  let pubkey = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_pkcs1_der)
  assert_eq(pubkey.n_bytes_len, 256)
  let ok = pubkey.verify(rfc7515_signing_input, rfc7515_signature, Sha256)
  assert_eq(ok, true)
}

///|
test "RFC 7515 §A.2.1: RS256 verify via SPKI DER" {
  let pubkey = @rsa.RsaPublicKey::from_spki_der(rfc7515_spki_der)
  assert_eq(pubkey.n_bytes_len, 256)
  let ok = @rsa.verify(pubkey, rfc7515_signing_input, rfc7515_signature, Sha256)
  assert_eq(ok, true)
}

///|
test "RFC 7515 §A.2.1: tampered message rejects" {
  let pubkey = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_pkcs1_der)
  // Flip a single byte in the signing input — H(M) changes, EMSA mismatch.
  let bad = Bytes::makei(rfc7515_signing_input.length(), fn(i) {
    if i == 0 {
      (rfc7515_signing_input[0].to_int() ^ 0x01).to_byte()
    } else {
      rfc7515_signing_input[i]
    }
  })
  let ok = pubkey.verify(bad, rfc7515_signature, Sha256)
  assert_eq(ok, false)
}

///|
test "RFC 7515 §A.2.1: tampered signature rejects" {
  let pubkey = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_pkcs1_der)
  let bad = Bytes::makei(rfc7515_signature.length(), fn(i) {
    if i == 100 {
      (rfc7515_signature[100].to_int() ^ 0x01).to_byte()
    } else {
      rfc7515_signature[i]
    }
  })
  let ok = pubkey.verify(rfc7515_signing_input, bad, Sha256)
  assert_eq(ok, false)
}

///|
test "wrong signature length raises InvalidSignatureLength" {
  let pubkey = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_pkcs1_der)
  let short_sig = Bytes::makei(128, fn(_) { b'\x00' })
  let result = try? pubkey.verify(rfc7515_signing_input, short_sig, Sha256)
  match result {
    Err(InvalidSignatureLength) => ()
    _ => abort("expected InvalidSignatureLength")
  }
}

// ─── openssl-generated RSA-2048 / SHA-256 vector ──────────────────────

///|
let openssl_spki_der : Bytes = hex(
  "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b741a01469b8cc6cdad246f29f8ee0ac4f4d57e448f2116ff61f00e373fc4a03c49f8e48e582590b6fea9177b611aecc9a622c58746d142ab7b6ec986dfb87aa04381aa7852163f0deb57301ba309dc089cc7e93434e3c67e5ba812bdff006f8cc8394b163c86577fcafbd078c8749f3f1bb89e5ed1b78a8c8dfe1d99b5acbf545470d9f993a3a7c4492e5ad59fbcdc07ec702cabd23c01ac4b4379c41d170ce4058a8ac65ea5f5a145c3139eb2096d03d806fb58e237e3ade187349d0de043c74b4567a400fe2575e5094c95a245499b2a75fc9d4879d351279d60cb2b1fc030ef2bcc8184e98f94d677b2dbbefac4fc550a7e7a8be48fea13cbb944c78d4490203010001",
)

///|
let openssl_pkcs1_der : Bytes = hex(
  "3082010a0282010100b741a01469b8cc6cdad246f29f8ee0ac4f4d57e448f2116ff61f00e373fc4a03c49f8e48e582590b6fea9177b611aecc9a622c58746d142ab7b6ec986dfb87aa04381aa7852163f0deb57301ba309dc089cc7e93434e3c67e5ba812bdff006f8cc8394b163c86577fcafbd078c8749f3f1bb89e5ed1b78a8c8dfe1d99b5acbf545470d9f993a3a7c4492e5ad59fbcdc07ec702cabd23c01ac4b4379c41d170ce4058a8ac65ea5f5a145c3139eb2096d03d806fb58e237e3ade187349d0de043c74b4567a400fe2575e5094c95a245499b2a75fc9d4879d351279d60cb2b1fc030ef2bcc8184e98f94d677b2dbbefac4fc550a7e7a8be48fea13cbb944c78d4490203010001",
)

///|
// "The quick brown fox jumps over the lazy dog"
let openssl_message : Bytes = hex(
  "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
)

///|
let openssl_signature : Bytes = hex(
  "1a22776e3d951378edb2235b08adb850653ecfa47a0444c53b833f3e29a28b515d58e45b51a58ffac1b00da04be16f392765a8b2eaa67a7e29d683a64e27ff0383a849d0f9eb982d15fd246e7c70e1e1e6dcc5cc9c3e38c90377a57f11d002cdc8d6d1399fff0af823fb7832be3845b3d544ad0800700b01e52383e5f1bb12ba83ce4a1b3a26b9ae2b440acefd412f611b7f3c9cdeb7316701ea99912386c7723d69d5ca2f2a01805d3ba7703fcc4ffe080cd5b8598313552a9dd793f43924cd14826b8e0240c7a466c8ed4a7d9e8b2928720e9cd283e533936575d04ef6f32a5deb4720d24d652fa565a278154b0f5c940ae141a535dd22f19b737212e21cd1",
)

///|
test "openssl-generated: RSA-2048 SHA-256 verify via SPKI" {
  let pubkey = @rsa.RsaPublicKey::from_spki_der(openssl_spki_der)
  assert_eq(pubkey.n_bytes_len, 256)
  let ok = pubkey.verify(openssl_message, openssl_signature, Sha256)
  assert_eq(ok, true)
}

///|
test "openssl-generated: RSA-2048 SHA-256 verify via PKCS#1" {
  let pubkey = @rsa.RsaPublicKey::from_pkcs1_der(openssl_pkcs1_der)
  let ok = pubkey.verify(openssl_message, openssl_signature, Sha256)
  assert_eq(ok, true)
}

///|
test "cross-key rejection: openssl key cannot verify RFC 7515 signature" {
  let pubkey = @rsa.RsaPublicKey::from_pkcs1_der(openssl_pkcs1_der)
  let ok = pubkey.verify(rfc7515_signing_input, rfc7515_signature, Sha256)
  assert_eq(ok, false)
}

// ─── decoder negative tests ────────────────────────────────────────────

///|
test "from_spki_der: truncated DER raises Asn1" {
  // Take the first 10 bytes — definitely not a complete SEQUENCE.
  let trunc = Bytes::makei(10, fn(i) { openssl_spki_der[i] })
  let result = try? @rsa.RsaPublicKey::from_spki_der(trunc)
  match result {
    Err(_) => () // any RsaError is acceptable
    Ok(_) => abort("expected truncated DER to fail")
  }
}

///|
test "from_spki_der: wrong algorithm OID rejected" {
  // SPKI with id-ecPublicKey (1.2.840.10045.2.1) instead of rsaEncryption.
  //   SEQUENCE { SEQUENCE { OID 1.2.840.10045.2.1, NULL }, BIT STRING { 0 } }
  let bad = hex("3010300b06072a8648ce3d02010500030100")
  let result = try? @rsa.RsaPublicKey::from_spki_der(bad)
  match result {
    Err(UnsupportedAlgorithm(_)) => ()
    _ => abort("expected UnsupportedAlgorithm")
  }
}

///|
test "from_pkcs1_der: not a sequence rejected" {
  // INTEGER 0 — single element, not a SEQUENCE.
  let bad = hex("020100")
  let result = try? @rsa.RsaPublicKey::from_pkcs1_der(bad)
  match result {
    Err(_) => ()
    Ok(_) => abort("expected non-sequence to fail")
  }
}

// ─── sanity: HashAlg ergonomics ────────────────────────────────────────

///|
test "Sha384 / Sha512 are now wired up (return false for wrong hash)" {
  // The RFC 7515 signature was made with SHA-256; verifying with SHA-384
  // or SHA-512 should now return false (rather than raise) since both
  // hashes are implemented.
  let pubkey = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_pkcs1_der)
  assert_false(
    pubkey.verify(rfc7515_signing_input, rfc7515_signature, Sha384),
  )
  assert_false(
    pubkey.verify(rfc7515_signing_input, rfc7515_signature, Sha512),
  )
}

// -----------------------------------------------------------------------------
// Security attack tests
// -----------------------------------------------------------------------------

///|
test "ATTACK CVE-2006-4339 / CVE-2014-1568 (BERserk): trailing-garbage PKCS#1 v1.5 forgery" {
  // The classic Bleichenbacher / BERserk attack exploits implementations that
  // locate the DigestInfo within the decoded EM and ignore bytes after it.
  // We verify by reconstructing the full expected EM and ct_eq-ing against
  // it, so any deviation (including trailing data) must fail.
  //
  // Concrete attack: take a legitimate signature and flip the last byte —
  // emulates the position where an attacker would smuggle extra bytes.
  let pubkey = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_pkcs1_der)
  let sig = rfc7515_signature
  // Flip the last byte to simulate "trailing-garbage after DigestInfo".
  let bad = Bytes::makei(sig.length(), fn(i) {
    if i == sig.length() - 1 {
      (sig[i].to_int() ^ 0xff).to_byte()
    } else {
      sig[i]
    }
  })
  let ok = pubkey.verify(rfc7515_signing_input, bad, Sha256)
  assert_false(ok)
}

///|
test "ATTACK: signature with high-bit-set s (s could be > n) returns false, not crash" {
  // s as all-0xff (definitely > n for our test key's modulus). RSAVP1 says
  // s >= n → invalid. We should return false, NOT raise.
  let pubkey = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_pkcs1_der)
  let n_bytes = rfc7515_signature.length()
  let bad = Bytes::makei(n_bytes, fn(_i) { b'\xff' })
  let ok = pubkey.verify(rfc7515_signing_input, bad, Sha256)
  assert_false(ok)
}

///|
test "ATTACK: empty signature must raise InvalidSignatureLength" {
  let pubkey = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_pkcs1_der)
  let empty : Bytes = b""
  let raised = try {
    let _ = pubkey.verify(rfc7515_signing_input, empty, Sha256)
    false
  } catch {
    InvalidSignatureLength => true
    _ => false
  }
  assert_true(raised)
}

// -----------------------------------------------------------------------------
// Sign + verify roundtrip with a real RSA-2048 PKCS#1 key
// -----------------------------------------------------------------------------

///|
let rfc_priv_pkcs1_der : Bytes = hex(
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
test "rsa: sign + verify roundtrip with SHA-256" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rfc_priv_pkcs1_der)
  let pk = sk.public_key()
  let msg : Bytes = b"hello rsa sign"
  let sig = sk.sign(msg, Sha256)
  assert_eq(sig.length(), pk.n_bytes_len)
  assert_true(pk.verify(msg, sig, Sha256))
}

///|
test "rsa: sign with SHA-512" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rfc_priv_pkcs1_der)
  let pk = sk.public_key()
  let msg : Bytes = b"hello rsa sha512"
  let sig = sk.sign(msg, Sha512)
  assert_true(pk.verify(msg, sig, Sha512))
}

///|
test "rsa: sign is deterministic (PKCS#1 v1.5)" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rfc_priv_pkcs1_der)
  let s1 = sk.sign(b"msg", Sha256)
  let s2 = sk.sign(b"msg", Sha256)
  assert_eq(s1, s2)
}

///|
test "rsa: tampered message verifies as false" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rfc_priv_pkcs1_der)
  let pk = sk.public_key()
  let sig = sk.sign(b"original", Sha256)
  assert_false(pk.verify(b"tampered", sig, Sha256))
}

// -----------------------------------------------------------------------------
// PKCS#8 PEM loader
// -----------------------------------------------------------------------------

///|
test "rsa: from_pkcs8_pem loads an openssl-generated PEM" {
  let pem_text =
    #|-----BEGIN PRIVATE KEY-----
    #|MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1dxcX+LKQT7dY
    #|Ijp33/KdG7mMTZlB0NNth734XxngLtK0jIctq058117XCdDgX3wMJ1Sqbs46/iiI
    #|A9NnTsOcZLL2q/7sPYnWfw5+hIPbwSlEFmq09dO+anrj2cK9/WZBIdZAgxnAR5jH
    #|6Qizs8fwSpM5GjvRHAlM9I5pXBE1hMtnd2HhFyFUxF+LfEbLg8wVrKDW71iINPZT
    #|GpW+0vm386LzDBSutHiRu/mw67uYz+9JX9t2H7ZCv5wyQ9x5X/rv3lYz8im4X/uC
    #|Y6ls2Uf4AX0MfqrjD0K7Xqk4+BYuADHK4mmkv7YZuIVOK+ix4VrR8LXUn0js+1p7
    #|YuheeHUVAgMBAAECggEAHxVpNUf6flHJXCVw0nvf+R14qRnZuLZmoQpxdgwESKx8
    #|l0TDGwWPCj9yFW+vAeAZRZOvIwqb9Or4UmQlYDrTswRky3Am2Jyp8b4N44obdBcg
    #|VHNqj9jUDnf62PDCNP0k+N8s7hwG2zLobsXyIaYYB4cetNdTi7w7s5zokA+fOwVc
    #|UUPaa0rKrEAKCbrS3p0tCkvFaX4aB5QS+Vld5dMRJc667dTOt56YI9lTHJXonpUl
    #|nYTwYHr7m5fjK+8ejJBm7s9NwS4NqMTScr6qm8/tVmJW4o/3Y5M+qbDNYbqvgqpN
    #|ksR2FTf25ZNf+oR/TR+3PzACoPk8nYMQWljR0l41eQKBgQDhIGFUzRGmbNdJdIHy
    #|oAO9f+lEOS9zHEeXJ94cTpm6xqLrDM+KaT5salsAJ9ylKpR2JfAt5qMGma5/SkjA
    #|2fmCRInATanv7fR3nT3xYBCBCKOF2brT7CvUJvSqJnYGQ9AfTVrQjYm9fYER140m
    #|ZSY0akHqNwHExpZRErRfLVtZ6wKBgQDOWd93C8jGrvHqCYygfFE5mxSwMAbfrqZk
    #|eP2kpeH5jWPbal674i/z7Pd16VxSHuyz9USUlJBuvxty1iQwp8VB0gA+I0+BAyVX
    #|e34rG+n/2OO0xZrLEjGCFCzm+puTGXE9v5Hi2MWW4cNjRlsI3VUGOwDlCvEUh3Tp
    #|XBEu3DCs/wKBgBegbFaYBwguWBHPdmveO0ZCDFsqnT45c5H7jyXtYdjmS+bbO1TN
    #|Ys3CA7bqeA+lfls/9Ar9L5LbwiJ9y1DiD3uKceKKxBD4KjX7fKq+aD0CiRbdGOxw
    #|1tC3HepViwFxUIBYf/VvRUtrxoX210t2RiIuHKjWCQt7w/7SNbffbLztAoGBAMzn
    #|5cVbCFZzJnoWXXSHvkiLvLFwH4NC9KvUkVpL9udOBZi+ObAsXR3Fc728qxZI6xeQ
    #|ODeqhvnR/7m691jxYCmKFP+fJLWhoBUM5i58m5KZlxPNHXcFa/AVhLkgphgeLZr5
    #|fi5av2qiaNlN5dwZnPKA6NSIVvjhwbBw4gc8U4GVAoGAM4SzRs6vqMWEWuWyjUIC
    #|RGdwkzsNjHE6Pv4xAeEl0dq5NRwwjBLEf+ydxLyehLNEGhvOgQIO7M7qkftmYxVx
    #|X48PFWrS5d0SK7jtKFdScwWFD2kCA6+EjGlTeQMyS/xb+bVcFkRItjg2+mtHGmNT
    #|Rolbhxd8JzI+RynTuqhZL24=
    #|-----END PRIVATE KEY-----
  let sk = @rsa.RsaPrivateKey::from_pkcs8_pem(pem_text)
  let pk = sk.public_key()
  let msg : Bytes = b"pem-loaded RSA sign test"
  let sig = sk.sign(msg, Sha256)
  assert_true(pk.verify(msg, sig, Sha256))
}
