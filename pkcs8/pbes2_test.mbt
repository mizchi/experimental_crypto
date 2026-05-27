// PBES2 (PKCS#5 v2.1) decryption tests.
//
// Fixture generated 2026-05 with OpenSSL 3.6.2:
//   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
//     | openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 \
//                     -passout pass:testpassword -out enc_priv.pem
//
// This is a throwaway key generated only to exercise this code path; it
// does not protect anything.

///|
let rsa_oid_str : String = "1.2.840.113549.1.1.1"

///|
fn oid(s : String) -> @asn1.ObjectIdentifier raise {
  @asn1.ObjectIdentifier::from_string(s)
}

///|
fn der_null() -> Bytes {
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_null, Null))
}

///|
fn alg_elem(oid_s : String, params : Bytes?) -> @asn1.Element raise {
  @pkix.algorithm_identifier_to_element({
    algorithm: oid(oid_s),
    parameters: params,
  })
}

///|
fn pbes2_params(pbkdf2_params : Bytes) -> Bytes raise {
  let kdf = alg_elem("1.2.840.113549.1.5.12", Some(pbkdf2_params))
  let iv = @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_octet_string,
      OctetString(Bytes::makei(16, fn(_) { b'\x00' })),
    ),
  )
  let enc = alg_elem("2.16.840.1.101.3.4.1.42", Some(iv))
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence([kdf, enc])))
}

///|
fn encrypted_with_pbkdf2_params(
  pbkdf2_params : Bytes,
) -> @pkcs8.EncryptedPrivateKeyInfo raise {
  {
    algorithm: {
      algorithm: oid("1.2.840.113549.1.5.13"),
      parameters: Some(pbes2_params(pbkdf2_params)),
    },
    encrypted_data: Bytes::makei(16, fn(_) { b'\x00' }),
  }
}

///|
fn test_private_key_info() -> @pkcs8.PrivateKeyInfo raise {
  let inner = @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([@asn1.Element::new(@asn1.tag_integer, Integer(b"\x00"))]),
    ),
  )
  {
    version: 0,
    algorithm: { algorithm: oid(rsa_oid_str), parameters: Some(der_null()) },
    private_key: inner,
    attributes: [],
    public_key: None,
  }
}

///|
fn pkcs7_pad_for_test(plain : Bytes) -> Bytes {
  let rem = plain.length() % 16
  let pad = if rem == 0 { 16 } else { 16 - rem }
  Bytes::makei(plain.length() + pad, fn(i) {
    if i < plain.length() {
      plain[i]
    } else {
      pad.to_byte()
    }
  })
}

///|
fn pbkdf2_params_for_test(
  hash : @pbkdf2.HashAlg,
  prf_oid : String,
  key_len : Int,
) -> Bytes raise {
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"salt")),
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x02")),
    @asn1.Element::new(
      @asn1.tag_integer,
      Integer(Bytes::makei(1, fn(_) { key_len.to_byte() })),
    ),
    alg_elem(prf_oid, Some(der_null())),
  ]
  // Keep hash referenced by the caller-side fixture builder so a mismatched
  // OID / enum pair fails in decryption rather than silently reusing SHA-256.
  let _ = hash
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence(items)))
}

///|
fn pbes2_params_for_test(
  hash : @pbkdf2.HashAlg,
  prf_oid : String,
  cipher_oid : String,
  key_len : Int,
  iv : Bytes,
) -> Bytes raise {
  let pbkdf2_params = pbkdf2_params_for_test(hash, prf_oid, key_len)
  let kdf = alg_elem("1.2.840.113549.1.5.12", Some(pbkdf2_params))
  let enc = alg_elem(
    cipher_oid,
    Some(
      @asn1.encode_der(
        @asn1.Element::new(@asn1.tag_octet_string, OctetString(iv)),
      ),
    ),
  )
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence([kdf, enc])))
}

///|
fn encrypted_fixture_for_test(
  hash : @pbkdf2.HashAlg,
  prf_oid : String,
  cipher_oid : String,
  key_len : Int,
) -> @pkcs8.EncryptedPrivateKeyInfo raise {
  let password : Bytes = b"pw"
  let iv = Bytes::makei(16, fn(i) { i.to_byte() })
  let plain = @pkcs8.serialize_der(test_private_key_info())
  let key = @pbkdf2.pbkdf2(hash, password, b"salt", 2, key_len)
  let encrypted_data = @aead.aes_cbc_encrypt(key, iv, pkcs7_pad_for_test(plain))
  {
    algorithm: {
      algorithm: oid("1.2.840.113549.1.5.13"),
      parameters: Some(
        pbes2_params_for_test(hash, prf_oid, cipher_oid, key_len, iv),
      ),
    },
    encrypted_data,
  }
}

///|
fn pbkdf2_params_with_tail(tail : Array[@asn1.Element]) -> Bytes {
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"salt")),
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
  ]
  for item in tail {
    items.push(item)
  }
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence(items)))
}

///|
let enc_rsa_pem : String =
  #|-----BEGIN ENCRYPTED PRIVATE KEY-----
  #|MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQ7antkrKEL1UdXF1a
  #|C/tYEAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEEogUwudefvCQ1fC
  #|SssIXgYEggTQemAy3ajiE+XSKKTqTd4OHP8JGyOnF/yDqbKQmtUvpetpnVOEhXD8
  #|IM9ZoJI+wpTXI/mEXJlb9tdKa+65YrNHs4nQmwL6h5iPJN6uHf5z3H+B4thdCWbT
  #|z3zj47sYTps2nfg4YxPSsKaTqZNTJucmxxpDIHq7uuLT4gsJV+mublffX9M4sfc8
  #|sQWWa/sbgbEIAVOZCVDEizZZ51xIs7Ufeif5FdWA0EOOS+Hai8VEXS5sB88lpReb
  #|Y7heXrJsy6ThAGijN69lm2Fqhx/+5aZp+zAZnw5BZfi558n6PC7WB1XE8EPEWQM9
  #|5ADt9D4WZT9J6bjvMW/bTsGof2WHCVzr5RYABNdh38IqncF1mPmJmciqJ3EOI4GC
  #|JrQDwppAF9u+PkNXvrOS1f298c0wGmGDLR/X8JXxAqClpDma86hbJ/P9EFf2BZz+
  #|DAFfcV7FI9XoZOzZMiiPKMZQDCtzO5Pu+347ULzibCkRYxbQunJwPjoBmYE1bDHu
  #|f9Naip8t0Wx1dnPysHPlQ48LN5I6PaMlcuyqz4ix+hbFSVn7KhXlQT8ILiL8mC48
  #|fxBZEg473attk3uiOudT0/xkK9jF1GPKvdPCH0qywzX9rftC/EFVM9LdIAhO2Fen
  #|dhZvkwrOAo4HfpeACahua4a/YfvpBRKb7lnpkYuRrEr+E0OMIbaJkZK16FcrulCX
  #|ZAkCh3s4L5ffQDoLuBtVcLgGmfIk9VcbyzbbfPGsMe4UzRB1oZWCDXslPtwE9pHY
  #|EAyLm/UsUBCfDOEIh+p+paxfGyiN9yWXt1y48c+Vwy/CIpU8rVgKtVrWh4HNVHCX
  #|rb+dwNEooIBDNV+4/TKvLvhX2h6AX688T36KGJgtN+AMMaBuliGp65dD+a9s3Buz
  #|jjuMnBKZ9HkmPgBl/pPrSfEVjuRLAf6UQGpiPwpQpM4bejMmvIr6q1VYNisi/hnj
  #|Ef1HqeTIucUWubfwiQHJ7CJOcmjqQgPQXsDIpAGH7NBMe6Zo+Mh13Kk/qs2qPyyn
  #|k7q1fpoPiiD2vNQqAAJty8OghtMaTYybAewAIPyV9gw1r/vkW6/zlfXCQT/nDXh7
  #|RA92S9DofZbhqnJDOYW6oz0vp5BEvRMPKE7v2esUTbPbLg5l5ZStzWY6wXydEc95
  #|iLxfC3/LyKM1OLfpUjUcJsdj1TIOZQbD5URpOAyyZM1ue6XjDDFmJKp3BIApLcq0
  #|JktDgSIicNh5SACisGsc4FaF6nTP/JGnE7XWUL7lyB1m9BFVC1bCzOQLTxIUuzaz
  #|f8RBBWMv6pNoFA09Lm5o/nZ5V2AVOyJa+Vx8niXTJrgzozXPzJZE0OAFvGRX6DfQ
  #|cugxKlwtG/eCHIhYSz7H5D86oVACGvDEDnTBl8IzVACN7M+S/x51R+12WsHID4nC
  #|Co9z95dFuVMED8C4LESe/4adTWCsObNgyr5PSsbOk2rVk5c4WsJYBpUC0cG4rSGz
  #|cqmq5Q0IClDJqmA4ZjyVgUFYSNesfXaS2q0PuzN6I7X2gV5bkCfTyMrrQDkTHCFW
  #|GOyWwtY3ZV1hECJ+MionqLLjgJJXikjpcaUcaHoFhAKTFogpLpuEr9LYqyMfYdKs
  #|Rl3148PUmbsCIecofwVSw0fkk2e7ugCSqVnhpP5eg0mht35+7rHu6UY=
  #|-----END ENCRYPTED PRIVATE KEY-----

///|
test "pbes2: decrypt openssl RSA fixture with correct password recovers RSA PrivateKeyInfo" {
  let key = @pkcs8.decrypt_pem(enc_rsa_pem, b"testpassword")
  // RSA PKCS#1 PrivateKey is wrapped in PKCS#8 with version 0 (v1 has no
  // public key field) and the rsaEncryption OID.
  @debug.assert_eq(key.version, 0)
  let rsa_oid = @asn1.ObjectIdentifier::from_string(rsa_oid_str)
  @debug.assert_eq(key.algorithm.algorithm, rsa_oid)
  // The inner privateKey bytes are an RSAPrivateKey SEQUENCE starting
  // with 0x30 (SEQUENCE) and decoding cleanly.
  assert_true(key.private_key.length() > 100)
  let inner = @asn1.decode_der(key.private_key)
  match inner.value {
    Sequence(items) => assert_true(items.length() >= 9) // RFC 8017 §A.1.2
    _ =>
      @debug.assert_eq(true, false, msg="expected inner RSAPrivateKey SEQUENCE")
  }
}

///|
test "pbes2: wrong password fails (InvalidPadding or downstream parse error)" {
  try @pkcs8.decrypt_pem(enc_rsa_pem, b"wrong-password") catch {
    _ => ()
  } noraise {
    _ =>
      @debug.assert_eq(true, false, msg="wrong password must not produce a key")
  }
}

///|
test "pbes2: tampered ciphertext fails" {
  // Parse, flip a byte in the encrypted data, re-serialize, then attempt
  // decryption. The CBC chaining will propagate corruption so padding
  // check usually catches it; if not, the parse_der after will reject.
  let original = @pkcs8.parse_encrypted_pem(enc_rsa_pem)
  let n = original.encrypted_data.length()
  // Tamper with the last block so padding strip notices.
  let tampered_bytes = Bytes::makei(n, fn(i) {
    if i == n - 17 {
      (original.encrypted_data[i].to_int() ^ 0x01).to_byte()
    } else {
      original.encrypted_data[i]
    }
  })
  let tampered : @pkcs8.EncryptedPrivateKeyInfo = {
    ..original,
    encrypted_data: tampered_bytes,
  }
  try @pkcs8.decrypt(tampered, b"testpassword") catch {
    _ => ()
  } noraise {
    _ =>
      @debug.assert_eq(true, false, msg="tampered ciphertext must not decrypt")
  }
}

///|
test "pbes2: parse_encrypted_pem still works without decryption (regression)" {
  let enc = @pkcs8.parse_encrypted_pem(enc_rsa_pem)
  let pbes2_oid = @asn1.ObjectIdentifier::from_string("1.2.840.113549.1.5.13")
  @debug.assert_eq(enc.algorithm.algorithm, pbes2_oid)
  assert_true(enc.encrypted_data.length() > 0)
  assert_true(enc.encrypted_data.length() % 16 == 0)
}

///|
test "pbes2: decrypts PBKDF2-HMAC-SHA1/SHA384/SHA512 fixtures" {
  let expected = test_private_key_info()
  let sha1 = @pkcs8.decrypt(
    encrypted_fixture_for_test(
      @pbkdf2.HashAlg::Sha1,
      "1.2.840.113549.2.7",
      "2.16.840.1.101.3.4.1.42",
      32,
    ),
    b"pw",
  )
  @debug.assert_eq(sha1.private_key, expected.private_key)
  let sha384 = @pkcs8.decrypt(
    encrypted_fixture_for_test(
      @pbkdf2.HashAlg::Sha384,
      "1.2.840.113549.2.10",
      "2.16.840.1.101.3.4.1.42",
      32,
    ),
    b"pw",
  )
  @debug.assert_eq(sha384.private_key, expected.private_key)
  let sha512 = @pkcs8.decrypt(
    encrypted_fixture_for_test(
      @pbkdf2.HashAlg::Sha512,
      "1.2.840.113549.2.11",
      "2.16.840.1.101.3.4.1.42",
      32,
    ),
    b"pw",
  )
  @debug.assert_eq(sha512.private_key, expected.private_key)
}

///|
test "pbes2: decrypts AES-192-CBC fixture" {
  let expected = test_private_key_info()
  let got = @pkcs8.decrypt(
    encrypted_fixture_for_test(
      @pbkdf2.HashAlg::Sha256,
      "1.2.840.113549.2.9",
      "2.16.840.1.101.3.4.1.22",
      24,
    ),
    b"pw",
  )
  @debug.assert_eq(got.private_key, expected.private_key)
}

///|
test "ATTACK pbes2: duplicate PBKDF2 keyLength is rejected" {
  let params = pbkdf2_params_with_tail([
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x20")),
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x20")),
    alg_elem("1.2.840.113549.2.9", Some(der_null())),
  ])
  try @pkcs8.decrypt(encrypted_with_pbkdf2_params(params), b"pw") catch {
    @pkcs8.UnexpectedStructure(_) => ()
    other => abort("expected UnexpectedStructure, got " + repr(other))
  } noraise {
    _ => abort("accepted duplicate PBKDF2 keyLength")
  }
}

///|
test "ATTACK pbes2: duplicate PBKDF2 prf is rejected" {
  let prf = alg_elem("1.2.840.113549.2.9", Some(der_null()))
  let params = pbkdf2_params_with_tail([
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x20")),
    prf,
    prf,
  ])
  try @pkcs8.decrypt(encrypted_with_pbkdf2_params(params), b"pw") catch {
    @pkcs8.UnexpectedStructure(_) => ()
    other => abort("expected UnexpectedStructure, got " + repr(other))
  } noraise {
    _ => abort("accepted duplicate PBKDF2 prf")
  }
}

///|
test "ATTACK pbes2: PBKDF2 prf rejects non-NULL parameters" {
  let bad_prf_params = @asn1.encode_der(
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"")),
  )
  let params = pbkdf2_params_with_tail([
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x20")),
    alg_elem("1.2.840.113549.2.9", Some(bad_prf_params)),
  ])
  try @pkcs8.decrypt(encrypted_with_pbkdf2_params(params), b"pw") catch {
    @pkcs8.UnexpectedStructure(_) => ()
    other => abort("expected UnexpectedStructure, got " + repr(other))
  } noraise {
    _ => abort("accepted PBKDF2 prf with non-NULL parameters")
  }
}

///|
test "ATTACK pbes2: PBKDF2 keyLength must be positive" {
  let params = pbkdf2_params_with_tail([
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x00")),
    alg_elem("1.2.840.113549.2.9", Some(der_null())),
  ])
  try @pkcs8.decrypt(encrypted_with_pbkdf2_params(params), b"pw") catch {
    @pkcs8.UnexpectedStructure(_) => ()
    other => abort("expected UnexpectedStructure, got " + repr(other))
  } noraise {
    _ => abort("accepted PBKDF2 keyLength=0")
  }
}
