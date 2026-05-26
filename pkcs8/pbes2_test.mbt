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
