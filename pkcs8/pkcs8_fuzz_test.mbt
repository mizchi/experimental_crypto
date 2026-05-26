// Property-based robustness fuzz for the pkcs8 module. Constructing a valid
// PKCS#8 PrivateKeyInfo / EncryptedPrivateKeyInfo by hand is involved, so
// these tests only assert the "garbage in → Pkcs8Error out, never panic"
// invariant on random Bytes and random String inputs.

///|
test "fuzz pkcs8: parse_der never panics on random bytes" {
  let n = 200
  for input in (@quickcheck.samples(n) : Array[Bytes]) {
    let _ = (try? @pkcs8.parse_der(input))

  }
}

///|
test "fuzz pkcs8: parse_encrypted_der never panics on random bytes" {
  let n = 200
  for input in (@quickcheck.samples(n) : Array[Bytes]) {
    let _ = (try? @pkcs8.parse_encrypted_der(input))

  }
}

///|
test "fuzz pkcs8: parse_pem never panics on random strings" {
  let n = 200
  for input in (@quickcheck.samples(n) : Array[String]) {
    let _ = (try? @pkcs8.parse_pem(input))

  }
}

///|
test "fuzz pkcs8: parse_encrypted_pem never panics on random strings" {
  let n = 200
  for input in (@quickcheck.samples(n) : Array[String]) {
    let _ = (try? @pkcs8.parse_encrypted_pem(input))

  }
}
