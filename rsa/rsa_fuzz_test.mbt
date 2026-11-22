// Parser robustness fuzz for RSA key loaders. Random DER/PEM is expected to
// fail most of the time; the invariant is that untrusted input returns an
// RsaError and never aborts the process.

///|
test "fuzz rsa: public key DER loaders never panic on random bytes" {
  for input in (@quickcheck.samples(200) : Array[Bytes]) {
    let _ = try Ok(@rsa.RsaPublicKey::from_pkcs1_der(input)) catch { e => Err(e) }
    let _ = try Ok(@rsa.RsaPublicKey::from_spki_der(input)) catch { e => Err(e) }
  }
}

///|
test "fuzz rsa: private key DER loaders never panic on random bytes" {
  for input in (@quickcheck.samples(200) : Array[Bytes]) {
    let _ = try Ok(@rsa.RsaPrivateKey::from_pkcs1_der(input)) catch { e => Err(e) }
    let _ = try Ok(@rsa.RsaPrivateKey::from_pkcs8_der(input)) catch { e => Err(e) }
  }
}

///|
test "fuzz rsa: private key PEM loader never panics on random strings" {
  for input in (@quickcheck.samples(200) : Array[String]) {
    let _ = try Ok(@rsa.RsaPrivateKey::from_pkcs8_pem(input)) catch { e => Err(e) }
  }
}
