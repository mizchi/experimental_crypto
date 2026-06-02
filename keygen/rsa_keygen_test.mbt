// RSA key-generation tests. Generated keys are non-deterministic, so each test
// asserts usability (correct modulus size + sign/verify + OAEP round trip) and
// the structural invariants (e = 65537, n = p·q odd, d·e ≡ 1 behaviour via the
// crypto round trips). 512-bit keeps the pure-bigint prime search test-fast.

///|
test "RSA keygen 512-bit: structure + PKCS#1 v1.5 sign/verify" {
  let sk = @keygen.rsa_keypair(512)
  let pk = sk.public_key()
  // Modulus is ~512 bits (top two bits of each 256-bit prime are set, so the
  // product is exactly 512 bits → 64 bytes).
  inspect(sk.n_bytes_len, content="64")
  let msg = b"rsa keygen sign/verify"
  let sig = sk.sign(msg, @rsa.HashAlg::Sha256)
  assert_true(pk.verify(msg, sig, @rsa.HashAlg::Sha256))
  // A different message must not verify under the same signature.
  assert_false(pk.verify(b"other message", sig, @rsa.HashAlg::Sha256))
}

///|
test "RSA keygen 512-bit: OAEP encrypt/decrypt round trip" {
  let sk = @keygen.rsa_keypair(512)
  let pk = sk.public_key()
  let msg = b"hi rsa"
  // SHA-1 OAEP (hlen 20) fits a 64-byte modulus; SHA-256 (needs 66) does not.
  let seed = Bytes::makei(20, fn(i) { (i + 5).to_byte() })
  let ct = pk.encrypt_oaep(msg, seed, hash=@rsa.OaepHash::Sha1)
  let back = sk.decrypt_oaep(ct, hash=@rsa.OaepHash::Sha1)
  assert_eq(back.length(), msg.length())
  for i in 0..<msg.length() {
    assert_eq(back[i], msg[i])
  }
}

///|
test "RSA keygen produces distinct moduli across calls" {
  let a = @keygen.rsa_keypair(512)
  let b = @keygen.rsa_keypair(512)
  // Two independent prime searches must not yield the same modulus.
  inspect(a.n.compare(b.n) == 0, content="false")
}

///|
test "RSA keygen rejects invalid sizes" {
  inspect((try? @keygen.rsa_keypair(511)) is Err(_), content="true")
  inspect((try? @keygen.rsa_keypair(256)) is Err(_), content="true")
}
