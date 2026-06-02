// Key-generation tests. Generated key pairs are non-deterministic, so each
// test asserts the *usability* of the pair (correct lengths + a sign/verify or
// ECDH round trip), not a fixed value.

///|
test "keygen P-256: scalar in range, derived key signs + verifies" {
  let (sk_b, pk_b) = @keygen.p256_keypair()
  inspect(sk_b.length(), content="32")
  inspect(pk_b.length(), content="65")
  inspect(pk_b[0].to_int(), content="4") // uncompressed point marker
  let sk = @p256.PrivateKey::from_bytes(sk_b)
  let pk = @p256.PublicKey::from_uncompressed(pk_b)
  let msg = b"keygen p256 round trip"
  let sig = sk.sign(msg, format=@p256.SignatureFormat::Der)
  assert_true(@p256.verify(pk, msg, sig, @p256.SignatureFormat::Der))
}

///|
test "keygen P-384: derived key signs + verifies" {
  let (sk_b, pk_b) = @keygen.p384_keypair()
  inspect(sk_b.length(), content="48")
  inspect(pk_b.length(), content="97")
  let sk = @p384.PrivateKey::from_bytes(sk_b)
  let pk = @p384.PublicKey::from_uncompressed(pk_b)
  let msg = b"keygen p384 round trip"
  let sig = sk.sign(msg, format=@p384.SignatureFormat::Der)
  assert_true(@p384.verify(pk, msg, sig, @p384.SignatureFormat::Der))
}

///|
test "keygen Ed25519: derived key signs + verifies" {
  let (seed, pk_b) = @keygen.ed25519_keypair()
  inspect(seed.length(), content="32")
  inspect(pk_b.length(), content="32")
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = @ed25519.PublicKey::from_bytes(pk_b)
  let msg = b"keygen ed25519 round trip"
  assert_true(pk.verify(msg, sk.sign(msg)))
}

///|
test "keygen X25519: two pairs agree on a shared secret" {
  let (a_sk, a_pk) = @keygen.x25519_keypair()
  let (b_sk, b_pk) = @keygen.x25519_keypair()
  inspect(a_sk.length(), content="32")
  inspect(a_pk.length(), content="32")
  let ska = @x25519.PrivateKey::from_bytes(a_sk)
  let skb = @x25519.PrivateKey::from_bytes(b_sk)
  let pka = @x25519.PublicKey::from_bytes(a_pk)
  let pkb = @x25519.PublicKey::from_bytes(b_pk)
  let ss_ab = @x25519.diffie_hellman(ska, pkb).to_bytes()
  let ss_ba = @x25519.diffie_hellman(skb, pka).to_bytes()
  let mut eq = true
  for i in 0..<32 {
    if ss_ab[i] != ss_ba[i] {
      eq = false
    }
  }
  assert_true(eq)
}

///|
test "keygen produces distinct P-256 keys across calls" {
  // With a working CSPRNG two independent scalars collide with probability
  // ~2^-256; a failure here means the RNG returned a constant.
  let (p1, _) = @keygen.p256_keypair()
  let (p2, _) = @keygen.p256_keypair()
  let mut same = true
  for i in 0..<32 {
    if p1[i] != p2[i] {
      same = false
    }
  }
  assert_false(same)
}
