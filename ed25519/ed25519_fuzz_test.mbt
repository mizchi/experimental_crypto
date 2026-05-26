// Property-based fuzz tests for Ed25519. quickcheck generates arbitrary Bytes
// for seeds / messages / signatures; we coerce to the right length where
// needed and check the core round-trips:
//
//   (1) seed -> sk -> pk derivation must not panic on any 32-byte seed.
//   (2) sign(message) -> verify(message, sig) is always true (round-trip).
//   (3) Tampering the signature by one bit must make verify return false.
//   (4) Tampering the message must make verify return false.
//   (5) verify against an arbitrary Bytes signature must not panic. A
//       wrong-length signature returns false from verify and raises
//       InvalidSignatureLength from verify_strict.

///|
fn ensure_32(b : Bytes) -> Bytes {
  if b.length() == 32 {
    b
  } else if b.length() > 32 {
    Bytes::makei(32, fn(i) { b[i] })
  } else if b.length() == 0 {
    Bytes::makei(32, fn(_) { b'\x00' })
  } else {
    Bytes::makei(32, fn(i) { b[i % b.length()] })
  }
}

///|
test "fuzz ed25519: seed -> public_key derivation does not panic" {
  let n = 100
  for raw in (@quickcheck.samples(n) : Array[Bytes]) {
    let seed = ensure_32(raw)
    let sk = @ed25519.PrivateKey::from_seed(seed)
    let _ = sk.public_key()

  }
}

///|
test "fuzz ed25519: sign / verify round-trip" {
  // sign is ~236 µs; 80 random (seed, message) pairs ≈ 38 ms of sign work.
  let n = 80
  for pair in (@quickcheck.samples(n) : Array[(Bytes, Bytes)]) {
    let seed = ensure_32(pair.0)
    let message = pair.1
    let sk = @ed25519.PrivateKey::from_seed(seed)
    let pk = sk.public_key()
    let sig = sk.sign(message)
    // Every honest signature must verify.
    assert_eq(pk.verify(message, sig), true)
  }
}

///|
test "fuzz ed25519: bit-flipped signature does not verify" {
  let n = 60
  for tuple in (@quickcheck.samples(n) : Array[(Bytes, Bytes, UInt)]) {
    let seed = ensure_32(tuple.0)
    let message = tuple.1
    let flip_pos = tuple.2 % 64U // signature is 64 bytes
    let sk = @ed25519.PrivateKey::from_seed(seed)
    let pk = sk.public_key()
    let sig = sk.sign(message)
    // Flip a single bit in the signature.
    let tampered = Bytes::makei(64, fn(i) {
      if i == flip_pos.reinterpret_as_int() {
        (sig[i].to_int() ^ 0x01).to_byte()
      } else {
        sig[i]
      }
    })
    // Either verify rejects, or — if the bit landed in a no-op position —
    // the property still holds because EdDSA encodes (R, S) and any bit
    // change in either half breaks the equation.
    assert_eq(pk.verify(message, tampered), false)
  }
}

///|
test "fuzz ed25519: tampered message does not verify" {
  let n = 60
  for pair in (@quickcheck.samples(n) : Array[(Bytes, Bytes)]) {
    let seed = ensure_32(pair.0)
    let message = pair.1
    let sk = @ed25519.PrivateKey::from_seed(seed)
    let pk = sk.public_key()
    let sig = sk.sign(message)
    // Append a sentinel byte so the tampered message is guaranteed different.
    let tampered = Bytes::makei(message.length() + 1, fn(i) {
      if i < message.length() {
        message[i]
      } else {
        b'\xff'
      }
    })
    assert_eq(pk.verify(tampered, sig), false)
  }
}

///|
test "fuzz ed25519: verify on arbitrary signature bytes does not panic" {
  // Make one fixed (sk, pk) so we exercise verify against many random sigs.
  let sk = @ed25519.PrivateKey::from_seed(
    Bytes::makei(32, fn(i) { (i + 1).to_byte() }),
  )
  let pk = sk.public_key()
  let n = 100
  for tuple in (@quickcheck.samples(n) : Array[(Bytes, Bytes)]) {
    let message = tuple.0
    let sig = tuple.1
    // Boolean verify: must never panic. Wrong-length sig returns false.
    let v = pk.verify(message, sig)
    if sig.length() != 64 {
      assert_eq(v, false)
    }
    // Strict verify: wrong length must raise InvalidSignatureLength.
    if sig.length() != 64 {
      match (try? pk.verify_strict(message, sig)) {
        Err(@ed25519.InvalidSignatureLength(got)) => assert_eq(got, sig.length())
        Err(_) => () // other shape-related errors are acceptable too
        Ok(_) => abort("verify_strict accepted non-64-byte signature")
      }
    } else {
      // For 64-byte random sig, verify_strict may raise InvalidEncoding for
      // non-canonical S or undecompressable R. Either error or boolean is
      // fine; we only require absence of panic.
      let _ = try? pk.verify_strict(message, sig)

    }
  }
}

///|
test "fuzz ed25519: from_seed rejects non-32-byte input" {
  let n = 60
  for raw in (@quickcheck.samples(n) : Array[Bytes]) {
    if raw.length() == 32 {
      continue
    }
    match (try? @ed25519.PrivateKey::from_seed(raw)) {
      Err(@ed25519.InvalidSeedLength(got)) => assert_eq(got, raw.length())
      Err(other) => abort("unexpected seed error: \{other}")
      Ok(_) => abort("from_seed accepted non-32-byte input")
    }
  }
}
