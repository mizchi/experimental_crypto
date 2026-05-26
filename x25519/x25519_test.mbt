// RFC 7748 §6.1 X25519 test vectors.

///|
test "x25519: RFC 7748 §5.2 vector 1" {
  let scalar : Bytes = b"\xa5\x46\xe3\x6b\xf0\x52\x7c\x9d\x3b\x16\x15\x4b\x82\x46\x5e\xdd\x62\x14\x4c\x0a\xc1\xfc\x5a\x18\x50\x6a\x22\x44\xba\x44\x9a\xc4"
  let u : Bytes = b"\xe6\xdb\x68\x67\x58\x30\x30\xdb\x35\x94\xc1\xa4\x24\xb1\x5f\x7c\x72\x66\x24\xec\x26\xb3\x35\x3b\x10\xa9\x03\xa6\xd0\xab\x1c\x4c"
  let expected : Bytes = b"\xc3\xda\x55\x37\x9d\xe9\xc6\x90\x8e\x94\xea\x4d\xf2\x8d\x08\x4f\x32\xec\xcf\x03\x49\x1c\x71\xf7\x54\xb4\x07\x55\x77\xa2\x85\x52"
  let sk = @x25519.PrivateKey::from_bytes(scalar)
  let pk = @x25519.PublicKey::from_bytes(u)
  let ss = @x25519.diffie_hellman(sk, pk)
  assert_eq(ss.to_bytes(), expected)
}

///|
test "x25519: RFC 7748 §5.2 vector 2" {
  let scalar : Bytes = b"\x4b\x66\xe9\xd4\xd1\xb4\x67\x3c\x5a\xd2\x26\x91\x95\x7d\x6a\xf5\xc1\x1b\x64\x21\xe0\xea\x01\xd4\x2c\xa4\x16\x9e\x79\x18\xba\x0d"
  let u : Bytes = b"\xe5\x21\x0f\x12\x78\x68\x11\xd3\xf4\xb7\x95\x9d\x05\x38\xae\x2c\x31\xdb\xe7\x10\x6f\xc0\x3c\x3e\xfc\x4c\xd5\x49\xc7\x15\xa4\x93"
  let expected : Bytes = b"\x95\xcb\xde\x94\x76\xe8\x90\x7d\x7a\xad\xe4\x5c\xb4\xb8\x73\xf8\x8b\x59\x5a\x68\x79\x9f\xa1\x52\xe6\xf8\xf7\x64\x7a\xac\x79\x57"
  let sk = @x25519.PrivateKey::from_bytes(scalar)
  let pk = @x25519.PublicKey::from_bytes(u)
  let ss = @x25519.diffie_hellman(sk, pk)
  assert_eq(ss.to_bytes(), expected)
}

///|
test "x25519: RFC 7748 §6.1 DH key exchange (Alice and Bob)" {
  let alice_priv : Bytes = b"\x77\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a"
  let alice_pub_expected : Bytes = b"\x85\x20\xf0\x09\x89\x30\xa7\x54\x74\x8b\x7d\xdc\xb4\x3e\xf7\x5a\x0d\xbf\x3a\x0d\x26\x38\x1a\xf4\xeb\xa4\xa9\x8e\xaa\x9b\x4e\x6a"
  let bob_priv : Bytes = b"\x5d\xab\x08\x7e\x62\x4a\x8a\x4b\x79\xe1\x7f\x8b\x83\x80\x0e\xe6\x6f\x3b\xb1\x29\x26\x18\xb6\xfd\x1c\x2f\x8b\x27\xff\x88\xe0\xeb"
  let bob_pub_expected : Bytes = b"\xde\x9e\xdb\x7d\x7b\x7d\xc1\xb4\xd3\x5b\x61\xc2\xec\xe4\x35\x37\x3f\x83\x43\xc8\x5b\x78\x67\x4d\xad\xfc\x7e\x14\x6f\x88\x2b\x4f"
  let shared_secret_expected : Bytes = b"\x4a\x5d\x9d\x5b\xa4\xce\x2d\xe1\x72\x8e\x3b\xf4\x80\x35\x0f\x25\xe0\x7e\x21\xc9\x47\xd1\x9e\x33\x76\xf0\x9b\x3c\x1e\x16\x17\x42"

  // Public-key derivation
  let alice_sk = @x25519.PrivateKey::from_bytes(alice_priv)
  let alice_pk = alice_sk.public_key()
  assert_eq(alice_pk.to_bytes(), alice_pub_expected)
  let bob_sk = @x25519.PrivateKey::from_bytes(bob_priv)
  let bob_pk = bob_sk.public_key()
  assert_eq(bob_pk.to_bytes(), bob_pub_expected)

  // ECDH
  let ss_alice = @x25519.diffie_hellman(alice_sk, bob_pk)
  let ss_bob = @x25519.diffie_hellman(bob_sk, alice_pk)
  assert_eq(ss_alice.to_bytes(), shared_secret_expected)
  assert_eq(ss_bob.to_bytes(), shared_secret_expected)
}

///|
test "x25519: PrivateKey clamps scalar bits per RFC 7748 §5" {
  // Set all bits high to verify clamping. After clamping:
  //   bytes[0] = 0xFF & 248 = 0xF8
  //   bytes[31] = (0xFF & 127) | 64 = 0x7F | 0x40 = 0x7F  (already had 0x40)
  let all_ones = Bytes::makei(32, fn(_) { b'\xff' })
  let sk = @x25519.PrivateKey::from_bytes(all_ones)
  let b = sk.to_bytes()
  assert_eq(b[0], b'\xf8')
  assert_eq(b[31], b'\x7f')
}

///|
test "x25519: rejects non-32-byte scalar or point" {
  match (try? @x25519.PrivateKey::from_bytes(b"\x01\x02")) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected InvalidScalarLength")
  }
  match (try? @x25519.PublicKey::from_bytes(b"\x01\x02")) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected InvalidPointLength")
  }
}

///|
test "x25519: all-zero peer key triggers AllZeroSharedSecret" {
  let sk = @x25519.PrivateKey::from_bytes(
    b"\x77\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a",
  )
  let pk = @x25519.PublicKey::from_bytes(Bytes::makei(32, fn(_) { b'\x00' }))
  match (try? @x25519.diffie_hellman(sk, pk)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected AllZeroSharedSecret")
  }
}

///|
test "x25519: PrivateKey::from_random is alias for from_bytes" {
  let seed : Bytes = b"\x77\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a"
  let sk_a = @x25519.PrivateKey::from_bytes(seed)
  let sk_b = @x25519.PrivateKey::from_random(seed)
  assert_eq(sk_a.to_bytes(), sk_b.to_bytes())
}

// -----------------------------------------------------------------------------
// Security attack tests
// -----------------------------------------------------------------------------

///|
test "ATTACK X25519 small-subgroup: pubkey=all-zero must raise AllZeroSharedSecret" {
  // All-zero is one of the small-subgroup points. Per RFC 7748 §6.1 the
  // resulting shared secret is all-zero and must be detected/rejected.
  let sk = @x25519.PrivateKey::from_bytes(Bytes::makei(32, fn(_) { b'\x42' }))
  let pk_bytes = Bytes::makei(32, fn(_) { b'\x00' })
  let pk = @x25519.PublicKey::from_bytes(pk_bytes)
  match (try? @x25519.diffie_hellman(sk, pk)) {
    Err(AllZeroSharedSecret) => ()
    other => abort("small-subgroup pubkey=0 NOT detected: \{other}")
  }
}

///|
test "ATTACK X25519 small-subgroup: pubkey=1 (low-order) must raise AllZeroSharedSecret" {
  // Another known low-order point: u=1.
  let sk = @x25519.PrivateKey::from_bytes(Bytes::makei(32, fn(_) { b'\x42' }))
  let pk_bytes = Bytes::makei(32, fn(i) {
    if i == 0 {
      b'\x01'
    } else {
      b'\x00'
    }
  })
  let pk = @x25519.PublicKey::from_bytes(pk_bytes)
  match (try? @x25519.diffie_hellman(sk, pk)) {
    Err(AllZeroSharedSecret) => ()
    other => abort("small-subgroup pubkey=1 NOT detected: \{other}")
  }
}
