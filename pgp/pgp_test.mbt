// Blackbox tests against real gpg-generated OpenPGP signatures.

///|
// PGP Ed25519 pubkey for mizchi-pgp-test@pgp.test. Generated locally with:
//   gpg --quick-generate-key 'mizchi-pgp-test <mizchi@pgp.test>' ed25519 sign 1y
//   gpg --export --armor <fingerprint>
let pubkey_armor : String =
  #|-----BEGIN PGP PUBLIC KEY BLOCK-----
  #|
  #|mDMEahVikBYJKwYBBAHaRw8BAQdAFcCGD4FWeFWaKP63iD2kaWB7PdCvi/qNbKdn
  #|+70X8FC0IW1pemNoaS1wZ3AtdGVzdCA8bWl6Y2hpQHBncC50ZXN0PoiWBBMWCgA+
  #|FiEEnw6WuikaohqHyZg0cghfOfzvGXwFAmoVYpACGwMFCQHhM4AFCwkIBwIGFQoJ
  #|CAsCBBYCAwECHgECF4AACgkQcghfOfzvGXw/MAEA0RIBVcaC7gDbfMxHEk2drqH1
  #|mr+rjnaWyQKuQR0bdasBAP2WT1Y/UmFzQ73PZ+F70U3Xj8zpjSdJ4pVDkGfc7q4H
  #|=WXNn
  #|-----END PGP PUBLIC KEY BLOCK-----

///|
// Detached signature over the ASCII string "hello pgp signing", produced
// with `gpg --detach-sign --armor` and the key above.
let detached_signature : String =
  #|-----BEGIN PGP SIGNATURE-----
  #|
  #|iHUEABYKAB0WIQSfDpa6KRqiGofJmDRyCF85/O8ZfAUCahVikQAKCRByCF85/O8Z
  #|fN3QAQDj1RLNT9SyabU1KvU4kaZAs0Ka44bversHDAgRXz78IAD/SeOuV4vuWMyh
  #|zPnq2Xp3evefYWxMMi30BVzsr6n43gU=
  #|=0DWT
  #|-----END PGP SIGNATURE-----

///|
fn message_bytes() -> Bytes {
  let s = "hello pgp signing"
  Bytes::makei(s.length(), fn(i) { s.get_char(i).unwrap().to_int().to_byte() })
}

///|
test "pgp: armor decode roundtrips through CRC24" {
  let a = @pgp.decode_armor(pubkey_armor)
  assert_eq(a.label, "PUBLIC KEY BLOCK")
  assert_true(a.data.length() > 0)
}

///|
test "pgp: parse Public-Key Packet from armor (Ed25519)" {
  let pk = @pgp.parse_pubkey_armor(pubkey_armor)
  assert_eq(pk.version, 4)
  assert_eq(pk.algo, @pgp.algo_eddsa_legacy)
  match pk.key {
    Ed25519(_) => ()
    _ => abort("expected Ed25519 key")
  }
}

///|
test "pgp: verify_armor against real gpg signature" {
  let pkpkt = @pgp.parse_pubkey_armor(pubkey_armor)
  assert_true(@pgp.verify_armor(detached_signature, message_bytes(), pkpkt.key))
}

///|
test "pgp: tampered message fails verify" {
  let pkpkt = @pgp.parse_pubkey_armor(pubkey_armor)
  let bad : Bytes = b"hello pgp signinG"
  assert_false(@pgp.verify_armor(detached_signature, bad, pkpkt.key))
}

///|
test "pgp: tampered signature fails verify" {
  // Flip a char in the body of the armor.
  let bad_sig =
    #|-----BEGIN PGP SIGNATURE-----
    #|
    #|jHUEABYKAB0WIQSfDpa6KRqiGofJmDRyCF85/O8ZfAUCahVikQAKCRByCF85/O8Z
    #|fN3QAQDj1RLNT9SyabU1KvU4kaZAs0Ka44bversHDAgRXz78IAD/SeOuV4vuWMyh
    #|zPnq2Xp3evefYWxMMi30BVzsr6n43gU=
    #|=0DWT
    #|-----END PGP SIGNATURE-----
  let pkpkt = @pgp.parse_pubkey_armor(pubkey_armor)
  match (try? @pgp.verify_armor(bad_sig, message_bytes(), pkpkt.key)) {
    Err(ArmorCrcMismatch) => () // CRC24 catches the byte flip first
    Err(_) => () // or parser rejects
    Ok(false) => () // or signature verify rejects
    Ok(true) => abort("tampered signature accepted!")
  }
}

///|
test "pgp: armor CRC mismatch is detected" {
  let bad_crc =
    #|-----BEGIN PGP PUBLIC KEY BLOCK-----
    #|
    #|mDMEahVikBYJKwYBBAHaRw8BAQdAFcCGD4FWeFWaKP63iD2kaWB7PdCvi/qNbKdn
    #|=AAAA
    #|-----END PGP PUBLIC KEY BLOCK-----
  match (try? @pgp.decode_armor(bad_crc)) {
    Err(ArmorCrcMismatch) => ()
    Err(other) => abort("expected ArmorCrcMismatch, got \{other}")
    Ok(_) => abort("expected ArmorCrcMismatch, got Ok")
  }
}

// -----------------------------------------------------------------------------
// Sign roundtrips (verify with our own verifier — gpg-binary
// interoperability is left as a follow-up since we don't emit a UserID
// packet, only the detached Signature packet).
// -----------------------------------------------------------------------------

///|
test "pgp: sign Ed25519 + verify roundtrip" {
  let seed = Bytes::makei(32, fn(i) { (i + 3).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"hello pgp ed25519",
  )
  assert_true(@pgp.verify_armor(armor, b"hello pgp ed25519", pk_pgp))
}

///|
test "pgp: sign ECDSA P-256 + verify roundtrip" {
  let scalar = Bytes::makei(32, fn(i) { (i + 7).to_byte() })
  let sk = @p256.PrivateKey::from_bytes(scalar)
  let pk_pgp = @pgp.PgpPublicKey::EcdsaP256(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::EcdsaP256(sk),
    b"hello pgp p256",
  )
  assert_true(@pgp.verify_armor(armor, b"hello pgp p256", pk_pgp))
}

///|
test "pgp: sign ECDSA P-384 + verify roundtrip" {
  let scalar = Bytes::makei(48, fn(i) { (i + 11).to_byte() })
  let sk = @p384.PrivateKey::from_bytes(scalar)
  let pk_pgp = @pgp.PgpPublicKey::EcdsaP384(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::EcdsaP384(sk),
    b"hello pgp p384",
  )
  assert_true(@pgp.verify_armor(armor, b"hello pgp p384", pk_pgp))
}

// -----------------------------------------------------------------------------
// v6 (RFC 9580) roundtrips.
//
// We could not produce a real v6 fixture from this host: gpg 2.4.9 is
// installed but its build advertises only EDDSA (algo 22) in
// `gpg --version`, and emits v4 signatures even with `future-default` /
// `--default-new-key-algo ed25519/cert,sign+cv25519/encr`. The
// supported-algorithms list does not include Ed25519 (algo 27, RFC 9580
// id-Ed25519). So we only exercise sign-then-verify against our own impl.
// -----------------------------------------------------------------------------

///|
test "pgp v6: sign Ed25519 + verify roundtrip" {
  let seed = Bytes::makei(32, fn(i) { (i + 13).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"hello pgp v6 ed25519",
    version=6,
  )
  assert_true(@pgp.verify_armor(armor, b"hello pgp v6 ed25519", pk_pgp))
}

///|
test "pgp v6: sign ECDSA P-256 + verify roundtrip" {
  let scalar = Bytes::makei(32, fn(i) { (i + 17).to_byte() })
  let sk = @p256.PrivateKey::from_bytes(scalar)
  let pk_pgp = @pgp.PgpPublicKey::EcdsaP256(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::EcdsaP256(sk),
    b"hello pgp v6 p256",
    version=6,
  )
  assert_true(@pgp.verify_armor(armor, b"hello pgp v6 p256", pk_pgp))
}

///|
test "pgp v6: tampered message fails" {
  let seed = Bytes::makei(32, fn(i) { (i + 19).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"hello pgp v6 ed25519",
    version=6,
  )
  assert_false(@pgp.verify_armor(armor, b"hello pgp v6 ed25519!", pk_pgp))
}

///|
test "pgp v6: tampered version byte rejected" {
  // Sign with v6 then mangle the packet body's first byte to 0x05 (an
  // unused/reserved version). The parser should raise UnsupportedPacketVersion.
  let seed = Bytes::makei(32, fn(i) { (i + 23).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_pgp = @pgp.PgpPublicKey::Ed25519(sk.public_key())
  let armor = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"hello v6 vbyte",
    version=6,
  )
  let decoded = @pgp.decode_armor(armor)
  let pkts = @pgp.parse_packets(decoded.data)
  let mut sig_body : Bytes = b""
  for p in pkts {
    if p.tag == 2 {
      sig_body = p.body
    }
  }
  let bad_body = Bytes::makei(sig_body.length(), fn(i) {
    if i == 0 {
      b'\x05'
    } else {
      sig_body[i]
    }
  })
  match (try? @pgp.parse_signature_packet(bad_body)) {
    Err(UnsupportedPacketVersion(5)) => ()
    Err(other) => abort("expected UnsupportedPacketVersion(5), got \{other}")
    Ok(_) => abort("expected rejection")
  }
  assert_true(@pgp.verify_armor(armor, b"hello v6 vbyte", pk_pgp))
}

///|
test "pgp v6: v4 and v6 produce different armors" {
  // Signature material differs between v4 (MPI-wrapped r||s, 70 bytes) and
  // v6 (raw 64 bytes); trailer byte differs (0x04 vs 0x06); algo ID differs.
  let seed = Bytes::makei(32, fn(i) { (i + 29).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let armor_v4 = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"compare v4 v6",
  )
  let armor_v6 = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"compare v4 v6",
    version=6,
  )
  assert_not_eq(armor_v4, armor_v6)
}

///|
test "pgp v6: wire format checks (algo 27, salt=0, raw 64-byte sig)" {
  let seed = Bytes::makei(32, fn(i) { (i + 31).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let armor_v4 = @pgp.sign_armor(@pgp.PgpPrivateKey::Ed25519(sk), b"algo-check")
  let armor_v6 = @pgp.sign_armor(
    @pgp.PgpPrivateKey::Ed25519(sk),
    b"algo-check",
    version=6,
  )
  let pkts_v4 = @pgp.parse_packets(@pgp.decode_armor(armor_v4).data)
  let pkts_v6 = @pgp.parse_packets(@pgp.decode_armor(armor_v6).data)
  let mut sig4 = @pgp.parse_signature_packet(pkts_v4[0].body)
  for p in pkts_v4 {
    if p.tag == 2 {
      sig4 = @pgp.parse_signature_packet(p.body)
    }
  }
  let mut sig6 = @pgp.parse_signature_packet(pkts_v6[0].body)
  for p in pkts_v6 {
    if p.tag == 2 {
      sig6 = @pgp.parse_signature_packet(p.body)
    }
  }
  assert_eq(sig4.version, 4)
  assert_eq(sig4.pubkey_algo, @pgp.algo_eddsa_legacy)
  assert_eq(sig4.salt.length(), 0)
  assert_eq(sig6.version, 6)
  assert_eq(sig6.pubkey_algo, @pgp.algo_ed25519)
  assert_eq(sig6.salt.length(), 0)
  assert_eq(sig6.signature_material.length(), 64) // raw Ed25519 sig
}
