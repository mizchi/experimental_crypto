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
  Bytes::makei(s.length(), fn(i) {
    s.get_char(i).unwrap().to_int().to_byte()
  })
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
