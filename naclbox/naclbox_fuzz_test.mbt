// Fuzz-style tests for NaCl secretbox/box wrappers. These exercise the API
// boundary where attacker-controlled bytes become nonces, plaintexts,
// ciphertexts, and seed material.

///|
fn nb_ensure_length(b : Bytes, target : Int) -> Bytes {
  if b.length() == target {
    b
  } else if b.length() == 0 {
    Bytes::makei(target, fn(i) { (i + 1).to_byte() })
  } else if b.length() > target {
    Bytes::makei(target, fn(i) { b[i] })
  } else {
    let n = b.length()
    Bytes::makei(target, fn(i) { b[i % n] })
  }
}

///|
fn nb_flip_first_body_byte(ciphertext : Bytes) -> Bytes {
  Bytes::makei(ciphertext.length(), fn(i) {
    if i == 16 {
      (ciphertext[i].to_int() ^ 0x01).to_byte()
    } else {
      ciphertext[i]
    }
  })
}

///|
test "fuzz naclbox: secretbox roundtrip and body tamper rejection" {
  let n = 50
  let keys : Array[Bytes] = @quickcheck.samples(n)
  let nonces : Array[Bytes] = @quickcheck.samples(n)
  let messages : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let key = nb_ensure_length(keys[i], 32)
    let nonce = nb_ensure_length(nonces[i], 24)
    let sealed_box = @naclbox.secretbox(key, nonce, messages[i])
    let opened = @naclbox.secretbox_open(key, nonce, sealed_box)
    @debug.assert_eq(opened, messages[i])
    if messages[i].length() > 0 {
      let tampered = nb_flip_first_body_byte(sealed_box)
      try @naclbox.secretbox_open(key, nonce, tampered) catch {
        @naclbox.AuthenticationFailed => ()
        e => abort("expected AuthenticationFailed, got " + repr(e))
      } noraise {
        _ => abort("tampered secretbox ciphertext must reject")
      }
    }
  }
}

///|
test "fuzz naclbox: public-key box roundtrip over arbitrary seeds" {
  let n = 50
  let alice_seeds : Array[Bytes] = @quickcheck.samples(n)
  let bob_seeds : Array[Bytes] = @quickcheck.samples(n)
  let nonces : Array[Bytes] = @quickcheck.samples(n)
  let messages : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let alice = @naclbox.KeyPair::from_seed(
      nb_ensure_length(alice_seeds[i], 32),
    )
    let bob = @naclbox.KeyPair::from_seed(nb_ensure_length(bob_seeds[i], 32))
    let nonce = nb_ensure_length(nonces[i], 24)
    let ct = @naclbox.box_(bob.public_key, alice.secret_key, nonce, messages[i])
    let opened = @naclbox.box_open(alice.public_key, bob.secret_key, nonce, ct)
    @debug.assert_eq(opened, messages[i])
  }
}
