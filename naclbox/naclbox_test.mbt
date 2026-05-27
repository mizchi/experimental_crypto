// Blackbox tests for mizchi/naclbox.
//
// Covers libsodium-compatible `secretbox` and `box` over
// `crypto_box_curve25519xchacha20poly1305`:
//   * secretbox round-trip + tag-tamper rejection
//   * box round-trip (Alice -> Bob, Bob -> Alice)
//   * beforenm commutativity (Alice's view ≡ Bob's view)
//   * size and error-path checks
//
// We do not embed libsodium-style canonical ciphertext vectors here because
// the upstream test suite does not publish them in a directly-copyable form
// for the xchacha20poly1305 variant; self-roundtrip + commutativity cover
// the symmetry that libsodium guarantees.

///|
fn hex(s : String) -> Bytes {
  let clean : Array[Char] = []
  for c in s {
    if c != ' ' && c != ':' && c != '\n' {
      clean.push(c)
    }
  }
  let n = clean.length() / 2
  Bytes::makei(n, fn(i) {
    let hi = hex_nibble(clean[i * 2])
    let lo = hex_nibble(clean[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn hex_nibble(c : Char) -> Int {
  let code = c.to_int()
  if code >= '0'.to_int() && code <= '9'.to_int() {
    code - '0'.to_int()
  } else if code >= 'a'.to_int() && code <= 'f'.to_int() {
    code - 'a'.to_int() + 10
  } else if code >= 'A'.to_int() && code <= 'F'.to_int() {
    code - 'A'.to_int() + 10
  } else {
    abort("non-hex char")
  }
}

///|
fn to_hex(b : Bytes) -> String {
  let buf = StringBuilder::new()
  let table : Array[Char] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  ]
  for i in 0..<b.length() {
    let v = b[i].to_int()
    buf.write_char(table[v >> 4])
    buf.write_char(table[v & 0xF])
  }
  buf.to_string()
}

///|
test "secretbox round-trip" {
  let key = Bytes::makei(32, fn(i) { (0x80 + i).to_byte() })
  let nonce = Bytes::makei(24, fn(i) { (0x40 + i).to_byte() })
  let msg = b"hello secretbox"
  let msg_bytes = Bytes::makei(msg.length(), fn(i) { msg[i] })
  let sealed_box = @naclbox.secretbox(key, nonce, msg_bytes)
  // tag(16) + ciphertext (len(msg))
  @debug.assert_eq(sealed_box.length(), 16 + msg.length())
  let recovered = @naclbox.secretbox_open(key, nonce, sealed_box)
  @debug.assert_eq(to_hex(recovered), to_hex(msg_bytes))
}

///|
test "secretbox rejects tag tamper" {
  let key = Bytes::makei(32, fn(_) { b'\x00' })
  let nonce = Bytes::makei(24, fn(_) { b'\x00' })
  let msg = b"a"
  let msg_bytes = Bytes::makei(msg.length(), fn(i) { msg[i] })
  let sealed_box = @naclbox.secretbox(key, nonce, msg_bytes)
  // Flip the first byte of the tag.
  let tampered = Bytes::makei(sealed_box.length(), fn(i) {
    if i == 0 {
      (sealed_box[i].to_int() ^ 0x01).to_byte()
    } else {
      sealed_box[i]
    }
  })
  let result : Result[Bytes, @naclbox.NaclBoxError] = try? @naclbox.secretbox_open(
    key, nonce, tampered,
  )
  match result {
    Ok(_) => abort("expected AuthenticationFailed")
    Err(@naclbox.AuthenticationFailed) => ()
    Err(e) => abort("expected AuthenticationFailed but got " + repr(e))
  }
}

///|
test "secretbox empty message round-trip" {
  let key = Bytes::makei(32, fn(_) { b'\x00' })
  let nonce = Bytes::makei(24, fn(_) { b'\x00' })
  let sealed_box = @naclbox.secretbox(key, nonce, b"")
  @debug.assert_eq(sealed_box.length(), 16) // just the tag
  let recovered = @naclbox.secretbox_open(key, nonce, sealed_box)
  @debug.assert_eq(recovered.length(), 0)
}

///|
test "secretbox rejects wrong key size" {
  let key = Bytes::makei(16, fn(_) { b'\x00' })
  let nonce = Bytes::makei(24, fn(_) { b'\x00' })
  let result : Result[Bytes, @naclbox.NaclBoxError] = try? @naclbox.secretbox(
    key, nonce, b"x",
  )
  match result {
    Err(@naclbox.InvalidKeyLength(16)) => ()
    Ok(_) => abort("expected InvalidKeyLength")
    Err(e) => abort("expected InvalidKeyLength but got " + repr(e))
  }
}

///|
test "secretbox rejects wrong nonce size" {
  let key = Bytes::makei(32, fn(_) { b'\x00' })
  let nonce = Bytes::makei(12, fn(_) { b'\x00' })
  let result : Result[Bytes, @naclbox.NaclBoxError] = try? @naclbox.secretbox(
    key, nonce, b"x",
  )
  match result {
    Err(@naclbox.InvalidNonceLength(12)) => ()
    Ok(_) => abort("expected InvalidNonceLength")
    Err(e) => abort("expected InvalidNonceLength but got " + repr(e))
  }
}

///|
test "secretbox_open rejects short ciphertext" {
  let key = Bytes::makei(32, fn(_) { b'\x00' })
  let nonce = Bytes::makei(24, fn(_) { b'\x00' })
  let too_short = Bytes::makei(8, fn(_) { b'\x00' })
  let result : Result[Bytes, @naclbox.NaclBoxError] = try? @naclbox.secretbox_open(
    key, nonce, too_short,
  )
  match result {
    Err(@naclbox.InvalidCiphertextLength(8)) => ()
    Ok(_) => abort("expected InvalidCiphertextLength")
    Err(e) => abort("expected InvalidCiphertextLength but got " + repr(e))
  }
}

// ─── Public-key box (Alice <-> Bob via X25519) ────────────────────────────

///|
fn alice_keypair() -> @naclbox.KeyPair raise {
  let sk = hex(
    "77076d0a7318a57d3c16c17251b26645" + "df4c2f87ebc0992ab177fba51db92c2a",
  )
  @naclbox.KeyPair::from_seed(sk)
}

///|
fn bob_keypair() -> @naclbox.KeyPair raise {
  let sk = hex(
    "5dab087e624a8a4b79e17f8b83800ee6" + "6f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  @naclbox.KeyPair::from_seed(sk)
}

///|
test "box round-trip Alice -> Bob" {
  let alice = alice_keypair()
  let bob = bob_keypair()
  let nonce = Bytes::makei(24, fn(i) { (0x10 + i).to_byte() })
  let msg = b"Hello, Bob, from Alice."
  let msg_bytes = Bytes::makei(msg.length(), fn(i) { msg[i] })
  let sealed_box = @naclbox.box_(
    bob.public_key,
    alice.secret_key,
    nonce,
    msg_bytes,
  )
  let recovered = @naclbox.box_open(
    alice.public_key,
    bob.secret_key,
    nonce,
    sealed_box,
  )
  @debug.assert_eq(to_hex(recovered), to_hex(msg_bytes))
}

///|
test "box_beforenm is commutative" {
  // The X25519 ECDH output is the same when computed from either side, and
  // HChaCha20 is deterministic. So both peers must derive the same SharedKey.
  let alice = alice_keypair()
  let bob = bob_keypair()
  let alice_view = @naclbox.box_beforenm(bob.public_key, alice.secret_key)
  let bob_view = @naclbox.box_beforenm(alice.public_key, bob.secret_key)
  @debug.assert_eq(to_hex(alice_view.to_bytes()), to_hex(bob_view.to_bytes()))
}

///|
test "box_afternm round-trip equals box_/box_open" {
  let alice = alice_keypair()
  let bob = bob_keypair()
  let nonce = Bytes::makei(24, fn(i) { (0x20 + i).to_byte() })
  let msg = b"shared key path"
  let msg_bytes = Bytes::makei(msg.length(), fn(i) { msg[i] })

  // Path A: use box_ directly.
  let ct_a = @naclbox.box_(bob.public_key, alice.secret_key, nonce, msg_bytes)

  // Path B: derive shared key once, then afternm.
  let sk = @naclbox.box_beforenm(bob.public_key, alice.secret_key)
  let ct_b = @naclbox.box_afternm(sk, nonce, msg_bytes)
  @debug.assert_eq(to_hex(ct_a), to_hex(ct_b))

  // Path B decrypt via box_open_afternm using Bob's side.
  let sk_bob = @naclbox.box_beforenm(alice.public_key, bob.secret_key)
  let pt = @naclbox.box_open_afternm(sk_bob, nonce, ct_b)
  @debug.assert_eq(to_hex(pt), to_hex(msg_bytes))
}

///|
test "box rejects tag tamper" {
  let alice = alice_keypair()
  let bob = bob_keypair()
  let nonce = Bytes::makei(24, fn(_) { b'\x00' })
  let msg_bytes = Bytes::makei(3, fn(_) { b'A' })
  let ct = @naclbox.box_(bob.public_key, alice.secret_key, nonce, msg_bytes)
  let tampered = Bytes::makei(ct.length(), fn(i) {
    if i == 0 {
      (ct[i].to_int() ^ 0x80).to_byte()
    } else {
      ct[i]
    }
  })
  let result : Result[Bytes, @naclbox.NaclBoxError] = try? @naclbox.box_open(
    alice.public_key,
    bob.secret_key,
    nonce,
    tampered,
  )
  match result {
    Err(@naclbox.AuthenticationFailed) => ()
    Ok(_) => abort("expected AuthenticationFailed")
    Err(e) => abort("expected AuthenticationFailed but got " + repr(e))
  }
}

///|
test "ATTACK box_beforenm rejects low-order public key" {
  let alice = alice_keypair()
  let low_order = @x25519.PublicKey::from_bytes(
    Bytes::makei(32, fn(_) { b'\x00' }),
  )
  let result : Result[@naclbox.SharedKey, @naclbox.NaclBoxError] = try? @naclbox.box_beforenm(
    low_order,
    alice.secret_key,
  )
  match result {
    Err(@naclbox.KeyGenerationError(_)) => ()
    Ok(_) => abort("expected KeyGenerationError")
    Err(e) => abort("expected KeyGenerationError but got " + repr(e))
  }
}

///|
test "ATTACK box_open rejects wrong sender public key" {
  let alice = alice_keypair()
  let bob = bob_keypair()
  let mallory = @naclbox.KeyPair::from_seed(
    Bytes::makei(32, fn(i) { (0xa0 + i).to_byte() }),
  )
  let nonce = Bytes::makei(24, fn(i) { (0x30 + i).to_byte() })
  let msg_bytes = b"authenticated sender"
  let ct = @naclbox.box_(bob.public_key, alice.secret_key, nonce, msg_bytes)
  let result : Result[Bytes, @naclbox.NaclBoxError] = try? @naclbox.box_open(
    mallory.public_key,
    bob.secret_key,
    nonce,
    ct,
  )
  match result {
    Err(@naclbox.AuthenticationFailed) => ()
    Ok(_) => abort("expected AuthenticationFailed")
    Err(e) => abort("expected AuthenticationFailed but got " + repr(e))
  }
}

///|
test "ATTACK secretbox_open rejects ciphertext body tamper" {
  let key = Bytes::makei(32, fn(i) { (0x55 + i).to_byte() })
  let nonce = Bytes::makei(24, fn(i) { (0x33 + i).to_byte() })
  let sealed_box = @naclbox.secretbox(key, nonce, b"ciphertext body")
  let tampered = Bytes::makei(sealed_box.length(), fn(i) {
    if i == 16 {
      (sealed_box[i].to_int() ^ 0x01).to_byte()
    } else {
      sealed_box[i]
    }
  })
  let result : Result[Bytes, @naclbox.NaclBoxError] = try? @naclbox.secretbox_open(
    key, nonce, tampered,
  )
  match result {
    Err(@naclbox.AuthenticationFailed) => ()
    Ok(_) => abort("expected AuthenticationFailed")
    Err(e) => abort("expected AuthenticationFailed but got " + repr(e))
  }
}

///|
test "KeyPair::from_seed rejects wrong length" {
  let bad = Bytes::makei(16, fn(_) { b'\x00' })
  let result : Result[@naclbox.KeyPair, @naclbox.NaclBoxError] = try? @naclbox.KeyPair::from_seed(
    bad,
  )
  match result {
    Err(@naclbox.InvalidKeyLength(16)) => ()
    Ok(_) => abort("expected InvalidKeyLength")
    Err(e) => abort("expected InvalidKeyLength but got " + repr(e))
  }
}

///|
test "KeyPair public key matches RFC 7748 §6.1 Alice/Bob" {
  // Sanity check on the keypair derivation: confirms KeyPair::from_seed
  // matches the published RFC 7748 §6.1 / libsodium test pubkeys before we
  // trust the box/secretbox derivations above.
  let alice = alice_keypair()
  let expected_alice_pk = hex(
    "8520f0098930a754748b7ddcb43ef75a" + "0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
  @debug.assert_eq(
    to_hex(alice.public_key.to_bytes()),
    to_hex(expected_alice_pk),
  )
  let bob = bob_keypair()
  let expected_bob_pk = hex(
    "de9edb7d7b7dc1b4d35b61c2ece43537" + "3f8343c85b78674dadfc7e146f882b4f",
  )
  @debug.assert_eq(to_hex(bob.public_key.to_bytes()), to_hex(expected_bob_pk))
}
