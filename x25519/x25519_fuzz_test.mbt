// Property-based fuzz tests for X25519. quickcheck generates arbitrary Bytes,
// we coerce them to 32-byte scalars / u-coordinates via `ensure_32`, then
// check structural invariants:
//
//   (1) PrivateKey::from_bytes on a 32-byte input must not panic. Clamping
//       is total — any 32-byte sequence is a valid clamped scalar.
//   (2) ECDH is commutative: dh(sk_a, pk_b) == dh(sk_b, pk_a) (when neither
//       side hits the all-zero small-subgroup signal).
//   (3) PublicKey::from_bytes is total on 32 bytes; the only failure mode is
//       wrong length. All-zero u-coord → diffie_hellman raises
//       AllZeroSharedSecret rather than returning a degenerate secret.
//   (4) Length-mismatched Bytes raises InvalidScalarLength / InvalidPointLength
//       instead of panicking.

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
test "fuzz x25519: PrivateKey::from_bytes does not panic on random 32-byte seeds" {
  let n = 200
  for raw in (@quickcheck.samples(n) : Array[Bytes]) {
    let seed = ensure_32(raw)
    let sk = @x25519.PrivateKey::from_bytes(seed)
    // public_key derivation must also be total.
    let _ = sk.public_key()
  }
}

///|
test "fuzz x25519: ECDH commutativity" {
  // x25519 is ~92 µs per ECDH; 100 pairs (200 ECDH ops) stays comfortable.
  for pair in (@quickcheck.samples(100) : Array[(Bytes, Bytes)]) {
    let seed_a = ensure_32(pair.0)
    let seed_b = ensure_32(pair.1)
    let sk_a = @x25519.PrivateKey::from_bytes(seed_a)
    let sk_b = @x25519.PrivateKey::from_bytes(seed_b)
    let pk_a = sk_a.public_key()
    let pk_b = sk_b.public_key()
    let r1 = try? @x25519.diffie_hellman(sk_a, pk_b)
    let r2 = try? @x25519.diffie_hellman(sk_b, pk_a)
    match (r1, r2) {
      (Ok(s1), Ok(s2)) => @debug.assert_eq(s1.to_bytes(), s2.to_bytes())
      // Symmetry: if one side hits AllZeroSharedSecret the other must too,
      // since the resulting u-coord depends only on the unordered pair.
      (Err(_), Err(_)) => ()
      _ =>
        // Asymmetric outcome would be a bug in either clamping or the ladder.
        abort("ECDH asymmetric success/failure on random seed pair")
    }
  }
}

///|
test "fuzz x25519: all-zero u-coord rejects as AllZeroSharedSecret" {
  let n = 50
  let zero_u : Bytes = Bytes::makei(32, fn(_) { b'\x00' })
  let pk_zero = @x25519.PublicKey::from_bytes(zero_u)
  for raw in (@quickcheck.samples(n) : Array[Bytes]) {
    let seed = ensure_32(raw)
    let sk = @x25519.PrivateKey::from_bytes(seed)
    try @x25519.diffie_hellman(sk, pk_zero) catch {
      @x25519.AllZeroSharedSecret => ()
      other =>
        abort("unexpected error on zero u: " + @debug.to_string(other) + "")
    } noraise {
      _ => abort("zero u-coord must yield AllZeroSharedSecret")
    }
  }
}

///|
test "fuzz x25519: scalarmult does not panic on random 32-byte u-coord" {
  // Pick one fixed scalar so we exercise the ladder against many points.
  let sk = @x25519.PrivateKey::from_bytes(
    Bytes::makei(32, fn(i) { (i + 1).to_byte() }),
  )
  let n = 100
  for raw in (@quickcheck.samples(n) : Array[Bytes]) {
    let u = ensure_32(raw)
    let pk = @x25519.PublicKey::from_bytes(u)
    // AllZeroSharedSecret is fine; we only care that nothing panics.
    let _ = try? @x25519.diffie_hellman(sk, pk)
  }
}

///|
test "fuzz x25519: non-32-byte input raises Invalid*Length" {
  let n = 100
  for raw in (@quickcheck.samples(n) : Array[Bytes]) {
    if raw.length() == 32 {
      continue
    }
    // PrivateKey::from_bytes must reject.
    try @x25519.PrivateKey::from_bytes(raw) catch {
      @x25519.InvalidScalarLength(got) => @debug.assert_eq(got, raw.length())
      other => abort("unexpected scalar error: " + @debug.to_string(other) + "")
    } noraise {
      _ => abort("PrivateKey::from_bytes accepted non-32-byte input")
    }
    // PublicKey::from_bytes must reject.
    try @x25519.PublicKey::from_bytes(raw) catch {
      @x25519.InvalidPointLength(got) => @debug.assert_eq(got, raw.length())
      other => abort("unexpected point error: " + @debug.to_string(other) + "")
    } noraise {
      _ => abort("PublicKey::from_bytes accepted non-32-byte input")
    }
  }
}
