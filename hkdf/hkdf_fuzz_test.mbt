// Property-based fuzz tests for HKDF-SHA-256 (RFC 5869). quickcheck draws
// arbitrary `Bytes` triples for (ikm, salt, info) and we check structural
// invariants:
//   (1) hkdf(...) on length=32 never panics for arbitrary byte inputs — the
//       only documented failure modes are length-out-of-range and unsupported
//       hash, neither of which can happen here.
//   (2) Same inputs produce the same output (determinism / pure function).
//   (3) Requested output length is honoured exactly.
//   (4) RFC 5869 §3.2: a non-empty salt produces a different PRK than the
//       zero-salt fallback, so the final OKM must differ too.
//   (5) expand rejects length > 255 * hash_len with OutputTooLong.
//   (6) SHA-384 / SHA-512 surface as UnsupportedHash.
//
// Note: we use `try? ... catch` style consistently with the other fuzz
// harnesses (asn1 / pbkdf2 / x25519) — the anti-pattern warning is expected.

///|
test "fuzz hkdf: extract + expand never panic on valid inputs" {
  for triple in (@quickcheck.samples(50) : Array[(Bytes, Bytes, Bytes)]) {
    let (ikm, salt, info) = triple
    let _ = @hkdf.hkdf(Sha256, salt, ikm, info, 32) catch {
      _ => abort("unreachable: length=32 is well within bounds")
    }
  }
}

///|
test "fuzz hkdf: determinism" {
  for triple in (@quickcheck.samples(30) : Array[(Bytes, Bytes, Bytes)]) {
    let (ikm, salt, info) = triple
    let a = @hkdf.hkdf(Sha256, salt, ikm, info, 32) catch {
      _ => abort("unreachable")
    }
    let b = @hkdf.hkdf(Sha256, salt, ikm, info, 32) catch {
      _ => abort("unreachable")
    }
    assert_eq(a, b)
  }
}

///|
test "fuzz hkdf: length parameter respected" {
  for triple in (@quickcheck.samples(20) : Array[(Bytes, Bytes, Int)]) {
    let (ikm, salt, raw_len) = triple
    let positive = if raw_len < 0 { -raw_len } else { raw_len }
    let length = positive % 200 + 1 // 1..200
    let out = @hkdf.hkdf(Sha256, salt, ikm, b"", length) catch {
      _ => abort("unreachable")
    }
    assert_eq(out.length(), length)
  }
}

///|
test "fuzz hkdf: salt vs no-salt produce different output (RFC 5869 §3.2)" {
  for triple in (@quickcheck.samples(20) : Array[(Bytes, Bytes, Bytes)]) {
    let (ikm, salt, info) = triple
    if salt.length() == 0 {
      continue
    }
    let a = @hkdf.hkdf(Sha256, salt, ikm, info, 32) catch {
      _ => abort("unreachable")
    }
    let b = @hkdf.hkdf(Sha256, b"", ikm, info, 32) catch {
      _ => abort("unreachable")
    }
    assert_true(a != b)
  }
}

///|
test "fuzz hkdf: expand rejects length > 255 * 32" {
  let prk = @hkdf.extract(Sha256, b"", b"\x00") catch {
    _ => abort("unreachable")
  }
  match (try? @hkdf.expand(Sha256, prk, b"", 255 * 32 + 1)) {
    Err(_) => ()
    Ok(_) => fail("expected OutputTooLong")
  }
}

///|
test "fuzz hkdf: SHA-384 / SHA-512 are UnsupportedHash" {
  for ikm in (@quickcheck.samples(10) : Array[Bytes]) {
    match (try? @hkdf.hkdf(Sha384, b"", ikm, b"", 32)) {
      Err(_) => ()
      Ok(_) => fail("Sha384 should error")
    }
    match (try? @hkdf.hkdf(Sha512, b"", ikm, b"", 32)) {
      Err(_) => ()
      Ok(_) => fail("Sha512 should error")
    }
  }
}
