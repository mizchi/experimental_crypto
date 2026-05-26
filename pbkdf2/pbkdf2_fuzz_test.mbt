// Property-based fuzz tests for PBKDF2-HMAC-SHA256. We exercise the public
// `pbkdf2` entry on random (password, salt) pairs at small iteration counts
// (c=1, c=2, c=100) and check the structural invariants:
//
//   (1) iterations < 1 must raise (InvalidIterations / similar) for any
//       random (password, salt).
//   (2) Valid params (c=1, dk_len=32) must succeed and never panic on
//       arbitrary password / salt bytes.
//   (3) Same params + same inputs must produce the same output
//       (determinism).
//   (4) Different iteration counts must produce different outputs for the
//       same (password, salt) — c=1 vs c=2 must always diverge.

///|
test "fuzz pbkdf2: non-positive iterations rejected" {
  let n = 50
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  let raws : Array[Int] = @quickcheck.samples(n)
  for i in 0..<n {
    let raw = raws[i]
    // Force the iteration count to be <= 0 by negating positives. Zero or
    // negatives are all expected to reject.
    let iter = if raw > 0 { -raw } else { raw }
    match (try? @pbkdf2.pbkdf2(Sha256, pwds[i], salts[i], iter, 32)) {
      Err(_) => ()
      Ok(_) => fail("non-positive iterations must reject")
    }
  }
}

///|
test "fuzz pbkdf2: c=1 dk_len=32 never panics" {
  let n = 50
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let _ = @pbkdf2.pbkdf2(Sha256, pwds[i], salts[i], 1, 32) catch {
      _ => abort("unreachable: c=1, dk=32 should succeed")
    }
  }
}

///|
test "fuzz pbkdf2: same params produce same output (determinism)" {
  let n = 30
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let a = @pbkdf2.pbkdf2(Sha256, pwds[i], salts[i], 100, 32) catch {
      _ => abort("unreachable")
    }
    let b = @pbkdf2.pbkdf2(Sha256, pwds[i], salts[i], 100, 32) catch {
      _ => abort("unreachable")
    }
    assert_eq(a, b)
  }
}

///|
test "fuzz pbkdf2: c=1 vs c=2 diverge on same inputs" {
  let n = 20
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let a = @pbkdf2.pbkdf2(Sha256, pwds[i], salts[i], 1, 32) catch {
      _ => abort("unreachable")
    }
    let b = @pbkdf2.pbkdf2(Sha256, pwds[i], salts[i], 2, 32) catch {
      _ => abort("unreachable")
    }
    assert_true(a != b)
  }
}

///|
test "fuzz pbkdf2: dk_len ∈ [1..96] never panics and length matches" {
  // Single-block, two-block and three-block outputs (h_len=32).
  let n = 30
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  let raws : Array[Int] = @quickcheck.samples(n)
  for i in 0..<n {
    let positive = if raws[i] < 0 { -raws[i] } else { raws[i] }
    let dk_len = positive % 96 + 1
    let out = @pbkdf2.pbkdf2(Sha256, pwds[i], salts[i], 1, dk_len) catch {
      _ => abort("unreachable: small dk_len should succeed")
    }
    assert_eq(out.length(), dk_len)
  }
}
