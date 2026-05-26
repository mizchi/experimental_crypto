// Property-based fuzz tests for scrypt. scrypt is memory-hard so we use
// the smallest possible parameters (log_n=4 → N=16, r=1, p=1) and a small
// sample size. We check four invariants:
//
//   (1) out-of-range params (log_n / r / p / dk_len) must raise.
//   (2) Small valid params must never panic on arbitrary (password, salt).
//   (3) PHC encoded roundtrip: hash_encoded → verify_encoded succeeds.
//   (4) Wrong password fails verify_encoded.

///|
fn small_params() -> @scrypt.Params {
  { log_n: 4, r: 1, p: 1, dk_len: 32 }
}

///|
/// Ensures the salt is at least 1 byte so PHC encoding has something to work
/// with. Empty Bytes is valid for derive_key but base64-encodes to an empty
/// segment which makes the encoded string ambiguous on roundtrip.
fn ensure_nonempty(b : Bytes) -> Bytes {
  if b.length() == 0 {
    b"\x00"
  } else {
    b
  }
}

///|
test "fuzz scrypt: invalid log_n / r / p / dk_len rejected" {
  let n = 30
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  let raws : Array[Int] = @quickcheck.samples(n)
  for i in 0..<n {
    // Pick one of four out-of-range params per iteration.
    let raw = if raws[i] < 0 { -raws[i] } else { raws[i] }
    let bad : @scrypt.Params = match raw % 4 {
      0 => { log_n: 0, r: 1, p: 1, dk_len: 32 } // log_n < 1
      1 => { log_n: 4, r: 0, p: 1, dk_len: 32 } // r < 1
      2 => { log_n: 4, r: 1, p: 0, dk_len: 32 } // p < 1
      _ => { log_n: 4, r: 1, p: 1, dk_len: 0 } // dk_len < 1
    }
    match (try? @scrypt.derive_key(bad, pwds[i], salts[i])) {
      Err(_) => ()
      Ok(_) => fail("out-of-range scrypt params must reject")
    }
  }
}

///|
test "fuzz scrypt: small params never panic" {
  let params = small_params()
  let n = 20
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let out = @scrypt.derive_key(params, pwds[i], salts[i]) catch {
      _ => abort("unreachable: small params should succeed")
    }
    assert_eq(out.length(), params.dk_len)
  }
}

///|
test "fuzz scrypt: PHC encoded roundtrip" {
  let params = small_params()
  let n = 15
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let password = ensure_nonempty(pwds[i])
    let salt = ensure_nonempty(salts[i])
    let encoded = @scrypt.hash_encoded(params, password, salt) catch {
      _ => abort("unreachable: hash_encoded should succeed")
    }
    @scrypt.verify_encoded(encoded, password) catch {
      _ => fail("verify_encoded must accept the original password")
    }
  }
}

///|
test "fuzz scrypt: wrong password fails verify_encoded" {
  let params = small_params()
  let n = 15
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let password = ensure_nonempty(pwds[i])
    let salt = ensure_nonempty(salts[i])
    let encoded = @scrypt.hash_encoded(params, password, salt) catch {
      _ => abort("unreachable")
    }
    // Append a sentinel byte so the candidate is guaranteed different.
    let wrong = Bytes::makei(password.length() + 1, fn(j) {
      if j < password.length() {
        password[j]
      } else {
        b'\xff'
      }
    })
    match (try? @scrypt.verify_encoded(encoded, wrong)) {
      Err(_) => () // expected
      Ok(_) => fail("verify_encoded must reject a wrong password")
    }
  }
}
