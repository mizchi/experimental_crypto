// Property-based fuzz tests for Argon2. Argon2 is memory-hard and slow
// even at minimum cost (interactive ≈ 25 ms), so we use the smallest
// legal params (t_cost=1, m_cost=8, parallelism=1) and tiny sample sizes.
//
//   (1) out-of-range params (parallelism / t_cost / m_cost / output_len)
//       must raise InvalidParams.
//   (2) Small valid params must never panic on arbitrary (password, salt).
//   (3) PHC encoded roundtrip: hash_encoded → verify_encoded succeeds.
//   (4) Wrong password fails verify_encoded.
//   (5) Argon2d / Argon2i / Argon2id produce three distinct outputs for the
//       same (password, salt, params), since the three variants differ in
//       their indexing function.

///|
fn small_params() -> @argon2.Params {
  // m_cost must be >= 8 * parallelism (per validate_params).
  { variant: Argon2id, m_cost: 8, t_cost: 1, parallelism: 1, output_len: 32 }
}

///|
/// Argon2 PHC parsing reconstructs the salt via base64; an empty salt
/// roundtrips to empty, which is technically legal but makes the test
/// degenerate. Pad short salts up to 8 bytes (RFC 9106 §3.1 recommended
/// minimum) so we exercise a realistic shape.
fn pad_salt(b : Bytes) -> Bytes {
  if b.length() >= 8 {
    b
  } else if b.length() == 0 {
    Bytes::makei(8, fn(_) { b'\x00' })
  } else {
    let n = b.length()
    Bytes::makei(8, fn(i) { b[i % n] })
  }
}

///|
test "fuzz argon2: invalid params rejected" {
  let n = 20
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  let raws : Array[Int] = @quickcheck.samples(n)
  for i in 0..<n {
    let raw = if raws[i] < 0 { -raws[i] } else { raws[i] }
    // Pick one of four out-of-range axes per iteration.
    let bad : @argon2.Params = match raw % 4 {
      0 =>
        {
          variant: Argon2id,
          m_cost: 8,
          t_cost: 0,
          parallelism: 1,
          output_len: 32,
        } // t_cost < 1
      1 =>
        {
          variant: Argon2id,
          m_cost: 8,
          t_cost: 1,
          parallelism: 0,
          output_len: 32,
        } // parallelism < 1
      // m_cost must be >= 8 * parallelism; with parallelism=2 the floor is 16, so 8 is invalid.
      2 =>
        {
          variant: Argon2id,
          m_cost: 8,
          t_cost: 1,
          parallelism: 2,
          output_len: 32,
        }
      _ =>
        {
          variant: Argon2id,
          m_cost: 8,
          t_cost: 1,
          parallelism: 1,
          output_len: 2,
        } // output_len < 4
    }
    match (try? @argon2.hash_raw(bad, pwds[i], salts[i])) {
      Err(_) => ()
      Ok(_) => fail("out-of-range argon2 params must reject")
    }
  }
}

///|
test "fuzz argon2: small params never panic" {
  let params = small_params()
  let n = 10
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let out = @argon2.hash_raw(params, pwds[i], pad_salt(salts[i])) catch {
      _ => abort("unreachable: small params should succeed")
    }
    assert_eq(out.length(), params.output_len)
  }
}

///|
test "fuzz argon2: PHC encoded roundtrip" {
  let params = small_params()
  let n = 8
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let password = pwds[i]
    let salt = pad_salt(salts[i])
    let encoded = @argon2.hash_encoded(params, password, salt) catch {
      _ => abort("unreachable: hash_encoded should succeed")
    }
    @argon2.verify_encoded(encoded, password) catch {
      _ => fail("verify_encoded must accept the original password")
    }
  }
}

///|
test "fuzz argon2: wrong password fails verify_encoded" {
  let params = small_params()
  let n = 8
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let password = pwds[i]
    let salt = pad_salt(salts[i])
    let encoded = @argon2.hash_encoded(params, password, salt) catch {
      _ => abort("unreachable")
    }
    // Append a sentinel so the candidate is guaranteed different.
    let wrong = Bytes::makei(password.length() + 1, fn(j) {
      if j < password.length() {
        password[j]
      } else {
        b'\xff'
      }
    })
    match (try? @argon2.verify_encoded(encoded, wrong)) {
      Err(_) => () // expected
      Ok(_) => fail("verify_encoded must reject a wrong password")
    }
  }
}

///|
test "fuzz argon2: three variants give different outputs for same input" {
  // d / i / id differ only in the indexing function, so for nontrivial
  // memory schedules they must produce distinct outputs.
  let base = small_params()
  let n = 5
  let pwds : Array[Bytes] = @quickcheck.samples(n)
  let salts : Array[Bytes] = @quickcheck.samples(n)
  for i in 0..<n {
    let password = pwds[i]
    let salt = pad_salt(salts[i])
    let pd : @argon2.Params = { ..base, variant: Argon2d }
    let pi : @argon2.Params = { ..base, variant: Argon2i }
    let pid : @argon2.Params = { ..base, variant: Argon2id }
    let d_out = @argon2.hash_raw(pd, password, salt) catch {
      _ => abort("unreachable")
    }
    let i_out = @argon2.hash_raw(pi, password, salt) catch {
      _ => abort("unreachable")
    }
    let id_out = @argon2.hash_raw(pid, password, salt) catch {
      _ => abort("unreachable")
    }
    assert_true(d_out != i_out)
    assert_true(i_out != id_out)
    assert_true(d_out != id_out)
  }
}
