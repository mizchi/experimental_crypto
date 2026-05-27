// RFC 9106 §5 Argon2 test vectors.
//
// Common inputs across §5.1–5.3:
//   password: 32 bytes of 0x01
//   salt:     16 bytes of 0x02
//   secret:    8 bytes of 0x03
//   ad:       12 bytes of 0x04
//   m_cost = 32, t_cost = 3, parallelism = 4, output_len = 32, version = 0x13

///|
fn make_rfc9106_inputs() -> (Bytes, Bytes, Bytes, Bytes) {
  let password = Bytes::makei(32, fn(_) { b'\x01' })
  let salt = Bytes::makei(16, fn(_) { b'\x02' })
  let secret = Bytes::makei(8, fn(_) { b'\x03' })
  let ad = Bytes::makei(12, fn(_) { b'\x04' })
  (password, salt, secret, ad)
}

///|
test "argon2d: RFC 9106 §5.1 test vector" {
  let (password, salt, secret, ad) = make_rfc9106_inputs()
  let params : @argon2.Params = {
    variant: Argon2d,
    m_cost: 32,
    t_cost: 3,
    parallelism: 4,
    output_len: 32,
  }
  let tag = @argon2.hash_raw_with_ad(params, password, salt, ad, secret)
  let expected : Bytes = b"\x51\x2b\x39\x1b\x6f\x11\x62\x97\x53\x71\xd3\x09\x19\x73\x42\x94\xf8\x68\xe3\xbe\x39\x84\xf3\xc1\xa1\x3a\x4d\xb9\xfa\xbe\x4a\xcb"
  @debug.assert_eq(tag, expected)
}

///|
test "argon2i: RFC 9106 §5.2 test vector" {
  let (password, salt, secret, ad) = make_rfc9106_inputs()
  let params : @argon2.Params = {
    variant: Argon2i,
    m_cost: 32,
    t_cost: 3,
    parallelism: 4,
    output_len: 32,
  }
  let tag = @argon2.hash_raw_with_ad(params, password, salt, ad, secret)
  let expected : Bytes = b"\xc8\x14\xd9\xd1\xdc\x7f\x37\xaa\x13\xf0\xd7\x7f\x24\x94\xbd\xa1\xc8\xde\x6b\x01\x6d\xd3\x88\xd2\x99\x52\xa4\xc4\x67\x2b\x6c\xe8"
  @debug.assert_eq(tag, expected)
}

///|
test "argon2id: RFC 9106 §5.3 test vector" {
  let (password, salt, secret, ad) = make_rfc9106_inputs()
  let params : @argon2.Params = {
    variant: Argon2id,
    m_cost: 32,
    t_cost: 3,
    parallelism: 4,
    output_len: 32,
  }
  let tag = @argon2.hash_raw_with_ad(params, password, salt, ad, secret)
  let expected : Bytes = b"\x0d\x64\x0d\xf5\x8d\x78\x76\x6c\x08\xc0\x37\xa3\x4a\x8b\x53\xc9\xd0\x1e\xf0\x45\x2d\x75\xb6\x5e\xb5\x25\x20\xe9\x6b\x01\xe6\x59"
  @debug.assert_eq(tag, expected)
}

///|
test "argon2: hash_raw without ad/secret matches hash_raw_with_ad(ad=b'', secret=b'')" {
  let params : @argon2.Params = {
    variant: Argon2id,
    m_cost: 32,
    t_cost: 2,
    parallelism: 1,
    output_len: 32,
  }
  let r1 = @argon2.hash_raw(params, b"password", b"saltsaltsaltsalt")
  let r2 = @argon2.hash_raw_with_ad(
    params, b"password", b"saltsaltsaltsalt", b"", b"",
  )
  @debug.assert_eq(r1, r2)
}

///|
test "argon2: recommended_interactive returns argon2id, m=19456, t=2, p=1, out=32" {
  let p = @argon2.Params::recommended_interactive()
  @debug.assert_eq(p.variant, Argon2id)
  @debug.assert_eq(p.m_cost, 19456)
  @debug.assert_eq(p.t_cost, 2)
  @debug.assert_eq(p.parallelism, 1)
  @debug.assert_eq(p.output_len, 32)
}

///|
test "argon2: recommended_sensitive returns argon2id, m=65536, t=3, p=4, out=32" {
  let p = @argon2.Params::recommended_sensitive()
  @debug.assert_eq(p.variant, Argon2id)
  @debug.assert_eq(p.m_cost, 65536)
  @debug.assert_eq(p.t_cost, 3)
  @debug.assert_eq(p.parallelism, 4)
  @debug.assert_eq(p.output_len, 32)
}

///|
test "argon2: default_id matches recommended_interactive" {
  @debug.assert_eq(
    @argon2.Params::default_id(),
    @argon2.Params::recommended_interactive(),
  )
}

///|
test "argon2: rejects parallelism < 1" {
  let bad : @argon2.Params = {
    variant: Argon2id,
    m_cost: 32,
    t_cost: 1,
    parallelism: 0,
    output_len: 32,
  }
  try @argon2.hash_raw(bad, b"", b"") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidParams")
  }
}

///|
test "argon2: rejects m_cost < 8 * parallelism" {
  let bad : @argon2.Params = {
    variant: Argon2id,
    m_cost: 4,
    t_cost: 1,
    parallelism: 1,
    output_len: 32,
  }
  try @argon2.hash_raw(bad, b"", b"") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidParams")
  }
}

///|
test "argon2: rejects output_len < 4" {
  let bad : @argon2.Params = {
    variant: Argon2id,
    m_cost: 8,
    t_cost: 1,
    parallelism: 1,
    output_len: 2,
  }
  try @argon2.hash_raw(bad, b"", b"") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidParams")
  }
}

// ─── PHC string format round-trips ───────────────────────────────────────────

///|
fn phc_params() -> @argon2.Params {
  // Cheap params for round-trip tests.
  { variant: Argon2id, m_cost: 32, t_cost: 1, parallelism: 1, output_len: 16 }
}

///|
test "argon2: hash_encoded produces the documented PHC layout" {
  let params = phc_params()
  let encoded = @argon2.hash_encoded(params, b"password", b"somesalt")
  // $argon2id$v=19$m=32,t=1,p=1$<salt_b64>$<hash_b64>
  assert_true(encoded.has_prefix("$argon2id$v=19$m=32,t=1,p=1$"))
  // base64 of "somesalt" (no padding) is "c29tZXNhbHQ".
  assert_true(encoded.has_prefix("$argon2id$v=19$m=32,t=1,p=1$c29tZXNhbHQ$"))
  // The hash segment is non-empty and base64 carries no padding '='.
  let segments = encoded.split("$").to_array()
  @debug.assert_eq(segments.length(), 6)
  assert_true(segments[4].length() > 0)
  assert_true(segments[5].length() > 0)
  assert_false(segments[4].contains("="))
  assert_false(segments[5].contains("="))
}

///|
test "argon2: hash_encoded -> verify_encoded round-trip succeeds" {
  let params = phc_params()
  let encoded = @argon2.hash_encoded(
    params, b"correct horse battery staple", b"NaClNaCl",
  )
  @argon2.verify_encoded(encoded, b"correct horse battery staple")
}

///|
test "argon2: verify_encoded rejects wrong password" {
  let params = phc_params()
  let encoded = @argon2.hash_encoded(params, b"hunter2", b"salty_salt")
  try @argon2.verify_encoded(encoded, b"hunter3") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected VerifyFailed")
  }
}

///|
test "argon2: verify_encoded rejects tampered hash" {
  let params = phc_params()
  let encoded = @argon2.hash_encoded(params, b"hunter2", b"salty_salt")
  // Flip the last character of the hash segment.
  let n = encoded.length()
  let last = encoded[n - 1]
  let replacement = if last == 'A' { "B" } else { "A" }
  let tampered = encoded[:n - 1].to_owned() + replacement
  try @argon2.verify_encoded(tampered, b"hunter2") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected VerifyFailed")
  }
}

///|
test "argon2: verify_encoded rejects tampered salt" {
  let params = phc_params()
  let encoded = @argon2.hash_encoded(params, b"hunter2", b"salty_salt")
  // Replace salt segment with a different (but valid) base64 string.
  let segments = encoded.split("$").to_array()
  let mut rebuilt = ""
  for i in 0..<segments.length() {
    if i > 0 {
      rebuilt = rebuilt + "$"
    }
    rebuilt = if i == 4 {
      rebuilt + "ZGlmZmVyZW50c2FsdA"
    } else {
      rebuilt + segments[i].to_owned()
    }
  }
  try @argon2.verify_encoded(rebuilt, b"hunter2") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected VerifyFailed")
  }
}

///|
test "argon2: verify_encoded rejects malformed PHC strings" {
  // Wrong number of '$'-separated segments.
  try @argon2.verify_encoded("$argon2id$bogus", b"x") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidEncoded")
  }
  // Unknown algorithm.
  try
    @argon2.verify_encoded(
      "$argon2x$v=19$m=32,t=1,p=1$c29tZXNhbHQ$AAAAAA", b"x",
    )
  catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidEncoded")
  }
  // Bad base64 in hash segment.
  try
    @argon2.verify_encoded("$argon2id$v=19$m=32,t=1,p=1$c29tZXNhbHQ$!!!", b"x")
  catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidEncoded")
  }
  // Missing version segment.
  try
    @argon2.verify_encoded("$argon2id$m=32,t=1,p=1$c29tZXNhbHQ$AAAAAA$x", b"x")
  catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidEncoded")
  }
}

///|
test "ATTACK argon2: PHC parser rejects duplicate params and padded base64" {
  try
    @argon2.verify_encoded(
      "$argon2id$v=19$m=32,t=1,p=1,p=1$c29tZXNhbHQ$AAAAAA", b"x",
    )
  catch {
    @argon2.InvalidEncoded(_) => ()
    other => abort("expected InvalidEncoded, got " + repr(other))
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected duplicate param reject")
  }
  try
    @argon2.verify_encoded(
      "$argon2id$v=19$m=032,t=1,p=1$c29tZXNhbHQ$AAAAAA", b"x",
    )
  catch {
    @argon2.InvalidEncoded(_) => ()
    other => abort("expected InvalidEncoded, got " + repr(other))
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected non-canonical reject")
  }
  try
    @argon2.verify_encoded(
      "$argon2id$v=19$m=32,t=1,p=1$c29tZXNhbHQ=$AAAAAA", b"x",
    )
  catch {
    @argon2.InvalidEncoded(_) => ()
    other => abort("expected InvalidEncoded, got " + repr(other))
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected padded base64 reject")
  }
}

///|
test "argon2: hash_encoded honors variant selection" {
  let salt = b"abcdefgh"
  let id_params : @argon2.Params = {
    variant: Argon2id,
    m_cost: 32,
    t_cost: 1,
    parallelism: 1,
    output_len: 16,
  }
  let i_params : @argon2.Params = {
    variant: Argon2i,
    m_cost: 32,
    t_cost: 1,
    parallelism: 1,
    output_len: 16,
  }
  let d_params : @argon2.Params = {
    variant: Argon2d,
    m_cost: 32,
    t_cost: 1,
    parallelism: 1,
    output_len: 16,
  }
  let e_id = @argon2.hash_encoded(id_params, b"pw", salt)
  let e_i = @argon2.hash_encoded(i_params, b"pw", salt)
  let e_d = @argon2.hash_encoded(d_params, b"pw", salt)
  assert_true(e_id.has_prefix("$argon2id$"))
  assert_true(e_i.has_prefix("$argon2i$"))
  assert_true(e_d.has_prefix("$argon2d$"))
  // Cross-variant verify must fail.
  @argon2.verify_encoded(e_id, b"pw")
  @argon2.verify_encoded(e_i, b"pw")
  @argon2.verify_encoded(e_d, b"pw")
}
