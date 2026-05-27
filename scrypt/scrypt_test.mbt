// RFC 7914 §11 scrypt test vectors.

///|
test "scrypt: RFC 7914 §11 vector 1 (P='', S='', N=16, r=1, p=1, dkLen=64)" {
  let params : @scrypt.Params = { log_n: 4, r: 1, p: 1, dk_len: 64 }
  let dk = @scrypt.derive_key(params, b"", b"")
  let expected : Bytes = b"\x77\xd6\x57\x62\x38\x65\x7b\x20\x3b\x19\xca\x42\xc1\x8a\x04\x97\xf1\x6b\x48\x44\xe3\x07\x4a\xe8\xdf\xdf\xfa\x3f\xed\xe2\x14\x42\xfc\xd0\x06\x9d\xed\x09\x48\xf8\x32\x6a\x75\x3a\x0f\xc8\x1f\x17\xe8\xd3\xe0\xfb\x2e\x0d\x36\x28\xcf\x35\xe2\x0c\x38\xd1\x89\x06"
  @debug.assert_eq(dk, expected)
}

///|
test "scrypt: RFC 7914 §11 vector 2 (P='password', S='NaCl', N=1024, r=8, p=16, dkLen=64)" {
  let params : @scrypt.Params = { log_n: 10, r: 8, p: 16, dk_len: 64 }
  let dk = @scrypt.derive_key(params, b"password", b"NaCl")
  let expected : Bytes = b"\xfd\xba\xbe\x1c\x9d\x34\x72\x00\x78\x56\xe7\x19\x0d\x01\xe9\xfe\x7c\x6a\xd7\xcb\xc8\x23\x78\x30\xe7\x73\x76\x63\x4b\x37\x31\x62\x2e\xaf\x30\xd9\x2e\x22\xa3\x88\x6f\xf1\x09\x27\x9d\x98\x30\xda\xc7\x27\xaf\xb9\x4a\x83\xee\x6d\x83\x60\xcb\xdf\xa2\xcc\x06\x40"
  @debug.assert_eq(dk, expected)
}

///|
test "scrypt: rejects invalid log_n" {
  let bad : @scrypt.Params = { log_n: 0, r: 8, p: 1, dk_len: 32 }
  try @scrypt.derive_key(bad, b"", b"") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidParams")
  }
}

///|
test "scrypt: rejects r < 1" {
  let bad : @scrypt.Params = { log_n: 4, r: 0, p: 1, dk_len: 32 }
  try @scrypt.derive_key(bad, b"", b"") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidParams")
  }
}

///|
test "scrypt: rejects dk_len < 1" {
  let bad : @scrypt.Params = { log_n: 4, r: 1, p: 1, dk_len: 0 }
  try @scrypt.derive_key(bad, b"", b"") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidParams")
  }
}

///|
test "scrypt: recommended_interactive returns log_n=15, r=8, p=1, dk_len=32" {
  let p = @scrypt.Params::recommended_interactive()
  @debug.assert_eq(p.log_n, 15)
  @debug.assert_eq(p.r, 8)
  @debug.assert_eq(p.p, 1)
  @debug.assert_eq(p.dk_len, 32)
}

///|
test "scrypt: small dkLen truncates" {
  // Same N=16, r=1, p=1 as vector 1 but dkLen=16 → matches the first 16 bytes
  // of expected.
  let params : @scrypt.Params = { log_n: 4, r: 1, p: 1, dk_len: 16 }
  let dk = @scrypt.derive_key(params, b"", b"")
  let expected : Bytes = b"\x77\xd6\x57\x62\x38\x65\x7b\x20\x3b\x19\xca\x42\xc1\x8a\x04\x97"
  @debug.assert_eq(dk, expected)
}

// ─── PHC string format round-trips ───────────────────────────────────────────

///|
fn phc_params() -> @scrypt.Params {
  // Cheap params for round-trip tests.
  { log_n: 4, r: 1, p: 1, dk_len: 16 }
}

///|
test "scrypt: hash_encoded produces the documented PHC layout" {
  let params = phc_params()
  let encoded = @scrypt.hash_encoded(params, b"password", b"saltysalt")
  // $scrypt$ln=4,r=1,p=1$<salt_b64>$<hash_b64>
  assert_true(encoded.has_prefix("$scrypt$ln=4,r=1,p=1$"))
  // base64 of "saltysalt" (no padding) is "c2FsdHlzYWx0".
  assert_true(encoded.has_prefix("$scrypt$ln=4,r=1,p=1$c2FsdHlzYWx0$"))
  let segments = encoded.split("$").to_array()
  @debug.assert_eq(segments.length(), 5)
  assert_true(segments[3].length() > 0)
  assert_true(segments[4].length() > 0)
  // No padding '=' inside the base64 segments.
  assert_false(segments[3].contains("="))
  assert_false(segments[4].contains("="))
}

///|
test "scrypt: hash_encoded -> verify_encoded round-trip succeeds" {
  let params = phc_params()
  let encoded = @scrypt.hash_encoded(
    params, b"correct horse battery staple", b"NaClNaCl",
  )
  @scrypt.verify_encoded(encoded, b"correct horse battery staple")
}

///|
test "scrypt: verify_encoded rejects wrong password" {
  let params = phc_params()
  let encoded = @scrypt.hash_encoded(params, b"hunter2", b"salty_salt")
  try @scrypt.verify_encoded(encoded, b"hunter3") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected VerifyFailed")
  }
}

///|
test "scrypt: verify_encoded rejects tampered hash" {
  let params = phc_params()
  let encoded = @scrypt.hash_encoded(params, b"hunter2", b"salty_salt")
  let n = encoded.length()
  let last = encoded[n - 1]
  let replacement = if last == 'A' { "B" } else { "A" }
  let tampered = encoded[:n - 1].to_owned() + replacement
  try @scrypt.verify_encoded(tampered, b"hunter2") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected VerifyFailed")
  }
}

///|
test "scrypt: verify_encoded rejects tampered salt" {
  let params = phc_params()
  let encoded = @scrypt.hash_encoded(params, b"hunter2", b"salty_salt")
  let segments = encoded.split("$").to_array()
  let mut rebuilt = ""
  for i in 0..<segments.length() {
    if i > 0 {
      rebuilt = rebuilt + "$"
    }
    rebuilt = if i == 3 {
      rebuilt + "ZGlmZmVyZW50c2FsdA"
    } else {
      rebuilt + segments[i].to_owned()
    }
  }
  try @scrypt.verify_encoded(rebuilt, b"hunter2") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected VerifyFailed")
  }
}

///|
test "scrypt: verify_encoded rejects malformed PHC strings" {
  // Wrong number of '$'-separated segments.
  try @scrypt.verify_encoded("$scrypt$bogus", b"x") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidEncoded")
  }
  // Unknown algorithm.
  try @scrypt.verify_encoded("$argon2id$ln=4,r=1,p=1$c2FsdA$AAAA", b"x") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidEncoded")
  }
  // Bad base64 in hash segment.
  try @scrypt.verify_encoded("$scrypt$ln=4,r=1,p=1$c2FsdA$!!!", b"x") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidEncoded")
  }
  // Missing 'p' parameter.
  try @scrypt.verify_encoded("$scrypt$ln=4,r=1$c2FsdA$AAAA", b"x") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidEncoded")
  }
  // Non-integer parameter.
  try @scrypt.verify_encoded("$scrypt$ln=4,r=abc,p=1$c2FsdA$AAAA", b"x") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidEncoded")
  }
}

///|
test "ATTACK scrypt: PHC parser rejects duplicate params and padded base64" {
  try
    @scrypt.verify_encoded("$scrypt$ln=4,r=1,p=1,p=1$c2FsdA$AAAAAA", b"x")
  catch {
    @scrypt.InvalidEncoded(_) => ()
    other => abort("expected InvalidEncoded, got " + repr(other))
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected duplicate param reject")
  }
  try
    @scrypt.verify_encoded("$scrypt$ln=04,r=1,p=1$c2FsdA$AAAAAA", b"x")
  catch {
    @scrypt.InvalidEncoded(_) => ()
    other => abort("expected InvalidEncoded, got " + repr(other))
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected non-canonical reject")
  }
  try
    @scrypt.verify_encoded("$scrypt$ln=4,r=1,p=1$c2FsdA=$AAAAAA", b"x")
  catch {
    @scrypt.InvalidEncoded(_) => ()
    other => abort("expected InvalidEncoded, got " + repr(other))
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected padded base64 reject")
  }
}
