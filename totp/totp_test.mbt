// HOTP / TOTP test vectors.
//
// HOTP: RFC 4226 Appendix D — key = "12345678901234567890" (ASCII),
//                              counter = 0..9, digits = 6.
// TOTP: RFC 6238 Appendix B — same ASCII key for SHA-1; longer ASCII
//                              keys for SHA-256 / SHA-512 ("12345678901234567890123456789012"
//                              and "1234567890123456789012345678901234567890123456789012345678901234"),
//                              digits = 8, t0 = 0, step = 30.

///|
fn ascii_to_bytes(s : String) -> Bytes {
  let arr = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    arr[i] = s.code_unit_at(i).to_int().to_byte()
  }
  Bytes::makei(s.length(), fn(i) { arr[i] })
}

///|
fn hex_to_bytes(s : String) -> Bytes {
  let n = s.length() / 2
  let arr = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble_t(s.code_unit_at(i * 2).to_int())
    let lo = hex_nibble_t(s.code_unit_at(i * 2 + 1).to_int())
    arr[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::makei(n, fn(i) { arr[i] })
}

///|
fn hex_nibble_t(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    abort("bad hex digit")
  }
}

// ──────────────────────────────────────────────────────────────────────
// HOTP RFC 4226 Appendix D
// ──────────────────────────────────────────────────────────────────────

///|
test "HOTP RFC 4226 Appendix D — 6-digit, counter 0..9" {
  let key = ascii_to_bytes("12345678901234567890")
  let expected = [
    "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
    "399871", "520489",
  ]
  for i = 0; i < expected.length(); i = i + 1 {
    @debug.assert_eq(@totp.hotp(key, i.to_uint64()), expected[i])
  }
}

// ──────────────────────────────────────────────────────────────────────
// TOTP RFC 6238 Appendix B — 8-digit SHA-1
// ──────────────────────────────────────────────────────────────────────

///|
test "TOTP RFC 6238 Appendix B — SHA-1, 8 digits" {
  let key = ascii_to_bytes("12345678901234567890")
  // (t_seconds, expected 8-digit code)
  let cases : Array[(Int64, String)] = [
    (59L, "94287082"),
    (1111111109L, "07081804"),
    (1111111111L, "14050471"),
    (1234567890L, "89005924"),
    (2000000000L, "69279037"),
    (20000000000L, "65353130"),
  ]
  for c in cases {
    let (t, expected) = c
    @debug.assert_eq(@totp.totp(key, t, digits=8, hash=Sha1), expected)
  }
}

// ──────────────────────────────────────────────────────────────────────
// TOTP RFC 6238 Appendix B — 8-digit SHA-256
// ──────────────────────────────────────────────────────────────────────

///|
test "TOTP RFC 6238 Appendix B — SHA-256, 8 digits" {
  let key = ascii_to_bytes("12345678901234567890123456789012")
  let cases : Array[(Int64, String)] = [
    (59L, "46119246"),
    (1111111109L, "68084774"),
    (1111111111L, "67062674"),
    (1234567890L, "91819424"),
    (2000000000L, "90698825"),
    (20000000000L, "77737706"),
  ]
  for c in cases {
    let (t, expected) = c
    @debug.assert_eq(@totp.totp(key, t, digits=8, hash=Sha256), expected)
  }
}

// ──────────────────────────────────────────────────────────────────────
// TOTP RFC 6238 Appendix B — 8-digit SHA-512
// ──────────────────────────────────────────────────────────────────────

///|
test "TOTP RFC 6238 Appendix B — SHA-512, 8 digits" {
  let key = ascii_to_bytes(
    "1234567890123456789012345678901234567890123456789012345678901234",
  )
  let cases : Array[(Int64, String)] = [
    (59L, "90693936"),
    (1111111109L, "25091201"),
    (1111111111L, "99943326"),
    (1234567890L, "93441116"),
    (2000000000L, "38618901"),
    (20000000000L, "47863826"),
  ]
  for c in cases {
    let (t, expected) = c
    @debug.assert_eq(@totp.totp(key, t, digits=8, hash=Sha512), expected)
  }
}

// ──────────────────────────────────────────────────────────────────────
// 6-digit derivation from 8-digit: a 6-digit code is the last 6 digits
// of the 8-digit code at the same time.
// ──────────────────────────────────────────────────────────────────────

///|
test "TOTP — 6-digit is suffix of 8-digit" {
  let key = ascii_to_bytes("12345678901234567890")
  // SHA-1 t=59: 8-digit = 94287082, expect 6-digit = 287082.
  @debug.assert_eq(@totp.totp(key, 59L, digits=6), "287082")
  // SHA-1 t=1111111109: 8-digit = 07081804, expect 6-digit = 081804.
  @debug.assert_eq(@totp.totp(key, 1111111109L, digits=6), "081804")
}

// ──────────────────────────────────────────────────────────────────────
// verify_totp — skew window
// ──────────────────────────────────────────────────────────────────────

///|
test "verify_totp — exact match" {
  let key = ascii_to_bytes("12345678901234567890")
  // T = 1111111109 / 30 = 37037036.96... but the code at exact 1111111109 is
  // the same as at 1111111111 (same 30-s window). Use 59s to keep it simple.
  let code = @totp.totp(key, 59L, digits=8)
  assert_true(@totp.verify_totp(key, code, 59L, digits=8, skew=0))
}

///|
test "verify_totp — accepts ±1 step within skew" {
  let key = ascii_to_bytes("12345678901234567890")
  // Compute code at t = 30 (counter = 1, step = 30s).
  let code_step1 = @totp.totp(key, 30L, digits=8)
  // Verify at t = 75 (counter = 2). With skew=1 this should pass.
  assert_true(@totp.verify_totp(key, code_step1, 75L, digits=8, skew=1))
  // With skew=0 it should fail.
  assert_false(@totp.verify_totp(key, code_step1, 75L, digits=8, skew=0))
}

///|
test "verify_totp — rejects bogus code" {
  let key = ascii_to_bytes("12345678901234567890")
  assert_false(@totp.verify_totp(key, "00000000", 59L, digits=8, skew=1))
}

///|
test "verify_totp — length mismatch rejected" {
  let key = ascii_to_bytes("12345678901234567890")
  assert_false(@totp.verify_totp(key, "1234", 59L, digits=8, skew=1))
}

///|
test "verify_totp — invalid timing and skew parameters fail closed" {
  let key = ascii_to_bytes("12345678901234567890")
  let code = @totp.totp(key, 59L)
  assert_false(@totp.verify_totp(key, code, 59L, step_seconds=0))
  assert_false(@totp.verify_totp(key, code, 0L, t0=30L))
  assert_false(@totp.verify_totp(key, code, 59L, skew=11))
}

///|
test "ATTACK TOTP — empty secret cannot generate or verify codes" {
  let empty : Bytes = b""
  @debug.assert_eq(@totp.hotp(empty, 0UL), "")
  @debug.assert_eq(@totp.totp(empty, 59L), "")
  assert_false(@totp.verify_totp(empty, "000000", 59L))
}

///|
test "ATTACK TOTP — non-ASCII digit lookalikes are rejected" {
  let key = ascii_to_bytes("12345678901234567890")
  assert_false(@totp.verify_totp(key, "１２３４５６", 59L))
}

///|
test "TOTP — invalid generation parameters return empty code" {
  let key = ascii_to_bytes("12345678901234567890")
  @debug.assert_eq(@totp.hotp(key, 0UL, digits=5), "")
  @debug.assert_eq(@totp.hotp(key, 0UL, digits=9), "")
  @debug.assert_eq(@totp.totp(key, 59L, step_seconds=0), "")
  @debug.assert_eq(@totp.totp(key, 0L, t0=30L), "")
}

// ──────────────────────────────────────────────────────────────────────
// provisioning_uri — sanity-check format
// ──────────────────────────────────────────────────────────────────────
//
// Reference: Google "Key URI Format" wiki examples:
//
//   secret = b"Hello!\xDE\xAD\xBE\xEF" -> base32 = "JBSWY3DPEHPK3PXP" (no padding)
//
// We construct the URI for a known label/issuer and compare bytewise.

///|
test "base32 encode — Hello!<DE><AD><BE><EF>" {
  // We can't reach the private helper directly from blackbox tests, but
  // provisioning_uri embeds it, so we observe via the full URI.
  let secret = hex_to_bytes("48656c6c6f21deadbeef")
  let uri = @totp.provisioning_uri(
    "Example:alice@example.com",
    secret,
    issuer="Example",
  )
  // Expected base32 of "Hello!<DE><AD><BE><EF>" is "JBSWY3DPEHPK3PXP".
  assert_true(uri.contains("secret=JBSWY3DPEHPK3PXP"))
}

///|
test "provisioning_uri — full URI for a known secret" {
  // Synthetic-but-deterministic sanity check.
  let secret = ascii_to_bytes("12345678901234567890")
  let uri = @totp.provisioning_uri(
    "alice@example.com",
    secret,
    issuer="ACME Co",
    digits=6,
    step_seconds=30,
    hash=Sha1,
  )
  // label percent-encoding: '@' -> %40
  assert_true(uri.has_prefix("otpauth://totp/alice%40example.com?"))
  // base32 of ASCII "12345678901234567890" = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
  assert_true(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))
  // issuer percent-encoding: space -> %20
  assert_true(uri.contains("issuer=ACME%20Co"))
  assert_true(uri.contains("digits=6"))
  assert_true(uri.contains("period=30"))
  assert_true(uri.contains("algorithm=SHA1"))
}

///|
test "provisioning_uri — no issuer omits issuer param" {
  let secret = ascii_to_bytes("12345678901234567890")
  let uri = @totp.provisioning_uri("bob", secret)
  assert_false(uri.contains("issuer="))
  assert_true(uri.contains("algorithm=SHA1"))
}

///|
test "provisioning_uri — sha512 emits SHA512 algorithm" {
  let secret = ascii_to_bytes("12345678901234567890")
  let uri = @totp.provisioning_uri("u", secret, hash=Sha512)
  assert_true(uri.contains("algorithm=SHA512"))
}
