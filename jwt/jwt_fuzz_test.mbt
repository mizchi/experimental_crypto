// Structured fuzz tests for JWT / JWKS trust-boundary handling. Pure random
// compact tokens exercise parser robustness; grammar-aware cases cover the
// security-sensitive `kid` selection rules.

///|
let fuzz_hs_secret : Bytes = b"jwt-fuzz-secret"

///|
fn fuzz_b64u_encode(b : Bytes) -> String {
  let s = @base64.encode(b[:], padding=false)
  let buf = StringBuilder::new()
  for c in s {
    let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
    buf.write_char(c2)
  }
  buf.to_string()
}

///|
fn fuzz_sign_hs256_with_header(
  header : Json,
  payload : Json,
  secret : Bytes,
) -> String {
  let header_b64 = fuzz_b64u_encode(@utf8.encode(header.stringify()[:]))
  let payload_b64 = fuzz_b64u_encode(@utf8.encode(payload.stringify()[:]))
  let signing_input = header_b64 + "." + payload_b64
  let sig = @hash.hmac_sha256(secret, @utf8.encode(signing_input[:]))
  signing_input + "." + fuzz_b64u_encode(sig)
}

///|
fn fuzz_safe_kid(raw : Bytes) -> String {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
  let len = if raw.length() == 0 { 1 } else { raw.length() % 32 + 1 }
  let buf = StringBuilder::new()
  for i = 0; i < len; i = i + 1 {
    let b = if raw.length() == 0 { i } else { raw[i % raw.length()].to_int() }
    let idx = b & 63
    buf.write_char(alphabet.get_char(idx).unwrap())
  }
  buf.to_string()
}

///|
fn fuzz_bad_kid(raw : Bytes) -> String {
  if raw.length() % 4 == 0 {
    ""
  } else if raw.length() % 4 == 1 {
    "bad kid"
  } else if raw.length() % 4 == 2 {
    "bad\nkid"
  } else {
    let buf = StringBuilder::new()
    for _i = 0; _i < 257; _i = _i + 1 {
      buf.write_char('A')
    }
    buf.to_string()
  }
}

///|
fn fuzz_jwks_two_same_kid(kid : String) -> String {
  "{ \"keys\": [ " +
  "{ \"kty\": \"oct\", \"kid\": \"" +
  kid +
  "\", \"alg\": \"HS256\", \"k\": \"YXR0YWNrZXItc2VjcmV0\" }, " +
  "{ \"kty\": \"oct\", \"kid\": \"" +
  kid +
  "\", \"alg\": \"HS256\", \"k\": \"bGVnaXQtc2VjcmV0\" } " +
  "] }"
}

///|
fn fuzz_hs256_header(kid : String) -> Map[String, Json] {
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["typ"] = Json::string("JWT")
  header["kid"] = Json::string(kid)
  header
}

///|
test "fuzz jwt: verify and peek_header never panic on random compact strings" {
  for input in (@quickcheck.samples(200) : Array[String]) {
    let _ = try? @jwt.peek_header(input)
    let _ = try? @jwt.verify(
      input,
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      @jwt.VerifyOptions::default(0L),
    )
  }
}

///|
test "fuzz jwt kid: sign accepts only safe generated kids" {
  for raw in (@quickcheck.samples(80) : Array[Bytes]) {
    let safe = fuzz_safe_kid(raw)
    let token = @jwt.sign(
      Json::object(Map([])),
      @jwt.Key::Hs256(secret=fuzz_hs_secret),
      kid=safe,
    )
    let verified = @jwt.verify(
      token,
      @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
      @jwt.VerifyOptions::default(0L),
    )
    @debug.assert_eq(verified.kid, Some(safe))

    let bad = fuzz_bad_kid(raw)
    let rejected = try {
      let _ = @jwt.sign(
        Json::object(Map([])),
        @jwt.Key::Hs256(secret=fuzz_hs_secret),
        kid=bad,
      )
      false
    } catch {
      InvalidHeader(_) => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "fuzz jwt kid: signed control-data kids reject at verify boundary" {
  for raw in (@quickcheck.samples(80) : Array[Bytes]) {
    let bad = fuzz_bad_kid(raw)
    let token = fuzz_sign_hs256_with_header(
      Json::object(fuzz_hs256_header(bad)),
      Json::object(Map([])),
      fuzz_hs_secret,
    )
    let rejected = try {
      let _ = @jwt.verify(
        token,
        @jwt.VerifyKey::Hs256(secret=fuzz_hs_secret),
        @jwt.VerifyOptions::default(0L),
      )
      false
    } catch {
      InvalidHeader(_) => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "fuzz jwks kid: duplicate kid never selects a first matching key" {
  for raw in (@quickcheck.samples(80) : Array[Bytes]) {
    let kid = fuzz_safe_kid(raw)
    let set = @jwk.parse_set(fuzz_jwks_two_same_kid(kid))
    let header = fuzz_hs256_header(kid)
    let rejected = try {
      let _ = @jwt.select_verify_key(set, header)
      false
    } catch {
      NoMatchingKey => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "fuzz jwks kid: malformed header kid rejects before key selection" {
  let jwks =
    #|{ "keys": [ { "kty": "oct", "kid": "safe", "alg": "HS256", "k": "c2VjcmV0" } ] }
  let set = @jwk.parse_set(jwks)
  for raw in (@quickcheck.samples(80) : Array[Bytes]) {
    let header = fuzz_hs256_header(fuzz_bad_kid(raw))
    let rejected = try {
      let _ = @jwt.select_verify_key(set, header)
      false
    } catch {
      InvalidHeader(_) => true
      _ => false
    }
    assert_true(rejected)
  }
}
