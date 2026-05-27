// Reference tests copied from IETF JWT-related RFC examples.
//
// These tests intentionally keep the RFC values visible instead of reducing
// them to only generated roundtrips. They are conformance sentinels for
// wire-level examples and profile-required claim semantics.

///|
fn ref_bytes_from_octets(octets : Array[Int]) -> Bytes {
  Bytes::makei(octets.length(), fn(i) { octets[i].to_byte() })
}

///|
fn ref_b64u_encode(b : Bytes) -> String {
  let s = @base64.encode(b[:], padding=false)
  let buf = StringBuilder::new()
  for c in s {
    let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
    buf.write_char(c2)
  }
  buf.to_string()
}

///|
fn ref_b64u_to_bytes(s : String) -> Bytes {
  let buf = StringBuilder::new()
  let mut n = 0
  for c in s {
    let c2 = if c == '-' { '+' } else if c == '_' { '/' } else { c }
    buf.write_char(c2)
    n = n + 1
  }
  let pad = (4 - n % 4) % 4
  for _ in 0..<pad {
    buf.write_char('=')
  }
  @base64.decode(buf.to_string()) catch {
    _ => abort("bad base64url reference value")
  }
}

///|
fn ref_sign_hs256_raw(
  header_json : String,
  payload_json : String,
  secret : Bytes,
) -> String {
  let header_b64 = ref_b64u_encode(@utf8.encode(header_json[:]))
  let payload_b64 = ref_b64u_encode(@utf8.encode(payload_json[:]))
  let signing_input = header_b64 + "." + payload_b64
  let sig = @hash.hmac_sha256(secret, @utf8.encode(signing_input[:]))
  signing_input + "." + ref_b64u_encode(sig)
}

///|
fn ref_sign_es256_raw(
  header_json : String,
  payload_json : String,
  sk : @p256.PrivateKey,
) -> String {
  let header_b64 = ref_b64u_encode(@utf8.encode(header_json[:]))
  let payload_b64 = ref_b64u_encode(@utf8.encode(payload_json[:]))
  let signing_input = header_b64 + "." + payload_b64
  let sig = sk.sign(@utf8.encode(signing_input[:]))
  signing_input + "." + ref_b64u_encode(sig)
}

///|
fn ref_verify_options(now : Int64) -> @jwt.VerifyOptions {
  {
    now,
    clock_skew_sec: 0L,
    require_exp: true,
    issuer: None,
    audience: None,
    typ_allowed: None,
  }
}

///|
test "reference RFC 7519 section 3.1 example JWT octets verify" {
  let header_octets = [
    123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108,
    103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125,
  ]
  let payload_octets = [
    123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101,
    120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34,
    104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111,
    109, 47, 105, 115, 95, 114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
  ]
  let header_b64 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
  let payload_b64 = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
  @debug.assert_eq(
    ref_b64u_encode(ref_bytes_from_octets(header_octets)),
    header_b64,
  )
  @debug.assert_eq(
    ref_b64u_encode(ref_bytes_from_octets(payload_octets)),
    payload_b64,
  )

  let secret = ref_b64u_to_bytes(
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
  )
  let token = header_b64 +
    "." +
    payload_b64 +
    ".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let opts : @jwt.VerifyOptions = {
    ..ref_verify_options(1300819300L),
    issuer: Some("joe"),
    typ_allowed: Some(["JWT"]),
  }
  let v = @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::HS256)
  match v.claims.get("http://example.com/is_root") {
    Some(True) => ()
    _ => abort("missing RFC 7519 private claim")
  }
}

///|
test "reference RFC 7519 section 6.1 unsecured JWT is rejected" {
  let token = "eyJhbGciOiJub25lIn0." +
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
  let header = @jwt.peek_header(token)
  match header.get("alg") {
    Some(String(s)) => @debug.assert_eq(s, "none")
    _ => abort("missing RFC 7519 alg=none header")
  }
  try
    @jwt.verify(
      token,
      @jwt.VerifyKey::Hs256(secret=b"unused"),
      ref_verify_options(0L),
    )
  catch {
    UnsupportedAlgorithm(_) => ()
    other => abort("expected UnsupportedAlgorithm, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted RFC 7519 unsecured JWT")
  }
}

///|
test "reference RFC 7523 section 4 JWT bearer assertion claims verify" {
  let scalar = ref_b64u_to_bytes("ya-p2EW6dRZrXCFXZrHWk05Qw9s26JsSe4piKxIPZyE")
  let sk = @p256.PrivateKey::from_bytes(scalar)
  let header = "{\"alg\":\"ES256\",\"kid\":\"16\"}"
  let payload = "{\"iss\":\"https://jwt-idp.example.com\",\"sub\":\"mailto:mike@example.com\",\"aud\":\"https://jwt-rp.example.net\",\"nbf\":1300815780,\"exp\":1300819380,\"http://claims.example.com/member\":true}"
  let token = ref_sign_es256_raw(header, payload, sk)
  let opts : @jwt.VerifyOptions = {
    ..ref_verify_options(1300816000L),
    issuer: Some("https://jwt-idp.example.com"),
    audience: Some("https://jwt-rp.example.net"),
  }
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Es256(pubkey=sk.public_key()),
    opts,
  )
  @debug.assert_eq(v.kid, Some("16"))
  match v.claims.get("sub") {
    Some(String(s)) => @debug.assert_eq(s, "mailto:mike@example.com")
    _ => abort("missing RFC 7523 sub")
  }
  match v.claims.get("http://claims.example.com/member") {
    Some(True) => ()
    _ => abort("missing RFC 7523 member claim")
  }
}

///|
test "reference RFC 9068 figure 2 access token claims verify" {
  let secret : Bytes = b"rfc9068-figure-2-local-signing-key"
  let header = "{\"typ\":\"at+JWT\",\"alg\":\"HS256\",\"kid\":\"RjEwOwOA\"}"
  let payload = "{\"iss\":\"https://authorization-server.example.com/\",\"sub\":\"5ba552d67\",\"aud\":\"https://rs.example.com/\",\"exp\":1639528912,\"iat\":1618354090,\"jti\":\"dbe39bf3a3ba4238a513f51d6e1691c4\",\"client_id\":\"s6BhdRkqt3\",\"scope\":\"openid profile reademail\"}"
  let token = ref_sign_hs256_raw(header, payload, secret)
  let opts : @jwt.Rfc9068VerifyOptions = {
    now: 1630000000L,
    clock_skew_sec: 0L,
    issuer: "https://authorization-server.example.com/",
    audience: "https://rs.example.com/",
    expected_client_id: Some("s6BhdRkqt3"),
    required_scopes: Some(["profile", "reademail"]),
    allowed_algorithms: Some([@jwt.Algorithm::HS256]),
  }
  let t = @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts)
  @debug.assert_eq(t.sub, "5ba552d67")
  @debug.assert_eq(t.jti, "dbe39bf3a3ba4238a513f51d6e1691c4")
  @debug.assert_eq(t.scope, Some(["openid", "profile", "reademail"]))
  @debug.assert_eq(t.jwt.kid, Some("RjEwOwOA"))
}
