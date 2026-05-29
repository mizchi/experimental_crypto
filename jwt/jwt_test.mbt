// Blackbox tests for mizchi/jwt.
//
// Cover RFC 7515 §A.1 (HS256) and RFC 8037 §A.4 (EdDSA) test vectors plus
// sign+verify roundtrip and the standard negative paths (tamper, expiry,
// audience/issuer, algorithm mismatch).

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

///|
fn hex_nibble(c : Int) -> Int {
  if c >= '0'.to_int() && c <= '9'.to_int() {
    c - '0'.to_int()
  } else if c >= 'a'.to_int() && c <= 'f'.to_int() {
    c - 'a'.to_int() + 10
  } else if c >= 'A'.to_int() && c <= 'F'.to_int() {
    c - 'A'.to_int() + 10
  } else {
    -1
  }
}

///|
fn hex_to_bytes(s : String) -> Bytes {
  let n = s.length() / 2
  let arr = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble(s.code_unit_at(i * 2).to_int())
    let lo = hex_nibble(s.code_unit_at(i * 2 + 1).to_int())
    arr[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::makei(n, fn(j) { arr[j] })
}

///|
// Decode a base64url string (no padding) into Bytes. Used to lift RFC
// test-vector strings into byte arrays without going through @jwt's
// internal helpers (those are private).
fn b64u_to_bytes(s : String) -> Bytes {
  // Map - -> + and _ -> /, then pad with '=' to a multiple of 4 and call
  // the standard base64 decoder.
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
    _ => abort("bad b64u in test")
  }
}

///|
fn b64u_encode(b : Bytes) -> String {
  let s = @base64.encode(b[:], padding=false)
  let buf = StringBuilder::new()
  for c in s {
    let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
    buf.write_char(c2)
  }
  buf.to_string()
}

///|
fn sign_hs256_token_with_header(
  header : Json,
  payload : Json,
  secret : Bytes,
) -> String {
  let header_b64 = b64u_encode(@utf8.encode(header.stringify()[:]))
  let payload_b64 = b64u_encode(@utf8.encode(payload.stringify()[:]))
  let signing_input = header_b64 + "." + payload_b64
  let sig = @hash.hmac_sha256(secret, @utf8.encode(signing_input[:]))
  signing_input + "." + b64u_encode(sig)
}

///|
fn sign_hs256_token_with_raw_json(
  header_json : String,
  payload_json : String,
  secret : Bytes,
) -> String {
  let header_b64 = b64u_encode(@utf8.encode(header_json[:]))
  let payload_b64 = b64u_encode(@utf8.encode(payload_json[:]))
  let signing_input = header_b64 + "." + payload_b64
  let sig = @hash.hmac_sha256(secret, @utf8.encode(signing_input[:]))
  signing_input + "." + b64u_encode(sig)
}

///|
fn sign_hs256_token_with_payload_bytes(
  header_json : String,
  payload : Bytes,
  secret : Bytes,
) -> String {
  let header_b64 = b64u_encode(@utf8.encode(header_json[:]))
  let payload_b64 = b64u_encode(payload)
  let signing_input = header_b64 + "." + payload_b64
  let sig = @hash.hmac_sha256(secret, @utf8.encode(signing_input[:]))
  signing_input + "." + b64u_encode(sig)
}

///|
fn sign_ps256_token_with_salt(
  header : Json,
  payload : Json,
  sk : @rsa.RsaPrivateKey,
  salt : Bytes,
) -> String {
  let header_b64 = b64u_encode(@utf8.encode(header.stringify()[:]))
  let payload_b64 = b64u_encode(@utf8.encode(payload.stringify()[:]))
  let signing_input = header_b64 + "." + payload_b64
  let sig = sk.sign_pss(
    @utf8.encode(signing_input[:]),
    @rsa.HashAlg::Sha256,
    salt,
  ) catch {
    _ => abort("PS256 fixture signing failed")
  }
  signing_input + "." + b64u_encode(sig)
}

///|
fn sign_ed25519_token_with_raw_json(
  header_json : String,
  payload_json : String,
  sk : @ed25519.PrivateKey,
) -> String {
  let header_b64 = b64u_encode(@utf8.encode(header_json[:]))
  let payload_b64 = b64u_encode(@utf8.encode(payload_json[:]))
  let signing_input = header_b64 + "." + payload_b64
  let sig = sk.sign(@utf8.encode(signing_input[:]))
  signing_input + "." + b64u_encode(sig)
}

// -----------------------------------------------------------------------------
// HS256: RFC 7515 §A.1 verify
// -----------------------------------------------------------------------------

///|
test "HS256: RFC 7515 §A.1 token verifies and decodes claims" {
  // Secret from RFC 7515 §A.1.1 (the 64-byte HMAC key, base64url encoded).
  let secret = b64u_to_bytes(
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
  )
  let token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  // exp = 1300819380 — that's already long past, so disable exp by setting
  // `now` well before it and skip the require_exp gate.
  let opts : @jwt.VerifyOptions = {
    now: 1300819300L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: None,
    typ_allowed: None,
  }
  let v = @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::HS256)
  // iss claim
  match v.claims.get("iss") {
    Some(String(s)) => @debug.assert_eq(s, "joe")
    _ => abort("missing iss")
  }
}

///|
test "HS256: tampered payload fails signature check" {
  let secret = b64u_to_bytes(
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
  )
  // Replace one character in the payload segment.
  let bad = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2VzIiwNCiAiZXhwIjoxMzAwODE5MzgwLA0KICJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(bad, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    InvalidSignature => ()
    e => abort("expected InvalidSignature, got " + repr(e) + "")
  } noraise {
    _ => abort("expected InvalidSignature, got Ok")
  }
}

///|
test "ATTACK jwt: non-canonical signature base64url is rejected" {
  // RFC 7515 A.1 token, but the final signature character is changed from
  // canonical "k" to "l". A lenient decoder produces the same signature
  // bytes because only pad bits changed; the verifier must reject the
  // alternate spelling before returning authenticated claims.
  let secret = b64u_to_bytes(
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
  )
  let token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl"
  let opts : @jwt.VerifyOptions = {
    now: 1300819300L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: None,
    typ_allowed: None,
  }
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    @jwt.InvalidToken(_) => ()
    e => abort("expected InvalidToken, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted non-canonical signature base64url")
  }
}

// -----------------------------------------------------------------------------
// HS256: sign + verify roundtrip
// -----------------------------------------------------------------------------

///|
test "HS256: sign + verify roundtrip preserves claims" {
  let secret : Bytes = b"my-very-secret-hmac-key"
  let claims_map : Map[String, Json] = Map([])
  claims_map["sub"] = Json::string("alice")
  claims_map["iat"] = Json::number(1_700_000_000.0)
  let payload = Json::object(claims_map)
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), kid="key-1")
  let opts = @jwt.VerifyOptions::default(1_700_000_100L)
  let v = @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::HS256)
  @debug.assert_eq(v.kid, Some("key-1"))
  match v.claims.get("sub") {
    Some(String(s)) => @debug.assert_eq(s, "alice")
    _ => abort("missing sub")
  }
}

///|
test "HS256: wrong secret fails verification" {
  let secret : Bytes = b"my-very-secret-hmac-key"
  let other_secret : Bytes = b"another-secret-hmac-key"
  let m : Map[String, Json] = Map([])
  m["sub"] = Json::string("bob")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts = @jwt.VerifyOptions::default(0L)
  try
    @jwt.verify(token, @jwt.VerifyKey::Hs256(secret=other_secret), opts)
  catch {
    InvalidSignature => ()
    e => abort("expected InvalidSignature, got " + repr(e) + "")
  } noraise {
    _ => abort("expected InvalidSignature")
  }
}

// -----------------------------------------------------------------------------
// EdDSA: RFC 8037 §A.4 verify
// -----------------------------------------------------------------------------

///|
test "EdDSA: RFC 8037 §A.4 raw JWS payload is rejected by JWT verify" {
  // Public key: x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
  let pk_bytes = b64u_to_bytes("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
  let pk = @ed25519.PublicKey::from_bytes(pk_bytes)
  // Token from RFC 8037 §A.4 (payload is the literal text
  // "Example of Ed25519 signing", not JSON).
  let token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::EdDsa(pubkey=pk), opts) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected ClaimsParseError for raw JWS payload")
  }
}

///|
test "EdDSA: corresponding private key signs the RFC 8037 payload" {
  // Round-trip with the same seed: signing the RFC payload should reproduce
  // a token that verifies under the published public key. Because our sign
  // path always emits the "typ":"JWT" header field (RFC 7515 §4.1.9 allows
  // this), the resulting token differs from RFC 8037's literal bytes — we
  // verify the relationship between sign and verify, not byte equality.
  let seed = b64u_to_bytes("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let m : Map[String, Json] = Map([])
  m["sub"] = Json::string("rfc8037-test")
  let token = @jwt.sign(Json::object(m), @jwt.Key::EdDsa(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(token, @jwt.VerifyKey::EdDsa(pubkey=pk), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::EdDSA)
  match v.claims.get("sub") {
    Some(String(s)) => @debug.assert_eq(s, "rfc8037-test")
    _ => abort("missing sub")
  }
}

///|
test "EdDSA: tampered signature fails verification" {
  let pk_bytes = b64u_to_bytes("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
  let pk = @ed25519.PublicKey::from_bytes(pk_bytes)
  // Last char of the signature flipped.
  let bad = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg__"
  let opts = @jwt.VerifyOptions::default(0L)
  // Note: the suffix change may also be caught as InvalidToken (base64 garbled)
  // — either is acceptable as long as we do not accept the token.
  try @jwt.verify(bad, @jwt.VerifyKey::EdDsa(pubkey=pk), opts) catch {
    InvalidSignature | InvalidToken(_) => ()
    e => abort("unexpected error: " + @debug.to_string(e))
  } noraise {
    _ => abort("expected verification failure")
  }
}

// -----------------------------------------------------------------------------
// Claim validation
// -----------------------------------------------------------------------------

///|
test "exp: expired token raises Expired" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map([])
  m["exp"] = Json::number(1_000.0)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts = @jwt.VerifyOptions::default(2_000L)
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    Expired => ()
    other => abort("expected Expired, got " + repr(other) + "")
  } noraise {
    other => abort("expected Expired, got " + repr(other) + "")
  }
}

///|
test "exp: clock_skew_sec absorbs small differences" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map([])
  m["exp"] = Json::number(1_000.0)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  // now = 1010, exp = 1000, skew = 60 -> allowed (exp + skew = 1060 >= now)
  let opts : @jwt.VerifyOptions = {
    now: 1_010L,
    clock_skew_sec: 60L,
    require_exp: false,
    issuer: None,
    audience: None,
    typ_allowed: None,
  }
  let v = @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::HS256)
}

///|
test "nbf: not yet valid raises NotYetValid" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map([])
  m["nbf"] = Json::number(5_000.0)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts = @jwt.VerifyOptions::default(1_000L)
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    NotYetValid => ()
    other => abort("expected NotYetValid, got " + repr(other) + "")
  } noraise {
    other => abort("expected NotYetValid, got " + repr(other) + "")
  }
}

///|
test "ATTACK NumericDate claims with non-number values are rejected" {
  let secret : Bytes = b"numeric-date-shape"
  for claim in ["exp", "nbf", "iat"] {
    let m : Map[String, Json] = Map([])
    m[claim] = Json::string("9999999999")
    let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
    let opts = @jwt.VerifyOptions::default(0L)
    try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
      ClaimsParseError(_) => ()
      other =>
        abort(
          "expected ClaimsParseError for non-numeric " +
          claim +
          ", got " +
          repr(other),
        )
    } noraise {
      _ => abort("accepted non-numeric NumericDate claim " + claim)
    }
  }
}

///|
test "ATTACK registered string claims with non-string values are rejected" {
  let secret : Bytes = b"registered-string-shape"
  for claim in ["iss", "sub", "jti"] {
    let m : Map[String, Json] = Map([])
    m[claim] = Json::number(42.0)
    let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
    let opts = @jwt.VerifyOptions::default(0L)
    try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
      ClaimsParseError(_) => ()
      other =>
        abort(
          "expected ClaimsParseError for non-string " +
          claim +
          ", got " +
          repr(other),
        )
    } noraise {
      _ => abort("accepted non-string registered claim " + claim)
    }
  }
}

///|
test "iss: wrong issuer raises InvalidIssuer" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("a")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: Some("b"),
    audience: None,
    typ_allowed: None,
  }
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    InvalidIssuer => ()
    other => abort("expected InvalidIssuer, got " + repr(other) + "")
  } noraise {
    other => abort("expected InvalidIssuer, got " + repr(other) + "")
  }
}

///|
test "aud: string and array forms both match" {
  let secret : Bytes = b"k"
  // string form
  let m1 : Map[String, Json] = Map([])
  m1["aud"] = Json::string("svc1")
  let t1 = @jwt.sign(Json::object(m1), @jwt.Key::Hs256(secret~))
  let opts1 : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: Some("svc1"),
    typ_allowed: None,
  }
  let _ = @jwt.verify(t1, @jwt.VerifyKey::Hs256(secret~), opts1)
  // array form
  let arr : Array[Json] = [Json::string("other"), Json::string("svc2")]
  let m2 : Map[String, Json] = Map([])
  m2["aud"] = Json::array(arr)
  let t2 = @jwt.sign(Json::object(m2), @jwt.Key::Hs256(secret~))
  let opts2 : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: Some("svc2"),
    typ_allowed: None,
  }
  let _ = @jwt.verify(t2, @jwt.VerifyKey::Hs256(secret~), opts2)
  // mismatch
  let opts3 : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: Some("nope"),
    typ_allowed: None,
  }
  try @jwt.verify(t2, @jwt.VerifyKey::Hs256(secret~), opts3) catch {
    InvalidAudience => ()
    other => abort("expected InvalidAudience, got " + repr(other) + "")
  } noraise {
    other => abort("expected InvalidAudience, got " + repr(other) + "")
  }
}

///|
test "ATTACK aud: malformed array does not match by ignoring bad entries" {
  let secret : Bytes = b"aud-shape"
  let arr : Array[Json] = [Json::string("svc"), Json::number(42.0)]
  let m : Map[String, Json] = Map([])
  m["aud"] = Json::array(arr)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: Some("svc"),
    typ_allowed: None,
  }
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    ClaimsParseError(_) => ()
    InvalidAudience => ()
    other => abort("expected aud-shape rejection, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted malformed aud array after finding matching string")
  }
}

///|
test "ATTACK aud: malformed audience is rejected even without expected audience" {
  let secret : Bytes = b"aud-generic-shape"
  let opts = @jwt.VerifyOptions::default(0L)
  let cases : Array[Json] = [
    Json::number(42.0),
    Json::array([Json::string("svc"), Json::number(42.0)]),
  ]
  for aud in cases {
    let m : Map[String, Json] = Map([])
    m["aud"] = aud
    let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
    try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
      ClaimsParseError(_) => ()
      other => abort("expected ClaimsParseError, got " + repr(other))
    } noraise {
      _ => abort("accepted malformed aud without expected audience")
    }
  }
}

// -----------------------------------------------------------------------------
// Structural / algorithm errors
// -----------------------------------------------------------------------------

///|
test "InvalidToken: wrong segment count" {
  let secret : Bytes = b"k"
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify("only.two", @jwt.VerifyKey::Hs256(secret~), opts) catch {
    InvalidToken(_) => ()
    other => abort("expected InvalidToken, got " + repr(other) + "")
  } noraise {
    other => abort("expected InvalidToken, got " + repr(other) + "")
  }
}

///|
test "UnsupportedAlgorithm: header alg=RS256 is rejected even with matching key shape" {
  // Hand-craft a header with alg=RS256 and a dummy HS-shaped key. We expect
  // either KeyAlgorithmMismatch (the verifier notices the key isn't an RSA
  // key — but we don't have an RSA VerifyKey variant) or UnsupportedAlgorithm.
  // In practice the alg check happens before signature verify and we ship
  // no RSA VerifyKey, so the failure is KeyAlgorithmMismatch.
  let header_b64 = "eyJhbGciOiJSUzI1NiJ9" // {"alg":"RS256"}
  let payload_b64 = "e30" // {}
  let sig_b64 = "AAAA" // bogus
  let token = header_b64 + "." + payload_b64 + "." + sig_b64
  let secret : Bytes = b"k"
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    KeyAlgorithmMismatch | UnsupportedAlgorithm(_) => ()
    other => abort("expected alg failure, got " + @debug.to_string(other))
  } noraise {
    other => abort("expected alg failure, got " + @debug.to_string(other))
  }
}

///|
test "KeyAlgorithmMismatch: HS256 token with EdDSA verify key" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map([])
  m["sub"] = Json::string("x")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  // Use an arbitrary Ed25519 public key — the alg-vs-key check should fire
  // long before we touch the signature.
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let pk = @ed25519.PrivateKey::from_seed(seed).public_key()
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::EdDsa(pubkey=pk), opts) catch {
    KeyAlgorithmMismatch => ()
    other => abort("expected KeyAlgorithmMismatch, got " + repr(other) + "")
  } noraise {
    other => abort("expected KeyAlgorithmMismatch, got " + repr(other) + "")
  }
}

///|
test "ATTACK jwt: duplicate JOSE header members are rejected" {
  let secret : Bytes = b"duplicate-json-secret"
  let token = sign_hs256_token_with_raw_json(
    "{\"alg\":\"HS256\",\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"sub\":\"alice\"}",
    secret,
  )
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    InvalidHeader(_) => ()
    other => abort("expected InvalidHeader, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted JWT with duplicate JOSE header member")
  }
}

///|
test "ATTACK jwt: duplicate claims members are rejected" {
  let secret : Bytes = b"duplicate-claims-secret"
  let token = sign_hs256_token_with_raw_json(
    "{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"iss\":\"trusted\",\"iss\":\"trusted\"}",
    secret,
  )
  let opts : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: Some("trusted"),
    audience: None,
    typ_allowed: None,
  }
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    ClaimsParseError(_) => ()
    other => abort("expected ClaimsParseError, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted JWT with duplicate claims member")
  }
}

///|
test "ATTACK jwt: malformed UTF-8 JOSE header is rejected" {
  let secret : Bytes = b"bad-header-utf8-secret"
  let token = b64u_encode(b"\xff") +
    "." +
    b64u_encode(b"{}") +
    "." +
    b64u_encode(b"sig")
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    InvalidHeader(_) => ()
    other => abort("expected InvalidHeader, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted JWT with malformed UTF-8 header")
  }
}

///|
test "ATTACK jwt: signed malformed UTF-8 payload is rejected after signature" {
  let secret : Bytes = b"bad-payload-utf8-secret"
  let token = sign_hs256_token_with_payload_bytes(
    "{\"alg\":\"HS256\",\"typ\":\"JWT\"}", b"\xff", secret,
  )
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    ClaimsParseError(_) => ()
    other => abort("expected ClaimsParseError, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted JWT with signed malformed UTF-8 payload")
  }
}

// -----------------------------------------------------------------------------
// RS256: RFC 7515 §A.2.1 verify
// -----------------------------------------------------------------------------

///|
// PKCS#1 RSAPublicKey DER built mechanically from the RFC 7515 §A.2.1 JWK
// (n, e) so that we can hand the byte stream straight to
// `@rsa.RsaPublicKey::from_pkcs1_der`. See rsa/rsa_test.mbt for the same
// blob expressed as raw n / e (and the SPKI variant).
let rfc7515_a2_pkcs1_der : Bytes = hex_to_bytes(
  "3082010a0282010100a1f8160ae2e3c9b465ce8d2d656263362b927dbe29e1f02477fc1625cc90a136e38bd93497c5b6ea63dd7711e67c7429f956b0fb8a8f089adc4b69893cc1333f53edd019b87784252fec914fe4857769594bea4280d32c0f55bf62944f130396bc6e9bdf6ebdd2bda3678eeca0c668f701b38dbffb38c8342ce2fe6d27fade4a5a4874979dd4b9cf9adec4c75b05852c2c0f5ef8a5c1750392f944e8ed64c110c6b647609aa4783aeb9c6c9ad755313050638b83665c6f6f7a82a396702a1f641b82d3ebf2392219491fb686872c5716f50af8358d9a8b9d17c340728f7f87d89a18d8fcab67ad84590c2ecf759339363c07034d6f606f9e21e05456cae5e9a10203010001",
)

///|
// The RFC 7515 §A.2.1 JWS token (header.payload.signature).
let rfc7515_a2_token : String = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

///|
test "RS256: RFC 7515 §A.2.1 token verifies and decodes claims" {
  let pk = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_a2_pkcs1_der)
  // exp claim is 1300819380 (long past) — set `now` before it so the time
  // check does not fire; we want to assert the signature path here.
  let opts : @jwt.VerifyOptions = {
    now: 1300819300L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: None,
    typ_allowed: None,
  }
  let v = @jwt.verify(rfc7515_a2_token, @jwt.VerifyKey::Rs256(pubkey=pk), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::RS256)
  match v.claims.get("iss") {
    Some(String(s)) => @debug.assert_eq(s, "joe")
    _ => abort("missing iss")
  }
}

///|
test "RS256: tampered payload fails signature check" {
  let pk = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_a2_pkcs1_der)
  // Replace the payload segment with a different base64url-valid payload
  // that decodes to a different JSON document. The signature was bound to
  // the original signing input, so the RSA verify must reject it.
  // Original payload: "eyJpc3M..." (= {"iss":"joe",...})
  // Replacement   :   base64url("{\"iss\":\"jon\"}") = "eyJpc3MiOiJqb24ifQ"
  let parts = rfc7515_a2_token.split(".").to_array()
  let bad_token = parts[0].to_owned() +
    "." +
    "eyJpc3MiOiJqb24ifQ" +
    "." +
    parts[2].to_owned()
  let opts = @jwt.VerifyOptions::default(1300819300L)
  try @jwt.verify(bad_token, @jwt.VerifyKey::Rs256(pubkey=pk), opts) catch {
    InvalidSignature => ()
    e => abort("expected InvalidSignature, got " + repr(e) + "")
  } noraise {
    _ => abort("expected InvalidSignature, got Ok")
  }
}

///|
test "RS256: KeyAlgorithmMismatch when alg=HS256 but key is Rs256" {
  // Sign an HS256 token, then try to verify with an Rs256 key.
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map([])
  m["sub"] = Json::string("x")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let pk = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_a2_pkcs1_der)
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::Rs256(pubkey=pk), opts) catch {
    KeyAlgorithmMismatch => ()
    other => abort("expected KeyAlgorithmMismatch, got " + repr(other) + "")
  } noraise {
    other => abort("expected KeyAlgorithmMismatch, got " + repr(other) + "")
  }
}

// -----------------------------------------------------------------------------
// ES256: RFC 7515 §A.3 verify
// -----------------------------------------------------------------------------

///|
fn rfc7515_a3_pubkey() -> @p256.PublicKey raise {
  // From RFC 7515 §A.3.1: P-256 JWK with x / y base64url-encoded. We embed
  // them as hex to keep the test self-contained.
  let x = hex_to_bytes(
    "7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445",
  )
  let y = hex_to_bytes(
    "c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad",
  )
  let bytes = Bytes::makei(65, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i < 33 {
      x[i - 1]
    } else {
      y[i - 33]
    }
  })
  @p256.PublicKey::from_uncompressed(bytes)
}

///|
test "ES256: RFC 7515 §A.3 token verifies" {
  let token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
  let pk = rfc7515_a3_pubkey()
  let opts : @jwt.VerifyOptions = {
    now: 1300819300L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: None,
    typ_allowed: None,
  }
  let v = @jwt.verify(token, @jwt.VerifyKey::Es256(pubkey=pk), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::ES256)
  match v.claims.get("iss") {
    Some(String(s)) => @debug.assert_eq(s, "joe")
    _ => abort("missing iss")
  }
}

///|
test "ES256: tampered signature fails" {
  // Flip one base64url char in the signature segment.
  let bad = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.AtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
  let pk = rfc7515_a3_pubkey()
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(bad, @jwt.VerifyKey::Es256(pubkey=pk), opts) catch {
    InvalidSignature => ()
    other => abort("expected InvalidSignature, got " + repr(other) + "")
  } noraise {
    other => abort("expected InvalidSignature, got " + repr(other) + "")
  }
}

///|
test "ES256: KeyAlgorithmMismatch when alg=HS256 but key is Es256" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map([])
  m["sub"] = Json::string("x")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let pk = rfc7515_a3_pubkey()
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::Es256(pubkey=pk), opts) catch {
    KeyAlgorithmMismatch => ()
    other => abort("expected KeyAlgorithmMismatch, got " + repr(other) + "")
  } noraise {
    other => abort("expected KeyAlgorithmMismatch, got " + repr(other) + "")
  }
}

// -----------------------------------------------------------------------------
// ES384: end-to-end (token + key generated via openssl secp384r1 + SHA-384)
// -----------------------------------------------------------------------------

///|
fn es384_pubkey() -> @p384.PublicKey raise {
  // Same SPKI as p384's openssl-generated key.
  let spki = hex_to_bytes(
    "3076301006072a8648ce3d020106052b8104002203620004fa918c3751c0b9adcd761351c9852ff7635ee3b696150bca4655a37583b5fc3f7c2e3aeb55eb4bc5d94e04e6ccc577f7cfab8c58bc51062ab204523d6e065fe54352340f069d5a395ededcbf1a363178b035a281dd2ee60369317f985a654b05",
  )
  @p384.PublicKey::from_spki_der(spki)
}

///|
test "ES384: token signed by openssl verifies" {
  // Generated with openssl secp384r1 + SHA-384 against signing input
  // `<header>.<payload>` from a JWT with `{"alg":"ES384","typ":"JWT"}` and
  // payload `{"sub":"mizchi","iss":"test"}`.
  let token = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtaXpjaGkiLCJpc3MiOiJ0ZXN0In0.IVF1bDvZX38ltujtQQIWXhPwZDUlHOx6FtRDDA4v1Q1ZS69tUr_BbH3sY3x8pxvp1x_ESP-nEzknjsz5vM6i51HOk1T3z0V_U_pnrCmbpIo--miUMdJIIHrUWofOCb9J"
  let pk = es384_pubkey()
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(token, @jwt.VerifyKey::Es384(pubkey=pk), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::ES384)
  match v.claims.get("sub") {
    Some(String(s)) => @debug.assert_eq(s, "mizchi")
    _ => abort("missing sub")
  }
}

///|
test "ES384: tampered signature fails" {
  // Flip the first char of the signature segment.
  let bad = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtaXpjaGkiLCJpc3MiOiJ0ZXN0In0.JVF1bDvZX38ltujtQQIWXhPwZDUlHOx6FtRDDA4v1Q1ZS69tUr_BbH3sY3x8pxvp1x_ESP-nEzknjsz5vM6i51HOk1T3z0V_U_pnrCmbpIo--miUMdJIIHrUWofOCb9J"
  let pk = es384_pubkey()
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(bad, @jwt.VerifyKey::Es384(pubkey=pk), opts) catch {
    InvalidSignature => ()
    other => abort("expected InvalidSignature, got " + repr(other) + "")
  } noraise {
    other => abort("expected InvalidSignature, got " + repr(other) + "")
  }
}

// -----------------------------------------------------------------------------
// ES512: end-to-end (token + key generated via openssl secp521r1 + SHA-512)
// -----------------------------------------------------------------------------

///|
fn es512_pubkey() -> @p521.PublicKey raise {
  let spki = hex_to_bytes(
    "30819b301006072a8648ce3d020106052b81040023038186000400ec6fb8a65ce4fd6a23921b5ae8735a42df399ff0ac1aeaf2e7d8c858872f10e60bda513e80075ee18d74cb02fd8dc1c7db746987efb7ca255fff7956874cc71ebb00badd91cffc9a1671cf15a9fb0c7c1728af82b858eed68b3a688e15a7c8208c1a231e511f9f095a7fa9ee0de2b521d6c51fab93786412436b7786a2051ae5ffab4b",
  )
  @p521.PublicKey::from_spki_der(spki)
}

///|
test "ES512: token signed by openssl verifies" {
  let token = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtaXpjaGkiLCJpc3MiOiJ0ZXN0In0.AeZDRUodvxfBoQLCzSs77adh1RMWZIxeF9t54DULpsa61Pj7XnEmD-f4rZfuiY-K-FNM6ttx498SlfwwXMt8rHUmAaZWrazReu5_bL6wcg_wOtjXxLDEZaHJDzXVlndKMEip30qUo5xe8rrjgZX0vy_JYBXIfjwDLhiLVFNFhQwFzUrN"
  let pk = es512_pubkey()
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(token, @jwt.VerifyKey::Es512(pubkey=pk), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::ES512)
  match v.claims.get("sub") {
    Some(String(s)) => @debug.assert_eq(s, "mizchi")
    _ => abort("missing sub")
  }
}

///|
test "ES512: tampered signature fails" {
  let bad = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtaXpjaGkiLCJpc3MiOiJ0ZXN0In0.BeZDRUodvxfBoQLCzSs77adh1RMWZIxeF9t54DULpsa61Pj7XnEmD-f4rZfuiY-K-FNM6ttx498SlfwwXMt8rHUmAaZWrazReu5_bL6wcg_wOtjXxLDEZaHJDzXVlndKMEip30qUo5xe8rrjgZX0vy_JYBXIfjwDLhiLVFNFhQwFzUrN"
  let pk = es512_pubkey()
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(bad, @jwt.VerifyKey::Es512(pubkey=pk), opts) catch {
    InvalidSignature => ()
    other => abort("expected InvalidSignature, got " + repr(other) + "")
  } noraise {
    other => abort("expected InvalidSignature, got " + repr(other) + "")
  }
}

// -----------------------------------------------------------------------------
// Security attack tests — these are exploits from well-known JWT CVEs.
// Each test asserts the implementation REJECTS the attack. A passing test
// means the attack was successfully blocked.
// -----------------------------------------------------------------------------

///|
test "ATTACK CVE-2015-9235: alg=none token must be rejected" {
  // Header: {"alg":"none","typ":"JWT"} payload: {"sub":"admin"}
  // Empty signature, classic alg=none bypass.
  let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."
  let opts = @jwt.VerifyOptions::default(0L)
  let secret : Bytes = b"any"
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    UnsupportedAlgorithm(s) => @debug.assert_eq(s, "none")
    KeyAlgorithmMismatch => () // also acceptable
    InvalidToken(_) => () // rejected at token shape
    other => abort("alg=none NOT rejected: " + repr(other) + "")
  } noraise {
    other => abort("alg=none NOT rejected: " + repr(other) + "")
  }
}

///|
test "ATTACK alg=None (titlecase variant) must be rejected" {
  // Same idea with mixed-case "None" — must not match.
  let token = "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."
  let opts = @jwt.VerifyOptions::default(0L)
  let secret : Bytes = b"any"
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    UnsupportedAlgorithm(_) => ()
    KeyAlgorithmMismatch => ()
    InvalidToken(_) => ()
    other => abort("alg=None NOT rejected: " + repr(other) + "")
  } noraise {
    other => abort("alg=None NOT rejected: " + repr(other) + "")
  }
}

///|
test "ATTACK generic verify: JSON scalar payload is not a JWT claims object" {
  let secret : Bytes = b"json-scalar-payload"
  let token = @jwt.sign(
    Json::string("not-a-claims-object"),
    @jwt.Key::Hs256(secret~),
  )
  try
    @jwt.verify(
      token,
      @jwt.VerifyKey::Hs256(secret~),
      @jwt.VerifyOptions::default(0L),
    )
  catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected ClaimsParseError for scalar JWT payload")
  }
}

///|
test "ATTACK CVE-2016-10555: alg confusion (HS256 token vs Rs256 key)" {
  // Take an RSA token-shaped header (HS256) and try to verify with an Rs256
  // key. Library must refuse to verify because the alg in the header does
  // not match the static key type — otherwise an attacker who controls the
  // alg field can choose HS256 and use the RSA public key bytes as the HMAC
  // secret.
  let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.AAAA"
  let pk = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_a2_pkcs1_der)
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::Rs256(pubkey=pk), opts) catch {
    KeyAlgorithmMismatch => ()
    other =>
      abort("alg confusion HS256↔Rs256 NOT blocked: " + repr(other) + "")
  } noraise {
    other =>
      abort("alg confusion HS256↔Rs256 NOT blocked: " + repr(other) + "")
  }
}

// -----------------------------------------------------------------------------
// JWT sign + verify roundtrip with the new private-key variants
// -----------------------------------------------------------------------------

///|
// Minimal RSA-2048 private key (PKCS#1 DER) for JWT RS256 sign tests.
let rs256_priv_pkcs1_der : Bytes = hex_to_bytes(
  "308204a30201000282010100a48f36ef8cfe5dd94faba96b3abf276fde0e82f9ad0b9963955c933413bf300a4dda0287" +
  "48590762459ddb2a4c2b9ce04e4f2d8f37ea0a1379cc9076ea17a97bad91178d7983c9e15a7f30db77268d3be00d85b9" +
  "60db3396d24ac0bf229bbb242c72b2b4d4ae15abc51d72b372b0132e75cf92265cb5e97747e617a69a78384d99dd5136" +
  "7575953c16e32cc45c3fbb28fdbd0064228043e39721e3bf5ee496d3fb9ced6fd4d7a0daf98fb016cfe8da87484765f9" +
  "c35115f12e095585aba390cb27eb03900045575854e0100d19f32fac1981f6c286567c6387791e642a7941096c92e89e" +
  "cc5cf3c934a363c5ca63f633940ce37965bcfe8b86d7ef432f799c2702030100010282010029ab461ae495e887c57fcf" +
  "57a2b992afe607c0ac9e5fe88869e2d63782a48ff29c020f4fd8470af29c743b71fb75b3b4acbfa9e6b11ee74c453442" +
  "848a0451db4a790a00bdfb5c1c5f4103cb1ee1b933a729656a2a9776f9c2e840e4654c0fd83a1515216b1565d168096b" +
  "e8faaa9140db7e2320e9aafaa244a783e7a107be21a856466f50e3d697cc685e221164d83918b8cfd6f3653c9e7748cf" +
  "ade136ed267ebab8433f9a981fd6af49c4edc149aa281fead06947fe52381009a9e6d49d63f8eb1ff94f15170929f3eb" +
  "0d66a3ec72b0fb1f14d54792a9a5c48cb6310d60771a26344f00dcabc959bb5acc9583cd74a744aa3c079c1b7ed1c746" +
  "7aaa115ee102818100d05869008488dbe1b9afa5c851af7f44ca1fd11f2c31ab19b014c194b32a553338c29fba82a384" +
  "0b0735e8b30cba04ef54c0cc74752d2075f93907ba6ba0654f29872cf6fbe82808e6db11fcce997331417600d6298085" +
  "94085d00b21ed3608e65c2d04d212494aad6edd1383c63154d758fd3145ee3e9df1724b47da56d1a1702818100ca32ef" +
  "5ff51a550e7b5f6434f4d04a3d22a18aa89cd4d628c2b3dca129805f02360da47b5dce7cf14932f19bb4a5e368a06462" +
  "912aa755f05913b89f4af5053fb3ecf2fdac49f636a7be5aecdd62f9aaa8b0d61976b31214b534f9d15d5648d1207e34" +
  "78080f96fa1f2112058d22332916cd2266e15c2036aed2bdd9a19ea8710281803277a7ffb31affc03edd7857fcc97917" +
  "adaa655a9ab6f14e48a3ce7c79a5e07b86dd4619c4b95d2bdab44948cde5657a9fda0fec89d1c392302b8b5eb1e16988" +
  "f273470610e11c89837a3f72308d6524e249764c6a433298382a6717be75cf66cee990d18e1cb1526cbbb0b9618f52c2" +
  "af9e862fe2086d4757f0d133ba55a2430281810088174c421ba8438361ca4c99d004b952f8921dcf6aef5dcd456ee59a" +
  "9b624990256d7d3d835fcd7c613626a4142c6b292a7b26546a8f022aa8e9bb238bc1ea6c7bdf8994ef77407e7cdc843a" +
  "54af9f371c1f199b3de73cce2f409ebc29c43f72721a3f9a62628bcd815232dd05a6f5243cb288eb11d77ddf103fcb84" +
  "456192210281803ef388d592aa5e24b930ab2d434f20a41742cee683fca57a59e2bf57fd090e45158c10952e37392381" +
  "312f139a39c3ad9c947b52e21a18bce16e6b8c0ecfec7556e277b8d34734ca3e7b9a1d95408cd976eba53406eb95905b" +
  "a101317dc5c5fd5b21783244e1b8a8bdd5a3e2e4339fb43248e8cc61307ccd278280b058ad9be1",
)

///|
test "JWT RS256 sign + verify roundtrip" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let claims = Map([])
  claims["sub"] = Json::string("rs256-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Rs256(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Rs256(pubkey=sk.public_key()),
    opts,
  )
  @debug.assert_eq(v.alg, @jwt.Algorithm::RS256)
  match v.claims.get("sub") {
    Some(String(s)) => @debug.assert_eq(s, "rs256-roundtrip")
    _ => abort("missing sub")
  }
}

///|
test "JWT RS384 sign + verify roundtrip" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let claims = Map([])
  claims["sub"] = Json::string("rs384-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Rs384(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Rs384(pubkey=sk.public_key()),
    opts,
  )
  @debug.assert_eq(v.alg, @jwt.Algorithm::RS384)
  match v.claims.get("sub") {
    Some(String(s)) => @debug.assert_eq(s, "rs384-roundtrip")
    _ => abort("missing sub")
  }
}

///|
test "JWT RS512 sign + verify roundtrip" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let claims = Map([])
  claims["sub"] = Json::string("rs512-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Rs512(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Rs512(pubkey=sk.public_key()),
    opts,
  )
  @debug.assert_eq(v.alg, @jwt.Algorithm::RS512)
  match v.claims.get("sub") {
    Some(String(s)) => @debug.assert_eq(s, "rs512-roundtrip")
    _ => abort("missing sub")
  }
}

///|
test "JWT PS256 sign + verify roundtrip (RFC 7518 sLen=hLen)" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let salt = Bytes::makei(32, fn(i) { (i + 11).to_byte() })
  let claims = Map([])
  claims["sub"] = Json::string("ps256-roundtrip")
  let token = @jwt.sign(
    Json::object(claims),
    @jwt.Key::Ps256(privkey=sk, salt~),
  )
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Ps256(pubkey=sk.public_key()),
    opts,
  )
  @debug.assert_eq(v.alg, @jwt.Algorithm::PS256)
  match v.claims.get("sub") {
    Some(String(s)) => @debug.assert_eq(s, "ps256-roundtrip")
    _ => abort("missing sub")
  }
}

///|
test "JWT PS256 sign rejects non-JWA salt length" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let claims = Map([])
  claims["sub"] = Json::string("ps256-bad-salt")
  try
    @jwt.sign(Json::object(claims), @jwt.Key::Ps256(privkey=sk, salt=b""))
  catch {
    UnsupportedAlgorithm(_) => ()
    other => abort("expected UnsupportedAlgorithm, got " + repr(other) + "")
  } noraise {
    _ => abort("PS256 accepted non-JWA salt length")
  }
}

///|
test "ATTACK JWT PS256: deterministic sLen=0 token is rejected" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("PS256")
  header["typ"] = Json::string("JWT")
  let claims : Map[String, Json] = Map([])
  claims["sub"] = Json::string("ps256-empty-salt")
  let token = sign_ps256_token_with_salt(
    Json::object(header),
    Json::object(claims),
    sk,
    b"",
  )
  try
    @jwt.verify(
      token,
      @jwt.VerifyKey::Ps256(pubkey=sk.public_key()),
      @jwt.VerifyOptions::default(0L),
    )
  catch {
    InvalidSignature => ()
    other => abort("expected InvalidSignature, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted PS256 token with sLen=0")
  }
}

///|
test "JWT PS384 sign + verify roundtrip" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let salt = Bytes::makei(48, fn(i) { (i + 23).to_byte() })
  let claims = Map([])
  claims["sub"] = Json::string("ps384-roundtrip")
  let token = @jwt.sign(
    Json::object(claims),
    @jwt.Key::Ps384(privkey=sk, salt~),
  )
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Ps384(pubkey=sk.public_key()),
    opts,
  )
  @debug.assert_eq(v.alg, @jwt.Algorithm::PS384)
}

///|
test "JWT PS512 sign + verify roundtrip" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let salt = Bytes::makei(64, fn(i) { (i + 37).to_byte() })
  let claims = Map([])
  claims["sub"] = Json::string("ps512-roundtrip")
  let token = @jwt.sign(
    Json::object(claims),
    @jwt.Key::Ps512(privkey=sk, salt~),
  )
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Ps512(pubkey=sk.public_key()),
    opts,
  )
  @debug.assert_eq(v.alg, @jwt.Algorithm::PS512)
}

///|
test "JWT PS256: KeyAlgorithmMismatch when alg=HS256 but key is Ps256" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map([])
  m["sub"] = Json::string("x")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let pk = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_a2_pkcs1_der)
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::Ps256(pubkey=pk), opts) catch {
    KeyAlgorithmMismatch => ()
    other => abort("expected KeyAlgorithmMismatch, got " + repr(other) + "")
  } noraise {
    other => abort("expected KeyAlgorithmMismatch, got " + repr(other) + "")
  }
}

///|
test "JWT PS256: tampered payload fails signature check" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let salt = Bytes::makei(32, fn(i) { (i + 41).to_byte() })
  let claims = Map([])
  claims["sub"] = Json::string("original")
  let token = @jwt.sign(
    Json::object(claims),
    @jwt.Key::Ps256(privkey=sk, salt~),
  )
  // Swap the payload segment for a different valid base64url.
  let parts = token.split(".").to_array()
  let bad_token = parts[0].to_owned() +
    "." +
    "eyJzdWIiOiJ0YW1wZXJlZCJ9" + // base64url({"sub":"tampered"})
    "." +
    parts[2].to_owned()
  let opts = @jwt.VerifyOptions::default(0L)
  try
    @jwt.verify(bad_token, @jwt.VerifyKey::Ps256(pubkey=sk.public_key()), opts)
  catch {
    InvalidSignature => ()
    other => abort("expected InvalidSignature, got " + repr(other) + "")
  } noraise {
    other => abort("expected InvalidSignature, got " + repr(other) + "")
  }
}

///|
test "JWT ES256 sign + verify roundtrip" {
  let scalar = hex_to_bytes(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let sk = @p256.PrivateKey::from_bytes(scalar)
  let claims = Map([])
  claims["sub"] = Json::string("es256-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Es256(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Es256(pubkey=sk.public_key()),
    opts,
  )
  @debug.assert_eq(v.alg, @jwt.Algorithm::ES256)
}

///|
test "JWT ES384 sign + verify roundtrip" {
  let scalar = hex_to_bytes(
    "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
  )
  let sk = @p384.PrivateKey::from_bytes(scalar)
  let claims = Map([])
  claims["sub"] = Json::string("es384-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Es384(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Es384(pubkey=sk.public_key()),
    opts,
  )
  @debug.assert_eq(v.alg, @jwt.Algorithm::ES384)
}

///|
test "JWT ES512 sign + verify roundtrip" {
  let scalar = hex_to_bytes(
    "01026f3296840cb512d4ddf291aefb09399d7ba6a87ed08d058afb300a5bf0b983e5162efe6bc0e042073a29f8307a13ee9ecda8d1a8b7538845a504da0d6d4b92a2",
  )
  let sk = @p521.PrivateKey::from_bytes(scalar)
  let claims = Map([])
  claims["sub"] = Json::string("es512-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Es512(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Es512(pubkey=sk.public_key()),
    opts,
  )
  @debug.assert_eq(v.alg, @jwt.Algorithm::ES512)
}

// -----------------------------------------------------------------------------
// Header-level RFC compliance attacks
// -----------------------------------------------------------------------------

///|
test "ATTACK RFC 7515 §4.1.11: token with `crit` header must be rejected" {
  // {"alg":"HS256","typ":"JWT","crit":["enc"]}.{"sub":"x"}.AAAA
  let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImNyaXQiOlsiZW5jIl19.eyJzdWIiOiJ4In0.AAAA"
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret=b"k"), opts) catch {
    InvalidHeader(_) => ()
    other => abort("crit header NOT rejected: " + repr(other) + "")
  } noraise {
    other => abort("crit header NOT rejected: " + repr(other) + "")
  }
}

///|
test "ATTACK RFC 7797: token with `b64=false` must be rejected" {
  // {"alg":"HS256","b64":false}.payload.AAAA
  let token = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2V9.cGF5bG9hZA.AAAA"
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret=b"k"), opts) catch {
    InvalidHeader(_) => ()
    other => abort("b64=false header NOT rejected: " + repr(other) + "")
  } noraise {
    other => abort("b64=false header NOT rejected: " + repr(other) + "")
  }
}

// -----------------------------------------------------------------------------
// HS384 / HS512 / RS384 / RS512 — new algorithms (Step 2)
// -----------------------------------------------------------------------------

///|
test "HS384: sign + verify roundtrip" {
  let secret : Bytes = b"hs384-secret"
  let claims : Map[String, Json] = Map([])
  claims["sub"] = Json::string("alice")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Hs384(secret~))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(token, @jwt.VerifyKey::Hs384(secret~), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::HS384)
}

///|
test "HS512: sign + verify roundtrip" {
  let secret : Bytes = b"hs512-secret-which-is-fairly-long-to-match-output-size"
  let claims : Map[String, Json] = Map([])
  claims["sub"] = Json::string("bob")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Hs512(secret~))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(token, @jwt.VerifyKey::Hs512(secret~), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::HS512)
}

///|
test "HS384: wrong secret fails verification" {
  let secret : Bytes = b"hs384-secret-correct"
  let other : Bytes = b"hs384-secret-attacker"
  let claims : Map[String, Json] = Map([])
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Hs384(secret~))
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(token, @jwt.VerifyKey::Hs384(secret=other), opts) catch {
    InvalidSignature => ()
    e => abort("expected InvalidSignature, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidSignature, got Ok")
  }
}

// -----------------------------------------------------------------------------
// typ allow-list (Step 1)
// -----------------------------------------------------------------------------

///|
test "typ: allow-list None accepts any typ" {
  let secret : Bytes = b"any-secret"
  let token = @jwt.sign(Json::object(Map([])), @jwt.Key::Hs256(secret~))
  let opts = @jwt.VerifyOptions::default(0L)
  // No typ_allowed → accept whatever sign emitted (`JWT`).
  let _ = @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)
}

///|
test "typ: allow-list matches header typ JWT" {
  let secret : Bytes = b"any-secret"
  let token = @jwt.sign(Json::object(Map([])), @jwt.Key::Hs256(secret~))
  let opts : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: None,
    typ_allowed: Some(["JWT"]),
  }
  let _ = @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)
}

///|
test "typ: typ='JWT' rejected when allow-list expects only 'at+jwt'" {
  let secret : Bytes = b"any-secret"
  let token = @jwt.sign(Json::object(Map([])), @jwt.Key::Hs256(secret~))
  let opts : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: None,
    typ_allowed: Some(["at+jwt"]),
  }
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType, got Ok")
  }
}

// -----------------------------------------------------------------------------
// iat future check (Step 4)
// -----------------------------------------------------------------------------

///|
test "iat: claim in the future raises IssuedInFuture" {
  let secret : Bytes = b"iat-future"
  let claims : Map[String, Json] = Map([])
  claims["iat"] = Json::number(2_000_000_000.0)
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Hs256(secret~))
  // now is well before iat; clock skew is 0.
  let opts = @jwt.VerifyOptions::default(1_000_000_000L)
  try @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    IssuedInFuture => ()
    e => abort("expected IssuedInFuture, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected IssuedInFuture, got Ok")
  }
}

///|
test "iat: claim slightly in the future is absorbed by clock_skew_sec" {
  let secret : Bytes = b"iat-skew"
  let claims : Map[String, Json] = Map([])
  claims["iat"] = Json::number(1_000_000_030.0)
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Hs256(secret~))
  let opts : @jwt.VerifyOptions = {
    now: 1_000_000_000L,
    clock_skew_sec: 60L,
    require_exp: false,
    issuer: None,
    audience: None,
    typ_allowed: None,
  }
  let _ = @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)
}

// -----------------------------------------------------------------------------
// JWKS resolution helper (Step 3)
// -----------------------------------------------------------------------------

///|
fn rsa_public_jwks_doc(alg : String, kid : String) -> String raise {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let pub_jwk = @jwk.serialise_public(
    @jwk.Jwk::Rsa(pubkey=sk.public_key(), privkey=None),
  )
  let parsed = @json.parse(pub_jwk[:]) catch {
    _ => abort("generated RSA JWK is not JSON")
  }
  let jwk_map = match parsed {
    Object(m) => m
    _ => abort("generated RSA JWK is not an object")
  }
  jwk_map["alg"] = Json::string(alg)
  jwk_map["kid"] = Json::string(kid)
  "{ \"keys\": [ " + Json::object(jwk_map).stringify() + " ] }"
}

///|
fn select_rsa_jwks_verify_key(alg : String) -> @jwt.VerifyKey raise {
  let set = @jwk.parse_set(rsa_public_jwks_doc(alg, "rsa-kid"))
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string(alg)
  header["kid"] = Json::string("rsa-kid")
  @jwt.select_verify_key(set, header)
}

///|
test "select_verify_key: single-key set with no kid" {
  // Round-trip an HMAC JWK through @jwk's serialise → @jwk.parse_set so we
  // exercise the public API rather than a hand-constructed entry.
  let jwk_doc =
    #|{ "keys": [ { "kty": "oct", "k": "c2VjcmV0", "alg": "HS256" } ] }
  let set = @jwk.parse_set(jwk_doc)
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  let vk = @jwt.select_verify_key(set, header)
  match vk {
    Hs256(secret~) => @debug.assert_eq(secret, b"secret")
    _ => abort("expected Hs256 VerifyKey")
  }
}

///|
test "select_verify_key: kid match picks the right entry" {
  let jwk_doc =
    #|{ "keys": [
    #|  { "kty": "oct", "k": "AAA", "kid": "k1", "alg": "HS256" },
    #|  { "kty": "oct", "k": "AQE", "kid": "k2", "alg": "HS256" }
    #|] }
  let set = @jwk.parse_set(jwk_doc)
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["kid"] = Json::string("k2")
  let vk = @jwt.select_verify_key(set, header)
  match vk {
    Hs256(secret~) => {
      // "AQE" base64url-decodes to 0x01 0x01
      @debug.assert_eq(secret.length(), 2)
      @debug.assert_eq(secret[0], b'\x01')
    }
    _ => abort("expected Hs256 VerifyKey")
  }
}

///|
test "ATTACK jwks: duplicate kid entries are ambiguous, not first-match-wins" {
  let jwk_doc =
    #|{ "keys": [
    #|  { "kty": "oct", "k": "YXR0YWNrZXItc2VjcmV0", "kid": "dup", "alg": "HS256" },
    #|  { "kty": "oct", "k": "bGVnaXQtc2VjcmV0", "kid": "dup", "alg": "HS256" }
    #|] }
  let set = @jwk.parse_set(jwk_doc) catch {
    @jwk.InvalidJson(_) => return
    e => abort("expected InvalidJson for duplicate kid, got " + repr(e) + "")
  }
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["kid"] = Json::string("dup")
  try @jwt.select_verify_key(set, header) catch {
    NoMatchingKey => ()
    e => abort("expected NoMatchingKey for ambiguous kid, got " + repr(e) + "")
  } noraise {
    _ => abort("expected ambiguous kid rejection, got Ok")
  }
}

///|
test "select_verify_key: unknown kid raises NoMatchingKey" {
  let jwk_doc =
    #|{ "keys": [ { "kty": "oct", "k": "AAA", "kid": "k1", "alg": "HS256" } ] }
  let set = @jwk.parse_set(jwk_doc)
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["kid"] = Json::string("no-such-key")
  try @jwt.select_verify_key(set, header) catch {
    NoMatchingKey => ()
    e => abort("expected NoMatchingKey, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected NoMatchingKey, got Ok")
  }
}

///|
test "select_verify_key: alg mismatch in JWKS rejected" {
  // JWKS entry tags the key as RS256-only, but the JWT claims HS256.
  let jwk_doc =
    #|{ "keys": [ { "kty": "oct", "k": "AAA", "kid": "k1", "alg": "RS256" } ] }
  let set = @jwk.parse_set(jwk_doc)
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["kid"] = Json::string("k1")
  try @jwt.select_verify_key(set, header) catch {
    AlgorithmMismatchInJwks(_) => ()
    e => abort("expected AlgorithmMismatchInJwks, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AlgorithmMismatchInJwks, got Ok")
  }
}

///|
test "select_verify_key: RSA JWKS maps RS384/RS512/PS384/PS512" {
  match select_rsa_jwks_verify_key("RS384") {
    Rs384(_) => ()
    _ => abort("expected Rs384 VerifyKey")
  }
  match select_rsa_jwks_verify_key("RS512") {
    Rs512(_) => ()
    _ => abort("expected Rs512 VerifyKey")
  }
  match select_rsa_jwks_verify_key("PS384") {
    Ps384(_) => ()
    _ => abort("expected Ps384 VerifyKey")
  }
  match select_rsa_jwks_verify_key("PS512") {
    Ps512(_) => ()
    _ => abort("expected Ps512 VerifyKey")
  }
}

///|
test "select_verify_key: EC P-521 JWKS maps ES512" {
  let jwk_doc =
    #|{ "keys": [ {
    #|  "kty":"EC",
    #|  "crv":"P-521",
    #|  "x":"AOxvuKZc5P1qI5IbWuhzWkLfOZ_wrBrq8ufYyFiHLxDmC9pRPoAHXuGNdMsC_Y3Bx9t0aYfvt8olX_95VodMxx67",
    #|  "y":"ALrdkc_8mhZxzxWp-wx8FyivgrhY7taLOmiOFafIIIwaIx5RH58JWn-p7g3itSHWxR-rk3hkEkNrd4aiBRrl_6tL",
    #|  "kid":"p521-kid",
    #|  "alg":"ES512"
    #|} ] }
  let set = @jwk.parse_set(jwk_doc)
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("ES512")
  header["kid"] = Json::string("p521-kid")
  match @jwt.select_verify_key(set, header) {
    Es512(_) => ()
    _ => abort("expected Es512 VerifyKey")
  }
}

///|
test "ATTACK jwt: verified result never returns control-character kid" {
  let secret : Bytes = b"kid-control-secret"
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["typ"] = Json::string("JWT")
  header["kid"] = Json::string("trusted\nissuer")
  let token = sign_hs256_token_with_header(
    Json::object(header),
    Json::object(Map([])),
    secret,
  )
  try
    @jwt.verify(
      token,
      @jwt.VerifyKey::Hs256(secret~),
      @jwt.VerifyOptions::default(0L),
    )
  catch {
    InvalidHeader(_) => ()
    e => abort("expected InvalidHeader for control kid, got " + repr(e) + "")
  } noraise {
    _ => abort("expected control-character kid rejection, got Ok")
  }
}

///|
test "ATTACK jwt: non-string kid rejected before surfaced to caller" {
  let secret : Bytes = b"kid-type-secret"
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["typ"] = Json::string("JWT")
  header["kid"] = Json::number(42.0)
  let token = sign_hs256_token_with_header(
    Json::object(header),
    Json::object(Map([])),
    secret,
  )
  try
    @jwt.verify(
      token,
      @jwt.VerifyKey::Hs256(secret~),
      @jwt.VerifyOptions::default(0L),
    )
  catch {
    InvalidHeader(msg) => @debug.assert_eq(msg, "kid must be a string")
    e => abort("expected InvalidHeader for non-string kid, got " + repr(e) + "")
  } noraise {
    _ => abort("expected non-string kid rejection, got Ok")
  }
}

///|
test "ATTACK jwt: jku and embedded jwk headers are not trusted key material" {
  let trusted_secret : Bytes = b"trusted-idp-secret"
  let attacker_secret : Bytes = b"attacker-controlled-secret"
  let payload : Map[String, Json] = Map([])
  payload["sub"] = Json::string("attacker")

  let jku_header : Map[String, Json] = Map([])
  jku_header["alg"] = Json::string("HS256")
  jku_header["typ"] = Json::string("JWT")
  jku_header["jku"] = Json::string("https://attacker.example/jwks.json")
  let jku_token = sign_hs256_token_with_header(
    Json::object(jku_header),
    Json::object(payload),
    attacker_secret,
  )
  try
    @jwt.verify(
      jku_token,
      @jwt.VerifyKey::Hs256(secret=trusted_secret),
      @jwt.VerifyOptions::default(0L),
    )
  catch {
    InvalidSignature => ()
    e => abort("expected InvalidSignature for ignored jku, got " + repr(e) + "")
  } noraise {
    _ => abort("expected InvalidSignature for ignored jku, got Ok")
  }

  let jwk : Map[String, Json] = Map([])
  jwk["kty"] = Json::string("oct")
  jwk["k"] = Json::string(b64u_encode(attacker_secret))
  let jwk_header : Map[String, Json] = Map([])
  jwk_header["alg"] = Json::string("HS256")
  jwk_header["typ"] = Json::string("JWT")
  jwk_header["jwk"] = Json::object(jwk)
  let jwk_token = sign_hs256_token_with_header(
    Json::object(jwk_header),
    Json::object(payload),
    attacker_secret,
  )
  try
    @jwt.verify(
      jwk_token,
      @jwt.VerifyKey::Hs256(secret=trusted_secret),
      @jwt.VerifyOptions::default(0L),
    )
  catch {
    InvalidSignature => ()
    e => abort("expected InvalidSignature for ignored jwk, got " + repr(e) + "")
  } noraise {
    _ => abort("expected InvalidSignature for ignored jwk, got Ok")
  }
}

///|
test "peek_header: malformed base64url and non-UTF8 headers are rejected" {
  try @jwt.peek_header("!!!!.e30.sig") catch {
    InvalidToken(_) => ()
    e => abort("expected InvalidToken, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidToken, got Ok")
  }
  try @jwt.peek_header("A.e30.sig") catch {
    InvalidToken(_) => ()
    e => abort("expected InvalidToken, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidToken, got Ok")
  }
  let non_utf8_header = b64u_encode(b"\xFF")
  try @jwt.peek_header(non_utf8_header + ".e30.sig") catch {
    InvalidHeader(_) => ()
    e => abort("expected InvalidHeader, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidHeader, got Ok")
  }
}

///|
test "peek_header: returns the JOSE header without verifying" {
  let secret : Bytes = b"peek-test"
  let token = @jwt.sign(
    Json::object(Map([])),
    @jwt.Key::Hs256(secret~),
    kid="probe",
  )
  let header = @jwt.peek_header(token)
  match header.get("alg") {
    Some(String(s)) => @debug.assert_eq(s, "HS256")
    _ => abort("missing alg in peeked header")
  }
  match header.get("kid") {
    Some(String(s)) => @debug.assert_eq(s, "probe")
    _ => abort("missing kid in peeked header")
  }
}

///|
test "ATTACK jwt: signed non-UTF8 payload is rejected as claims parse error" {
  let secret : Bytes = b"non-utf8-payload-secret"
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["typ"] = Json::string("JWT")
  let header_b64 = b64u_encode(
    @utf8.encode(Json::object(header).stringify()[:]),
  )
  let payload_b64 = b64u_encode(b"\xFF")
  let signing_input = header_b64 + "." + payload_b64
  let sig = @hash.hmac_sha256(secret, @utf8.encode(signing_input[:]))
  let token = signing_input + "." + b64u_encode(sig)
  try
    @jwt.verify(
      token,
      @jwt.VerifyKey::Hs256(secret~),
      @jwt.VerifyOptions::default(0L),
    )
  catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + repr(e) + "")
  } noraise {
    _ => abort("expected ClaimsParseError, got Ok")
  }
}

// -----------------------------------------------------------------------------
// RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
// -----------------------------------------------------------------------------

///|
fn rfc9068_test_claims(now : Int64, iss : String, aud : Json) -> Json {
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string(iss)
  m["sub"] = Json::string("user-42")
  m["aud"] = aud
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("c0ffee-id")
  m["client_id"] = Json::string("s6BhdRkqt3")
  m["scope"] = Json::string("openid profile email")
  Json::object(m)
}

///|
test "rfc9068: happy path with at+jwt typ" {
  let now = 1_700_000_000L
  let secret : Bytes = b"hs256-test-secret-for-9068"
  let payload = rfc9068_test_claims(
    now,
    "https://as.example.com/",
    Json::string("https://rs.example.com/"),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), typ="at+jwt")
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now + 10L,
    "https://as.example.com/",
    "https://rs.example.com/",
  )
  let t = @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts)
  @debug.assert_eq(t.sub, "user-42")
  @debug.assert_eq(t.client_id, "s6BhdRkqt3")
  @debug.assert_eq(t.aud, ["https://rs.example.com/"])
  @debug.assert_eq(t.scope, Some(["openid", "profile", "email"]))
}

///|
test "rfc9068: cnf object is exposed for proof binding" {
  let now = 1_700_000_000L
  let secret : Bytes = b"hs256-test-secret-for-9068"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["sub"] = Json::string("user-42")
  m["aud"] = Json::string("https://rs.example.com/")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("c0ffee-id")
  m["client_id"] = Json::string("s6BhdRkqt3")
  let jwk : Map[String, Json] = Map([])
  jwk["kty"] = Json::string("EC")
  let cnf : Map[String, Json] = Map([])
  cnf["jkt"] = Json::string("proof-key-thumbprint")
  cnf["x5t#S256"] = Json::string("cert-thumbprint")
  cnf["jwk"] = Json::object(jwk)
  m["cnf"] = Json::object(cnf)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~), typ="at+jwt")
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now, "https://as.example.com/", "https://rs.example.com/",
  )
  let t = @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts)
  match t.cnf {
    Some(c) => {
      @debug.assert_eq(c.jkt, Some("proof-key-thumbprint"))
      @debug.assert_eq(c.x5t_s256, Some("cert-thumbprint"))
      match c.jwk {
        Some(j) =>
          match j.get("kty") {
            Some(String(s)) => @debug.assert_eq(s, "EC")
            _ => abort("missing cnf.jwk.kty")
          }
        None => abort("missing cnf.jwk")
      }
    }
    None => abort("missing cnf")
  }
}

///|
test "rfc9068: scalar cnf is rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"hs256-test-secret-for-9068"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["sub"] = Json::string("user-42")
  m["aud"] = Json::string("https://rs.example.com/")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("c0ffee-id")
  m["client_id"] = Json::string("s6BhdRkqt3")
  m["cnf"] = Json::string("proof-key-thumbprint")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~), typ="at+jwt")
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now, "https://as.example.com/", "https://rs.example.com/",
  )
  try @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected ClaimsParseError, got Ok")
  }
}

///|
test "ATTACK rfc9068: malformed cnf members are rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"hs256-test-secret-for-9068"
  fn base_claims(cnf : Map[String, Json]) -> Json {
    let m : Map[String, Json] = Map([])
    m["iss"] = Json::string("https://as.example.com/")
    m["sub"] = Json::string("user-42")
    m["aud"] = Json::string("https://rs.example.com/")
    m["exp"] = Json::number((now + 600L).to_double())
    m["iat"] = Json::number(now.to_double())
    m["jti"] = Json::string("c0ffee-id")
    m["client_id"] = Json::string("s6BhdRkqt3")
    m["cnf"] = Json::object(cnf)
    Json::object(m)
  }
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now, "https://as.example.com/", "https://rs.example.com/",
  )
  let cases : Array[Map[String, Json]] = []
  let bad_jwk : Map[String, Json] = Map([])
  bad_jwk["jwk"] = Json::string("not-an-object")
  cases.push(bad_jwk)
  let bad_jkt : Map[String, Json] = Map([])
  bad_jkt["jkt"] = Json::number(42.0)
  cases.push(bad_jkt)
  let bad_x5t : Map[String, Json] = Map([])
  bad_x5t["x5t#S256"] = Json::array([])
  cases.push(bad_x5t)
  let unknown : Map[String, Json] = Map([])
  unknown["kid"] = Json::string("unimplemented-confirmation-method")
  cases.push(unknown)
  for cnf in cases {
    let token = @jwt.sign(
      base_claims(cnf),
      @jwt.Key::Hs256(secret~),
      typ="at+jwt",
    )
    try @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
      ClaimsParseError(_) => ()
      e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
    } noraise {
      _ => abort("accepted malformed cnf member")
    }
  }
}

///|
test "ATTACK rfc9068: malformed optional string claims are rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"hs256-test-secret-for-9068-optional-shape"
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now, "https://as.example.com/", "https://rs.example.com/",
  )
  for key in ["scope", "acr", "jti"] {
    let payload = rfc9068_test_claims(
      now,
      "https://as.example.com/",
      Json::string("https://rs.example.com/"),
    )
    let m = match payload {
      Object(obj) => obj
      _ => abort("expected object")
    }
    m[key] = Json::number(42.0)
    let token = @jwt.sign(
      Json::object(m),
      @jwt.Key::Hs256(secret~),
      typ="at+jwt",
    )
    try @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
      ClaimsParseError(_) => ()
      e => abort("expected ClaimsParseError for " + key + ", got " + repr(e))
    } noraise {
      _ => abort("accepted RFC 9068 token with malformed " + key)
    }
  }
}

///|
test "rfc9068: aud as JSON array containing the resource indicator" {
  let now = 1_700_000_000L
  let secret : Bytes = b"hs256-test-secret-for-9068"
  let aud = Json::array([
    Json::string("https://rs1.example.com/"),
    Json::string("https://rs2.example.com/"),
  ])
  let payload = rfc9068_test_claims(now, "https://as.example.com/", aud)
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), typ="at+jwt")
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now, "https://as.example.com/", "https://rs2.example.com/",
  )
  let t = @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts)
  @debug.assert_eq(t.aud.length(), 2)
}

///|
test "rfc9068: missing typ rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"hs256-test-secret-for-9068"
  let payload = rfc9068_test_claims(
    now,
    "https://as.example.com/",
    Json::string("https://rs.example.com/"),
  )
  // typ defaults to "JWT", not "at+jwt" — RFC 9068 must reject.
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now, "https://as.example.com/", "https://rs.example.com/",
  )
  try @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType, got Ok")
  }
}

///|
test "rfc9068: missing client_id raises MissingRequiredClaim" {
  let now = 1_700_000_000L
  let secret : Bytes = b"hs256-test-secret-for-9068"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["sub"] = Json::string("u")
  m["aud"] = Json::string("https://rs.example.com/")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("j1")
  // client_id intentionally omitted
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~), typ="at+jwt")
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now, "https://as.example.com/", "https://rs.example.com/",
  )
  try @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    MissingRequiredClaim(c) => @debug.assert_eq(c, "client_id")
    e => abort("expected MissingRequiredClaim, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected MissingRequiredClaim, got Ok")
  }
}

///|
test "rfc9068: client_id mismatch" {
  let now = 1_700_000_000L
  let secret : Bytes = b"hs256-test-secret-for-9068"
  let payload = rfc9068_test_claims(
    now,
    "https://as.example.com/",
    Json::string("https://rs.example.com/"),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), typ="at+jwt")
  let opts : @jwt.Rfc9068VerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://as.example.com/",
    audience: "https://rs.example.com/",
    expected_client_id: Some("different-client"),
    required_scopes: None,
    allowed_algorithms: None,
  }
  try @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    ClientIdMismatch => ()
    e => abort("expected ClientIdMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected ClientIdMismatch, got Ok")
  }
}

///|
test "rfc9068: required scope missing" {
  let now = 1_700_000_000L
  let secret : Bytes = b"hs256-test-secret-for-9068"
  let payload = rfc9068_test_claims(
    now,
    "https://as.example.com/",
    Json::string("https://rs.example.com/"),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), typ="at+jwt")
  let opts : @jwt.Rfc9068VerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://as.example.com/",
    audience: "https://rs.example.com/",
    expected_client_id: None,
    // Token has openid/profile/email but no "admin".
    required_scopes: Some(["admin"]),
    allowed_algorithms: None,
  }
  try @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    MissingScopes(missing) => @debug.assert_eq(missing, ["admin"])
    e => abort("expected MissingScopes, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected MissingScopes, got Ok")
  }
}

///|
test "rfc9068: algorithm allow-list rejects non-listed alg" {
  let now = 1_700_000_000L
  let secret : Bytes = b"hs256-test-secret-for-9068"
  let payload = rfc9068_test_claims(
    now,
    "https://as.example.com/",
    Json::string("https://rs.example.com/"),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), typ="at+jwt")
  // Pin to EdDSA only — token is HS256, expect AlgorithmNotAllowed.
  let opts : @jwt.Rfc9068VerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://as.example.com/",
    audience: "https://rs.example.com/",
    expected_client_id: None,
    required_scopes: None,
    allowed_algorithms: Some([@jwt.Algorithm::EdDSA]),
  }
  try @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    AlgorithmNotAllowed(_) => ()
    e => abort("expected AlgorithmNotAllowed, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AlgorithmNotAllowed, got Ok")
  }
}

///|
test "rfc9068: verify_rfc9068_jwks (round-trip via JWKS)" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jwks-route-secret"
  let payload = rfc9068_test_claims(
    now,
    "https://as.example.com/",
    Json::string("https://rs.example.com/"),
  )
  let token = @jwt.sign(
    payload,
    @jwt.Key::Hs256(secret~),
    typ="at+jwt",
    kid="k1",
  )
  // "anvrcy1yb3V0ZS1zZWNyZXQ" decodes to b"jwks-route-secret"
  let jwks =
    #|{ "keys": [ { "kty": "oct", "kid": "k1", "alg": "HS256",
    #|              "k": "andrcy1yb3V0ZS1zZWNyZXQ" } ] }
  let set = @jwk.parse_set(jwks)
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now, "https://as.example.com/", "https://rs.example.com/",
  )
  let t = @jwt.verify_rfc9068_jwks(token, set, opts)
  @debug.assert_eq(t.client_id, "s6BhdRkqt3")
  @debug.assert_eq(t.sub, "user-42")
}

///|
test "ATTACK rfc9068_jwks: duplicate kid cannot pick attacker-controlled first key" {
  let now = 1_700_000_000L
  let attacker_secret : Bytes = b"attacker-secret"
  let payload = rfc9068_test_claims(
    now,
    "https://as.example.com/",
    Json::string("https://rs.example.com/"),
  )
  let token = @jwt.sign(
    payload,
    @jwt.Key::Hs256(secret=attacker_secret),
    typ="at+jwt",
    kid="dup",
  )
  let jwks =
    #|{ "keys": [
    #|  { "kty": "oct", "kid": "dup", "alg": "HS256", "k": "YXR0YWNrZXItc2VjcmV0" },
    #|  { "kty": "oct", "kid": "dup", "alg": "HS256", "k": "bGVnaXQtc2VjcmV0" }
    #|] }
  let set = @jwk.parse_set(jwks) catch {
    @jwk.InvalidJson(_) => return
    e => abort("expected InvalidJson for duplicate kid, got " + repr(e) + "")
  }
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now, "https://as.example.com/", "https://rs.example.com/",
  )
  try @jwt.verify_rfc9068_jwks(token, set, opts) catch {
    NoMatchingKey => ()
    e => abort("expected NoMatchingKey for duplicate kid, got " + repr(e) + "")
  } noraise {
    _ => abort("expected duplicate-kid rejection, got Ok")
  }
}

// -----------------------------------------------------------------------------
// OIDC ID Token verify (OIDC Core 1.0 §3.1.3.7)
// -----------------------------------------------------------------------------

///|
fn oidc_id_token_claims(
  now : Int64,
  iss : String,
  aud : Json,
  extra : Map[String, Json],
) -> Json {
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string(iss)
  m["sub"] = Json::string("user-42")
  m["aud"] = aud
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  for k, v in extra {
    m[k] = v
  }
  Json::object(m)
}

///|
test "oidc: happy path with single audience" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-test-secret"
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    Map([]),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), kid="k1")
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  let id = @jwt.verify_oidc_id_token(
    token,
    @jwt.VerifyKey::Hs256(secret~),
    opts,
  )
  @debug.assert_eq(id.sub, "user-42")
  @debug.assert_eq(id.aud, ["client-abc"])
  @debug.assert_eq(id.jwt.kid, Some("k1"))
}

///|
test "oidc: jwks path and algorithm allow-list" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-jwks-secret"
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    Map([]),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), kid="oidc-kid")
  let jwks = "{ \"keys\": [ { \"kty\": \"oct\", \"kid\": \"oidc-kid\", \"alg\": \"HS256\", \"k\": \"" +
    b64u_encode(secret) +
    "\" } ] }"
  let set = @jwk.parse_set(jwks)
  let opts : @jwt.OidcIdTokenVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://accounts.example.com/",
    client_id: "client-abc",
    expected_nonce: None,
    access_token: None,
    authorization_code: None,
    max_age_sec: None,
    expected_acr: None,
    allowed_algorithms: Some([@jwt.Algorithm::HS256]),
  }
  let id = @jwt.verify_oidc_id_token_jwks(token, set, opts)
  @debug.assert_eq(id.sub, "user-42")
  let bad_opts : @jwt.OidcIdTokenVerifyOptions = {
    ..opts,
    allowed_algorithms: Some([@jwt.Algorithm::EdDSA]),
  }
  try @jwt.verify_oidc_id_token_jwks(token, set, bad_opts) catch {
    AlgorithmNotAllowed(_) => ()
    e => abort("expected AlgorithmNotAllowed, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AlgorithmNotAllowed, got Ok")
  }
}

///|
test "ATTACK oidc: issuer and audience substitution rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-mixup-secret"
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )

  let evil_issuer_payload = oidc_id_token_claims(
    now,
    "https://evil.example.com/",
    Json::string("client-abc"),
    Map([]),
  )
  let evil_issuer_token = @jwt.sign(
    evil_issuer_payload,
    @jwt.Key::Hs256(secret~),
  )
  try
    @jwt.verify_oidc_id_token(
      evil_issuer_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    InvalidIssuer => ()
    e => abort("expected InvalidIssuer, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidIssuer, got Ok")
  }

  let wrong_audience_payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("other-client"),
    Map([]),
  )
  let wrong_audience_token = @jwt.sign(
    wrong_audience_payload,
    @jwt.Key::Hs256(secret~),
  )
  try
    @jwt.verify_oidc_id_token(
      wrong_audience_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    InvalidAudience => ()
    e => abort("expected InvalidAudience, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidAudience, got Ok")
  }
}

///|
test "oidc: multi-aud requires azp == client_id" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-multi-aud"
  let aud = Json::array([Json::string("client-abc"), Json::string("other-rp")])
  let extra : Map[String, Json] = Map([])
  extra["azp"] = Json::string("client-abc")
  let payload = oidc_id_token_claims(
    now, "https://accounts.example.com/", aud, extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  let id = @jwt.verify_oidc_id_token(
    token,
    @jwt.VerifyKey::Hs256(secret~),
    opts,
  )
  @debug.assert_eq(id.azp, Some("client-abc"))
}

///|
test "oidc: multi-aud without azp rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-no-azp"
  let aud = Json::array([Json::string("client-abc"), Json::string("other-rp")])
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    aud,
    Map([]),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    InvalidAudience => ()
    e => abort("expected InvalidAudience, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidAudience, got Ok")
  }
}

///|
test "oidc: multi-aud with wrong azp rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-wrong-azp"
  let aud = Json::array([Json::string("client-abc"), Json::string("other-rp")])
  let extra : Map[String, Json] = Map([])
  extra["azp"] = Json::string("other-rp")
  let payload = oidc_id_token_claims(
    now, "https://accounts.example.com/", aud, extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    InvalidAudience => ()
    e => abort("expected InvalidAudience, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidAudience, got Ok")
  }
}

///|
test "oidc: nonce mismatch raises NonceMismatch" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-nonce"
  let extra : Map[String, Json] = Map([])
  extra["nonce"] = Json::string("attacker-replayed-nonce")
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts : @jwt.OidcIdTokenVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://accounts.example.com/",
    client_id: "client-abc",
    expected_nonce: Some("fresh-nonce-from-authrequest"),
    access_token: None,
    authorization_code: None,
    max_age_sec: None,
    expected_acr: None,
    allowed_algorithms: None,
  }
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    NonceMismatch => ()
    e => abort("expected NonceMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected NonceMismatch, got Ok")
  }
}

///|
test "oidc: strict options require and verify nonce" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-strict-nonce"
  let extra : Map[String, Json] = Map([])
  extra["nonce"] = Json::string("fresh-nonce")
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts = @jwt.OidcIdTokenVerifyOptions::strict(
    now, "https://accounts.example.com/", "client-abc", "fresh-nonce",
  )
  let id = @jwt.verify_oidc_id_token(
    token,
    @jwt.VerifyKey::Hs256(secret~),
    opts,
  )
  @debug.assert_eq(id.nonce, Some("fresh-nonce"))
}

///|
test "ATTACK oidc: malformed amr array is rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-amr-shape"
  let extra : Map[String, Json] = Map([])
  extra["amr"] = Json::array([Json::string("pwd"), Json::number(42.0)])
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted ID token with malformed amr array")
  }
}

///|
test "ATTACK oidc: malformed email_verified is rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-email-verified-shape"
  let extra : Map[String, Json] = Map([])
  extra["email"] = Json::string("user@example.com")
  extra["email_verified"] = Json::string("true")
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted ID token with malformed email_verified")
  }
}

///|
test "ATTACK oidc: malformed optional string claims are rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-optional-string-shape"
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  for
    key in [
      "azp", "nonce", "at_hash", "c_hash", "acr", "email", "name", "preferred_username",
    ] {
    let extra : Map[String, Json] = Map([])
    extra[key] = Json::number(42.0)
    let payload = oidc_id_token_claims(
      now,
      "https://accounts.example.com/",
      Json::string("client-abc"),
      extra,
    )
    let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
    try
      @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
    catch {
      ClaimsParseError(_) => ()
      e => abort("expected ClaimsParseError for " + key + ", got " + repr(e))
    } noraise {
      _ => abort("accepted ID token with malformed " + key)
    }
  }
}

///|
test "oidc: at_hash binding accepts matching access_token" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-at-hash"
  // Pre-compute at_hash for access_token "foo-access" under SHA-256:
  //   sha256("foo-access") = 71a4...c93f
  //   left half (16 bytes) = 71a4 ad6e 13f8 1937 e8d8 4be7 0afd 75bf
  //   base64url(no pad) = "caStbhP4GTfo2EvnCv11vw"
  let access_token = "foo-access"
  let at_hash_value = @jwt.compute_x_hash(@jwt.Algorithm::HS256, access_token)
  let extra : Map[String, Json] = Map([])
  extra["at_hash"] = Json::string(at_hash_value)
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts : @jwt.OidcIdTokenVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://accounts.example.com/",
    client_id: "client-abc",
    expected_nonce: None,
    access_token: Some(access_token),
    authorization_code: None,
    max_age_sec: None,
    expected_acr: None,
    allowed_algorithms: None,
  }
  let id = @jwt.verify_oidc_id_token(
    token,
    @jwt.VerifyKey::Hs256(secret~),
    opts,
  )
  @debug.assert_eq(id.at_hash, Some(at_hash_value))
}

///|
test "oidc: at_hash mismatch with wrong access_token rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-at-hash-attack"
  let at_hash_value = @jwt.compute_x_hash(
    @jwt.Algorithm::HS256,
    "real-access-token",
  )
  let extra : Map[String, Json] = Map([])
  extra["at_hash"] = Json::string(at_hash_value)
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts : @jwt.OidcIdTokenVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://accounts.example.com/",
    client_id: "client-abc",
    expected_nonce: None,
    access_token: Some("different-access-token"), // attacker substituted
    authorization_code: None,
    max_age_sec: None,
    expected_acr: None,
    allowed_algorithms: None,
  }
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    AtHashMismatch => ()
    e => abort("expected AtHashMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AtHashMismatch, got Ok")
  }
}

///|
test "oidc: max_age requires auth_time within window" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-max-age"
  let extra : Map[String, Json] = Map([])
  extra["auth_time"] = Json::number((now - 7200L).to_double()) // 2h ago
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts : @jwt.OidcIdTokenVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://accounts.example.com/",
    client_id: "client-abc",
    expected_nonce: None,
    access_token: None,
    authorization_code: None,
    max_age_sec: Some(3600L), // require auth within last hour
    expected_acr: None,
    allowed_algorithms: None,
  }
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    AuthTimeTooOld => ()
    e => abort("expected AuthTimeTooOld, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AuthTimeTooOld, got Ok")
  }
}

///|
test "oidc: acr pin enforces context class" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-acr"
  let extra : Map[String, Json] = Map([])
  extra["acr"] = Json::string("urn:mace:incommon:iap:bronze")
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts : @jwt.OidcIdTokenVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://accounts.example.com/",
    client_id: "client-abc",
    expected_nonce: None,
    access_token: None,
    authorization_code: None,
    max_age_sec: None,
    expected_acr: Some("urn:mace:incommon:iap:silver"),
    allowed_algorithms: None,
  }
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    AcrMismatch => ()
    e => abort("expected AcrMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AcrMismatch, got Ok")
  }
}

///|
test "oidc: missing nonce, hashes, auth_time, and acr reject when expected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-missing-bindings"
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    Map([]),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let base = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  let nonce_opts : @jwt.OidcIdTokenVerifyOptions = {
    ..base,
    expected_nonce: Some("nonce-from-auth-request"),
  }
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), nonce_opts)
  catch {
    NonceMismatch => ()
    e => abort("expected NonceMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected NonceMismatch, got Ok")
  }
  let at_opts : @jwt.OidcIdTokenVerifyOptions = {
    ..base,
    access_token: Some("access-token"),
  }
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), at_opts)
  catch {
    AtHashMismatch => ()
    e => abort("expected AtHashMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AtHashMismatch, got Ok")
  }
  let code_opts : @jwt.OidcIdTokenVerifyOptions = {
    ..base,
    authorization_code: Some("auth-code"),
  }
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), code_opts)
  catch {
    CHashMismatch => ()
    e => abort("expected CHashMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected CHashMismatch, got Ok")
  }
  let max_age_opts : @jwt.OidcIdTokenVerifyOptions = {
    ..base,
    max_age_sec: Some(60L),
  }
  try
    @jwt.verify_oidc_id_token(
      token,
      @jwt.VerifyKey::Hs256(secret~),
      max_age_opts,
    )
  catch {
    AuthTimeTooOld => ()
    e => abort("expected AuthTimeTooOld, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AuthTimeTooOld, got Ok")
  }
  let acr_opts : @jwt.OidcIdTokenVerifyOptions = {
    ..base,
    expected_acr: Some("urn:example:loa:2"),
  }
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), acr_opts)
  catch {
    AcrMismatch => ()
    e => abort("expected AcrMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AcrMismatch, got Ok")
  }
}

///|
test "oidc: c_hash mismatch with wrong authorization code rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"oidc-c-hash"
  let extra : Map[String, Json] = Map([])
  extra["c_hash"] = Json::string(
    @jwt.compute_x_hash(@jwt.Algorithm::HS256, "real-code"),
  )
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts : @jwt.OidcIdTokenVerifyOptions = {
    ..@jwt.OidcIdTokenVerifyOptions::default(
      now, "https://accounts.example.com/", "client-abc",
    ),
    authorization_code: Some("substituted-code"),
  }
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    CHashMismatch => ()
    e => abort("expected CHashMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected CHashMismatch, got Ok")
  }
}

// -----------------------------------------------------------------------------
// RFC 7523 — JWT Profile for OAuth 2.0 Client Authentication
// -----------------------------------------------------------------------------

///|
fn client_assertion_claims(now : Int64, client_id : String, aud : Json) -> Json {
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string(client_id)
  m["sub"] = Json::string(client_id)
  m["aud"] = aud
  m["exp"] = Json::number((now + 300L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("ja-id-1")
  Json::object(m)
}

///|
test "rfc7523: happy path client_assertion verifies" {
  let now = 1_700_000_000L
  let secret : Bytes = b"client-shared-secret"
  let payload = client_assertion_claims(
    now,
    "client-xyz",
    Json::string("https://as.example.com/token"),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts = @jwt.ClientAssertionVerifyOptions::default(
    now, "client-xyz", "https://as.example.com/token",
  )
  let a = @jwt.verify_client_assertion(
    token,
    @jwt.VerifyKey::Hs256(secret~),
    opts,
  )
  @debug.assert_eq(a.client_id, "client-xyz")
  @debug.assert_eq(a.jti, Some("ja-id-1"))
}

///|
test "rfc7523: jwks path verifies and alg policy is enforced" {
  let now = 1_700_000_000L
  let secret : Bytes = b"client-jwks-secret"
  let payload = client_assertion_claims(
    now,
    "client-xyz",
    Json::string("https://as.example.com/token"),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), kid="client-kid")
  let jwks = "{ \"keys\": [ { \"kty\": \"oct\", \"kid\": \"client-kid\", \"alg\": \"HS256\", \"k\": \"" +
    b64u_encode(secret) +
    "\" } ] }"
  let set = @jwk.parse_set(jwks)
  let opts : @jwt.ClientAssertionVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_client_id: "client-xyz",
    token_endpoint: "https://as.example.com/token",
    require_jti: true,
    max_iat_age_sec: Some(300L),
    max_exp_lifetime_sec: Some(300L),
    allowed_algorithms: Some([@jwt.Algorithm::HS256]),
  }
  let a = @jwt.verify_client_assertion_jwks(token, set, opts)
  @debug.assert_eq(a.client_id, "client-xyz")
  let bad_opts : @jwt.ClientAssertionVerifyOptions = {
    ..opts,
    allowed_algorithms: Some([@jwt.Algorithm::EdDSA]),
  }
  try @jwt.verify_client_assertion_jwks(token, set, bad_opts) catch {
    AlgorithmNotAllowed(_) => ()
    e => abort("expected AlgorithmNotAllowed, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AlgorithmNotAllowed, got Ok")
  }
}

///|
test "ATTACK rfc7523: assertion with attacker jku still uses caller key" {
  let now = 1_700_000_000L
  let trusted_secret : Bytes = b"trusted-client-secret"
  let attacker_secret : Bytes = b"attacker-client-secret"
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["typ"] = Json::string("JWT")
  header["jku"] = Json::string("https://attacker.example/client-jwks.json")
  let payload = client_assertion_claims(
    now,
    "client-xyz",
    Json::string("https://as.example.com/token"),
  )
  let token = sign_hs256_token_with_header(
    Json::object(header),
    payload,
    attacker_secret,
  )
  let opts = @jwt.ClientAssertionVerifyOptions::default(
    now, "client-xyz", "https://as.example.com/token",
  )
  try
    @jwt.verify_client_assertion(
      token,
      @jwt.VerifyKey::Hs256(secret=trusted_secret),
      opts,
    )
  catch {
    InvalidSignature => ()
    e => abort("expected InvalidSignature, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidSignature, got Ok")
  }
}

///|
test "rfc7523: iss != client_id rejected as InvalidIssuer" {
  let now = 1_700_000_000L
  let secret : Bytes = b"impersonator"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("attacker-client")
  m["sub"] = Json::string("client-xyz")
  m["aud"] = Json::string("https://as.example.com/token")
  m["exp"] = Json::number((now + 300L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("j")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts = @jwt.ClientAssertionVerifyOptions::default(
    now, "client-xyz", "https://as.example.com/token",
  )
  try
    @jwt.verify_client_assertion(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    InvalidIssuer => ()
    e => abort("expected InvalidIssuer, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidIssuer, got Ok")
  }
}

///|
test "rfc7523: sub != iss raises SubjectMismatch" {
  let now = 1_700_000_000L
  let secret : Bytes = b"sub-mismatch"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("client-xyz")
  m["sub"] = Json::string("end-user-42") // OIDC-style sub, not RFC 7523 shape
  m["aud"] = Json::string("https://as.example.com/token")
  m["exp"] = Json::number((now + 300L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("j")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts = @jwt.ClientAssertionVerifyOptions::default(
    now, "client-xyz", "https://as.example.com/token",
  )
  try
    @jwt.verify_client_assertion(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    SubjectMismatch => ()
    e => abort("expected SubjectMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected SubjectMismatch, got Ok")
  }
}

///|
test "rfc7523: wrong token endpoint in aud rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"wrong-aud"
  let payload = client_assertion_claims(
    now,
    "client-xyz",
    Json::string("https://attacker.example.com/token"),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts = @jwt.ClientAssertionVerifyOptions::default(
    now, "client-xyz", "https://as.example.com/token", // legitimate AS
  )
  try
    @jwt.verify_client_assertion(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    InvalidAudience => ()
    e => abort("expected InvalidAudience, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidAudience, got Ok")
  }
}

///|
test "ATTACK rfc7523: defaults reject replay-friendly assertions" {
  let now = 1_700_000_000L
  let secret : Bytes = b"client-assertion-replay"
  let opts = @jwt.ClientAssertionVerifyOptions::default(
    now, "client-xyz", "https://as.example.com/token",
  )

  let missing_jti : Map[String, Json] = Map([])
  missing_jti["iss"] = Json::string("client-xyz")
  missing_jti["sub"] = Json::string("client-xyz")
  missing_jti["aud"] = Json::string("https://as.example.com/token")
  missing_jti["exp"] = Json::number((now + 300L).to_double())
  missing_jti["iat"] = Json::number(now.to_double())
  let missing_jti_token = @jwt.sign(
    Json::object(missing_jti),
    @jwt.Key::Hs256(secret~),
  )
  try
    @jwt.verify_client_assertion(
      missing_jti_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    MissingRequiredClaim(c) => @debug.assert_eq(c, "jti")
    e => abort("expected MissingRequiredClaim(jti), got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected missing jti rejection")
  }

  let stale_iat : Map[String, Json] = Map([])
  stale_iat["iss"] = Json::string("client-xyz")
  stale_iat["sub"] = Json::string("client-xyz")
  stale_iat["aud"] = Json::string("https://as.example.com/token")
  stale_iat["exp"] = Json::number((now + 300L).to_double())
  stale_iat["iat"] = Json::number((now - 600L).to_double())
  stale_iat["jti"] = Json::string("j-stale")
  let stale_iat_token = @jwt.sign(
    Json::object(stale_iat),
    @jwt.Key::Hs256(secret~),
  )
  try
    @jwt.verify_client_assertion(
      stale_iat_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    IssuedInFuture => ()
    e => abort("expected stale iat rejection, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected stale iat rejection")
  }

  let long_lived : Map[String, Json] = Map([])
  long_lived["iss"] = Json::string("client-xyz")
  long_lived["sub"] = Json::string("client-xyz")
  long_lived["aud"] = Json::string("https://as.example.com/token")
  long_lived["exp"] = Json::number((now + 3600L).to_double())
  long_lived["iat"] = Json::number(now.to_double())
  long_lived["jti"] = Json::string("j-long")
  let long_lived_token = @jwt.sign(
    Json::object(long_lived),
    @jwt.Key::Hs256(secret~),
  )
  try
    @jwt.verify_client_assertion(
      long_lived_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    ClaimsParseError(_) => ()
    e => abort("expected lifetime rejection, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected lifetime rejection")
  }
}

///|
test "ATTACK rfc7523: malformed optional jti is rejected when replay guard disabled" {
  let now = 1_700_000_000L
  let secret : Bytes = b"client-assertion-jti-shape"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("client-xyz")
  m["sub"] = Json::string("client-xyz")
  m["aud"] = Json::string("https://as.example.com/token")
  m["exp"] = Json::number((now + 300L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::number(42.0)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.ClientAssertionVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_client_id: "client-xyz",
    token_endpoint: "https://as.example.com/token",
    require_jti: false,
    max_iat_age_sec: None,
    max_exp_lifetime_sec: None,
    allowed_algorithms: None,
  }
  try
    @jwt.verify_client_assertion(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted client assertion with malformed optional jti")
  }
}

// -----------------------------------------------------------------------------
// ES256K (RFC 8812) — ECDSA-secp256k1-SHA256
// -----------------------------------------------------------------------------

///|
test "ES256K: sign + verify roundtrip" {
  let seed = Bytes::makei(32, fn(i) { (i + 1).to_byte() })
  let sk = @secp256k1.PrivateKey::from_bytes(seed)
  let pk = sk.public_key()
  let m : Map[String, Json] = Map([])
  m["sub"] = Json::string("web3-user")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Es256k(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(token, @jwt.VerifyKey::Es256k(pubkey=pk), opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::ES256K)
}

///|
test "ES256K: tampered token rejected" {
  let seed = Bytes::makei(32, fn(i) { (i + 2).to_byte() })
  let sk = @secp256k1.PrivateKey::from_bytes(seed)
  let pk = sk.public_key()
  let m : Map[String, Json] = Map([])
  m["sub"] = Json::string("web3-user")
  let good = @jwt.sign(Json::object(m), @jwt.Key::Es256k(privkey=sk))
  // Flip a base64url char in the middle of the signature segment. The
  // very last char has unused tail bits (64-byte signature → 85.33
  // base64 chars, so flipping it can be a no-op on the decoded bytes).
  let n = good.length()
  let mid = n - 10
  let c = good.get_char(mid).unwrap()
  let flipped = if c == 'A' { 'B' } else { 'A' }
  let bad = good[:mid].to_owned() +
    flipped.to_string() +
    good[mid + 1:].to_owned()
  let opts = @jwt.VerifyOptions::default(0L)
  try @jwt.verify(bad, @jwt.VerifyKey::Es256k(pubkey=pk), opts) catch {
    InvalidSignature => ()
    e => abort("expected InvalidSignature, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidSignature, got Ok")
  }
}

///|
test "ES256K: jwks resolution via select_verify_key" {
  let seed = Bytes::makei(32, fn(i) { (i + 7).to_byte() })
  let sk = @secp256k1.PrivateKey::from_bytes(seed)
  let pk = sk.public_key()
  let m : Map[String, Json] = Map([])
  m["sub"] = Json::string("web3-user")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Es256k(privkey=sk), kid="k1")
  // Build a JWKS with this pubkey. JWK for secp256k1 uses kty="EC", crv="secp256k1".
  let uncomp = pk.to_uncompressed()
  // skip the 04 prefix; take 32-byte x and y
  let x_bytes = Bytes::makei(32, fn(i) { uncomp[1 + i] })
  let y_bytes = Bytes::makei(32, fn(i) { uncomp[33 + i] })
  let b64u = fn(b : Bytes) -> String {
    let s = @base64.encode(b[:], padding=false)
    let buf = StringBuilder::new()
    for c in s {
      let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
      buf.write_char(c2)
    }
    buf.to_string()
  }
  let jwks = "{ \"keys\": [ { \"kty\": \"EC\", \"crv\": \"secp256k1\", \"kid\": \"k1\", \"alg\": \"ES256K\", " +
    "\"x\": \"" +
    b64u(x_bytes) +
    "\", \"y\": \"" +
    b64u(y_bytes) +
    "\" } ] }"
  let set = @jwk.parse_set(jwks)
  let header = @jwt.peek_header(token)
  let vk = @jwt.select_verify_key(set, header)
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(token, vk, opts)
  @debug.assert_eq(v.alg, @jwt.Algorithm::ES256K)
}

// -----------------------------------------------------------------------------
// RFC 7800 cnf + RFC 9449 DPoP
// -----------------------------------------------------------------------------

///|
test "cnf: rfc9068 token surfaces cnf.jkt" {
  let now = 1_700_000_000L
  let secret : Bytes = b"cnf-test"
  let cnf : Map[String, Json] = Map([])
  cnf["jkt"] = Json::string("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["sub"] = Json::string("u")
  m["aud"] = Json::string("https://rs.example.com/")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("j1")
  m["client_id"] = Json::string("c1")
  m["cnf"] = Json::object(cnf)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~), typ="at+jwt")
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now, "https://as.example.com/", "https://rs.example.com/",
  )
  let t = @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts)
  match t.cnf {
    Some(c) =>
      @debug.assert_eq(
        c.jkt,
        Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"),
      )
    None => abort("cnf missing")
  }
}

///|
fn make_ed25519_dpop_proof(
  sk : @ed25519.PrivateKey,
  htm : String,
  htu : String,
  iat : Int64,
  ath? : String? = None,
  nonce? : String? = None,
) -> String {
  let pk = sk.public_key()
  let pk_bytes = pk.to_bytes()
  let x_b64u = {
    let s = @base64.encode(pk_bytes[:], padding=false)
    let buf = StringBuilder::new()
    for c in s {
      let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
      buf.write_char(c2)
    }
    buf.to_string()
  }
  // Inline JWK in header. Sort fields lexicographically as RFC 7638
  // canonical form expects (kty, crv, x).
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("EdDSA")
  header["typ"] = Json::string("dpop+jwt")
  let jwk : Map[String, Json] = Map([])
  jwk["kty"] = Json::string("OKP")
  jwk["crv"] = Json::string("Ed25519")
  jwk["x"] = Json::string(x_b64u)
  header["jwk"] = Json::object(jwk)
  let claims : Map[String, Json] = Map([])
  claims["htm"] = Json::string(htm)
  claims["htu"] = Json::string(htu)
  claims["iat"] = Json::number(iat.to_double())
  claims["jti"] = Json::string("dpop-jti-1")
  match ath {
    Some(s) => claims["ath"] = Json::string(s)
    None => ()
  }
  match nonce {
    Some(s) => claims["nonce"] = Json::string(s)
    None => ()
  }
  // Manually assemble the JWS so we can use a custom header (sign() only
  // emits typ/alg/kid). base64url encode header + payload, sign EdDSA.
  let b64u = fn(b : Bytes) -> String {
    let s = @base64.encode(b[:], padding=false)
    let out = StringBuilder::new()
    for c in s {
      let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
      out.write_char(c2)
    }
    out.to_string()
  }
  let header_b64 = b64u(@utf8.encode(Json::object(header).stringify()[:]))
  let claims_b64 = b64u(@utf8.encode(Json::object(claims).stringify()[:]))
  let signing_input = header_b64 + "." + claims_b64
  let signature = sk.sign(@utf8.encode(signing_input[:]))
  signing_input + "." + b64u(signature)
}

///|
fn dpop_header_json_for_test(sk : @ed25519.PrivateKey) -> String {
  let x = b64u_encode(sk.public_key().to_bytes())
  "{\"alg\":\"EdDSA\",\"typ\":\"dpop+jwt\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" +
  x +
  "\"}}"
}

///|
fn dpop_opts_for_test(now : Int64) -> @jwt.DpopVerifyOptions {
  {
    now,
    max_iat_age_sec: 30L,
    clock_skew_sec: 0L,
    http_method: "POST",
    http_uri: "https://rs.example.com/resource",
    bound_access_token: None,
    expected_jkt: None,
    expected_nonce: None,
    allowed_algorithms: Some([@jwt.Algorithm::EdDSA]),
  }
}

///|
test "dpop: happy path verifies proof + htm/htu/iat" {
  let seed = Bytes::makei(32, fn(i) { (i + 11).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let now = 1_700_000_000L
  let proof = make_ed25519_dpop_proof(
    sk, "POST", "https://rs.example.com/resource", now,
  )
  let opts : @jwt.DpopVerifyOptions = {
    now,
    max_iat_age_sec: 30L,
    clock_skew_sec: 0L,
    http_method: "POST",
    http_uri: "https://rs.example.com/resource",
    bound_access_token: None,
    expected_jkt: None,
    expected_nonce: None,
    allowed_algorithms: None,
  }
  let r = @jwt.verify_dpop_proof(proof, opts)
  @debug.assert_eq(r.htm, "POST")
  @debug.assert_eq(r.htu, "https://rs.example.com/resource")
}

///|
test "ATTACK dpop: duplicate embedded jwk members reject before map collapse" {
  let seed = Bytes::makei(32, fn(i) { (i + 12).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let x = b64u_encode(sk.public_key().to_bytes())
  let now = 1_700_000_000L
  let header_json = "{\"alg\":\"EdDSA\",\"typ\":\"dpop+jwt\",\"jwk\":{\"kty\":\"OKP\",\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" +
    x +
    "\"}}"
  let payload_json = "{\"htm\":\"POST\",\"htu\":\"https://rs.example.com/resource\",\"iat\":1700000000,\"jti\":\"dup-jwk\"}"
  let proof = sign_ed25519_token_with_raw_json(header_json, payload_json, sk)
  let opts : @jwt.DpopVerifyOptions = {
    now,
    max_iat_age_sec: 30L,
    clock_skew_sec: 0L,
    http_method: "POST",
    http_uri: "https://rs.example.com/resource",
    bound_access_token: None,
    expected_jkt: None,
    expected_nonce: None,
    allowed_algorithms: Some([@jwt.Algorithm::EdDSA]),
  }
  try @jwt.verify_dpop_proof(proof, opts) catch {
    InvalidHeader(_) => ()
    InvalidDpopProof(_) => ()
    other => abort("expected duplicate jwk rejection, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted DPoP proof with duplicate embedded jwk member")
  }
}

///|
test "ATTACK dpop: embedded public jwk rejects private key material" {
  let seed = Bytes::makei(32, fn(i) { (i + 21).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let x = b64u_encode(sk.public_key().to_bytes())
  let d = b64u_encode(seed)
  let now = 1_700_000_000L
  let header_json = "{\"alg\":\"EdDSA\",\"typ\":\"dpop+jwt\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" +
    x +
    "\",\"d\":\"" +
    d +
    "\"}}"
  let payload_json = "{\"htm\":\"POST\",\"htu\":\"https://rs.example.com/resource\",\"iat\":1700000000,\"jti\":\"private-jwk\"}"
  let proof = sign_ed25519_token_with_raw_json(header_json, payload_json, sk)
  try @jwt.verify_dpop_proof(proof, dpop_opts_for_test(now)) catch {
    InvalidDpopProof(_) => ()
    other => abort("expected InvalidDpopProof, got " + repr(other) + "")
  } noraise {
    _ =>
      abort(
        "accepted DPoP proof whose inline jwk contained private key material",
      )
  }
}

///|
test "ATTACK dpop: malformed jwk header shape is rejected" {
  let seed = Bytes::makei(32, fn(i) { (i + 13).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let now = 1_700_000_000L
  let header_json = "{\"alg\":\"EdDSA\",\"typ\":\"dpop+jwt\",\"jwk\":[]}"
  let payload_json = "{\"htm\":\"POST\",\"htu\":\"https://rs.example.com/resource\",\"iat\":1700000000,\"jti\":\"bad-jwk-shape\"}"
  let proof = sign_ed25519_token_with_raw_json(header_json, payload_json, sk)
  try @jwt.verify_dpop_proof(proof, dpop_opts_for_test(now)) catch {
    InvalidDpopProof(_) => ()
    other => abort("expected InvalidDpopProof, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted DPoP proof with non-object jwk header")
  }
}

///|
test "ATTACK dpop: non-string htm claim is rejected" {
  let seed = Bytes::makei(32, fn(i) { (i + 14).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let now = 1_700_000_000L
  let payload_json = "{\"htm\":42,\"htu\":\"https://rs.example.com/resource\",\"iat\":1700000000,\"jti\":\"bad-htm-shape\"}"
  let proof = sign_ed25519_token_with_raw_json(
    dpop_header_json_for_test(sk),
    payload_json,
    sk,
  )
  try @jwt.verify_dpop_proof(proof, dpop_opts_for_test(now)) catch {
    InvalidDpopProof(_) => ()
    other => abort("expected InvalidDpopProof, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted DPoP proof with non-string htm")
  }
}

///|
test "ATTACK dpop: malformed optional string claims are rejected" {
  let seed = Bytes::makei(32, fn(i) { (i + 16).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let now = 1_700_000_000L
  for key in ["nonce", "ath"] {
    let payload_json = "{\"htm\":\"POST\",\"htu\":\"https://rs.example.com/resource\",\"iat\":1700000000,\"jti\":\"bad-" +
      key +
      "-shape\",\"" +
      key +
      "\":42}"
    let proof = sign_ed25519_token_with_raw_json(
      dpop_header_json_for_test(sk),
      payload_json,
      sk,
    )
    try @jwt.verify_dpop_proof(proof, dpop_opts_for_test(now)) catch {
      InvalidDpopProof(_) => ()
      other =>
        abort("expected InvalidDpopProof for " + key + ", got " + repr(other))
    } noraise {
      _ => abort("accepted DPoP proof with malformed " + key)
    }
  }
}

///|
test "ATTACK dpop: non-numeric iat claim is rejected" {
  let seed = Bytes::makei(32, fn(i) { (i + 17).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let now = 1_700_000_000L
  let payload_json = "{\"htm\":\"POST\",\"htu\":\"https://rs.example.com/resource\",\"iat\":\"1700000000\",\"jti\":\"bad-iat-shape\"}"
  let proof = sign_ed25519_token_with_raw_json(
    dpop_header_json_for_test(sk),
    payload_json,
    sk,
  )
  try @jwt.verify_dpop_proof(proof, dpop_opts_for_test(now)) catch {
    InvalidDpopProof(_) => ()
    other => abort("expected InvalidDpopProof, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted DPoP proof with non-numeric iat")
  }
}

///|
test "dpop: nonce, ath, jkt, and alg policy bindings reject attacker proof" {
  let seed = Bytes::makei(32, fn(i) { (i + 16).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let now = 1_700_000_000L
  let proof = make_ed25519_dpop_proof(
    sk, "GET", "https://rs.example.com/resource", now,
  )
  let base_opts : @jwt.DpopVerifyOptions = {
    now,
    max_iat_age_sec: 30L,
    clock_skew_sec: 0L,
    http_method: "GET",
    http_uri: "https://rs.example.com/resource",
    bound_access_token: None,
    expected_jkt: None,
    expected_nonce: None,
    allowed_algorithms: Some([@jwt.Algorithm::EdDSA]),
  }
  let ok = @jwt.verify_dpop_proof(proof, base_opts)
  @debug.assert_eq(ok.htm, "GET")

  let nonce_opts : @jwt.DpopVerifyOptions = {
    ..base_opts,
    expected_nonce: Some("server-nonce"),
  }
  try @jwt.verify_dpop_proof(proof, nonce_opts) catch {
    InvalidDpopProof(_) => ()
    e => abort("expected InvalidDpopProof, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidDpopProof, got Ok")
  }

  let ath_opts : @jwt.DpopVerifyOptions = {
    ..base_opts,
    bound_access_token: Some("access-token"),
  }
  try @jwt.verify_dpop_proof(proof, ath_opts) catch {
    InvalidDpopProof(_) => ()
    e => abort("expected InvalidDpopProof, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidDpopProof, got Ok")
  }

  let jkt_opts : @jwt.DpopVerifyOptions = {
    ..base_opts,
    expected_jkt: Some("not-the-proof-key"),
  }
  try @jwt.verify_dpop_proof(proof, jkt_opts) catch {
    CnfJktMismatch => ()
    e => abort("expected CnfJktMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected CnfJktMismatch, got Ok")
  }

  let alg_opts : @jwt.DpopVerifyOptions = {
    ..base_opts,
    allowed_algorithms: Some([@jwt.Algorithm::ES256]),
  }
  try @jwt.verify_dpop_proof(proof, alg_opts) catch {
    InvalidDpopProof(_) => ()
    e => abort("expected InvalidDpopProof, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidDpopProof, got Ok")
  }
}

///|
test "dpop: htm mismatch rejected" {
  let seed = Bytes::makei(32, fn(i) { (i + 12).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let now = 1_700_000_000L
  let proof = make_ed25519_dpop_proof(
    sk, "POST", "https://rs.example.com/resource", now,
  )
  let opts : @jwt.DpopVerifyOptions = {
    now,
    max_iat_age_sec: 30L,
    clock_skew_sec: 0L,
    http_method: "GET", // request says GET, proof says POST
    http_uri: "https://rs.example.com/resource",
    bound_access_token: None,
    expected_jkt: None,
    expected_nonce: None,
    allowed_algorithms: None,
  }
  try @jwt.verify_dpop_proof(proof, opts) catch {
    InvalidDpopProof(_) => ()
    e => abort("expected InvalidDpopProof, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidDpopProof, got Ok")
  }
}

///|
test "dpop: iat too old rejected" {
  let seed = Bytes::makei(32, fn(i) { (i + 13).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let now = 1_700_000_000L
  let proof = make_ed25519_dpop_proof(
    sk,
    "GET",
    "https://rs.example.com/x",
    now - 600L, // 10 minutes ago
  )
  let opts : @jwt.DpopVerifyOptions = {
    now,
    max_iat_age_sec: 60L,
    clock_skew_sec: 0L,
    http_method: "GET",
    http_uri: "https://rs.example.com/x",
    bound_access_token: None,
    expected_jkt: None,
    expected_nonce: None,
    allowed_algorithms: None,
  }
  try @jwt.verify_dpop_proof(proof, opts) catch {
    InvalidDpopProof(_) => ()
    e => abort("expected InvalidDpopProof, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidDpopProof, got Ok")
  }
}

///|
test "dpop: ath binds proof to access_token" {
  let seed = Bytes::makei(32, fn(i) { (i + 14).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let now = 1_700_000_000L
  let access_token = "this-is-an-access-token"
  let h = @hash.sha256(@utf8.encode(access_token[:]))
  let ath = {
    let s = @base64.encode(h[:], padding=false)
    let buf = StringBuilder::new()
    for c in s {
      let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
      buf.write_char(c2)
    }
    buf.to_string()
  }
  let proof = make_ed25519_dpop_proof(
    sk,
    "GET",
    "https://rs.example.com/resource",
    now,
    ath=Some(ath),
  )
  let unbound_opts : @jwt.DpopVerifyOptions = {
    now,
    max_iat_age_sec: 30L,
    clock_skew_sec: 0L,
    http_method: "GET",
    http_uri: "https://rs.example.com/resource",
    bound_access_token: None,
    expected_jkt: None,
    expected_nonce: None,
    allowed_algorithms: None,
  }
  let unbound = @jwt.verify_dpop_proof(proof, unbound_opts)
  let missing_jkt_opts : @jwt.DpopVerifyOptions = {
    ..unbound_opts,
    bound_access_token: Some(access_token),
  }
  try @jwt.verify_dpop_proof(proof, missing_jkt_opts) catch {
    InvalidDpopProof(_) => ()
    e => abort("expected InvalidDpopProof, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected DPoP jkt binding requirement")
  }
  let opts : @jwt.DpopVerifyOptions = {
    ..missing_jkt_opts,
    expected_jkt: Some(unbound.jkt),
  }
  let r = @jwt.verify_dpop_proof(proof, opts)
  @debug.assert_eq(r.ath, Some(ath))
}

///|
test "dpop: wrong ath against bound_access_token rejected" {
  let seed = Bytes::makei(32, fn(i) { (i + 15).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let now = 1_700_000_000L
  // Compute ath for the WRONG access token and embed it.
  let h = @hash.sha256(@utf8.encode("other-token"[:]))
  let ath = {
    let s = @base64.encode(h[:], padding=false)
    let buf = StringBuilder::new()
    for c in s {
      let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
      buf.write_char(c2)
    }
    buf.to_string()
  }
  let proof = make_ed25519_dpop_proof(
    sk,
    "GET",
    "https://rs.example.com/resource",
    now,
    ath=Some(ath),
  )
  let opts : @jwt.DpopVerifyOptions = {
    now,
    max_iat_age_sec: 30L,
    clock_skew_sec: 0L,
    http_method: "GET",
    http_uri: "https://rs.example.com/resource",
    bound_access_token: Some("real-token"), // mismatch
    expected_jkt: None,
    expected_nonce: None,
    allowed_algorithms: None,
  }
  try @jwt.verify_dpop_proof(proof, opts) catch {
    InvalidDpopProof(_) => ()
    e => abort("expected InvalidDpopProof, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidDpopProof, got Ok")
  }
}

///|
test "dpop: HMAC alg in proof rejected" {
  // DPoP forbids symmetric algs. Build a synthetic HMAC proof and confirm
  // verify_dpop_proof refuses before signature work.
  let secret : Bytes = b"oops-hmac-dpop"
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["typ"] = Json::string("dpop+jwt")
  // jwk is a placeholder (HMAC has no jwk shape anyway); the alg check
  // should fire first.
  let jwk : Map[String, Json] = Map([])
  jwk["kty"] = Json::string("oct")
  header["jwk"] = Json::object(jwk)
  let claims : Map[String, Json] = Map([])
  claims["htm"] = Json::string("GET")
  claims["htu"] = Json::string("https://rs.example.com/r")
  claims["iat"] = Json::number(1_700_000_000.0)
  claims["jti"] = Json::string("j")
  let b64u = fn(b : Bytes) -> String {
    let s = @base64.encode(b[:], padding=false)
    let buf = StringBuilder::new()
    for c in s {
      let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
      buf.write_char(c2)
    }
    buf.to_string()
  }
  let header_b64 = b64u(@utf8.encode(Json::object(header).stringify()[:]))
  let claims_b64 = b64u(@utf8.encode(Json::object(claims).stringify()[:]))
  let signing_input = header_b64 + "." + claims_b64
  let sig = @hash.hmac_sha256(secret, @utf8.encode(signing_input[:]))
  let proof = signing_input + "." + b64u(sig)
  let opts : @jwt.DpopVerifyOptions = {
    now: 1_700_000_000L,
    max_iat_age_sec: 30L,
    clock_skew_sec: 0L,
    http_method: "GET",
    http_uri: "https://rs.example.com/r",
    bound_access_token: None,
    expected_jkt: None,
    expected_nonce: None,
    allowed_algorithms: None,
  }
  try @jwt.verify_dpop_proof(proof, opts) catch {
    InvalidDpopProof(_) => ()
    e => abort("expected InvalidDpopProof, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidDpopProof, got Ok")
  }
}

// -----------------------------------------------------------------------------
// OIDC Back-Channel Logout 1.0 — Logout Token
// -----------------------------------------------------------------------------

///|
fn logout_token_claims(
  now : Int64,
  sub? : String? = None,
  sid? : String? = None,
) -> Json {
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("logout-jti-1")
  let events : Map[String, Json] = Map([])
  events["http://schemas.openid.net/event/backchannel-logout"] = Json::object(
    Map([]),
  )
  m["events"] = Json::object(events)
  match sub {
    Some(s) => m["sub"] = Json::string(s)
    None => ()
  }
  match sid {
    Some(s) => m["sid"] = Json::string(s)
    None => ()
  }
  Json::object(m)
}

///|
test "logout-token: happy path with sub" {
  let now = 1_700_000_000L
  let secret : Bytes = b"logout-test-secret"
  let payload = logout_token_claims(now, sub=Some("user-42"))
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), typ="logout+jwt")
  let opts = @jwt.LogoutTokenVerifyOptions::default(
    now, "https://as.example.com/", "client-abc",
  )
  let l = @jwt.verify_logout_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  @debug.assert_eq(l.sub, Some("user-42"))
  @debug.assert_eq(l.jti, "logout-jti-1")
}

///|
test "logout-token: jwks path verifies and stale iat rejects" {
  let now = 1_700_000_000L
  let secret : Bytes = b"logout-jwks-secret"
  let payload = logout_token_claims(now, sub=Some("user-42"))
  let token = @jwt.sign(
    payload,
    @jwt.Key::Hs256(secret~),
    typ="logout+jwt",
    kid="logout-kid",
  )
  let jwks = "{ \"keys\": [ { \"kty\": \"oct\", \"kid\": \"logout-kid\", \"alg\": \"HS256\", \"k\": \"" +
    b64u_encode(secret) +
    "\" } ] }"
  let set = @jwk.parse_set(jwks)
  let opts : @jwt.LogoutTokenVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://as.example.com/",
    client_id: "client-abc",
    max_iat_age_sec: Some(300L),
    allowed_algorithms: Some([@jwt.Algorithm::HS256]),
  }
  let l = @jwt.verify_logout_token_jwks(token, set, opts)
  @debug.assert_eq(l.sub, Some("user-42"))
  let stale_opts : @jwt.LogoutTokenVerifyOptions = {
    ..opts,
    now: now + 120L,
    max_iat_age_sec: Some(60L),
  }
  try @jwt.verify_logout_token_jwks(token, set, stale_opts) catch {
    IssuedInFuture => ()
    e => abort("expected stale iat rejection, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected stale iat rejection, got Ok")
  }
}

///|
test "logout-token: nonce present rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"logout-with-nonce"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("j")
  m["sub"] = Json::string("u")
  m["nonce"] = Json::string("definitely-not-allowed-here")
  let events : Map[String, Json] = Map([])
  events["http://schemas.openid.net/event/backchannel-logout"] = Json::object(
    Map([]),
  )
  m["events"] = Json::object(events)
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="logout+jwt",
  )
  let opts = @jwt.LogoutTokenVerifyOptions::default(
    now, "https://as.example.com/", "client-abc",
  )
  try
    @jwt.verify_logout_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    LogoutTokenForbiddenNonce => ()
    e => abort("expected LogoutTokenForbiddenNonce, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected LogoutTokenForbiddenNonce, got Ok")
  }
}

///|
test "logout-token: missing events claim rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"logout-no-events"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("j")
  m["sub"] = Json::string("u")
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="logout+jwt",
  )
  let opts = @jwt.LogoutTokenVerifyOptions::default(
    now, "https://as.example.com/", "client-abc",
  )
  try
    @jwt.verify_logout_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    MissingLogoutEvent => ()
    e => abort("expected MissingLogoutEvent, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected MissingLogoutEvent, got Ok")
  }
}

///|
test "logout-token: events object without logout member rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"logout-wrong-event"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("j")
  m["sub"] = Json::string("u")
  let events : Map[String, Json] = Map([])
  events["https://example.com/not-logout"] = Json::object(Map([]))
  m["events"] = Json::object(events)
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="logout+jwt",
  )
  let opts = @jwt.LogoutTokenVerifyOptions::default(
    now, "https://as.example.com/", "client-abc",
  )
  try
    @jwt.verify_logout_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    MissingLogoutEvent => ()
    e => abort("expected MissingLogoutEvent, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected MissingLogoutEvent, got Ok")
  }
}

///|
test "ATTACK logout-token: logout event member must be an object" {
  let now = 1_700_000_000L
  let secret : Bytes = b"logout-event-shape"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["iat"] = Json::number(now.to_double())
  m["jti"] = Json::string("j")
  m["sub"] = Json::string("u")
  let events : Map[String, Json] = Map([])
  events["http://schemas.openid.net/event/backchannel-logout"] = Json::string(
    "not-an-object",
  )
  m["events"] = Json::object(events)
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="logout+jwt",
  )
  let opts = @jwt.LogoutTokenVerifyOptions::default(
    now, "https://as.example.com/", "client-abc",
  )
  try
    @jwt.verify_logout_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    MissingLogoutEvent => ()
    e => abort("expected MissingLogoutEvent, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected MissingLogoutEvent, got Ok")
  }
}

///|
test "ATTACK logout-token: generic security event typ cannot be replayed as logout" {
  let now = 1_700_000_000L
  let secret : Bytes = b"logout-secevent"
  let payload = logout_token_claims(now, sub=Some("user-42"))
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), typ="secevent+jwt")
  let opts = @jwt.LogoutTokenVerifyOptions::default(
    now, "https://as.example.com/", "client-abc",
  )
  try
    @jwt.verify_logout_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType, got Ok")
  }
}

///|
test "logout-token: both sub and sid missing rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"logout-no-subject"
  let payload = logout_token_claims(now) // sub=None, sid=None
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), typ="logout+jwt")
  let opts = @jwt.LogoutTokenVerifyOptions::default(
    now, "https://as.example.com/", "client-abc",
  )
  try
    @jwt.verify_logout_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    LogoutSubAndSidMissing => ()
    e => abort("expected LogoutSubAndSidMissing, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected LogoutSubAndSidMissing, got Ok")
  }
}

///|
test "ATTACK logout-token: malformed optional subject identifiers are rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"logout-subject-shape"
  let opts = @jwt.LogoutTokenVerifyOptions::default(
    now, "https://as.example.com/", "client-abc",
  )

  let bad_sub : Map[String, Json] = Map([])
  bad_sub["iss"] = Json::string("https://as.example.com/")
  bad_sub["aud"] = Json::string("client-abc")
  bad_sub["iat"] = Json::number(now.to_double())
  bad_sub["jti"] = Json::string("j")
  bad_sub["sub"] = Json::number(42.0)
  bad_sub["sid"] = Json::string("session-1")
  let events1 : Map[String, Json] = Map([])
  events1["http://schemas.openid.net/event/backchannel-logout"] = Json::object(
    Map([]),
  )
  bad_sub["events"] = Json::object(events1)
  let bad_sub_token = @jwt.sign(
    Json::object(bad_sub),
    @jwt.Key::Hs256(secret~),
    typ="logout+jwt",
  )
  try
    @jwt.verify_logout_token(
      bad_sub_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError for sub, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted logout token with malformed sub")
  }

  let bad_sid : Map[String, Json] = Map([])
  bad_sid["iss"] = Json::string("https://as.example.com/")
  bad_sid["aud"] = Json::string("client-abc")
  bad_sid["iat"] = Json::number(now.to_double())
  bad_sid["jti"] = Json::string("j")
  bad_sid["sub"] = Json::string("user-42")
  bad_sid["sid"] = Json::number(42.0)
  let events2 : Map[String, Json] = Map([])
  events2["http://schemas.openid.net/event/backchannel-logout"] = Json::object(
    Map([]),
  )
  bad_sid["events"] = Json::object(events2)
  let bad_sid_token = @jwt.sign(
    Json::object(bad_sid),
    @jwt.Key::Hs256(secret~),
    typ="logout+jwt",
  )
  try
    @jwt.verify_logout_token(
      bad_sid_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError for sid, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted logout token with malformed sid")
  }
}

// -----------------------------------------------------------------------------
// OIDC UserInfo signed-JWT response (Core §5.3.2)
// -----------------------------------------------------------------------------

///|
test "userinfo-jws: sub mismatch rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"userinfo-test"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["sub"] = Json::string("attacker-substituted-sub")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.UserInfoVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://as.example.com/",
    client_id: "client-abc",
    expected_sub: "real-user-from-id-token",
    allowed_algorithms: None,
  }
  try
    @jwt.verify_userinfo_jws(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    UserInfoSubMismatch => ()
    e => abort("expected UserInfoSubMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected UserInfoSubMismatch, got Ok")
  }
}

///|
test "userinfo-jws: matching sub verifies and surfaces profile claims" {
  let now = 1_700_000_000L
  let secret : Bytes = b"userinfo-ok"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["sub"] = Json::string("user-42")
  m["email"] = Json::string("u@example.com")
  m["email_verified"] = Json::boolean(true)
  m["name"] = Json::string("User 42")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.UserInfoVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://as.example.com/",
    client_id: "client-abc",
    expected_sub: "user-42",
    allowed_algorithms: None,
  }
  let u = @jwt.verify_userinfo_jws(token, @jwt.VerifyKey::Hs256(secret~), opts)
  @debug.assert_eq(u.email, Some("u@example.com"))
  @debug.assert_eq(u.email_verified, Some(true))
  @debug.assert_eq(u.name, Some("User 42"))
}

///|
test "ATTACK userinfo-jws: malformed email_verified is rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"userinfo-email-verified-shape"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["sub"] = Json::string("user-42")
  m["email"] = Json::string("u@example.com")
  m["email_verified"] = Json::string("true")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.UserInfoVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://as.example.com/",
    client_id: "client-abc",
    expected_sub: "user-42",
    allowed_algorithms: None,
  }
  try
    @jwt.verify_userinfo_jws(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted UserInfo with malformed email_verified")
  }
}

///|
test "ATTACK userinfo-jws: malformed optional string claims are rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"userinfo-optional-string-shape"
  let opts : @jwt.UserInfoVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://as.example.com/",
    client_id: "client-abc",
    expected_sub: "user-42",
    allowed_algorithms: None,
  }
  for key in ["email", "name", "preferred_username"] {
    let m : Map[String, Json] = Map([])
    m["iss"] = Json::string("https://as.example.com/")
    m["aud"] = Json::string("client-abc")
    m["sub"] = Json::string("user-42")
    m[key] = Json::number(42.0)
    let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
    try
      @jwt.verify_userinfo_jws(token, @jwt.VerifyKey::Hs256(secret~), opts)
    catch {
      ClaimsParseError(_) => ()
      e => abort("expected ClaimsParseError for " + key + ", got " + repr(e))
    } noraise {
      _ => abort("accepted UserInfo with malformed " + key)
    }
  }
}

///|
test "userinfo-jws: jwks path and algorithm allow-list" {
  let now = 1_700_000_000L
  let secret : Bytes = b"userinfo-jwks-secret"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["sub"] = Json::string("user-42")
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    kid="userinfo-kid",
  )
  let jwks = "{ \"keys\": [ { \"kty\": \"oct\", \"kid\": \"userinfo-kid\", \"alg\": \"HS256\", \"k\": \"" +
    b64u_encode(secret) +
    "\" } ] }"
  let set = @jwk.parse_set(jwks)
  let opts : @jwt.UserInfoVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://as.example.com/",
    client_id: "client-abc",
    expected_sub: "user-42",
    allowed_algorithms: Some([@jwt.Algorithm::HS256]),
  }
  let u = @jwt.verify_userinfo_jws_jwks(token, set, opts)
  @debug.assert_eq(u.sub, "user-42")
  let bad_opts : @jwt.UserInfoVerifyOptions = {
    ..opts,
    allowed_algorithms: Some([@jwt.Algorithm::EdDSA]),
  }
  try @jwt.verify_userinfo_jws_jwks(token, set, bad_opts) catch {
    AlgorithmNotAllowed(_) => ()
    e => abort("expected AlgorithmNotAllowed, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AlgorithmNotAllowed, got Ok")
  }
}

///|
test "ATTACK userinfo-jws: same sub from wrong issuer or audience rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"userinfo-substitution"
  let opts : @jwt.UserInfoVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    issuer: "https://as.example.com/",
    client_id: "client-abc",
    expected_sub: "user-42",
    allowed_algorithms: None,
  }

  let wrong_issuer : Map[String, Json] = Map([])
  wrong_issuer["iss"] = Json::string("https://evil.example.com/")
  wrong_issuer["aud"] = Json::string("client-abc")
  wrong_issuer["sub"] = Json::string("user-42")
  let wrong_issuer_token = @jwt.sign(
    Json::object(wrong_issuer),
    @jwt.Key::Hs256(secret~),
  )
  try
    @jwt.verify_userinfo_jws(
      wrong_issuer_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    InvalidIssuer => ()
    e => abort("expected InvalidIssuer, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidIssuer, got Ok")
  }

  let wrong_aud : Map[String, Json] = Map([])
  wrong_aud["iss"] = Json::string("https://as.example.com/")
  wrong_aud["aud"] = Json::string("other-client")
  wrong_aud["sub"] = Json::string("user-42")
  let wrong_aud_token = @jwt.sign(
    Json::object(wrong_aud),
    @jwt.Key::Hs256(secret~),
  )
  try
    @jwt.verify_userinfo_jws(
      wrong_aud_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    InvalidAudience => ()
    e => abort("expected InvalidAudience, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidAudience, got Ok")
  }
}

// -----------------------------------------------------------------------------
// RFC 9101 JAR — Request Object
// -----------------------------------------------------------------------------

///|
test "JAR: request object verifies and exposes params" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jar-test"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("client-abc")
  m["aud"] = Json::string("https://as.example.com/")
  m["exp"] = Json::number((now + 300L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["response_type"] = Json::string("code")
  m["client_id"] = Json::string("client-abc")
  m["redirect_uri"] = Json::string("https://rp.example.com/cb")
  m["scope"] = Json::string("openid profile")
  m["state"] = Json::string("state-xyz")
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="oauth-authz-req+jwt",
  )
  let opts = @jwt.RequestObjectVerifyOptions::default(
    now, "client-abc", "https://as.example.com/",
  )
  let r = @jwt.verify_request_object(
    token,
    @jwt.VerifyKey::Hs256(secret~),
    opts,
  )
  @debug.assert_eq(r.client_id, "client-abc")
  match r.params.get("response_type") {
    Some(String(s)) => @debug.assert_eq(s, "code")
    _ => abort("missing response_type")
  }
}

///|
test "JAR: missing client_id claim is allowed but alg policy is enforced" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jar-no-client-id"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("client-abc")
  m["aud"] = Json::string("https://as.example.com/")
  m["exp"] = Json::number((now + 300L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["response_type"] = Json::string("code")
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="oauth-authz-req+jwt",
  )
  let opts : @jwt.RequestObjectVerifyOptions = {
    ..@jwt.RequestObjectVerifyOptions::default(
      now, "client-abc", "https://as.example.com/",
    ),
    allowed_algorithms: Some([@jwt.Algorithm::HS256]),
  }
  let r = @jwt.verify_request_object(
    token,
    @jwt.VerifyKey::Hs256(secret~),
    opts,
  )
  @debug.assert_eq(r.client_id, "client-abc")
  let bad_opts : @jwt.RequestObjectVerifyOptions = {
    ..opts,
    allowed_algorithms: Some([@jwt.Algorithm::EdDSA]),
  }
  try
    @jwt.verify_request_object(token, @jwt.VerifyKey::Hs256(secret~), bad_opts)
  catch {
    AlgorithmNotAllowed(_) => ()
    e => abort("expected AlgorithmNotAllowed, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AlgorithmNotAllowed, got Ok")
  }
}

///|
test "ATTACK JAR: embedded client_id substitution rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jar-client-substitution"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("client-abc")
  m["aud"] = Json::string("https://as.example.com/")
  m["exp"] = Json::number((now + 300L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["response_type"] = Json::string("code")
  m["client_id"] = Json::string("attacker-client")
  m["redirect_uri"] = Json::string("https://attacker.example/cb")
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="oauth-authz-req+jwt",
  )
  let opts = @jwt.RequestObjectVerifyOptions::default(
    now, "client-abc", "https://as.example.com/",
  )
  try
    @jwt.verify_request_object(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    ClientIdMismatch => ()
    e => abort("expected ClientIdMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected ClientIdMismatch, got Ok")
  }
}

///|
test "ATTACK JAR: malformed embedded client_id is rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jar-client-shape"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("client-abc")
  m["aud"] = Json::string("https://as.example.com/")
  m["exp"] = Json::number((now + 300L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["response_type"] = Json::string("code")
  m["client_id"] = Json::number(42.0)
  m["redirect_uri"] = Json::string("https://client.example/cb")
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="oauth-authz-req+jwt",
  )
  let opts = @jwt.RequestObjectVerifyOptions::default(
    now, "client-abc", "https://as.example.com/",
  )
  try
    @jwt.verify_request_object(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted request object with malformed client_id")
  }
}

///|
test "ATTACK JAR: default options require request object typ" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jar-typ-required"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("client-abc")
  m["aud"] = Json::string("https://as.example.com/")
  m["exp"] = Json::number((now + 300L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["response_type"] = Json::string("code")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~)) // typ="JWT"
  let opts = @jwt.RequestObjectVerifyOptions::default(
    now, "client-abc", "https://as.example.com/",
  )
  try
    @jwt.verify_request_object(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType for generic JWT typ")
  }
}

///|
test "ATTACK JAR: missing exp and stale iat rejected by default options" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jar-replay-window"
  let opts = @jwt.RequestObjectVerifyOptions::default(
    now, "client-abc", "https://as.example.com/",
  )
  let no_exp : Map[String, Json] = Map([])
  no_exp["iss"] = Json::string("client-abc")
  no_exp["aud"] = Json::string("https://as.example.com/")
  no_exp["iat"] = Json::number(now.to_double())
  no_exp["response_type"] = Json::string("code")
  let no_exp_token = @jwt.sign(
    Json::object(no_exp),
    @jwt.Key::Hs256(secret~),
    typ="oauth-authz-req+jwt",
  )
  try
    @jwt.verify_request_object(
      no_exp_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected ClaimsParseError, got Ok")
  }

  let stale : Map[String, Json] = Map([])
  stale["iss"] = Json::string("client-abc")
  stale["aud"] = Json::string("https://as.example.com/")
  stale["exp"] = Json::number((now + 300L).to_double())
  stale["iat"] = Json::number((now - 600L).to_double())
  stale["response_type"] = Json::string("code")
  let stale_token = @jwt.sign(
    Json::object(stale),
    @jwt.Key::Hs256(secret~),
    typ="oauth-authz-req+jwt",
  )
  try
    @jwt.verify_request_object(
      stale_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    IssuedInFuture => ()
    e => abort("expected stale iat rejection, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected stale iat rejection, got Ok")
  }
}

// -----------------------------------------------------------------------------
// JARM
// -----------------------------------------------------------------------------

///|
test "JARM: authorization response verifies + state round-trip" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jarm-test"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 300L).to_double())
  m["code"] = Json::string("auth-code-xyz")
  m["state"] = Json::string("rp-state-xyz")
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="oauth-authz-resp+jwt",
  )
  let opts = @jwt.JarmVerifyOptions::strict(
    now, "https://as.example.com/", "client-abc", "rp-state-xyz",
  )
  let r = @jwt.verify_jarm(token, @jwt.VerifyKey::Hs256(secret~), opts)
  match r.params.get("code") {
    Some(String(c)) => @debug.assert_eq(c, "auth-code-xyz")
    _ => abort("missing code")
  }
}

///|
test "ATTACK JARM: strict options require authorization response typ" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jarm-typ-required"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 300L).to_double())
  m["code"] = Json::string("auth-code-xyz")
  m["state"] = Json::string("rp-state-xyz")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~)) // typ="JWT"
  let opts = @jwt.JarmVerifyOptions::strict(
    now, "https://as.example.com/", "client-abc", "rp-state-xyz",
  )
  try @jwt.verify_jarm(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType for generic JWT typ")
  }
}

///|
test "JARM: state mismatch rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jarm-state-mismatch"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 300L).to_double())
  m["state"] = Json::string("wrong-state")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.JarmVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_issuer: "https://as.example.com/",
    client_id: "client-abc",
    expected_state: Some("expected-state"),
    allowed_algorithms: None,
    typ_allowed: None,
  }
  try @jwt.verify_jarm(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected ClaimsParseError, got Ok")
  }
}

///|
test "JARM: expected state absent rejects, optional state accepts" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jarm-missing-state"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 300L).to_double())
  m["code"] = Json::string("auth-code")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let optional_opts : @jwt.JarmVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_issuer: "https://as.example.com/",
    client_id: "client-abc",
    expected_state: None,
    allowed_algorithms: Some([@jwt.Algorithm::HS256]),
    typ_allowed: None,
  }
  let r = @jwt.verify_jarm(token, @jwt.VerifyKey::Hs256(secret~), optional_opts)
  match r.params.get("code") {
    Some(String(c)) => @debug.assert_eq(c, "auth-code")
    _ => abort("missing code")
  }
  let required_opts : @jwt.JarmVerifyOptions = {
    ..optional_opts,
    expected_state: Some("rp-state"),
  }
  try
    @jwt.verify_jarm(token, @jwt.VerifyKey::Hs256(secret~), required_opts)
  catch {
    MissingRequiredClaim(c) => @debug.assert_eq(c, "state")
    e => abort("expected MissingRequiredClaim, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected MissingRequiredClaim, got Ok")
  }
  let bad_alg_opts : @jwt.JarmVerifyOptions = {
    ..optional_opts,
    allowed_algorithms: Some([@jwt.Algorithm::EdDSA]),
  }
  try
    @jwt.verify_jarm(token, @jwt.VerifyKey::Hs256(secret~), bad_alg_opts)
  catch {
    AlgorithmNotAllowed(_) => ()
    e => abort("expected AlgorithmNotAllowed, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AlgorithmNotAllowed, got Ok")
  }
}

///|
test "ATTACK JARM: malformed optional state is rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jarm-state-shape"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://as.example.com/")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 300L).to_double())
  m["code"] = Json::string("auth-code")
  m["state"] = Json::number(42.0)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.JarmVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_issuer: "https://as.example.com/",
    client_id: "client-abc",
    expected_state: None,
    allowed_algorithms: None,
    typ_allowed: None,
  }
  try @jwt.verify_jarm(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted JARM with malformed optional state")
  }
}

///|
test "ATTACK JARM: authorization response mix-up rejected by iss and aud" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jarm-mixup"
  let opts : @jwt.JarmVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_issuer: "https://as.example.com/",
    client_id: "client-abc",
    expected_state: Some("rp-state"),
    allowed_algorithms: None,
    typ_allowed: None,
  }

  let wrong_issuer : Map[String, Json] = Map([])
  wrong_issuer["iss"] = Json::string("https://evil.example.com/")
  wrong_issuer["aud"] = Json::string("client-abc")
  wrong_issuer["exp"] = Json::number((now + 300L).to_double())
  wrong_issuer["code"] = Json::string("attacker-code")
  wrong_issuer["state"] = Json::string("rp-state")
  let wrong_issuer_token = @jwt.sign(
    Json::object(wrong_issuer),
    @jwt.Key::Hs256(secret~),
  )
  try
    @jwt.verify_jarm(wrong_issuer_token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    InvalidIssuer => ()
    e => abort("expected InvalidIssuer, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidIssuer, got Ok")
  }

  let wrong_aud : Map[String, Json] = Map([])
  wrong_aud["iss"] = Json::string("https://as.example.com/")
  wrong_aud["aud"] = Json::string("other-client")
  wrong_aud["exp"] = Json::number((now + 300L).to_double())
  wrong_aud["code"] = Json::string("attacker-code")
  wrong_aud["state"] = Json::string("rp-state")
  let wrong_aud_token = @jwt.sign(
    Json::object(wrong_aud),
    @jwt.Key::Hs256(secret~),
  )
  try
    @jwt.verify_jarm(wrong_aud_token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    InvalidAudience => ()
    e => abort("expected InvalidAudience, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidAudience, got Ok")
  }
}

// -----------------------------------------------------------------------------
// OIDC Self-Issued OP v2
// -----------------------------------------------------------------------------

///|
fn self_issued_ed25519_fixture(
  now : Int64,
  sub_override? : String? = None,
  nonce? : String? = None,
  nonce_json? : Json? = None,
  include_sub_jwk? : Bool = true,
) -> (String, String) raise {
  let seed = Bytes::makei(32, fn(i) { (i + 99).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_bytes = sk.public_key().to_bytes()
  let sub_jwk : Map[String, Json] = Map([])
  sub_jwk["kty"] = Json::string("OKP")
  sub_jwk["crv"] = Json::string("Ed25519")
  sub_jwk["x"] = Json::string(b64u_encode(pk_bytes))
  let parsed = @jwk.parse_public(Json::object(sub_jwk).stringify())
  let thumb = @jwk.thumbprint_base64url(parsed)
  let claims : Map[String, Json] = Map([])
  claims["iss"] = Json::string("https://self-issued.me/v2")
  claims["sub"] = Json::string(
    match sub_override {
      Some(s) => s
      None => thumb
    },
  )
  if include_sub_jwk {
    claims["sub_jwk"] = Json::object(sub_jwk)
  }
  claims["aud"] = Json::string("rp-redirect-uri")
  claims["exp"] = Json::number((now + 300L).to_double())
  claims["iat"] = Json::number(now.to_double())
  match nonce_json {
    Some(v) => claims["nonce"] = v
    None =>
      match nonce {
        Some(n) => claims["nonce"] = Json::string(n)
        None => ()
      }
  }
  let token = @jwt.sign(Json::object(claims), @jwt.Key::EdDsa(privkey=sk))
  (token, thumb)
}

///|
test "siop-v2: sub == thumbprint(sub_jwk) verifies" {
  let now = 1_700_000_000L
  let seed = Bytes::makei(32, fn(i) { (i + 99).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  // Build sub_jwk for the holder's Ed25519 pubkey.
  let pk_bytes = pk.to_bytes()
  let b64u = fn(b : Bytes) -> String {
    let s = @base64.encode(b[:], padding=false)
    let buf = StringBuilder::new()
    for c in s {
      let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
      buf.write_char(c2)
    }
    buf.to_string()
  }
  let sub_jwk : Map[String, Json] = Map([])
  sub_jwk["kty"] = Json::string("OKP")
  sub_jwk["crv"] = Json::string("Ed25519")
  sub_jwk["x"] = Json::string(b64u(pk_bytes))
  // Compute the canonical thumbprint via @jwk.
  let parsed = @jwk.parse_public(Json::object(sub_jwk).stringify())
  let thumb = @jwk.thumbprint_base64url(parsed)
  let claims : Map[String, Json] = Map([])
  claims["iss"] = Json::string("https://self-issued.me/v2")
  claims["sub"] = Json::string(thumb)
  claims["sub_jwk"] = Json::object(sub_jwk)
  claims["aud"] = Json::string("rp-redirect-uri")
  claims["exp"] = Json::number((now + 300L).to_double())
  claims["iat"] = Json::number(now.to_double())
  let token = @jwt.sign(Json::object(claims), @jwt.Key::EdDsa(privkey=sk))
  let opts : @jwt.SelfIssuedVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_aud: Some("rp-redirect-uri"),
    expected_nonce: None,
    allowed_algorithms: None,
  }
  let s = @jwt.verify_self_issued_id_token(token, opts)
  @debug.assert_eq(s.sub, thumb)
  @debug.assert_eq(s.iss, "https://self-issued.me/v2")
}

///|
test "siop-v2: missing sub_jwk, sub mismatch, nonce mismatch, and alg policy reject" {
  let now = 1_700_000_000L
  let opts : @jwt.SelfIssuedVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_aud: Some("rp-redirect-uri"),
    expected_nonce: None,
    allowed_algorithms: None,
  }
  let (missing_sub_jwk, _) = self_issued_ed25519_fixture(
    now,
    include_sub_jwk=false,
  )
  try @jwt.verify_self_issued_id_token(missing_sub_jwk, opts) catch {
    MissingRequiredClaim(c) => @debug.assert_eq(c, "sub_jwk")
    e => abort("expected MissingRequiredClaim, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected MissingRequiredClaim, got Ok")
  }

  let (bad_sub, _) = self_issued_ed25519_fixture(
    now,
    sub_override=Some("not-the-thumbprint"),
  )
  try @jwt.verify_self_issued_id_token(bad_sub, opts) catch {
    SelfIssuedSubMismatch => ()
    e => abort("expected SelfIssuedSubMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected SelfIssuedSubMismatch, got Ok")
  }

  let (nonce_token, _) = self_issued_ed25519_fixture(
    now,
    nonce=Some("token-nonce"),
  )
  let nonce_opts : @jwt.SelfIssuedVerifyOptions = {
    ..opts,
    expected_nonce: Some("request-nonce"),
  }
  try @jwt.verify_self_issued_id_token(nonce_token, nonce_opts) catch {
    NonceMismatch => ()
    e => abort("expected NonceMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected NonceMismatch, got Ok")
  }

  let (valid_token, _) = self_issued_ed25519_fixture(now)
  let alg_opts : @jwt.SelfIssuedVerifyOptions = {
    ..opts,
    allowed_algorithms: Some([@jwt.Algorithm::HS256]),
  }
  try @jwt.verify_self_issued_id_token(valid_token, alg_opts) catch {
    AlgorithmNotAllowed(_) => ()
    e => abort("expected AlgorithmNotAllowed, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AlgorithmNotAllowed, got Ok")
  }
}

///|
test "ATTACK siop-v2: malformed optional nonce is rejected" {
  let now = 1_700_000_000L
  let (token, _) = self_issued_ed25519_fixture(
    now,
    nonce_json=Some(Json::number(42.0)),
  )
  let opts : @jwt.SelfIssuedVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    expected_aud: Some("rp-redirect-uri"),
    expected_nonce: None,
    allowed_algorithms: None,
  }
  try @jwt.verify_self_issued_id_token(token, opts) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted self-issued ID token with malformed optional nonce")
  }
}

///|
test "oidc encrypted id token: nested JWE wraps signed ID token" {
  let now = 1_700_000_000L
  let sign_secret : Bytes = b"oidc-inner-id-token-secret"
  let inner_payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    Map([]),
  )
  let inner = @jwt.sign(inner_payload, @jwt.Key::Hs256(secret=sign_secret))
  let cek = Bytes::makei(32, fn(i) { (i + 1).to_byte() })
  let iv = Bytes::makei(12, fn(i) { (i + 7).to_byte() })
  let extra_header : Map[String, Json] = Map([])
  extra_header["cty"] = Json::string("JWT")
  let outer = @jwe.encrypt(
    @utf8.encode(inner[:]),
    @jwe.JweAlg::Dir,
    @jwe.JweEnc::A256gcm,
    @jwe.EncryptionKey::EncDir(cek~),
    iv~,
    extra_header~,
  )
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  let id = @jwt.verify_oidc_id_token_encrypted(
    outer,
    @jwe.DecryptionKey::DecDir(cek~),
    @jwt.VerifyKey::Hs256(secret=sign_secret),
    opts,
  )
  @debug.assert_eq(id.sub, "user-42")
  let wrong_cek = Bytes::makei(32, fn(i) { (i + 33).to_byte() })
  try
    @jwt.verify_oidc_id_token_encrypted(
      outer,
      @jwe.DecryptionKey::DecDir(cek=wrong_cek),
      @jwt.VerifyKey::Hs256(secret=sign_secret),
      opts,
    )
  catch {
    InvalidToken(_) => ()
    e => abort("expected InvalidToken, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidToken, got Ok")
  }
}

///|
test "ATTACK encrypted id token: wrong outer cty and inner issuer rejected" {
  let now = 1_700_000_000L
  let sign_secret : Bytes = b"oidc-inner-mixup-secret"
  let cek = Bytes::makei(32, fn(i) { (i + 41).to_byte() })
  let iv = Bytes::makei(12, fn(i) { (i + 9).to_byte() })
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )

  let good_inner = @jwt.sign(
    oidc_id_token_claims(
      now,
      "https://accounts.example.com/",
      Json::string("client-abc"),
      Map([]),
    ),
    @jwt.Key::Hs256(secret=sign_secret),
  )
  let wrong_cty_header : Map[String, Json] = Map([])
  wrong_cty_header["cty"] = Json::string("text/plain")
  let wrong_cty = @jwe.encrypt(
    @utf8.encode(good_inner[:]),
    @jwe.JweAlg::Dir,
    @jwe.JweEnc::A256gcm,
    @jwe.EncryptionKey::EncDir(cek~),
    iv~,
    extra_header=wrong_cty_header,
  )
  try
    @jwt.verify_oidc_id_token_encrypted(
      wrong_cty,
      @jwe.DecryptionKey::DecDir(cek~),
      @jwt.VerifyKey::Hs256(secret=sign_secret),
      opts,
    )
  catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType, got Ok")
  }

  let evil_inner = @jwt.sign(
    oidc_id_token_claims(
      now,
      "https://evil.example.com/",
      Json::string("client-abc"),
      Map([]),
    ),
    @jwt.Key::Hs256(secret=sign_secret),
  )
  let nested_header : Map[String, Json] = Map([])
  nested_header["cty"] = Json::string("application/jwt")
  let nested = @jwe.encrypt(
    @utf8.encode(evil_inner[:]),
    @jwe.JweAlg::Dir,
    @jwe.JweEnc::A256gcm,
    @jwe.EncryptionKey::EncDir(cek~),
    iv~,
    extra_header=nested_header,
  )
  try
    @jwt.verify_oidc_id_token_encrypted(
      nested,
      @jwe.DecryptionKey::DecDir(cek~),
      @jwt.VerifyKey::Hs256(secret=sign_secret),
      opts,
    )
  catch {
    InvalidIssuer => ()
    e => abort("expected InvalidIssuer, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidIssuer, got Ok")
  }
}

// -----------------------------------------------------------------------------
// Aggregated / Distributed claims
// -----------------------------------------------------------------------------

///|
test "aggregated-distributed: parser extracts sources and names" {
  let claims : Map[String, Json] = Map([])
  let sources : Map[String, Json] = Map([])
  let src1 : Map[String, Json] = Map([])
  src1["JWT"] = Json::string("aggregated.jwt.here")
  sources["src1"] = Json::object(src1)
  let src2 : Map[String, Json] = Map([])
  src2["endpoint"] = Json::string("https://claims.example.com/age")
  src2["access_token"] = Json::string("ksj3n1v")
  sources["src2"] = Json::object(src2)
  claims["_claim_sources"] = Json::object(sources)
  let names : Map[String, Json] = Map([])
  names["address"] = Json::string("src1")
  names["birthdate"] = Json::string("src2")
  claims["_claim_names"] = Json::object(names)
  let ad = @jwt.extract_aggregated_distributed_claims(claims)
  match ad {
    Some(a) => {
      @debug.assert_eq(a.names.get("address"), Some("src1"))
      @debug.assert_eq(a.names.get("birthdate"), Some("src2"))
      match a.sources.get("src1") {
        Some(Aggregated(jwt~)) => @debug.assert_eq(jwt, "aggregated.jwt.here")
        _ => abort("expected Aggregated for src1")
      }
      match a.sources.get("src2") {
        Some(Distributed(endpoint~, access_token~)) => {
          @debug.assert_eq(endpoint, "https://claims.example.com/age")
          @debug.assert_eq(access_token, Some("ksj3n1v"))
        }
        _ => abort("expected Distributed for src2")
      }
    }
    None => abort("expected aggregated/distributed metadata")
  }
}

///|
test "aggregated-distributed: absent metadata returns None" {
  let empty : Map[String, Json] = Map([])
  match @jwt.extract_aggregated_distributed_claims(empty) {
    None => ()
    Some(_) => abort("expected no aggregated/distributed metadata")
  }
}

///|
test "ATTACK aggregated-distributed: malformed metadata is rejected" {
  let claims : Map[String, Json] = Map([])
  let sources : Map[String, Json] = Map([])
  sources["scalar"] = Json::string("not-an-object")
  let dist : Map[String, Json] = Map([])
  dist["endpoint"] = Json::string("https://claims.example.com/email")
  sources["dist"] = Json::object(dist)
  claims["_claim_sources"] = Json::object(sources)
  let names : Map[String, Json] = Map([])
  names["email"] = Json::string("dist")
  claims["_claim_names"] = Json::object(names)
  try @jwt.extract_aggregated_distributed_claims(claims) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted malformed claim source")
  }
}

///|
test "ATTACK aggregated-distributed: ambiguous and dangling metadata is rejected" {
  let ambiguous : Map[String, Json] = Map([])
  let sources1 : Map[String, Json] = Map([])
  let src1 : Map[String, Json] = Map([])
  src1["JWT"] = Json::string("aggregated.jwt")
  src1["endpoint"] = Json::string("https://claims.example.com")
  sources1["src1"] = Json::object(src1)
  ambiguous["_claim_sources"] = Json::object(sources1)
  let names1 : Map[String, Json] = Map([])
  names1["email"] = Json::string("src1")
  ambiguous["_claim_names"] = Json::object(names1)
  try @jwt.extract_aggregated_distributed_claims(ambiguous) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted claim source with both JWT and endpoint")
  }

  let dangling : Map[String, Json] = Map([])
  let sources2 : Map[String, Json] = Map([])
  let src2 : Map[String, Json] = Map([])
  src2["endpoint"] = Json::string("https://claims.example.com/email")
  sources2["src2"] = Json::object(src2)
  dangling["_claim_sources"] = Json::object(sources2)
  let names2 : Map[String, Json] = Map([])
  names2["email"] = Json::string("missing-src")
  dangling["_claim_names"] = Json::object(names2)
  try @jwt.extract_aggregated_distributed_claims(dangling) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted _claim_names reference to missing source")
  }
}

// -----------------------------------------------------------------------------
// OIDC Discovery — Provider Metadata parser
// -----------------------------------------------------------------------------

///|
test "discovery: parses Google-style provider metadata" {
  let doc =
    #|{
    #|  "issuer": "https://accounts.google.com",
    #|  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    #|  "token_endpoint": "https://oauth2.googleapis.com/token",
    #|  "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
    #|  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
    #|  "response_types_supported": ["code", "token", "id_token"],
    #|  "subject_types_supported": ["public"],
    #|  "id_token_signing_alg_values_supported": ["RS256"],
    #|  "scopes_supported": ["openid", "email", "profile"],
    #|  "token_endpoint_auth_methods_supported": [
    #|    "client_secret_post", "client_secret_basic"
    #|  ]
    #|}
  let m = @jwt.parse_provider_metadata(doc)
  @debug.assert_eq(m.issuer, "https://accounts.google.com")
  @debug.assert_eq(
    m.jwks_uri,
    Some("https://www.googleapis.com/oauth2/v3/certs"),
  )
  @debug.assert_eq(m.id_token_signing_alg_values_supported, ["RS256"])
  match m.scopes_supported {
    Some(s) => @debug.assert_eq(s.length(), 3)
    None => abort("scopes_supported missing")
  }
}

///|
test "discovery: missing issuer rejected" {
  let doc =
    #|{
    #|  "response_types_supported": ["code"],
    #|  "subject_types_supported": ["public"],
    #|  "id_token_signing_alg_values_supported": ["RS256"]
    #|}
  try @jwt.parse_provider_metadata(doc) catch {
    MissingRequiredClaim(c) => @debug.assert_eq(c, "issuer")
    e => abort("expected MissingRequiredClaim, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected MissingRequiredClaim, got Ok")
  }
}

///|
test "discovery: required metadata arrays are enforced" {
  let missing_response_types =
    #|{
    #|  "issuer": "https://accounts.example.com",
    #|  "subject_types_supported": ["public"],
    #|  "id_token_signing_alg_values_supported": ["RS256"]
    #|}
  try @jwt.parse_provider_metadata(missing_response_types) catch {
    MissingRequiredClaim(c) => @debug.assert_eq(c, "response_types_supported")
    e => abort("expected MissingRequiredClaim, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected MissingRequiredClaim, got Ok")
  }

  let missing_subject_types =
    #|{
    #|  "issuer": "https://accounts.example.com",
    #|  "response_types_supported": ["code"],
    #|  "id_token_signing_alg_values_supported": ["RS256"]
    #|}
  try @jwt.parse_provider_metadata(missing_subject_types) catch {
    MissingRequiredClaim(c) => @debug.assert_eq(c, "subject_types_supported")
    e => abort("expected MissingRequiredClaim, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected MissingRequiredClaim, got Ok")
  }

  let missing_alg_values =
    #|{
    #|  "issuer": "https://accounts.example.com",
    #|  "response_types_supported": ["code"],
    #|  "subject_types_supported": ["public"]
    #|}
  try @jwt.parse_provider_metadata(missing_alg_values) catch {
    MissingRequiredClaim(c) =>
      @debug.assert_eq(c, "id_token_signing_alg_values_supported")
    e => abort("expected MissingRequiredClaim, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected MissingRequiredClaim, got Ok")
  }
}

///|
test "ATTACK discovery: malformed string arrays are rejected" {
  let doc =
    #|{
    #|  "issuer": "https://issuer.example/",
    #|  "authorization_endpoint": "https://issuer.example/authorize",
    #|  "jwks_uri": "https://issuer.example/jwks.json",
    #|  "response_types_supported": ["code", 42],
    #|  "subject_types_supported": ["public"],
    #|  "id_token_signing_alg_values_supported": ["RS256"]
    #|}
  try @jwt.parse_provider_metadata(doc) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted malformed discovery string array")
  }
}

///|
test "ATTACK discovery: malformed string endpoints are rejected" {
  let doc =
    #|{
    #|  "issuer": "https://issuer.example/",
    #|  "authorization_endpoint": "https://issuer.example/authorize",
    #|  "jwks_uri": 42,
    #|  "response_types_supported": ["code"],
    #|  "subject_types_supported": ["public"],
    #|  "id_token_signing_alg_values_supported": ["RS256"]
    #|}
  try @jwt.parse_provider_metadata(doc) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted malformed discovery string endpoint")
  }
}

///|
test "ATTACK discovery: duplicate provider metadata members are rejected" {
  let duplicate_issuer =
    #|{
    #|  "issuer": "https://issuer.example/",
    #|  "issuer": "https://attacker.example/",
    #|  "response_types_supported": ["code"],
    #|  "subject_types_supported": ["public"],
    #|  "id_token_signing_alg_values_supported": ["RS256"]
    #|}
  try @jwt.parse_provider_metadata(duplicate_issuer) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted duplicate discovery issuer")
  }

  let duplicate_jwks =
    #|{
    #|  "issuer": "https://issuer.example/",
    #|  "jwks_uri": "https://issuer.example/jwks.json",
    #|  "jwks_uri": "https://attacker.example/jwks.json",
    #|  "response_types_supported": ["code"],
    #|  "subject_types_supported": ["public"],
    #|  "id_token_signing_alg_values_supported": ["RS256"]
    #|}
  try @jwt.parse_provider_metadata(duplicate_jwks) catch {
    ClaimsParseError(_) => ()
    e => abort("expected ClaimsParseError, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted duplicate discovery jwks_uri")
  }
}

// -----------------------------------------------------------------------------
// OIDC Federation 1.0 — Entity Statement verify
// -----------------------------------------------------------------------------

///|
fn entity_statement_claims_for_coverage(
  now : Int64,
  issuer : String,
  subject : String,
  include_jwks? : Bool = true,
  include_optional? : Bool = false,
) -> Json {
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string(issuer)
  m["sub"] = Json::string(subject)
  m["exp"] = Json::number((now + 86400L).to_double())
  m["iat"] = Json::number(now.to_double())
  if include_jwks {
    let jwks : Map[String, Json] = Map([])
    jwks["keys"] = Json::array([])
    m["jwks"] = Json::object(jwks)
  }
  let metadata : Map[String, Json] = Map([])
  let op : Map[String, Json] = Map([])
  op["issuer"] = Json::string(subject)
  metadata["openid_provider"] = Json::object(op)
  m["metadata"] = Json::object(metadata)
  if include_optional {
    m["authority_hints"] = Json::array([Json::string("https://ta.example.org")])
    m["source_endpoint"] = Json::string(
      "https://op.example.com/federation/source",
    )
    m["trust_marks"] = Json::array([Json::string("trust-mark.jwt")])
    let constraints : Map[String, Json] = Map([])
    constraints["max_path_length"] = Json::number(3.0)
    m["constraints"] = Json::object(constraints)
    let policy : Map[String, Json] = Map([])
    policy["openid_relying_party"] = Json::object(Map([]))
    m["metadata_policy"] = Json::object(policy)
  }
  Json::object(m)
}

///|
test "federation: entity Configuration (iss == sub) verifies" {
  let now = 1_700_000_000L
  let secret : Bytes = b"federation-config"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://op.example.com")
  m["sub"] = Json::string("https://op.example.com")
  m["exp"] = Json::number((now + 86400L).to_double())
  m["iat"] = Json::number(now.to_double())
  let jwks : Map[String, Json] = Map([])
  jwks["keys"] = Json::array([])
  m["jwks"] = Json::object(jwks)
  let metadata : Map[String, Json] = Map([])
  let op : Map[String, Json] = Map([])
  op["issuer"] = Json::string("https://op.example.com")
  metadata["openid_provider"] = Json::object(op)
  m["metadata"] = Json::object(metadata)
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="entity-statement+jwt",
  )
  let opts : @jwt.EntityStatementVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    subject: "https://op.example.com",
    expected_issuer: Some("https://op.example.com"),
    expected_kind: Some(@jwt.EntityStatementKind::Configuration),
    allowed_algorithms: None,
  }
  let es = @jwt.verify_entity_statement(
    token,
    @jwt.VerifyKey::Hs256(secret~),
    opts,
  )
  @debug.assert_eq(es.kind, @jwt.EntityStatementKind::Configuration)
  @debug.assert_eq(es.iss, "https://op.example.com")
}

///|
test "federation: entity Subordinate (iss != sub) verifies" {
  let now = 1_700_000_000L
  let secret : Bytes = b"federation-subord"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://federation.example.org/anchor")
  m["sub"] = Json::string("https://op.example.com")
  m["exp"] = Json::number((now + 86400L).to_double())
  m["iat"] = Json::number(now.to_double())
  let jwks : Map[String, Json] = Map([])
  jwks["keys"] = Json::array([])
  m["jwks"] = Json::object(jwks)
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="entity-statement+jwt",
  )
  let opts : @jwt.EntityStatementVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    subject: "https://op.example.com",
    expected_issuer: Some("https://federation.example.org/anchor"),
    expected_kind: Some(@jwt.EntityStatementKind::Subordinate),
    allowed_algorithms: None,
  }
  let es = @jwt.verify_entity_statement(
    token,
    @jwt.VerifyKey::Hs256(secret~),
    opts,
  )
  @debug.assert_eq(es.kind, @jwt.EntityStatementKind::Subordinate)
  @debug.assert_eq(es.iss, "https://federation.example.org/anchor")
}

///|
test "federation: wrong typ rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"federation-wrong-typ"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://op.example.com")
  m["sub"] = Json::string("https://op.example.com")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  let jwks : Map[String, Json] = Map([])
  jwks["keys"] = Json::array([])
  m["jwks"] = Json::object(jwks)
  // typ defaults to "JWT", not "entity-statement+jwt".
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.EntityStatementVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    subject: "https://op.example.com",
    expected_issuer: None,
    expected_kind: None,
    allowed_algorithms: None,
  }
  try
    @jwt.verify_entity_statement(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType, got Ok")
  }
}

///|
test "federation: optional trust metadata is surfaced and alg is pinned" {
  let now = 1_700_000_000L
  let secret : Bytes = b"federation-optional"
  let payload = entity_statement_claims_for_coverage(
    now,
    "https://op.example.com",
    "https://op.example.com",
    include_optional=true,
  )
  let token = @jwt.sign(
    payload,
    @jwt.Key::Hs256(secret~),
    typ="entity-statement+jwt",
  )
  let opts : @jwt.EntityStatementVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    subject: "https://op.example.com",
    expected_issuer: Some("https://op.example.com"),
    expected_kind: Some(@jwt.EntityStatementKind::Configuration),
    allowed_algorithms: Some([@jwt.Algorithm::HS256]),
  }
  let es = @jwt.verify_entity_statement(
    token,
    @jwt.VerifyKey::Hs256(secret~),
    opts,
  )
  @debug.assert_eq(es.authority_hints, Some(["https://ta.example.org"]))
  @debug.assert_eq(
    es.source_endpoint,
    Some("https://op.example.com/federation/source"),
  )
  match es.trust_marks {
    Some(items) => @debug.assert_eq(items.length(), 1)
    None => abort("missing trust_marks")
  }
  match es.constraints {
    Some(c) =>
      match c.get("max_path_length") {
        Some(Number(n, ..)) => @debug.assert_eq(n, 3.0)
        _ => abort("missing constraints.max_path_length")
      }
    None => abort("missing constraints")
  }
  match es.policy {
    Some(p) =>
      match p.get("openid_relying_party") {
        Some(Object(_)) => ()
        _ => abort("missing metadata_policy.openid_relying_party")
      }
    None => abort("missing metadata_policy")
  }
  let bad_opts : @jwt.EntityStatementVerifyOptions = {
    ..opts,
    allowed_algorithms: Some([@jwt.Algorithm::EdDSA]),
  }
  try
    @jwt.verify_entity_statement(
      token,
      @jwt.VerifyKey::Hs256(secret~),
      bad_opts,
    )
  catch {
    AlgorithmNotAllowed(_) => ()
    e => abort("expected AlgorithmNotAllowed, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AlgorithmNotAllowed, got Ok")
  }
}

///|
test "ATTACK federation: malformed optional trust metadata rejects" {
  let now = 1_700_000_000L
  let secret : Bytes = b"federation-optional-shape"
  fn expect_reject(payload : Json) -> Unit raise {
    let token = @jwt.sign(
      payload,
      @jwt.Key::Hs256(secret~),
      typ="entity-statement+jwt",
    )
    let opts : @jwt.EntityStatementVerifyOptions = {
      now,
      clock_skew_sec: 0L,
      subject: "https://op.example.com",
      expected_issuer: Some("https://op.example.com"),
      expected_kind: Some(@jwt.EntityStatementKind::Configuration),
      allowed_algorithms: None,
    }
    try
      @jwt.verify_entity_statement(token, @jwt.VerifyKey::Hs256(secret~), opts)
    catch {
      ClaimsParseError(_) | InvalidEntityStatement(_) => ()
      e =>
        abort("expected metadata shape rejection, got " + @debug.to_string(e))
    } noraise {
      _ => abort("accepted malformed federation optional metadata")
    }
  }

  let bad_metadata = entity_statement_claims_for_coverage(
    now, "https://op.example.com", "https://op.example.com",
  )
  match bad_metadata {
    Object(m) => m["metadata"] = Json::string("not-an-object")
    _ => abort("fixture claims not object")
  }
  expect_reject(bad_metadata)

  let bad_source_endpoint = entity_statement_claims_for_coverage(
    now, "https://op.example.com", "https://op.example.com",
  )
  match bad_source_endpoint {
    Object(m) => m["source_endpoint"] = Json::number(42.0)
    _ => abort("fixture claims not object")
  }
  expect_reject(bad_source_endpoint)

  let bad_trust_marks = entity_statement_claims_for_coverage(
    now, "https://op.example.com", "https://op.example.com",
  )
  match bad_trust_marks {
    Object(m) => m["trust_marks"] = Json::string("trust-mark.jwt")
    _ => abort("fixture claims not object")
  }
  expect_reject(bad_trust_marks)

  let bad_constraints = entity_statement_claims_for_coverage(
    now, "https://op.example.com", "https://op.example.com",
  )
  match bad_constraints {
    Object(m) => m["constraints"] = Json::array([])
    _ => abort("fixture claims not object")
  }
  expect_reject(bad_constraints)

  let bad_policy = entity_statement_claims_for_coverage(
    now, "https://op.example.com", "https://op.example.com",
  )
  match bad_policy {
    Object(m) => m["metadata_policy"] = Json::string("not-an-object")
    _ => abort("fixture claims not object")
  }
  expect_reject(bad_policy)
}

///|
test "federation: kind mismatch and missing jwks reject" {
  let now = 1_700_000_000L
  let secret : Bytes = b"federation-negative"
  let subordinate_payload = entity_statement_claims_for_coverage(
    now, "https://anchor.example.org", "https://op.example.com",
  )
  let subordinate_token = @jwt.sign(
    subordinate_payload,
    @jwt.Key::Hs256(secret~),
    typ="entity-statement+jwt",
  )
  let kind_opts : @jwt.EntityStatementVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    subject: "https://op.example.com",
    expected_issuer: Some("https://anchor.example.org"),
    expected_kind: Some(@jwt.EntityStatementKind::Configuration),
    allowed_algorithms: None,
  }
  try
    @jwt.verify_entity_statement(
      subordinate_token,
      @jwt.VerifyKey::Hs256(secret~),
      kind_opts,
    )
  catch {
    InvalidEntityStatement(_) => ()
    e => abort("expected InvalidEntityStatement, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidEntityStatement, got Ok")
  }

  let no_jwks_payload = entity_statement_claims_for_coverage(
    now,
    "https://op.example.com",
    "https://op.example.com",
    include_jwks=false,
  )
  let no_jwks_token = @jwt.sign(
    no_jwks_payload,
    @jwt.Key::Hs256(secret~),
    typ="entity-statement+jwt",
  )
  let no_jwks_opts : @jwt.EntityStatementVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    subject: "https://op.example.com",
    expected_issuer: Some("https://op.example.com"),
    expected_kind: Some(@jwt.EntityStatementKind::Configuration),
    allowed_algorithms: None,
  }
  try
    @jwt.verify_entity_statement(
      no_jwks_token,
      @jwt.VerifyKey::Hs256(secret~),
      no_jwks_opts,
    )
  catch {
    InvalidEntityStatement(_) => ()
    e => abort("expected InvalidEntityStatement, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidEntityStatement, got Ok")
  }
}

///|
test "ATTACK federation: subject substitution under trusted anchor rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"federation-subject-substitution"
  let payload = entity_statement_claims_for_coverage(
    now, "https://anchor.example.org", "https://attacker-op.example.com",
  )
  let token = @jwt.sign(
    payload,
    @jwt.Key::Hs256(secret~),
    typ="entity-statement+jwt",
  )
  let opts : @jwt.EntityStatementVerifyOptions = {
    now,
    clock_skew_sec: 0L,
    subject: "https://op.example.com",
    expected_issuer: Some("https://anchor.example.org"),
    expected_kind: Some(@jwt.EntityStatementKind::Subordinate),
    allowed_algorithms: None,
  }
  try
    @jwt.verify_entity_statement(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    InvalidEntityStatement(_) => ()
    e => abort("expected InvalidEntityStatement, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidEntityStatement, got Ok")
  }
}

// -----------------------------------------------------------------------------
// OIDC CIBA — auth_req_id + rt_hash binding
// -----------------------------------------------------------------------------

///|
test "ciba: auth_req_id round-trips and rt_hash binds to refresh token" {
  let now = 1_700_000_000L
  let secret : Bytes = b"ciba-test"
  let refresh_token = "rt-abc"
  let rt_hash_value = @jwt.compute_x_hash(@jwt.Algorithm::HS256, refresh_token)
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://accounts.example.com/")
  m["sub"] = Json::string("u")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["urn:openid:params:jwt:claim:auth_req_id"] = Json::string("auth-req-1")
  m["urn:openid:params:jwt:claim:rt_hash"] = Json::string(rt_hash_value)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let oidc_opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  let opts : @jwt.CibaVerifyOptions = {
    oidc: oidc_opts,
    expected_auth_req_id: Some("auth-req-1"),
    refresh_token: Some(refresh_token),
  }
  let c = @jwt.verify_ciba_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  @debug.assert_eq(c.auth_req_id, Some("auth-req-1"))
  @debug.assert_eq(c.rt_hash, Some(rt_hash_value))
}

///|
test "ciba: auth_req_id mismatch rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"ciba-areqid-bad"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://accounts.example.com/")
  m["sub"] = Json::string("u")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["urn:openid:params:jwt:claim:auth_req_id"] = Json::string("attacker-id")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.CibaVerifyOptions = {
    oidc: @jwt.OidcIdTokenVerifyOptions::default(
      now, "https://accounts.example.com/", "client-abc",
    ),
    expected_auth_req_id: Some("real-id"),
    refresh_token: None,
  }
  try
    @jwt.verify_ciba_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    AuthReqIdMismatch => ()
    e => abort("expected AuthReqIdMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AuthReqIdMismatch, got Ok")
  }
}

///|
test "ciba: missing auth_req_id and rt_hash reject when bound" {
  let now = 1_700_000_000L
  let secret : Bytes = b"ciba-missing-bindings"
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    Map([]),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let oidc = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  let auth_opts : @jwt.CibaVerifyOptions = {
    oidc,
    expected_auth_req_id: Some("auth-req-1"),
    refresh_token: None,
  }
  try
    @jwt.verify_ciba_id_token(token, @jwt.VerifyKey::Hs256(secret~), auth_opts)
  catch {
    AuthReqIdMismatch => ()
    e => abort("expected AuthReqIdMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AuthReqIdMismatch, got Ok")
  }

  let rt_opts : @jwt.CibaVerifyOptions = {
    oidc,
    expected_auth_req_id: None,
    refresh_token: Some("refresh-token"),
  }
  try
    @jwt.verify_ciba_id_token(token, @jwt.VerifyKey::Hs256(secret~), rt_opts)
  catch {
    RtHashMismatch => ()
    e => abort("expected RtHashMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected RtHashMismatch, got Ok")
  }
}

///|
test "ATTACK ciba: rt_hash for different refresh token rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"ciba-rt-substitution"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://accounts.example.com/")
  m["sub"] = Json::string("u")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["urn:openid:params:jwt:claim:auth_req_id"] = Json::string("auth-req-1")
  m["urn:openid:params:jwt:claim:rt_hash"] = Json::string(
    @jwt.compute_x_hash(@jwt.Algorithm::HS256, "attacker-refresh-token"),
  )
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.CibaVerifyOptions = {
    oidc: @jwt.OidcIdTokenVerifyOptions::default(
      now, "https://accounts.example.com/", "client-abc",
    ),
    expected_auth_req_id: Some("auth-req-1"),
    refresh_token: Some("real-refresh-token"),
  }
  try
    @jwt.verify_ciba_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    RtHashMismatch => ()
    e => abort("expected RtHashMismatch, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected RtHashMismatch, got Ok")
  }
}

///|
test "ATTACK ciba: malformed optional binding claims are rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"ciba-binding-shape"
  let opts : @jwt.CibaVerifyOptions = {
    oidc: @jwt.OidcIdTokenVerifyOptions::default(
      now, "https://accounts.example.com/", "client-abc",
    ),
    expected_auth_req_id: None,
    refresh_token: None,
  }
  for
    key in [
      "urn:openid:params:jwt:claim:auth_req_id", "urn:openid:params:jwt:claim:rt_hash",
    ] {
    let extra : Map[String, Json] = Map([])
    extra[key] = Json::number(42.0)
    let payload = oidc_id_token_claims(
      now,
      "https://accounts.example.com/",
      Json::string("client-abc"),
      extra,
    )
    let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
    try
      @jwt.verify_ciba_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
    catch {
      ClaimsParseError(_) => ()
      e => abort("expected ClaimsParseError for " + key + ", got " + repr(e))
    } noraise {
      _ => abort("accepted CIBA ID token with malformed " + key)
    }
  }
}

// -----------------------------------------------------------------------------
// FAPI 2.0 profile guard
// -----------------------------------------------------------------------------

///|
test "fapi: HS256 token rejected by fapi_check_alg" {
  let now = 1_700_000_000L
  let secret : Bytes = b"fapi-reject-hmac"
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    Map([]),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~))
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  let id = @jwt.verify_oidc_id_token(
    token,
    @jwt.VerifyKey::Hs256(secret~),
    opts,
  )
  try @jwt.fapi_check_alg(id.jwt) catch {
    FapiPolicyViolation(_) => ()
    e => abort("expected FapiPolicyViolation, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected FapiPolicyViolation, got Ok")
  }
}

///|
test "fapi: EdDSA token accepted; fapi_oidc_options pins alg" {
  let now = 1_700_000_000L
  let seed = Bytes::makei(32, fn(i) { (i + 23).to_byte() })
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let extra : Map[String, Json] = Map([])
  extra["nonce"] = Json::string("fapi-nonce")
  let payload = oidc_id_token_claims(
    now,
    "https://accounts.example.com/",
    Json::string("client-abc"),
    extra,
  )
  let token = @jwt.sign(payload, @jwt.Key::EdDsa(privkey=sk))
  let opts = @jwt.fapi_oidc_options(
    now, "https://accounts.example.com/", "client-abc", "fapi-nonce",
  )
  let id = @jwt.verify_oidc_id_token(
    token,
    @jwt.VerifyKey::EdDsa(pubkey=pk),
    opts,
  )
  @jwt.fapi_check_alg(id.jwt)
}

///|
test "fapi: rfc9068 options pin access-token alg and client_id" {
  let now = 1_700_000_000L
  let secret : Bytes = b"fapi-rfc9068-hmac"
  let payload = rfc9068_test_claims(
    now,
    "https://as.example.com/",
    Json::string("https://rs.example.com/"),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), typ="at+jwt")
  let opts = @jwt.fapi_rfc9068_options(
    now, "https://as.example.com/", "https://rs.example.com/", "s6BhdRkqt3",
  )
  try @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    AlgorithmNotAllowed(_) => ()
    e => abort("expected AlgorithmNotAllowed, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected AlgorithmNotAllowed, got Ok")
  }
}

// -----------------------------------------------------------------------------
// Privilege-escalation regression tests
// -----------------------------------------------------------------------------

///|
test "ATTACK typ-confusion: logout+jwt rejected when ID token expected" {
  // An IdP signs both ID tokens and logout tokens with the same key.
  // An attacker captures a logout token and replays it where the RP
  // expects an ID token. The default OidcIdTokenVerifyOptions has
  // typ_allowed=None; verify() must still refuse the specialised typ.
  let now = 1_700_000_000L
  let secret : Bytes = b"shared-idp-key"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://accounts.example.com/")
  m["sub"] = Json::string("user-42")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  let logout_token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="logout+jwt",
  )
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  try
    @jwt.verify_oidc_id_token(
      logout_token,
      @jwt.VerifyKey::Hs256(secret~),
      opts,
    )
  catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType (cross-class confusion), got Ok")
  }
}

///|
test "ATTACK typ-confusion: dpop+jwt rejected by generic verify default" {
  let now = 1_700_000_000L
  let secret : Bytes = b"any-key"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://accounts.example.com/")
  m["sub"] = Json::string("u")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="dpop+jwt",
  )
  try
    @jwt.verify(
      token,
      @jwt.VerifyKey::Hs256(secret~),
      @jwt.VerifyOptions::default(now),
    )
  catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType (cross-class confusion), got Ok")
  }
}

///|
test "ATTACK typ-confusion: malformed typ header is rejected" {
  let now = 1_700_000_000L
  let secret : Bytes = b"bad-typ-header"
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["typ"] = Json::number(42.0)
  let claims : Map[String, Json] = Map([])
  claims["iss"] = Json::string("https://accounts.example.com/")
  claims["sub"] = Json::string("u")
  claims["aud"] = Json::string("client-abc")
  claims["exp"] = Json::number((now + 600L).to_double())
  claims["iat"] = Json::number(now.to_double())
  let token = sign_hs256_token_with_header(
    Json::object(header),
    Json::object(claims),
    secret,
  )
  try
    @jwt.verify(
      token,
      @jwt.VerifyKey::Hs256(secret~),
      @jwt.VerifyOptions::default(now),
    )
  catch {
    InvalidHeader(_) => ()
    e => abort("expected InvalidHeader, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted JWT with malformed typ header")
  }
}

///|
test "ATTACK typ-confusion: JARM response typ rejected when ID token expected" {
  // JARM and ID tokens are both signed by the AS and often share issuer /
  // audience. A response JWT with enough ID-token-shaped claims must still not
  // authenticate as an ID token when typ_allowed=None.
  let now = 1_700_000_000L
  let secret : Bytes = b"jarm-as-id-key"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://accounts.example.com/")
  m["sub"] = Json::string("user-42")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["state"] = Json::string("rp-state")
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="oauth-authz-resp+jwt",
  )
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    now, "https://accounts.example.com/", "client-abc",
  )
  try
    @jwt.verify_oidc_id_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType for JARM-as-ID-token confusion")
  }
}

///|
test "ATTACK typ-confusion: JAR request typ rejected by generic verify default" {
  let now = 1_700_000_000L
  let secret : Bytes = b"jar-generic-key"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("client-abc")
  m["aud"] = Json::string("https://as.example.com/")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  m["response_type"] = Json::string("code")
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="application/oauth-authz-req+jwt",
  )
  try
    @jwt.verify(
      token,
      @jwt.VerifyKey::Hs256(secret~),
      @jwt.VerifyOptions::default(now),
    )
  catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType for JAR generic typ confusion")
  }
}

///|
test "ATTACK typ-confusion: mixed-case specialised typ rejected by default" {
  let now = 1_700_000_000L
  let secret : Bytes = b"mixed-case-typ"
  let m : Map[String, Json] = Map([])
  m["iss"] = Json::string("https://accounts.example.com/")
  m["sub"] = Json::string("u")
  m["aud"] = Json::string("client-abc")
  m["exp"] = Json::number((now + 600L).to_double())
  m["iat"] = Json::number(now.to_double())
  let token = @jwt.sign(
    Json::object(m),
    @jwt.Key::Hs256(secret~),
    typ="Application/AT+JWT",
  )
  try
    @jwt.verify(
      token,
      @jwt.VerifyKey::Hs256(secret~),
      @jwt.VerifyOptions::default(now),
    )
  catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType for mixed-case specialised typ, got Ok")
  }
}

///|
test "ATTACK typ-confusion: at+jwt rejected by RFC 9068 negative case" {
  // Even the RFC 9068 path should not be tricked into accepting a JWT
  // labelled "logout+jwt" instead of "at+jwt".
  let now = 1_700_000_000L
  let secret : Bytes = b"shared-as-key"
  let payload = rfc9068_test_claims(
    now,
    "https://as.example.com/",
    Json::string("https://rs.example.com/"),
  )
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), typ="logout+jwt")
  let opts = @jwt.Rfc9068VerifyOptions::default(
    now, "https://as.example.com/", "https://rs.example.com/",
  )
  try @jwt.verify_rfc9068(token, @jwt.VerifyKey::Hs256(secret~), opts) catch {
    InvalidType(_) => ()
    e => abort("expected InvalidType, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType (cross-class confusion), got Ok")
  }
}

///|
test "ATTACK use=enc: JWKS encryption key rejected for verify" {
  let jwks =
    #|{ "keys": [
    #|  { "kty": "oct", "kid": "k1", "alg": "HS256", "use": "enc",
    #|    "k": "c2VjcmV0" }
    #|] }
  let set = @jwk.parse_set(jwks)
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["kid"] = Json::string("k1")
  try @jwt.select_verify_key(set, header) catch {
    NoMatchingKey => ()
    e => abort("expected NoMatchingKey for use=enc, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected NoMatchingKey for use=enc, got Ok")
  }
}

///|
test "ATTACK key_ops: JWKS key without verify op rejected for verify" {
  let jwks =
    #|{ "keys": [
    #|  { "kty": "oct", "kid": "k1", "alg": "HS256",
    #|    "key_ops": ["encrypt"], "k": "c2VjcmV0" }
    #|] }
  let set = @jwk.parse_set(jwks)
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("HS256")
  header["kid"] = Json::string("k1")
  try @jwt.select_verify_key(set, header) catch {
    NoMatchingKey => ()
    e => abort("expected NoMatchingKey for key_ops, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected NoMatchingKey for key_ops without verify, got Ok")
  }
}

///|
test "logout-token default: max_iat_age_sec=300 closes long replay window" {
  // An IdP-emitted logout token with iat > 5 min in the past must be
  // refused under the new default. Without max_iat_age_sec the token
  // would have been accepted indefinitely (no exp claim in logout tokens).
  let secret : Bytes = b"logout-replay-default"
  let payload = logout_token_claims(1_700_000_000L, sub=Some("u"))
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), typ="logout+jwt")
  let opts = @jwt.LogoutTokenVerifyOptions::default(
    1_700_001_000L, // 1000 s after iat — well past the 300 s default window
     "https://as.example.com/", "client-abc",
  )
  try
    @jwt.verify_logout_token(token, @jwt.VerifyKey::Hs256(secret~), opts)
  catch {
    IssuedInFuture => () // we reuse IssuedInFuture for "iat too old"
    e => abort("expected iat-too-old, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected iat-too-old rejection, got Ok")
  }
}

///|
test "ATTACK encrypted ID token: missing cty rejected" {
  // Hand-craft a compact JWE with no cty header, valid 5 segments, dummy
  // payload — the outer-header check must fire before decryption work.
  let header : Map[String, Json] = Map([])
  header["alg"] = Json::string("dir")
  header["enc"] = Json::string("A256GCM")
  // intentionally no `cty`
  let b64u = fn(b : Bytes) -> String {
    let s = @base64.encode(b[:], padding=false)
    let buf = StringBuilder::new()
    for c in s {
      let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
      buf.write_char(c2)
    }
    buf.to_string()
  }
  let header_b64 = b64u(@utf8.encode(Json::object(header).stringify()[:]))
  // Five segments: header.encrypted_key.iv.ciphertext.tag — values
  // don't have to decrypt; verify_oidc_id_token_encrypted must reject
  // on the missing cty BEFORE calling @jwe.decrypt.
  let bogus = header_b64 + ".AA.AA.AA.AA"
  // Build a dummy decryption key shape via @jwe (`dir` flow needs the
  // 32-byte CEK). Using all-zeros — we only need a typed value.
  let cek = Bytes::makei(32, fn(_) { b'\x00' })
  let dec_key : @jwe.DecryptionKey = @jwe.DecryptionKey::DecDir(cek~)
  let opts = @jwt.OidcIdTokenVerifyOptions::default(
    1_700_000_000L, "https://accounts.example.com/", "client-abc",
  )
  let any_vk = @jwt.VerifyKey::Hs256(secret=b"unused")
  try @jwt.verify_oidc_id_token_encrypted(bogus, dec_key, any_vk, opts) catch {
    InvalidType(_) => ()
    e =>
      abort("expected InvalidType for missing cty, got " + @debug.to_string(e))
  } noraise {
    _ => abort("expected InvalidType for missing cty, got Ok")
  }
}
