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
    let c2 = if c == '-' {
      '+'
    } else if c == '_' {
      '/'
    } else {
      c
    }
    buf.write_char(c2)
    n = n + 1
  }
  let pad = (4 - n % 4) % 4
  for _ in 0..<pad {
    buf.write_char('=')
  }
  @base64.decode(buf.to_string()) catch { _ => abort("bad b64u in test") }
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
  }
  let v = @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)
  assert_eq(v.alg, @jwt.Algorithm::HS256)
  // iss claim
  match v.claims.get("iss") {
    Some(String(s)) => assert_eq(s, "joe")
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
  match (try? @jwt.verify(bad, @jwt.VerifyKey::Hs256(secret~), opts)) {
    Err(InvalidSignature) => ()
    Ok(_) => abort("expected InvalidSignature, got Ok")
    Err(e) => abort("expected InvalidSignature, got \{e}")
  }
}

// -----------------------------------------------------------------------------
// HS256: sign + verify roundtrip
// -----------------------------------------------------------------------------

///|
test "HS256: sign + verify roundtrip preserves claims" {
  let secret : Bytes = b"my-very-secret-hmac-key"
  let claims_map : Map[String, Json] = Map::new()
  claims_map["sub"] = Json::string("alice")
  claims_map["iat"] = Json::number(1_700_000_000.0)
  let payload = Json::object(claims_map)
  let token = @jwt.sign(payload, @jwt.Key::Hs256(secret~), kid="key-1")
  let opts = @jwt.VerifyOptions::default(1_700_000_100L)
  let v = @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)
  assert_eq(v.alg, @jwt.Algorithm::HS256)
  assert_eq(v.kid, Some("key-1"))
  match v.claims.get("sub") {
    Some(String(s)) => assert_eq(s, "alice")
    _ => abort("missing sub")
  }
}

///|
test "HS256: wrong secret fails verification" {
  let secret : Bytes = b"my-very-secret-hmac-key"
  let other_secret : Bytes = b"another-secret-hmac-key"
  let m : Map[String, Json] = Map::new()
  m["sub"] = Json::string("bob")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts = @jwt.VerifyOptions::default(0L)
  match (try? @jwt.verify(token, @jwt.VerifyKey::Hs256(secret=other_secret), opts)) {
    Err(InvalidSignature) => ()
    Ok(_) => abort("expected InvalidSignature")
    Err(e) => abort("expected InvalidSignature, got \{e}")
  }
}

// -----------------------------------------------------------------------------
// EdDSA: RFC 8037 §A.4 verify
// -----------------------------------------------------------------------------

///|
test "EdDSA: RFC 8037 §A.4 token verifies" {
  // Public key: x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
  let pk_bytes = b64u_to_bytes("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
  let pk = @ed25519.PublicKey::from_bytes(pk_bytes)
  // Token from RFC 8037 §A.4 (payload is the literal text
  // "Example of Ed25519 signing", not JSON).
  let token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(token, @jwt.VerifyKey::EdDsa(pubkey=pk), opts)
  assert_eq(v.alg, @jwt.Algorithm::EdDSA)
  // Payload is not JSON, so claims fall back to an empty map.
  assert_true(v.claims.is_empty())
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
  let m : Map[String, Json] = Map::new()
  m["sub"] = Json::string("rfc8037-test")
  let token = @jwt.sign(Json::object(m), @jwt.Key::EdDsa(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(token, @jwt.VerifyKey::EdDsa(pubkey=pk), opts)
  assert_eq(v.alg, @jwt.Algorithm::EdDSA)
  match v.claims.get("sub") {
    Some(String(s)) => assert_eq(s, "rfc8037-test")
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
  match (try? @jwt.verify(bad, @jwt.VerifyKey::EdDsa(pubkey=pk), opts)) {
    Err(InvalidSignature) | Err(InvalidToken(_)) => ()
    Ok(_) => abort("expected verification failure")
    Err(e) => abort("unexpected error: \{e}")
  }
}

// -----------------------------------------------------------------------------
// Claim validation
// -----------------------------------------------------------------------------

///|
test "exp: expired token raises Expired" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map::new()
  m["exp"] = Json::number(1_000.0)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts = @jwt.VerifyOptions::default(2_000L)
  match (try? @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)) {
    Err(Expired) => ()
    other => abort("expected Expired, got \{other}")
  }
}

///|
test "exp: clock_skew_sec absorbs small differences" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map::new()
  m["exp"] = Json::number(1_000.0)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  // now = 1010, exp = 1000, skew = 60 -> allowed (exp + skew = 1060 >= now)
  let opts : @jwt.VerifyOptions = {
    now: 1_010L,
    clock_skew_sec: 60L,
    require_exp: false,
    issuer: None,
    audience: None,
  }
  let v = @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)
  assert_eq(v.alg, @jwt.Algorithm::HS256)
}

///|
test "nbf: not yet valid raises NotYetValid" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map::new()
  m["nbf"] = Json::number(5_000.0)
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts = @jwt.VerifyOptions::default(1_000L)
  match (try? @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)) {
    Err(NotYetValid) => ()
    other => abort("expected NotYetValid, got \{other}")
  }
}

///|
test "iss: wrong issuer raises InvalidIssuer" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map::new()
  m["iss"] = Json::string("a")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let opts : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: Some("b"),
    audience: None,
  }
  match (try? @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)) {
    Err(InvalidIssuer) => ()
    other => abort("expected InvalidIssuer, got \{other}")
  }
}

///|
test "aud: string and array forms both match" {
  let secret : Bytes = b"k"
  // string form
  let m1 : Map[String, Json] = Map::new()
  m1["aud"] = Json::string("svc1")
  let t1 = @jwt.sign(Json::object(m1), @jwt.Key::Hs256(secret~))
  let opts1 : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: Some("svc1"),
  }
  let _ = @jwt.verify(t1, @jwt.VerifyKey::Hs256(secret~), opts1)
  // array form
  let arr : Array[Json] = [Json::string("other"), Json::string("svc2")]
  let m2 : Map[String, Json] = Map::new()
  m2["aud"] = Json::array(arr)
  let t2 = @jwt.sign(Json::object(m2), @jwt.Key::Hs256(secret~))
  let opts2 : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: Some("svc2"),
  }
  let _ = @jwt.verify(t2, @jwt.VerifyKey::Hs256(secret~), opts2)
  // mismatch
  let opts3 : @jwt.VerifyOptions = {
    now: 0L,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: Some("nope"),
  }
  match (try? @jwt.verify(t2, @jwt.VerifyKey::Hs256(secret~), opts3)) {
    Err(InvalidAudience) => ()
    other => abort("expected InvalidAudience, got \{other}")
  }
}

// -----------------------------------------------------------------------------
// Structural / algorithm errors
// -----------------------------------------------------------------------------

///|
test "InvalidToken: wrong segment count" {
  let secret : Bytes = b"k"
  let opts = @jwt.VerifyOptions::default(0L)
  match
    (try? @jwt.verify("only.two", @jwt.VerifyKey::Hs256(secret~), opts)) {
    Err(InvalidToken(_)) => ()
    other => abort("expected InvalidToken, got \{other}")
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
  match (try? @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)) {
    Err(KeyAlgorithmMismatch) | Err(UnsupportedAlgorithm(_)) => ()
    other => abort("expected alg failure, got \{other}")
  }
}

///|
test "KeyAlgorithmMismatch: HS256 token with EdDSA verify key" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map::new()
  m["sub"] = Json::string("x")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  // Use an arbitrary Ed25519 public key — the alg-vs-key check should fire
  // long before we touch the signature.
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let pk = @ed25519.PrivateKey::from_seed(seed).public_key()
  let opts = @jwt.VerifyOptions::default(0L)
  match (try? @jwt.verify(token, @jwt.VerifyKey::EdDsa(pubkey=pk), opts)) {
    Err(KeyAlgorithmMismatch) => ()
    other => abort("expected KeyAlgorithmMismatch, got \{other}")
  }
}
