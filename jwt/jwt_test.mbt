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
  match
    (try? @jwt.verify(token, @jwt.VerifyKey::Hs256(secret=other_secret), opts)) {
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
  match (try? @jwt.verify("only.two", @jwt.VerifyKey::Hs256(secret~), opts)) {
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
  }
  let v = @jwt.verify(rfc7515_a2_token, @jwt.VerifyKey::Rs256(pubkey=pk), opts)
  assert_eq(v.alg, @jwt.Algorithm::RS256)
  match v.claims.get("iss") {
    Some(String(s)) => assert_eq(s, "joe")
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
  let bad_token = parts[0].to_string() +
    "." +
    "eyJpc3MiOiJqb24ifQ" +
    "." +
    parts[2].to_string()
  let opts = @jwt.VerifyOptions::default(1300819300L)
  match (try? @jwt.verify(bad_token, @jwt.VerifyKey::Rs256(pubkey=pk), opts)) {
    Err(InvalidSignature) => ()
    Ok(_) => abort("expected InvalidSignature, got Ok")
    Err(e) => abort("expected InvalidSignature, got \{e}")
  }
}

///|
test "RS256: KeyAlgorithmMismatch when alg=HS256 but key is Rs256" {
  // Sign an HS256 token, then try to verify with an Rs256 key.
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map::new()
  m["sub"] = Json::string("x")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let pk = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_a2_pkcs1_der)
  let opts = @jwt.VerifyOptions::default(0L)
  match (try? @jwt.verify(token, @jwt.VerifyKey::Rs256(pubkey=pk), opts)) {
    Err(KeyAlgorithmMismatch) => ()
    other => abort("expected KeyAlgorithmMismatch, got \{other}")
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
  }
  let v = @jwt.verify(token, @jwt.VerifyKey::Es256(pubkey=pk), opts)
  assert_eq(v.alg, @jwt.Algorithm::ES256)
  match v.claims.get("iss") {
    Some(String(s)) => assert_eq(s, "joe")
    _ => abort("missing iss")
  }
}

///|
test "ES256: tampered signature fails" {
  // Flip one base64url char in the signature segment.
  let bad = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.AtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
  let pk = rfc7515_a3_pubkey()
  let opts = @jwt.VerifyOptions::default(0L)
  match (try? @jwt.verify(bad, @jwt.VerifyKey::Es256(pubkey=pk), opts)) {
    Err(InvalidSignature) => ()
    other => abort("expected InvalidSignature, got \{other}")
  }
}

///|
test "ES256: KeyAlgorithmMismatch when alg=HS256 but key is Es256" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map::new()
  m["sub"] = Json::string("x")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let pk = rfc7515_a3_pubkey()
  let opts = @jwt.VerifyOptions::default(0L)
  match (try? @jwt.verify(token, @jwt.VerifyKey::Es256(pubkey=pk), opts)) {
    Err(KeyAlgorithmMismatch) => ()
    other => abort("expected KeyAlgorithmMismatch, got \{other}")
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
  assert_eq(v.alg, @jwt.Algorithm::ES384)
  match v.claims.get("sub") {
    Some(String(s)) => assert_eq(s, "mizchi")
    _ => abort("missing sub")
  }
}

///|
test "ES384: tampered signature fails" {
  // Flip the first char of the signature segment.
  let bad = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtaXpjaGkiLCJpc3MiOiJ0ZXN0In0.JVF1bDvZX38ltujtQQIWXhPwZDUlHOx6FtRDDA4v1Q1ZS69tUr_BbH3sY3x8pxvp1x_ESP-nEzknjsz5vM6i51HOk1T3z0V_U_pnrCmbpIo--miUMdJIIHrUWofOCb9J"
  let pk = es384_pubkey()
  let opts = @jwt.VerifyOptions::default(0L)
  match (try? @jwt.verify(bad, @jwt.VerifyKey::Es384(pubkey=pk), opts)) {
    Err(InvalidSignature) => ()
    other => abort("expected InvalidSignature, got \{other}")
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
  match (try? @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)) {
    Err(UnsupportedAlgorithm(s)) => assert_eq(s, "none")
    Err(KeyAlgorithmMismatch) => () // also acceptable
    Err(InvalidToken(_)) => () // rejected at token shape
    other => abort("alg=none NOT rejected: \{other}")
  }
}

///|
test "ATTACK alg=None (titlecase variant) must be rejected" {
  // Same idea with mixed-case "None" — must not match.
  let token = "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."
  let opts = @jwt.VerifyOptions::default(0L)
  let secret : Bytes = b"any"
  match (try? @jwt.verify(token, @jwt.VerifyKey::Hs256(secret~), opts)) {
    Err(UnsupportedAlgorithm(_)) => ()
    Err(KeyAlgorithmMismatch) => ()
    Err(InvalidToken(_)) => ()
    other => abort("alg=None NOT rejected: \{other}")
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
  match (try? @jwt.verify(token, @jwt.VerifyKey::Rs256(pubkey=pk), opts)) {
    Err(KeyAlgorithmMismatch) => ()
    other => abort("alg confusion HS256↔Rs256 NOT blocked: \{other}")
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
  let claims = Map::new()
  claims["sub"] = Json::string("rs256-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Rs256(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Rs256(pubkey=sk.public_key()),
    opts,
  )
  assert_eq(v.alg, @jwt.Algorithm::RS256)
  match v.claims.get("sub") {
    Some(String(s)) => assert_eq(s, "rs256-roundtrip")
    _ => abort("missing sub")
  }
}

///|
test "JWT PS256 sign + verify roundtrip (deterministic sLen=0)" {
  // Internal sign / verify use deterministic PSS (sLen = 0). This matches
  // the closed-loop behaviour described in the jwt module comment; it is
  // NOT RFC 7518 §3.5 interoperable.
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let claims = Map::new()
  claims["sub"] = Json::string("ps256-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Ps256(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Ps256(pubkey=sk.public_key()),
    opts,
  )
  assert_eq(v.alg, @jwt.Algorithm::PS256)
  match v.claims.get("sub") {
    Some(String(s)) => assert_eq(s, "ps256-roundtrip")
    _ => abort("missing sub")
  }
}

///|
test "JWT PS384 sign + verify roundtrip" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let claims = Map::new()
  claims["sub"] = Json::string("ps384-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Ps384(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Ps384(pubkey=sk.public_key()),
    opts,
  )
  assert_eq(v.alg, @jwt.Algorithm::PS384)
}

///|
test "JWT PS512 sign + verify roundtrip" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let claims = Map::new()
  claims["sub"] = Json::string("ps512-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Ps512(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Ps512(pubkey=sk.public_key()),
    opts,
  )
  assert_eq(v.alg, @jwt.Algorithm::PS512)
}

///|
test "JWT PS256: KeyAlgorithmMismatch when alg=HS256 but key is Ps256" {
  let secret : Bytes = b"k"
  let m : Map[String, Json] = Map::new()
  m["sub"] = Json::string("x")
  let token = @jwt.sign(Json::object(m), @jwt.Key::Hs256(secret~))
  let pk = @rsa.RsaPublicKey::from_pkcs1_der(rfc7515_a2_pkcs1_der)
  let opts = @jwt.VerifyOptions::default(0L)
  match (try? @jwt.verify(token, @jwt.VerifyKey::Ps256(pubkey=pk), opts)) {
    Err(KeyAlgorithmMismatch) => ()
    other => abort("expected KeyAlgorithmMismatch, got \{other}")
  }
}

///|
test "JWT PS256: tampered payload fails signature check" {
  let sk = @rsa.RsaPrivateKey::from_pkcs1_der(rs256_priv_pkcs1_der)
  let claims = Map::new()
  claims["sub"] = Json::string("original")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Ps256(privkey=sk))
  // Swap the payload segment for a different valid base64url.
  let parts = token.split(".").to_array()
  let bad_token = parts[0].to_string() +
    "." +
    "eyJzdWIiOiJ0YW1wZXJlZCJ9" + // base64url({"sub":"tampered"})
    "." +
    parts[2].to_string()
  let opts = @jwt.VerifyOptions::default(0L)
  match
    (try? @jwt.verify(
      bad_token,
      @jwt.VerifyKey::Ps256(pubkey=sk.public_key()),
      opts,
    )) {
    Err(InvalidSignature) => ()
    other => abort("expected InvalidSignature, got \{other}")
  }
}

///|
test "JWT ES256 sign + verify roundtrip" {
  let scalar = hex_to_bytes(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let sk = @p256.PrivateKey::from_bytes(scalar)
  let claims = Map::new()
  claims["sub"] = Json::string("es256-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Es256(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Es256(pubkey=sk.public_key()),
    opts,
  )
  assert_eq(v.alg, @jwt.Algorithm::ES256)
}

///|
test "JWT ES384 sign + verify roundtrip" {
  let scalar = hex_to_bytes(
    "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
  )
  let sk = @p384.PrivateKey::from_bytes(scalar)
  let claims = Map::new()
  claims["sub"] = Json::string("es384-roundtrip")
  let token = @jwt.sign(Json::object(claims), @jwt.Key::Es384(privkey=sk))
  let opts = @jwt.VerifyOptions::default(0L)
  let v = @jwt.verify(
    token,
    @jwt.VerifyKey::Es384(pubkey=sk.public_key()),
    opts,
  )
  assert_eq(v.alg, @jwt.Algorithm::ES384)
}

// -----------------------------------------------------------------------------
// Header-level RFC compliance attacks
// -----------------------------------------------------------------------------

///|
test "ATTACK RFC 7515 §4.1.11: token with `crit` header must be rejected" {
  // {"alg":"HS256","typ":"JWT","crit":["enc"]}.{"sub":"x"}.AAAA
  let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImNyaXQiOlsiZW5jIl19.eyJzdWIiOiJ4In0.AAAA"
  let opts = @jwt.VerifyOptions::default(0L)
  match (try? @jwt.verify(token, @jwt.VerifyKey::Hs256(secret=b"k"), opts)) {
    Err(InvalidHeader(_)) => ()
    other => abort("crit header NOT rejected: \{other}")
  }
}

///|
test "ATTACK RFC 7797: token with `b64=false` must be rejected" {
  // {"alg":"HS256","b64":false}.payload.AAAA
  let token = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2V9.cGF5bG9hZA.AAAA"
  let opts = @jwt.VerifyOptions::default(0L)
  match (try? @jwt.verify(token, @jwt.VerifyKey::Hs256(secret=b"k"), opts)) {
    Err(InvalidHeader(_)) => ()
    other => abort("b64=false header NOT rejected: \{other}")
  }
}
