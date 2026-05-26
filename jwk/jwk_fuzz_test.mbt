// Structured fuzz tests for JWK parser and serialiser boundaries. Random JSON
// strings exercise robustness; generated `oct` keys cover base64url and
// symmetric-key exposure invariants.

///|
fn fuzz_jwk_b64u_encode(b : Bytes) -> String {
  let s = @base64.encode(b[:], padding=false)
  let buf = StringBuilder::new()
  for c in s {
    let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
    buf.write_char(c2)
  }
  buf.to_string()
}

///|
fn fuzz_jwk_bytes(raw : Bytes, len : Int) -> Bytes {
  Bytes::makei(len, fn(i) {
    if raw.length() == 0 {
      ((i * 17 + 1) & 0xff).to_byte()
    } else {
      ((raw[i % raw.length()].to_int() + i * 17) & 0xff).to_byte()
    }
  })
}

///|
fn fuzz_jwk_oct_json(secret : Bytes) -> String {
  let m : Map[String, Json] = Map([])
  m["kty"] = Json::string("oct")
  m["k"] = Json::string(fuzz_jwk_b64u_encode(secret))
  Json::object(m).stringify()
}

///|
fn fuzz_jwk_bad_b64(raw : Bytes) -> String {
  if raw.length() % 4 == 0 {
    "!!!!"
  } else if raw.length() % 4 == 1 {
    "AA=A"
  } else if raw.length() % 4 == 2 {
    "AA AA"
  } else {
    "AA\nAA"
  }
}

///|
test "fuzz jwk: parsers never panic on random strings" {
  for input in (@quickcheck.samples(200) : Array[String]) {
    let _ = try? @jwk.parse_public(input)
    let _ = try? @jwk.parse_private(input)
    let _ = try? @jwk.parse_set(input)
  }
}

///|
test "fuzz jwk: generated oct private keys round-trip without public leakage" {
  for raw in (@quickcheck.samples(100) : Array[Bytes]) {
    let secret = fuzz_jwk_bytes(raw, raw.length() % 64 + 1)
    let json = fuzz_jwk_oct_json(secret)
    let jwk = @jwk.parse_private(json)
    let reparsed = @jwk.parse_private(@jwk.serialise_private(jwk))
    @debug.assert_eq(
      @jwk.thumbprint_base64url(reparsed),
      @jwk.thumbprint_base64url(jwk),
    )

    let public_json = @jwk.serialise_public(jwk)
    assert_false(public_json.contains("\"k\""))
    assert_false(public_json.contains(fuzz_jwk_b64u_encode(secret)))

    let public_rejected = try {
      let _ = @jwk.parse_public(json)
      false
    } catch {
      _ => true
    }
    assert_true(public_rejected)
  }
}

///|
test "fuzz jwk: malformed base64url key material rejects" {
  for raw in (@quickcheck.samples(80) : Array[Bytes]) {
    let bad = fuzz_jwk_bad_b64(raw)
    let m : Map[String, Json] = Map([])
    m["kty"] = Json::string("oct")
    m["k"] = Json::string(bad)
    let rejected = try {
      let _ = @jwk.parse_private(Json::object(m).stringify())
      false
    } catch {
      InvalidBase64Url(_) => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "fuzz jwk: generated key sets preserve metadata and key thumbprints" {
  for raw in (@quickcheck.samples(80) : Array[Bytes]) {
    let secret = fuzz_jwk_bytes(raw, raw.length() % 48 + 16)
    let key : Map[String, Json] = Map([])
    key["kty"] = Json::string("oct")
    key["k"] = Json::string(fuzz_jwk_b64u_encode(secret))
    key["kid"] = Json::string("kid-" + raw.length().to_string())
    key["alg"] = Json::string("HS256")
    key["use"] = Json::string("sig")
    let set : Map[String, Json] = Map([])
    set["keys"] = Json::array([Json::object(key)])
    let parsed = @jwk.parse_set(Json::object(set).stringify())
    @debug.assert_eq(parsed.length(), 1)
    @debug.assert_eq(parsed[0].kid, Some("kid-" + raw.length().to_string()))
    @debug.assert_eq(parsed[0].alg, Some("HS256"))
    @debug.assert_eq(parsed[0].use_, Some("sig"))
    @debug.assert_eq(
      @jwk.thumbprint_base64url(parsed[0].jwk),
      @jwk.thumbprint_base64url(@jwk.parse_private(fuzz_jwk_oct_json(secret))),
    )
  }
}
