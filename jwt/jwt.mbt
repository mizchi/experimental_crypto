// JWT (RFC 7519) over JWS (RFC 7515) compact serialization.
//
// Supported algorithms: HS256, EdDSA (RFC 8037 §3.1). Everything else
// (RS256, ES256, HS384/512, ES384/512, PS256/384/512) is recognized in
// `Algorithm` for completeness but raises `UnsupportedAlgorithm` at
// sign / verify time. Adding a new alg is a matter of extending `Key`
// / `VerifyKey` and a `match` arm in `sign` / `verify`.

///|
pub(all) enum Algorithm {
  HS256
  HS384
  HS512
  RS256
  RS384
  RS512
  ES256
  ES384
  ES512
  PS256
  PS384
  PS512
  EdDSA
} derive(Eq, Show)

///|
pub(all) enum Key {
  Hs256(secret~ : Bytes)
  EdDsa(privkey~ : @ed25519.PrivateKey)
}

///|
pub(all) enum VerifyKey {
  Hs256(secret~ : Bytes)
  EdDsa(pubkey~ : @ed25519.PublicKey)
}

///|
pub suberror JwtError {
  InvalidToken(String)
  InvalidHeader(String)
  UnsupportedAlgorithm(String)
  KeyAlgorithmMismatch
  InvalidSignature
  Expired
  NotYetValid
  InvalidAudience
  InvalidIssuer
  ClaimsParseError(String)
} derive(Show)

///|
pub(all) struct VerifiedJwt {
  header : Map[String, Json]
  claims : Map[String, Json]
  alg : Algorithm
  kid : String?
} derive(Show)

///|
pub(all) struct VerifyOptions {
  now : Int64
  clock_skew_sec : Int64
  require_exp : Bool
  issuer : String?
  audience : String?
} derive(Eq, Show)

///|
pub fn VerifyOptions::default(now : Int64) -> VerifyOptions {
  { now, clock_skew_sec: 0L, require_exp: false, issuer: None, audience: None }
}

// -----------------------------------------------------------------------------
// base64url
// -----------------------------------------------------------------------------

///|
fn base64url_encode(b : Bytes) -> String {
  let s = @base64.encode(b[:], padding=false)
  let buf = StringBuilder::new()
  for c in s {
    let c2 = if c == '+' {
      '-'
    } else if c == '/' {
      '_'
    } else {
      c
    }
    buf.write_char(c2)
  }
  buf.to_string()
}

///|
fn base64url_decode(s : String) -> Bytes raise JwtError {
  // StringBuilder has no length() accessor, so we track the visible character
  // count manually for padding. Each c added is one ASCII byte in the
  // base64url alphabet so the count corresponds 1:1 to the decoded length.
  let buf = StringBuilder::new()
  let mut n = 0
  for c in s {
    // Reject any character that is outside the base64url alphabet up front;
    // the underlying decoder is lenient and we want a single failure mode.
    let is_valid = (c >= 'A' && c <= 'Z') ||
      (c >= 'a' && c <= 'z') ||
      (c >= '0' && c <= '9') ||
      c == '-' ||
      c == '_'
    if not(is_valid) {
      raise InvalidToken("invalid base64url character")
    }
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
  let pad_count = (4 - n % 4) % 4
  for _ in 0..<pad_count {
    buf.write_char('=')
  }
  @base64.decode(buf.to_string()) catch {
    _ => raise InvalidToken("invalid base64url segment")
  }
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

///|
fn alg_to_str(alg : Algorithm) -> String {
  match alg {
    HS256 => "HS256"
    HS384 => "HS384"
    HS512 => "HS512"
    RS256 => "RS256"
    RS384 => "RS384"
    RS512 => "RS512"
    ES256 => "ES256"
    ES384 => "ES384"
    ES512 => "ES512"
    PS256 => "PS256"
    PS384 => "PS384"
    PS512 => "PS512"
    EdDSA => "EdDSA"
  }
}

///|
fn alg_from_str(s : String) -> Algorithm raise JwtError {
  match s {
    "HS256" => HS256
    "HS384" => HS384
    "HS512" => HS512
    "RS256" => RS256
    "RS384" => RS384
    "RS512" => RS512
    "ES256" => ES256
    "ES384" => ES384
    "ES512" => ES512
    "PS256" => PS256
    "PS384" => PS384
    "PS512" => PS512
    "EdDSA" => EdDSA
    _ => raise UnsupportedAlgorithm(s)
  }
}

///|
fn key_alg(k : Key) -> Algorithm {
  match k {
    Hs256(..) => HS256
    EdDsa(..) => EdDSA
  }
}

///|
fn verify_key_alg(k : VerifyKey) -> Algorithm {
  match k {
    Hs256(..) => HS256
    EdDsa(..) => EdDSA
  }
}

///|
fn build_header_json(alg : Algorithm, kid : String?) -> Json {
  // Header order is irrelevant for verification (the signing input is the
  // exact base64url-encoded bytes we produce here), so we just emit the
  // fields we care about.
  let m : Map[String, Json] = Map::new()
  m["alg"] = Json::string(alg_to_str(alg))
  m["typ"] = Json::string("JWT")
  match kid {
    Some(k) => m["kid"] = Json::string(k)
    None => ()
  }
  Json::object(m)
}

///|
fn json_to_compact_string(j : Json) -> String {
  // core/json's stringify with no indent produces a compact form, which is
  // what JWT expects (no whitespace within the encoded payload).
  j.stringify()
}

// -----------------------------------------------------------------------------
// sign
// -----------------------------------------------------------------------------

///|
pub fn sign(payload : Json, key : Key, kid? : String) -> String raise JwtError {
  let alg = key_alg(key)
  let header = build_header_json(alg, kid)
  let header_b64 = base64url_encode(@utf8.encode(json_to_compact_string(header)[:]))
  let payload_b64 = base64url_encode(
    @utf8.encode(json_to_compact_string(payload)[:]),
  )
  let signing_input = header_b64 + "." + payload_b64
  let signing_bytes = @utf8.encode(signing_input[:])
  let signature : Bytes = match key {
    Hs256(secret~) => hmac_sha256(secret, signing_bytes)
    EdDsa(privkey~) => privkey.sign(signing_bytes)
  }
  signing_input + "." + base64url_encode(signature)
}

// -----------------------------------------------------------------------------
// verify
// -----------------------------------------------------------------------------

///|
fn parse_json_object(s : String) -> Map[String, Json] raise JwtError {
  let parsed = @json.parse(s[:]) catch {
    _ => raise InvalidHeader("invalid JSON")
  }
  match parsed {
    Object(m) => m
    _ => raise InvalidHeader("expected JSON object")
  }
}

///|
fn get_string(m : Map[String, Json], key : String) -> String? {
  match m.get(key) {
    Some(String(s)) => Some(s)
    _ => None
  }
}

///|
// Pull a unix-seconds claim out of the claims map. JWT spec (RFC 7519 §2)
// calls these "NumericDate"s, defined as a JSON numeric value. We accept any
// JSON number (including fractional) and truncate to Int64.
fn get_numeric_date(m : Map[String, Json], key : String) -> Int64? {
  match m.get(key) {
    Some(Number(n, ..)) => Some(n.to_int64())
    _ => None
  }
}

///|
// `aud` may be a single string or an array of strings (RFC 7519 §4.1.3).
fn audience_matches(claim : Json, expected : String) -> Bool {
  match claim {
    String(s) => s == expected
    Array(arr) => {
      for v in arr {
        match v {
          String(s) => if s == expected {
              return true
            }
          _ => ()
        }
      }
      false
    }
    _ => false
  }
}

///|
pub fn verify(
  token : String,
  key : VerifyKey,
  opts : VerifyOptions,
) -> VerifiedJwt raise JwtError {
  let parts = token.split(".").to_array()
  if parts.length() != 3 {
    raise InvalidToken("expected 3 segments")
  }
  let header_b64 = parts[0].to_string()
  let payload_b64 = parts[1].to_string()
  let sig_b64 = parts[2].to_string()

  // ---- header ----
  let header_bytes = base64url_decode(header_b64)
  let header_str = @utf8.decode(header_bytes[:]) catch {
    _ => raise InvalidHeader("header is not valid UTF-8")
  }
  let header = parse_json_object(header_str)
  let alg = match get_string(header, "alg") {
    Some(s) => alg_from_str(s)
    None => raise InvalidHeader("missing alg")
  }
  if alg != verify_key_alg(key) {
    raise KeyAlgorithmMismatch
  }

  // ---- signature ----
  let signing_input = header_b64 + "." + payload_b64
  let signing_bytes = @utf8.encode(signing_input[:])
  let provided_sig = base64url_decode(sig_b64)
  let ok = match (alg, key) {
    (HS256, Hs256(secret~)) => {
      let expected = hmac_sha256(secret, signing_bytes)
      ct_eq(expected, provided_sig)
    }
    (EdDSA, EdDsa(pubkey~)) =>
      // Ed25519 verification is itself constant-time over the signature
      // bytes, so we can call straight through.
      pubkey.verify(signing_bytes, provided_sig)
    (_, _) =>
      // Either alg is a recognized-but-unsupported value (RS256, etc) or
      // we hit a key shape we never wired up. Both are spec-side gaps.
      raise UnsupportedAlgorithm(alg_to_str(alg))
  }
  if not(ok) {
    raise InvalidSignature
  }

  // ---- claims ----
  let payload_bytes = base64url_decode(payload_b64)
  let payload_str = @utf8.decode(payload_bytes[:]) catch {
    _ => raise ClaimsParseError("payload is not valid UTF-8")
  }
  // JWS payload is not required to be JSON, but for JWT it is. We accept
  // both shapes: if parsing as JSON fails, leave claims empty (RFC 8037
  // sample uses a raw string payload, for example).
  let claims : Map[String, Json] = try {
    match @json.parse(payload_str[:]) {
      Object(m) => m
      _ => Map::new()
    }
  } catch {
    _ => Map::new()
  }

  // ---- exp / nbf / iss / aud ----
  let exp = get_numeric_date(claims, "exp")
  if opts.require_exp && exp.is_empty() {
    raise ClaimsParseError("exp claim is required")
  }
  match exp {
    Some(e) => if e + opts.clock_skew_sec < opts.now {
        raise Expired
      }
    None => ()
  }
  match get_numeric_date(claims, "nbf") {
    Some(nbf) => if nbf > opts.now + opts.clock_skew_sec {
        raise NotYetValid
      }
    None => ()
  }
  match opts.issuer {
    Some(expected) =>
      match get_string(claims, "iss") {
        Some(s) => if s != expected {
            raise InvalidIssuer
          }
        None => raise InvalidIssuer
      }
    None => ()
  }
  match opts.audience {
    Some(expected) =>
      match claims.get("aud") {
        Some(v) => if not(audience_matches(v, expected)) {
            raise InvalidAudience
          }
        None => raise InvalidAudience
      }
    None => ()
  }
  let kid = get_string(header, "kid")
  { header, claims, alg, kid }
}
