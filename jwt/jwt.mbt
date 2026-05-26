// JWT (RFC 7519) over JWS (RFC 7515) compact serialization.
//
// Supported algorithms:
//   - sign + verify: HS256, EdDSA (RFC 8037 §3.1), RS256, ES256, ES384,
//                    PS256, PS384, PS512 (RFC 7518 §3.5)
// Everything else (HS384/512, RS384/512, ES512) is recognized in
// `Algorithm` for completeness but raises `UnsupportedAlgorithm` at sign
// / verify time. Adding a new alg is a matter of extending `Key` /
// `VerifyKey` and a `match` arm in `sign` / `verify`.
//
// PSx caveat: RFC 7518 §3.5 requires sLen = hLen for PS256 / PS384 / PS512,
// but the workspace does not yet expose a vetted RNG for the JWT layer.
// To keep the roundtrip self-consistent without a hidden non-deterministic
// dependency, both `sign` and `verify` for PSx use **deterministic PSS with
// sLen = 0** (allowed by RFC 8017 §A.2.3). This means:
//   * tokens we produce will NOT verify under strict RFC 7518 verifiers
//     (which expect sLen = hLen);
//   * tokens produced by strict RFC 7518 verifiers will NOT verify here.
// Callers that need either direction of RFC 7518 interop should call
// `@rsa.RsaPrivateKey::sign_pss` / `@rsa.RsaPublicKey::verify_pss`
// directly with a real RNG-supplied salt and assemble or split the
// compact JWS by hand. The defaults here are an interop-bug-resistant
// closed loop, not an RFC 7518 implementation.

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
} derive(Eq, Debug)

///|
pub(all) enum Key {
  // HMAC sign (RFC 7518 §3.2). The secret length must be at least the hash
  // output size; shorter secrets are accepted but reduce the effective
  // strength of the MAC.
  Hs256(secret~ : Bytes)
  Hs384(secret~ : Bytes)
  Hs512(secret~ : Bytes)
  EdDsa(privkey~ : @ed25519.PrivateKey)
  // RS256 / RS384 / RS512: RSASSA-PKCS1-v1_5 sign with SHA-{256,384,512}.
  Rs256(privkey~ : @rsa.RsaPrivateKey)
  Rs384(privkey~ : @rsa.RsaPrivateKey)
  Rs512(privkey~ : @rsa.RsaPrivateKey)
  // ES256 / ES384: ECDSA-SHA-{256,384} sign with RFC 6979 deterministic nonce.
  Es256(privkey~ : @p256.PrivateKey)
  Es384(privkey~ : @p384.PrivateKey)
  // PS256 / PS384 / PS512: RSASSA-PSS sign with deterministic empty salt.
  // See the module comment for the sLen = 0 caveat vs RFC 7518 §3.5.
  Ps256(privkey~ : @rsa.RsaPrivateKey)
  Ps384(privkey~ : @rsa.RsaPrivateKey)
  Ps512(privkey~ : @rsa.RsaPrivateKey)
}

///|
pub(all) enum VerifyKey {
  // HMAC verify (RFC 7518 §3.2). Compared via `@hash.ct_eq` so the result is
  // independent of how many leading tag bytes match.
  Hs256(secret~ : Bytes)
  Hs384(secret~ : Bytes)
  Hs512(secret~ : Bytes)
  EdDsa(pubkey~ : @ed25519.PublicKey)
  // RS256 / RS384 / RS512 verify-only: we hold an RSA public key but never
  // any private material, mirroring the verify-only scope of `mizchi/rsa`.
  Rs256(pubkey~ : @rsa.RsaPublicKey)
  Rs384(pubkey~ : @rsa.RsaPublicKey)
  Rs512(pubkey~ : @rsa.RsaPublicKey)
  // ES256 (ECDSA with P-256 + SHA-256, RFC 7518 §3.4). Signature is the JOSE
  // raw form r||s (64 bytes); verify-only for now.
  Es256(pubkey~ : @p256.PublicKey)
  // ES384 (ECDSA with P-384 + SHA-384, RFC 7518 §3.4). JOSE raw r||s = 96B.
  Es384(pubkey~ : @p384.PublicKey)
  // PS256 / PS384 / PS512: RSASSA-PSS verify with sLen = 0 (matches our
  // sign path, NOT the RFC 7518 sLen = hLen convention — see module
  // comment for the interop tradeoff).
  Ps256(pubkey~ : @rsa.RsaPublicKey)
  Ps384(pubkey~ : @rsa.RsaPublicKey)
  Ps512(pubkey~ : @rsa.RsaPublicKey)
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
  // RFC 8725 §3.11: explicit typing. Returned when `VerifyOptions.typ_allowed`
  // is set and the JOSE header's `typ` is absent or not in the allow-list.
  InvalidType(String)
  // RFC 8725 §3.10: an `iat` claim more than `clock_skew_sec` in the future
  // is suspicious; reject so a smuggled future-issued token can't be
  // replayed once the clock catches up.
  IssuedInFuture
  // JWKS helper rejections: returned by `select_verify_key`.
  NoMatchingKey
  AlgorithmMismatchInJwks(String)
} derive(Debug)

///|
pub(all) struct VerifiedJwt {
  header : Map[String, Json]
  claims : Map[String, Json]
  alg : Algorithm
  kid : String?
} derive(Debug)

///|
pub(all) struct VerifyOptions {
  now : Int64
  clock_skew_sec : Int64
  require_exp : Bool
  issuer : String?
  audience : String?
  // RFC 8725 §3.11 — if `Some(allowed)`, the JOSE header MUST carry a `typ`
  // member whose value is in `allowed`. Use `Some(["JWT"])` for ID tokens
  // and `Some(["at+jwt"])` for RFC 9068 access tokens. Defaults to `None`
  // (no constraint) to preserve historic behaviour.
  typ_allowed : Array[String]?
} derive(Eq, Debug)

///|
pub fn VerifyOptions::default(now : Int64) -> VerifyOptions {
  {
    now,
    clock_skew_sec: 0L,
    require_exp: false,
    issuer: None,
    audience: None,
    typ_allowed: None,
  }
}

// -----------------------------------------------------------------------------
// base64url
// -----------------------------------------------------------------------------

///|
fn base64url_encode(b : Bytes) -> String {
  let s = @base64.encode(b[:], padding=false)
  let buf = StringBuilder::new()
  for c in s {
    let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
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
    if !is_valid {
      raise InvalidToken("invalid base64url character")
    }
    let c2 = if c == '-' { '+' } else if c == '_' { '/' } else { c }
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
    Hs384(..) => HS384
    Hs512(..) => HS512
    EdDsa(..) => EdDSA
    Rs256(..) => RS256
    Rs384(..) => RS384
    Rs512(..) => RS512
    Es256(..) => ES256
    Es384(..) => ES384
    Ps256(..) => PS256
    Ps384(..) => PS384
    Ps512(..) => PS512
  }
}

///|
fn verify_key_alg(k : VerifyKey) -> Algorithm {
  match k {
    Hs256(..) => HS256
    Hs384(..) => HS384
    Hs512(..) => HS512
    EdDsa(..) => EdDSA
    Rs256(..) => RS256
    Rs384(..) => RS384
    Rs512(..) => RS512
    Es256(..) => ES256
    Es384(..) => ES384
    Ps256(..) => PS256
    Ps384(..) => PS384
    Ps512(..) => PS512
  }
}

///|
fn build_header_json(alg : Algorithm, kid : String?) -> Json {
  // Header order is irrelevant for verification (the signing input is the
  // exact base64url-encoded bytes we produce here), so we just emit the
  // fields we care about.
  let m : Map[String, Json] = Map([])
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
  let header_b64 = base64url_encode(
    @utf8.encode(json_to_compact_string(header)[:]),
  )
  let payload_b64 = base64url_encode(
    @utf8.encode(json_to_compact_string(payload)[:]),
  )
  let signing_input = header_b64 + "." + payload_b64
  let signing_bytes = @utf8.encode(signing_input[:])
  let signature : Bytes = match key {
    Hs256(secret~) => @hash.hmac_sha256(secret, signing_bytes)
    Hs384(secret~) => @hash.hmac_sha384(secret, signing_bytes)
    Hs512(secret~) => @hash.hmac_sha512(secret, signing_bytes)
    EdDsa(privkey~) => privkey.sign(signing_bytes)
    Rs256(privkey~) =>
      privkey.sign(signing_bytes, @rsa.HashAlg::Sha256) catch {
        e =>
          raise UnsupportedAlgorithm(
            "RS256 sign failed: " + @debug.to_string(e),
          )
      }
    Rs384(privkey~) =>
      privkey.sign(signing_bytes, @rsa.HashAlg::Sha384) catch {
        e =>
          raise UnsupportedAlgorithm(
            "RS384 sign failed: " + @debug.to_string(e),
          )
      }
    Rs512(privkey~) =>
      privkey.sign(signing_bytes, @rsa.HashAlg::Sha512) catch {
        e =>
          raise UnsupportedAlgorithm(
            "RS512 sign failed: " + @debug.to_string(e),
          )
      }
    Es256(privkey~) => privkey.sign(signing_bytes)
    Es384(privkey~) => privkey.sign(signing_bytes)
    // PSS with sLen = 0 (deterministic) — see module comment.
    Ps256(privkey~) =>
      privkey.sign_pss(signing_bytes, @rsa.HashAlg::Sha256, b"") catch {
        e =>
          raise UnsupportedAlgorithm(
            "PS256 sign failed: " + @debug.to_string(e),
          )
      }
    Ps384(privkey~) =>
      privkey.sign_pss(signing_bytes, @rsa.HashAlg::Sha384, b"") catch {
        e =>
          raise UnsupportedAlgorithm(
            "PS384 sign failed: " + @debug.to_string(e),
          )
      }
    Ps512(privkey~) =>
      privkey.sign_pss(signing_bytes, @rsa.HashAlg::Sha512, b"") catch {
        e =>
          raise UnsupportedAlgorithm(
            "PS512 sign failed: " + @debug.to_string(e),
          )
      }
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
          String(s) => if s == expected { return true }
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
  let header_b64 = parts[0].to_owned()
  let payload_b64 = parts[1].to_owned()
  let sig_b64 = parts[2].to_owned()

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
  // RFC 7515 §4.1.11: a verifier MUST reject any JWS whose `crit` header
  // names extensions the verifier does not recognise. We recognise none,
  // so the presence of a non-empty `crit` array is itself a refusal
  // signal. This blocks all "smuggle a critical extension that we
  // silently ignore" attacks.
  match header.get("crit") {
    Some(_) =>
      raise InvalidHeader(
        "crit header is present but no extensions are supported",
      )
    None => ()
  }
  // RFC 7797: `"b64":false` changes the signing-input construction;
  // we sign over the literal base64 segments, never the raw payload.
  // Reject so an attacker can't bypass our integrity check.
  match header.get("b64") {
    Some(_) => raise InvalidHeader("b64 header is not supported")
    None => ()
  }
  // RFC 8725 §3.11: explicit typing. When the caller asks for a `typ`
  // allow-list, the header MUST carry one of the listed values. This is
  // what RFC 9068 §4 requires for `at+jwt` access tokens and what RFC
  // 7519 IdPs use to disambiguate ID tokens from generic JWS payloads.
  match opts.typ_allowed {
    Some(allowed) => {
      let actual = match get_string(header, "typ") {
        Some(s) => s
        None => raise InvalidType("missing typ header")
      }
      let mut ok = false
      for t in allowed {
        if t == actual {
          ok = true
          break
        }
      }
      if !ok {
        raise InvalidType("typ '" + actual + "' not in allow-list")
      }
    }
    None => ()
  }

  // ---- signature ----
  let signing_input = header_b64 + "." + payload_b64
  let signing_bytes = @utf8.encode(signing_input[:])
  let provided_sig = base64url_decode(sig_b64)
  let ok = match (alg, key) {
    (HS256, Hs256(secret~)) => {
      let expected = @hash.hmac_sha256(secret, signing_bytes)
      @hash.ct_eq(expected, provided_sig)
    }
    (HS384, Hs384(secret~)) => {
      let expected = @hash.hmac_sha384(secret, signing_bytes)
      @hash.ct_eq(expected, provided_sig)
    }
    (HS512, Hs512(secret~)) => {
      let expected = @hash.hmac_sha512(secret, signing_bytes)
      @hash.ct_eq(expected, provided_sig)
    }
    (EdDSA, EdDsa(pubkey~)) =>
      // Ed25519 verification is itself constant-time over the signature
      // bytes, so we can call straight through.
      pubkey.verify(signing_bytes, provided_sig)
    (RS256, Rs256(pubkey~)) =>
      // mizchi/rsa raises on signature-length mismatch (which usually
      // signals a wrong key); fold that into our InvalidSignature so
      // the verify boundary stays simple for callers.
      pubkey.verify(signing_bytes, provided_sig, @rsa.HashAlg::Sha256) catch {
        _ => raise InvalidSignature
      }
    (RS384, Rs384(pubkey~)) =>
      pubkey.verify(signing_bytes, provided_sig, @rsa.HashAlg::Sha384) catch {
        _ => raise InvalidSignature
      }
    (RS512, Rs512(pubkey~)) =>
      pubkey.verify(signing_bytes, provided_sig, @rsa.HashAlg::Sha512) catch {
        _ => raise InvalidSignature
      }
    (ES256, Es256(pubkey~)) =>
      // RFC 7515 §3.4: the JWS signature is r||s, 64 bytes total.
      @p256.verify(
        pubkey,
        signing_bytes,
        provided_sig,
        @p256.SignatureFormat::Raw,
      ) catch {
        _ => raise InvalidSignature
      }
    (ES384, Es384(pubkey~)) =>
      // r||s, 96 bytes total for ES384.
      @p384.verify(
        pubkey,
        signing_bytes,
        provided_sig,
        @p384.SignatureFormat::Raw,
      ) catch {
        _ => raise InvalidSignature
      }
    // PSS verify with sLen = 0 (matches the sign path; see module comment).
    (PS256, Ps256(pubkey~)) =>
      pubkey.verify_pss(
        signing_bytes,
        provided_sig,
        @rsa.HashAlg::Sha256,
        salt_len=0,
      ) catch {
        _ => raise InvalidSignature
      }
    (PS384, Ps384(pubkey~)) =>
      pubkey.verify_pss(
        signing_bytes,
        provided_sig,
        @rsa.HashAlg::Sha384,
        salt_len=0,
      ) catch {
        _ => raise InvalidSignature
      }
    (PS512, Ps512(pubkey~)) =>
      pubkey.verify_pss(
        signing_bytes,
        provided_sig,
        @rsa.HashAlg::Sha512,
        salt_len=0,
      ) catch {
        _ => raise InvalidSignature
      }
    (_, _) =>
      // Either alg is a recognized-but-unsupported value (RS384, etc) or
      // we hit a key shape we never wired up. Both are spec-side gaps.
      raise UnsupportedAlgorithm(alg_to_str(alg))
  }
  if !ok {
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
      _ => Map([])
    }
  } catch {
    _ => Map([])
  }

  // ---- iat / exp / nbf / iss / aud ----
  // RFC 8725 §3.10: an `iat` more than `clock_skew_sec` in the future is
  // not a legitimately-issued token. Reject so a stockpiled future-dated
  // token can't be replayed once the clock catches up. iat is optional
  // (RFC 7519 §4.1.6), so missing iat is fine.
  match get_numeric_date(claims, "iat") {
    Some(iat) => if iat > opts.now + opts.clock_skew_sec { raise IssuedInFuture }
    None => ()
  }
  let exp = get_numeric_date(claims, "exp")
  if opts.require_exp && exp is None {
    raise ClaimsParseError("exp claim is required")
  }
  match exp {
    Some(e) => if e + opts.clock_skew_sec < opts.now { raise Expired }
    None => ()
  }
  match get_numeric_date(claims, "nbf") {
    Some(nbf) => if nbf > opts.now + opts.clock_skew_sec { raise NotYetValid }
    None => ()
  }
  match opts.issuer {
    Some(expected) =>
      match get_string(claims, "iss") {
        Some(s) => if s != expected { raise InvalidIssuer }
        None => raise InvalidIssuer
      }
    None => ()
  }
  match opts.audience {
    Some(expected) =>
      match claims.get("aud") {
        Some(v) => if !audience_matches(v, expected) { raise InvalidAudience }
        None => raise InvalidAudience
      }
    None => ()
  }
  let kid = get_string(header, "kid")
  { header, claims, alg, kid }
}

// -----------------------------------------------------------------------------
// JWKS resolution helper
// -----------------------------------------------------------------------------

///|
/// Pick a `VerifyKey` from an RFC 7517 §5 JWK Set that matches a JOSE
/// header. The standard OIDC ID-token flow:
///
/// 1. Fetch the IdP's JWKS document, parse it with `@jwk.parse_set`.
/// 2. Read the JWT's header (caller can pass `verify`'s `header` on a
///    `JwtError::InvalidSignature` retry, or pre-parse via `peek_header`).
/// 3. Hand both to `select_verify_key` to get the `VerifyKey` for `verify`.
///
/// Selection rules:
/// - If the header has a `kid`, only JWKS entries whose `kid` matches are
///   considered. If none match, `NoMatchingKey` is raised.
/// - If the header has no `kid` and the set has exactly one entry, that
///   one is used. Otherwise `NoMatchingKey` is raised (ambiguous).
/// - If the JWKS entry has its own `alg` and it does not equal the JWT
///   header's `alg`, `AlgorithmMismatchInJwks` is raised. This prevents
///   an attacker from picking an HS256 key off a JWKS that the IdP
///   intended only for RS256 use.
/// - The selected `Jwk` is converted to a `VerifyKey` for the header's
///   `alg`. Algorithm/key-type mismatches raise `UnsupportedAlgorithm`.
pub fn select_verify_key(
  set : Array[@jwk.JwkSetEntry],
  header : Map[String, Json],
) -> VerifyKey raise JwtError {
  let alg = match get_string(header, "alg") {
    Some(s) => alg_from_str(s)
    None => raise InvalidHeader("missing alg")
  }
  let header_kid = get_string(header, "kid")
  let candidates : Array[@jwk.JwkSetEntry] = match header_kid {
    Some(want) => {
      let out : Array[@jwk.JwkSetEntry] = []
      for entry in set {
        match entry.kid {
          Some(k) => if k == want { out.push(entry) }
          None => ()
        }
      }
      out
    }
    None =>
      if set.length() == 1 {
        [set[0]]
      } else {
        raise NoMatchingKey
      }
  }
  if candidates.length() == 0 {
    raise NoMatchingKey
  }
  // Use the first candidate. RFC 7517 §4.5 allows multiple JWKs to share a
  // kid (rare); we don't try to disambiguate by alg in that case — first
  // match wins, and the alg-mismatch check below catches type confusion.
  let entry = candidates[0]
  match entry.alg {
    Some(s) => {
      let entry_alg = alg_from_str(s) catch {
        _ => raise AlgorithmMismatchInJwks(s)
      }
      if entry_alg != alg {
        raise AlgorithmMismatchInJwks(alg_to_str(alg))
      }
    }
    None => ()
  }
  jwk_to_verify_key(entry.jwk, alg)
}

///|
fn jwk_to_verify_key(
  jwk : @jwk.Jwk,
  alg : Algorithm,
) -> VerifyKey raise JwtError {
  match (alg, jwk) {
    (HS256, Hmac(secret~)) => Hs256(secret~)
    (HS384, Hmac(secret~)) => Hs384(secret~)
    (HS512, Hmac(secret~)) => Hs512(secret~)
    (RS256, Rsa(pubkey~, ..)) => Rs256(pubkey~)
    (RS384, Rsa(pubkey~, ..)) => Rs384(pubkey~)
    (RS512, Rsa(pubkey~, ..)) => Rs512(pubkey~)
    (PS256, Rsa(pubkey~, ..)) => Ps256(pubkey~)
    (PS384, Rsa(pubkey~, ..)) => Ps384(pubkey~)
    (PS512, Rsa(pubkey~, ..)) => Ps512(pubkey~)
    (ES256, EcP256(pubkey~, ..)) => Es256(pubkey~)
    (ES384, EcP384(pubkey~, ..)) => Es384(pubkey~)
    (EdDSA, OkpEd25519(pubkey~, ..)) => EdDsa(pubkey~)
    _ =>
      raise UnsupportedAlgorithm(
        "JWKS entry kty does not match JWT alg " + alg_to_str(alg),
      )
  }
}

///|
/// Peek at the JOSE header of a compact JWT without verifying or even
/// validating it. Handy for picking a `VerifyKey` out of a JWKS before
/// the full `verify` call. The returned map is exactly what
/// `select_verify_key` expects.
///
/// Use with caution: nothing in this map is authenticated — the kid /
/// alg an attacker put there is what you get back. Cross-check the
/// returned `alg` against your own policy before trusting it.
pub fn peek_header(token : String) -> Map[String, Json] raise JwtError {
  let parts = token.split(".").to_array()
  if parts.length() != 3 {
    raise InvalidToken("expected 3 segments")
  }
  let header_bytes = base64url_decode(parts[0].to_owned())
  let header_str = @utf8.decode(header_bytes[:]) catch {
    _ => raise InvalidHeader("header is not valid UTF-8")
  }
  parse_json_object(header_str)
}
