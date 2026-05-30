// JWT (RFC 7519) over JWS (RFC 7515) compact serialization.
//
// Supported algorithms:
//   - sign + verify: HS256, HS384, HS512, EdDSA (RFC 8037 §3.1),
//                    RS256, RS384, RS512, ES256, ES384, ES512, ES256K,
//                    PS256, PS384, PS512 (RFC 7518 §3.5)
//
// ES512 uses NIST P-521 / secp521r1 with SHA-512. This workspace does not
// implement a curve literally named "P-512".
//
// PSx note: RFC 7518 §3.5 requires sLen = hLen for PS256 / PS384 / PS512.
// The workspace does not provide an RNG at the JWT layer, so PSx signing
// requires the caller to provide a freshly sampled salt of exactly the hash
// length. Verification always enforces sLen = hLen. Non-standard no-salt PSS
// tokens are rejected under `alg=PS256/384/512` to avoid authentication
// false positives against strict JWA semantics.

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
  // RFC 8812 §3.1 — ECDSA with secp256k1 + SHA-256, used in DID / Web3
  // ecosystems and OpenID Connect for blockchain-backed identities.
  ES256K
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
  // ES256 / ES384 / ES512: ECDSA-SHA-{256,384,512} sign with RFC 6979
  // deterministic nonce.
  Es256(privkey~ : @p256.PrivateKey)
  Es384(privkey~ : @p384.PrivateKey)
  Es512(privkey~ : @p521.PrivateKey)
  // ES256K (RFC 8812): ECDSA-secp256k1-SHA256 with RFC 6979 + BIP-62 low-s.
  // Signature is the JOSE raw form r||s (64 bytes) regardless of the curve.
  Es256k(privkey~ : @secp256k1.PrivateKey)
  // PS256 / PS384 / PS512: RSASSA-PSS sign with caller-supplied salt.
  // The salt must be exactly hLen bytes (32 / 48 / 64 respectively).
  Ps256(privkey~ : @rsa.RsaPrivateKey, salt~ : Bytes)
  Ps384(privkey~ : @rsa.RsaPrivateKey, salt~ : Bytes)
  Ps512(privkey~ : @rsa.RsaPrivateKey, salt~ : Bytes)
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
  // ES512 (ECDSA with P-521 + SHA-512, RFC 7518 §3.4). JOSE raw r||s = 132B.
  Es512(pubkey~ : @p521.PublicKey)
  // ES256K (RFC 8812 §3.1): ECDSA-secp256k1-SHA256. JOSE raw r||s = 64B.
  // Verify is permissive on high-s per the underlying SEC 2 / FIPS 186-5
  // shape — strict BIP-66 rejection is the caller's job.
  Es256k(pubkey~ : @secp256k1.PublicKey)
  // PS256 / PS384 / PS512: RSASSA-PSS verify with sLen = hLen, as required
  // by RFC 7518 §3.5.
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
  // RFC 9068 (OAuth 2.0 access tokens) extra failures. The base error
  // family covers structural / signature / iss / aud / exp / nbf / iat
  // checks; these surface the 9068-specific gates.
  MissingRequiredClaim(String)
  AlgorithmNotAllowed(String)
  ClientIdMismatch
  MissingScopes(Array[String])
  // OIDC Core 1.0 §3.1.3.7 — ID Token validation. Each surface is its own
  // error so callers can branch on policy violations (replay, code/token
  // binding, fresh-auth requirement, etc.).
  NonceMismatch
  AtHashMismatch
  CHashMismatch
  AuthTimeTooOld
  AcrMismatch
  // RFC 7523 — OAuth 2.0 JWT Bearer client authentication. iss and sub
  // MUST both equal the client_id; if they disagree the assertion is
  // not from the claimed client.
  SubjectMismatch
  // RFC 9449 — Demonstrating Proof of Possession (DPoP). The proof JWT
  // failed one of: typ="dpop+jwt"; HTTP method / URI binding; iat
  // freshness; jkt binding against the paired access token; ath hash
  // of the access token; embedded `jwk` header missing or malformed.
  InvalidDpopProof(String)
  // The access token's `cnf.jkt` does not match the SHA-256 thumbprint
  // of the DPoP proof's embedded jwk. Separated from InvalidDpopProof
  // so callers can branch on token-binding failure specifically.
  CnfJktMismatch
  // OIDC Back-Channel Logout 1.0 §2.4 — `nonce` MUST NOT appear in a
  // logout token. Returning it would imply the IdP confused an ID
  // token with a logout assertion; reject so the RP doesn't replay
  // login-context nonces into a logout pipeline.
  LogoutTokenForbiddenNonce
  // OIDC Back-Channel Logout §2.4 — `events` must contain the
  // back-channel-logout schema URL as a JSON-object member.
  MissingLogoutEvent
  // OIDC Back-Channel Logout §2.4 — at least one of `sub` or `sid`
  // MUST be present so the RP knows whose session to terminate.
  LogoutSubAndSidMissing
  // OIDC Core §5.3.2 — when the UserInfo response is signed, `sub`
  // MUST equal the `sub` from the paired ID token. Mismatch implies
  // a substituted identity.
  UserInfoSubMismatch
  // OIDC Self-Issued OP v2 — `sub` MUST equal the SHA-256 thumbprint
  // of the inline `sub_jwk`; if they disagree the holder is asserting
  // an identity that doesn't bind to the key they signed with.
  SelfIssuedSubMismatch
  // OIDC Federation 1.0 — Entity Statement must use the entity
  // statement typ and pair iss / sub correctly for the statement
  // kind (configuration vs. subordinate).
  InvalidEntityStatement(String)
  // OIDC CIBA — when the verifier knows the auth_req_id it issued,
  // the ID token's matching claim MUST round-trip.
  AuthReqIdMismatch
  // OIDC CIBA — rt_hash binding fails the same way at_hash does for
  // an OIDC ID token; raised when opts.refresh_token is set but the
  // hash does not match.
  RtHashMismatch
  // FAPI profile guard — the token violated one of the strict-default
  // policy gates (alg list, missing claim, time bound, etc.). The
  // detail string identifies the violated rule.
  FapiPolicyViolation(String)
} derive(Debug)

///|
pub(all) struct VerifiedJwt {
  header : Map[String, Json]
  claims : Map[String, Json]
  alg : Algorithm
  kid : String?
} derive(Debug)

///|
pub(all) struct Cnf {
  // Full JWK if the IdP shipped it inline. Stored as the raw JSON map
  // so callers can re-parse with `@jwk.parse_public` when needed.
  jwk : Map[String, Json]?
  // JWK SHA-256 thumbprint (RFC 7638) base64url. DPoP relies on this.
  jkt : String?
  // Client-cert SHA-256 thumbprint base64url. mTLS uses this.
  x5t_s256 : String?
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
  let mut last_val = 0
  for c in s {
    // Reject any character that is outside the base64url alphabet up front;
    // the underlying decoder is lenient and we want a single failure mode.
    let val = if c >= 'A' && c <= 'Z' {
      c.to_int() - 'A'.to_int()
    } else if c >= 'a' && c <= 'z' {
      c.to_int() - 'a'.to_int() + 26
    } else if c >= '0' && c <= '9' {
      c.to_int() - '0'.to_int() + 52
    } else if c == '-' {
      62
    } else if c == '_' {
      63
    } else {
      raise InvalidToken("invalid base64url character")
    }
    last_val = val
    let c2 = if c == '-' { '+' } else if c == '_' { '/' } else { c }
    buf.write_char(c2)
    n = n + 1
  }
  if n % 4 == 1 {
    raise InvalidToken("invalid base64url length")
  }
  // RFC 7515 §2 / RFC 4648 §3.5: reject non-canonical encodings. A final
  // quantum of 2 chars leaves the last sextet with 4 unused low bits; of 3
  // chars, 2 unused low bits. Those MUST be zero — otherwise two distinct
  // strings decode to the same octets (signature / token malleability).
  if n % 4 == 2 && (last_val & 0x0F) != 0 {
    raise InvalidToken("non-canonical base64url (trailing bits set)")
  }
  if n % 4 == 3 && (last_val & 0x03) != 0 {
    raise InvalidToken("non-canonical base64url (trailing bits set)")
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
    ES256K => "ES256K"
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
    "ES256K" => ES256K
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
    Es512(..) => ES512
    Es256k(..) => ES256K
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
    Es512(..) => ES512
    Es256k(..) => ES256K
    Ps256(..) => PS256
    Ps384(..) => PS384
    Ps512(..) => PS512
  }
}

///|
fn require_pss_salt_len(
  alg : String,
  salt : Bytes,
  expected : Int,
) -> Unit raise JwtError {
  if salt.length() != expected {
    raise UnsupportedAlgorithm(
      alg + " requires " + expected.to_string() + "-byte PSS salt (sLen=hLen)",
    )
  }
}

///|
fn build_header_json(alg : Algorithm, kid : String?, typ : String) -> Json {
  // Header order is irrelevant for verification (the signing input is the
  // exact base64url-encoded bytes we produce here), so we just emit the
  // fields we care about.
  let m : Map[String, Json] = Map([])
  m["alg"] = Json::string(alg_to_str(alg))
  m["typ"] = Json::string(typ)
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
pub fn sign(
  payload : Json,
  key : Key,
  kid? : String,
  typ? : String = "JWT",
) -> String raise JwtError {
  // RFC 8725 §3.11: a producer SHOULD set `typ` to a value other than
  // "JWT" when the JWS is consumed in a context that has a specific
  // type (e.g., RFC 9068 access tokens use `"at+jwt"`). Default stays
  // "JWT" so existing callers keep working.
  let alg = key_alg(key)
  match kid {
    Some(k) => validate_kid(k)
    None => ()
  }
  let header = build_header_json(alg, kid, typ)
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
    Es512(privkey~) => privkey.sign(signing_bytes)
    Es256k(privkey~) =>
      // @secp256k1.sign defaults to BIP-62 low-s + DER; JOSE wants raw r||s.
      privkey.sign(signing_bytes, format=@secp256k1.SignatureFormat::Raw)
    Ps256(privkey~, salt~) => {
      require_pss_salt_len("PS256", salt, 32)
      privkey.sign_pss(signing_bytes, @rsa.HashAlg::Sha256, salt) catch {
        e =>
          raise UnsupportedAlgorithm(
            "PS256 sign failed: " + @debug.to_string(e),
          )
      }
    }
    Ps384(privkey~, salt~) => {
      require_pss_salt_len("PS384", salt, 48)
      privkey.sign_pss(signing_bytes, @rsa.HashAlg::Sha384, salt) catch {
        e =>
          raise UnsupportedAlgorithm(
            "PS384 sign failed: " + @debug.to_string(e),
          )
      }
    }
    Ps512(privkey~, salt~) => {
      require_pss_salt_len("PS512", salt, 64)
      privkey.sign_pss(signing_bytes, @rsa.HashAlg::Sha512, salt) catch {
        e =>
          raise UnsupportedAlgorithm(
            "PS512 sign failed: " + @debug.to_string(e),
          )
      }
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
fn raise_json_shape_error(
  header_context : Bool,
  message : String,
) -> Unit raise JwtError {
  if header_context {
    raise InvalidHeader(message)
  } else {
    raise ClaimsParseError(message)
  }
}

///|
fn skip_json_ws(s : String, start : Int) -> Int {
  let mut i = start
  while i < s.length() {
    let c = s.get_char(i).unwrap()
    if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
      i = i + 1
    } else {
      break
    }
  }
  i
}

///|
fn read_top_level_json_key(
  s : String,
  start : Int,
  header_context : Bool,
) -> (String, Int) raise JwtError {
  let buf = StringBuilder::new()
  let mut i = start + 1
  while i < s.length() {
    let c = s.get_char(i).unwrap()
    if c == '"' {
      return (buf.to_string(), i + 1)
    }
    if c == '\\' {
      raise_json_shape_error(
        header_context, "escaped JSON member names are not supported",
      )
    }
    buf.write_char(c)
    i = i + 1
  }
  raise_json_shape_error(header_context, "unterminated JSON member name")
  ("", i)
}

///|
fn skip_json_string_value(
  s : String,
  start : Int,
  header_context : Bool,
) -> Int raise JwtError {
  let mut i = start + 1
  while i < s.length() {
    let c = s.get_char(i).unwrap()
    if c == '"' {
      return i + 1
    }
    if c == '\\' {
      i = i + 2
    } else {
      i = i + 1
    }
  }
  raise_json_shape_error(header_context, "unterminated JSON string")
  i
}

///|
fn scan_json_array_no_duplicates(
  s : String,
  start : Int,
  header_context : Bool,
) -> Int raise JwtError {
  let mut i = start + 1
  while true {
    i = skip_json_ws(s, i)
    if i >= s.length() {
      raise_json_shape_error(header_context, "unterminated JSON array")
    }
    if s.get_char(i).unwrap() == ']' {
      return i + 1
    }
    i = skip_json_value(s, i, header_context)
    i = skip_json_ws(s, i)
    if i >= s.length() {
      raise_json_shape_error(header_context, "unterminated JSON array")
    }
    let sep = s.get_char(i).unwrap()
    if sep == ',' {
      i = i + 1
    } else if sep == ']' {
      return i + 1
    } else {
      raise_json_shape_error(header_context, "expected ',' or ']'")
    }
  }
  i
}

///|
fn scan_json_object_no_duplicates(
  s : String,
  start : Int,
  header_context : Bool,
) -> Int raise JwtError {
  let keys : Array[String] = []
  let mut i = start + 1
  while true {
    i = skip_json_ws(s, i)
    if i >= s.length() {
      raise_json_shape_error(header_context, "unterminated JSON object")
    }
    if s.get_char(i).unwrap() == '}' {
      return i + 1
    }
    if s.get_char(i).unwrap() != '"' {
      raise_json_shape_error(header_context, "expected JSON member name")
    }
    let (key, next) = read_top_level_json_key(s, i, header_context)
    for prev in keys {
      if prev == key {
        raise_json_shape_error(
          header_context,
          "duplicate JSON member '" + key + "'",
        )
      }
    }
    keys.push(key)
    i = skip_json_ws(s, next)
    if i >= s.length() || s.get_char(i).unwrap() != ':' {
      raise_json_shape_error(header_context, "expected ':' after JSON member")
    }
    i = skip_json_value(s, i + 1, header_context)
    i = skip_json_ws(s, i)
    if i >= s.length() {
      raise_json_shape_error(header_context, "unterminated JSON object")
    }
    let sep = s.get_char(i).unwrap()
    if sep == ',' {
      i = i + 1
    } else if sep == '}' {
      return i + 1
    } else {
      raise_json_shape_error(header_context, "expected ',' or '}'")
    }
  }
  i
}

///|
fn skip_json_value(
  s : String,
  start : Int,
  header_context : Bool,
) -> Int raise JwtError {
  let mut i = skip_json_ws(s, start)
  if i >= s.length() {
    raise_json_shape_error(header_context, "missing JSON value")
  }
  let c = s.get_char(i).unwrap()
  if c == '"' {
    return skip_json_string_value(s, i, header_context)
  }
  if c == '{' {
    return scan_json_object_no_duplicates(s, i, header_context)
  }
  if c == '[' {
    return scan_json_array_no_duplicates(s, i, header_context)
  }
  while i < s.length() {
    let x = s.get_char(i).unwrap()
    if x == ',' || x == '}' || x == ']' {
      return i
    }
    i = i + 1
  }
  i
}

///|
fn reject_duplicate_top_level_json_keys(
  s : String,
  header_context : Bool,
) -> Unit raise JwtError {
  let keys : Array[String] = []
  let mut i = skip_json_ws(s, 0)
  if i >= s.length() || s.get_char(i).unwrap() != '{' {
    raise_json_shape_error(header_context, "expected JSON object")
  }
  i = i + 1
  let mut done = false
  while !done {
    i = skip_json_ws(s, i)
    if i >= s.length() {
      raise_json_shape_error(header_context, "unterminated JSON object")
    }
    if s.get_char(i).unwrap() == '}' {
      i = i + 1
      done = true
      continue
    }
    if s.get_char(i).unwrap() != '"' {
      raise_json_shape_error(header_context, "expected JSON member name")
    }
    let (key, next) = read_top_level_json_key(s, i, header_context)
    for prev in keys {
      if prev == key {
        raise_json_shape_error(
          header_context,
          "duplicate top-level JSON member '" + key + "'",
        )
      }
    }
    keys.push(key)
    i = skip_json_ws(s, next)
    if i >= s.length() || s.get_char(i).unwrap() != ':' {
      raise_json_shape_error(header_context, "expected ':' after JSON member")
    }
    i = skip_json_value(s, i + 1, header_context)
    i = skip_json_ws(s, i)
    if i >= s.length() {
      raise_json_shape_error(header_context, "unterminated JSON object")
    }
    let sep = s.get_char(i).unwrap()
    if sep == ',' {
      i = i + 1
    } else if sep == '}' {
      i = i + 1
      done = true
    } else {
      raise_json_shape_error(header_context, "expected ',' or '}'")
    }
  }
  i = skip_json_ws(s, i)
  if i != s.length() {
    raise_json_shape_error(header_context, "trailing data after JSON object")
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
fn ascii_lower(s : String) -> String {
  let buf = StringBuilder::new()
  for c in s {
    let n = c.to_int()
    if n >= 0x41 && n <= 0x5a {
      buf.write_char((n + 0x20).to_char().unwrap())
    } else {
      buf.write_char(c)
    }
  }
  buf.to_string()
}

///|
let max_kid_len : Int = 256

///|
fn validate_kid(kid : String) -> Unit raise JwtError {
  if kid.length() == 0 {
    raise InvalidHeader("kid must not be empty")
  }
  if kid.length() > max_kid_len {
    raise InvalidHeader("kid too long")
  }
  for c in kid {
    let v = c.to_int()
    if v < 0x21 || v > 0x7e {
      raise InvalidHeader("kid must be printable ASCII without whitespace")
    }
  }
}

///|
fn get_header_kid(header : Map[String, Json]) -> String? raise JwtError {
  match header.get("kid") {
    Some(String(k)) => {
      validate_kid(k)
      Some(k)
    }
    Some(_) => raise InvalidHeader("kid must be a string")
    None => None
  }
}

///|
// Pull a unix-seconds claim out of the claims map. JWT spec (RFC 7519 §2)
// calls these "NumericDate"s, defined as a JSON numeric value. Missing claims
// remain optional, but a present non-number is malformed and must not silently
// disable time-based validation.
fn get_numeric_date(
  m : Map[String, Json],
  key : String,
) -> Int64? raise JwtError {
  match m.get(key) {
    Some(Number(n, ..)) => Some(n.to_int64())
    Some(_) =>
      raise ClaimsParseError("claim '" + key + "' is not a NumericDate")
    _ => None
  }
}

///|
// `aud` may be a single string or an array of strings (RFC 7519 §4.1.3).
fn audience_matches(claim : Json, expected : String) -> Bool raise JwtError {
  validate_aud_claim_shape(claim)
  match claim {
    String(s) => s == expected
    Array(arr) => {
      let mut matched = false
      for v in arr {
        match v {
          String(s) => if s == expected { matched = true }
          _ => raise ClaimsParseError("aud array entry not a string")
        }
      }
      matched
    }
    _ => raise ClaimsParseError("aud is neither string nor array")
  }
}

///|
fn validate_registered_string_claim_shape(
  m : Map[String, Json],
  key : String,
) -> Unit raise JwtError {
  match m.get(key) {
    Some(String(_)) | None => ()
    Some(_) => raise ClaimsParseError("claim '" + key + "' is not a string")
  }
}

///|
fn validate_aud_claim_shape(claim : Json) -> Unit raise JwtError {
  match claim {
    String(_) => ()
    Array(arr) =>
      for v in arr {
        match v {
          String(_) => ()
          _ => raise ClaimsParseError("aud array entry not a string")
        }
      }
    _ => raise ClaimsParseError("aud is neither string nor array")
  }
}

///|
fn validate_registered_claim_shapes(
  claims : Map[String, Json],
) -> Unit raise JwtError {
  // RFC 7519 registered string claims are optional, but once present their
  // JSON type is part of the verified token's contract. Rejecting here keeps
  // generic `verify` callers from receiving a signed-but-malformed claim set.
  for key in ["iss", "sub", "jti"] {
    validate_registered_string_claim_shape(claims, key)
  }
  match claims.get("aud") {
    Some(v) => validate_aud_claim_shape(v)
    None => ()
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
  reject_duplicate_top_level_json_keys(header_str, true)
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
  let typ = match header.get("typ") {
    Some(String(s)) => Some(s)
    Some(_) => raise InvalidHeader("typ must be a string")
    None => None
  }
  // RFC 8725 §3.11: explicit typing. When the caller asks for a `typ`
  // allow-list, the header MUST carry one of the listed values. This is
  // what RFC 9068 §4 requires for `at+jwt` access tokens and what RFC
  // 7519 IdPs use to disambiguate ID tokens from generic JWS payloads.
  match opts.typ_allowed {
    Some(allowed) => {
      let actual = match typ {
        Some(s) => s
        None => raise InvalidType("missing typ header")
      }
      let actual_norm = ascii_lower(actual)
      let mut ok = false
      for t in allowed {
        if ascii_lower(t) == actual_norm {
          ok = true
          break
        }
      }
      if !ok {
        raise InvalidType("typ '" + actual + "' not in allow-list")
      }
    }
    None =>
      // Defence in depth: when the caller hasn't pinned a typ allow-list,
      // still reject typ values that name a *different* JWS class. An IdP
      // that signs ID tokens and (say) DPoP proofs with the same key
      // would otherwise let an attacker present a DPoP proof to a code
      // path expecting an ID token — same signature, different
      // authorisation semantics. The denylist below names every typ this
      // module knows about; callers who genuinely want one of them must
      // pass `typ_allowed=Some([...])` to opt in.
      match typ {
        Some(t) => {
          let t_norm = ascii_lower(t)
          let denied = [
            "at+jwt", "application/at+jwt", "logout+jwt", "application/logout+jwt",
            "dpop+jwt", "application/dpop+jwt", "entity-statement+jwt", "application/entity-statement+jwt",
            "secevent+jwt", "application/secevent+jwt", "ciba+jwt", "application/ciba+jwt",
            "oauth-authz-req+jwt", "application/oauth-authz-req+jwt", "oauth-authz-resp+jwt",
            "application/oauth-authz-resp+jwt",
          ]
          for d in denied {
            if t_norm == d {
              raise InvalidType(
                "specialised typ '" +
                t +
                "' rejected by default; pass typ_allowed to opt in",
              )
            }
          }
        }
        None => ()
      }
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
    (ES512, Es512(pubkey~)) =>
      // r||s, 132 bytes total for ES512 / P-521.
      @p521.verify(
        pubkey,
        signing_bytes,
        provided_sig,
        @p521.SignatureFormat::Raw,
      ) catch {
        _ => raise InvalidSignature
      }
    (ES256K, Es256k(pubkey~)) =>
      // r||s, 64 bytes total. RFC 8812 §3.1.
      @secp256k1.verify(
        pubkey,
        signing_bytes,
        provided_sig,
        @secp256k1.SignatureFormat::Raw,
      ) catch {
        _ => raise InvalidSignature
      }
    (PS256, Ps256(pubkey~)) =>
      pubkey.verify_pss(signing_bytes, provided_sig, @rsa.HashAlg::Sha256) catch {
        _ => raise InvalidSignature
      }
    (PS384, Ps384(pubkey~)) =>
      pubkey.verify_pss(signing_bytes, provided_sig, @rsa.HashAlg::Sha384) catch {
        _ => raise InvalidSignature
      }
    (PS512, Ps512(pubkey~)) =>
      pubkey.verify_pss(signing_bytes, provided_sig, @rsa.HashAlg::Sha512) catch {
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
  reject_duplicate_top_level_json_keys(payload_str, false)
  // JWS payload is not required to be JSON, but JWT claims must be a JSON
  // object. Reject raw JWS payloads and JSON scalars so callers cannot
  // accidentally treat a non-JWT as an empty-claims JWT.
  let payload_json = @json.parse(payload_str[:]) catch {
    _ => raise ClaimsParseError("payload is not valid JSON")
  }
  let claims : Map[String, Json] = match payload_json {
    Object(m) => m
    _ => raise ClaimsParseError("payload is not a JSON object")
  }
  validate_registered_claim_shapes(claims)

  // ---- iat / exp / nbf / iss / aud ----
  // RFC 8725 §3.10: an `iat` more than `clock_skew_sec` in the future is
  // not a legitimately-issued token. Reject so a stockpiled future-dated
  // token can't be replayed once the clock catches up. iat is optional
  // (RFC 7519 §4.1.6), so missing iat is fine.
  match get_numeric_date(claims, "iat") {
    Some(iat) =>
      if iat > opts.now + opts.clock_skew_sec {
        raise IssuedInFuture
      }
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
  let kid = get_header_kid(header)
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
///   considered. If none or more than one match, `NoMatchingKey` is raised
///   so duplicate `kid` entries cannot become first-match-wins.
/// - If the header has no `kid` and the set has exactly one entry, that
///   one is used. Otherwise `NoMatchingKey` is raised (ambiguous).
/// - `kid` must be non-empty printable ASCII without whitespace; this keeps
///   the returned / logged identifier from carrying control data.
/// - If the JWKS entry has `use` or `key_ops`, the metadata must permit
///   signature verification (`use="sig"` and/or `key_ops` containing
///   `"verify"`).
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
  let header_kid = get_header_kid(header)
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
    None => if set.length() == 1 { [set[0]] } else { raise NoMatchingKey }
  }
  if candidates.length() != 1 {
    raise NoMatchingKey
  }
  let entry = candidates[0]
  // RFC 7517 §4.2 — `use` declares the JWK's intended purpose. For
  // signature verification only "sig" or an absent field is valid;
  // a key tagged `use="enc"` is for encryption and MUST NOT be
  // accepted as a verification key. This blocks a JWKS-poisoning
  // attack where an attacker substitutes an encryption key under
  // the kid of a signing key (the alg-mismatch check above stops
  // most of these, but `use` adds defence in depth when the JWKS
  // entry's `alg` field is absent).
  match entry.use_ {
    Some(u) => if u != "sig" { raise NoMatchingKey }
    None => ()
  }
  match entry.key_ops {
    Some(ops) => {
      let mut ok = false
      for op in ops {
        if op == "verify" {
          ok = true
          break
        }
      }
      if !ok {
        raise NoMatchingKey
      }
    }
    None => ()
  }
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
    (ES512, EcP521(pubkey~, ..)) => Es512(pubkey~)
    (ES256K, EcSecp256k1(pubkey~, ..)) => Es256k(pubkey~)
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
  reject_duplicate_top_level_json_keys(header_str, true)
  parse_json_object(header_str)
}

// -----------------------------------------------------------------------------
// RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
// -----------------------------------------------------------------------------
//
// Per RFC 9068 §2, an access token MUST carry:
//   * a `typ` header of "at+jwt" (or "application/at+jwt")
//   * the claims `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`
//
// Per §4 the resource server MUST validate signature + iss + aud + exp + nbf
// + iat, and reject `none` / unexpected algorithms.

///|
/// Caller policy for `verify_rfc9068`. `issuer` and `audience` are
/// mandatory per the RFC (the AS issuer and the resource indicator the
/// RS expects to find in `aud`). The optional fields layer on extra
/// gates the deployment may want.
pub(all) struct Rfc9068VerifyOptions {
  now : Int64
  clock_skew_sec : Int64
  // Expected AS issuer URL. The token's `iss` claim must equal this.
  issuer : String
  // Resource indicator the RS expects in `aud`. The token's `aud` claim
  // must contain this value (either as a JSON string or inside the
  // JSON array form of `aud`).
  audience : String
  // If `Some(c)`, the token's `client_id` must equal `c`. None permits
  // any client_id (the claim is still required to be present).
  expected_client_id : String?
  // If `Some(s)`, each scope in `s` must appear in the token's space-
  // separated `scope` claim. RFC 8693 §4.2 / RFC 9068 §2.2.3.
  required_scopes : Array[String]?
  // If `Some(algs)`, the JWT's `alg` must be one of these. Use this to
  // pin to e.g. ES256 only. RFC 9068 §4 step 7 — the RS rejects tokens
  // signed with an algorithm outside its policy. `none` is always
  // rejected regardless (no typed VerifyKey variant exists for it).
  allowed_algorithms : Array[Algorithm]?
} derive(Eq, Debug)

///|
pub fn Rfc9068VerifyOptions::default(
  now : Int64,
  issuer : String,
  audience : String,
) -> Rfc9068VerifyOptions {
  {
    now,
    clock_skew_sec: 0L,
    issuer,
    audience,
    expected_client_id: None,
    required_scopes: None,
    allowed_algorithms: None,
  }
}

///|
/// Result of a successful RFC 9068 verify. Required claims are hoisted
/// out for direct field access; optional standard claims (`nbf`,
/// `auth_time`, `acr`, `amr`, `scope`) are exposed as `Option`. Anything
/// else the IdP put in the payload is still accessible via `jwt.claims`.
pub(all) struct Rfc9068Token {
  iss : String
  sub : String
  aud : Array[String]
  exp : Int64
  iat : Int64
  jti : String
  client_id : String
  nbf : Int64?
  auth_time : Int64?
  acr : String?
  amr : Array[String]?
  scope : Array[String]?
  // RFC 7800 confirmation claim. If present, encodes the proof-of-
  // possession key (DPoP `jkt`, mTLS `x5t#S256`, or full `jwk`). The
  // resource server validates it against the DPoP proof / mTLS cert
  // out of band — see verify_dpop_proof.
  cnf : Cnf?
  jwt : VerifiedJwt
}

///|
/// Verify a JWT against the RFC 9068 OAuth 2.0 access-token profile and
/// return the structured token. Performs every check `verify` does plus
/// the 9068-required claim presence, audience semantics, and the
/// optional policy gates from `opts`.
pub fn verify_rfc9068(
  token : String,
  key : VerifyKey,
  opts : Rfc9068VerifyOptions,
) -> Rfc9068Token raise JwtError {
  let base : VerifyOptions = {
    now: opts.now,
    clock_skew_sec: opts.clock_skew_sec,
    require_exp: true,
    issuer: Some(opts.issuer),
    audience: Some(opts.audience),
    typ_allowed: Some(["at+jwt", "application/at+jwt"]),
  }
  let v = verify(token, key, base)
  finalise_rfc9068(v, opts)
}

///|
/// JWKS-driven variant. Picks the verify key out of the set using the
/// token's header (per `select_verify_key`), then runs the 9068
/// validation pipeline.
pub fn verify_rfc9068_jwks(
  token : String,
  set : Array[@jwk.JwkSetEntry],
  opts : Rfc9068VerifyOptions,
) -> Rfc9068Token raise JwtError {
  let header = peek_header(token)
  let key = select_verify_key(set, header)
  verify_rfc9068(token, key, opts)
}

///|
fn finalise_rfc9068(
  v : VerifiedJwt,
  opts : Rfc9068VerifyOptions,
) -> Rfc9068Token raise JwtError {
  // Algorithm allow-list. The signature already verified under whatever
  // `alg` the JWS declared, so this is an *additional* policy gate. We
  // run it after verify() so we never accept-then-reject — verify()
  // itself would have refused unknown algorithms.
  match opts.allowed_algorithms {
    Some(allowed) => {
      let mut ok = false
      for a in allowed {
        if a == v.alg {
          ok = true
          break
        }
      }
      if !ok {
        raise AlgorithmNotAllowed(alg_to_str(v.alg))
      }
    }
    None => ()
  }
  let iss = require_string_claim(v.claims, "iss")
  let sub = require_string_claim(v.claims, "sub")
  let aud = extract_aud(v.claims)
  let exp = require_numeric_claim(v.claims, "exp")
  let iat = require_numeric_claim(v.claims, "iat")
  let jti = require_string_claim(v.claims, "jti")
  let client_id = require_string_claim(v.claims, "client_id")
  match opts.expected_client_id {
    Some(want) => if want != client_id { raise ClientIdMismatch }
    None => ()
  }
  let scope = match extract_string(v.claims, "scope") {
    Some(s) => Some(split_space(s))
    None => None
  }
  match opts.required_scopes {
    Some(required) => {
      let have = match scope {
        Some(s) => s
        None => []
      }
      let missing : Array[String] = []
      for need in required {
        let mut found = false
        for h in have {
          if h == need {
            found = true
            break
          }
        }
        if !found {
          missing.push(need)
        }
      }
      if missing.length() > 0 {
        raise MissingScopes(missing)
      }
    }
    None => ()
  }
  {
    iss,
    sub,
    aud,
    exp,
    iat,
    jti,
    client_id,
    nbf: get_numeric_date(v.claims, "nbf"),
    auth_time: get_numeric_date(v.claims, "auth_time"),
    acr: extract_string(v.claims, "acr"),
    amr: extract_string_array(v.claims, "amr"),
    scope,
    cnf: extract_cnf(v.claims),
    jwt: v,
  }
}

///|
fn require_string_claim(
  m : Map[String, Json],
  key : String,
) -> String raise JwtError {
  match m.get(key) {
    Some(String(s)) => s
    Some(_) => raise ClaimsParseError("claim '" + key + "' is not a string")
    None => raise MissingRequiredClaim(key)
  }
}

///|
fn require_numeric_claim(
  m : Map[String, Json],
  key : String,
) -> Int64 raise JwtError {
  match get_numeric_date(m, key) {
    Some(n) => n
    None => raise MissingRequiredClaim(key)
  }
}

///|
fn extract_aud(m : Map[String, Json]) -> Array[String] raise JwtError {
  // RFC 7519 §4.1.3: `aud` is either a String or an Array of strings.
  // Normalise to Array[String] for uniform handling.
  match m.get("aud") {
    Some(String(s)) => [s]
    Some(Array(items)) => {
      let out : Array[String] = []
      for it in items {
        match it {
          String(s) => out.push(s)
          _ => raise ClaimsParseError("aud array entry not a string")
        }
      }
      out
    }
    Some(_) => raise ClaimsParseError("aud is neither string nor array")
    None => raise MissingRequiredClaim("aud")
  }
}

///|
fn extract_string_array(
  m : Map[String, Json],
  key : String,
) -> Array[String]? raise JwtError {
  match m.get(key) {
    Some(Array(items)) => {
      let out : Array[String] = []
      for it in items {
        match it {
          String(s) => out.push(s)
          _ => raise ClaimsParseError(key + " array entry not a string")
        }
      }
      Some(out)
    }
    Some(_) => raise ClaimsParseError(key + " is not an array of strings")
    None => None
  }
}

///|
fn split_space(s : String) -> Array[String] {
  // RFC 6749 §3.3 / RFC 8693 §4.2: scope values are space-separated. Empty
  // tokens (consecutive spaces, leading/trailing space) are dropped.
  let out : Array[String] = []
  let buf = StringBuilder::new()
  let mut have = false
  for c in s {
    if c == ' ' {
      if have {
        out.push(buf.to_string())
        buf.reset()
        have = false
      }
    } else {
      buf.write_char(c)
      have = true
    }
  }
  if have {
    out.push(buf.to_string())
  }
  out
}

// -----------------------------------------------------------------------------
// OpenID Connect Core 1.0 §3.1.3.7 — ID Token validation
// -----------------------------------------------------------------------------
//
// ID tokens differ from RFC 9068 access tokens in a few important ways:
//   * `typ` is usually omitted (no allow-list).
//   * `aud` MUST contain the relying party's `client_id`. If multiple
//     audiences are listed, the `azp` claim MUST equal `client_id`.
//   * `nonce` (if the auth request carried one) MUST match exactly.
//   * `at_hash` and `c_hash` (RFC 7515 §3.1.3.6 / §3.3.2.11) bind the ID
//     token to a specific access token / authorization code by hashing
//     the value with the JWS alg's digest and taking the left half.
//   * `auth_time` may be required under `max_age`.

///|
/// Verification policy for `verify_oidc_id_token`. Bind each optional
/// field iff the deployment expects that check to apply:
///
/// - `expected_nonce`: set to the `nonce` value the relying party sent
///   in the authorization request. Replay-defence is meaningless if you
///   forget this in interactive flows.
/// - `access_token` / `authorization_code`: triggers the matching
///   `at_hash` / `c_hash` binding check (hybrid + implicit flows).
/// - `max_age_sec`: if the auth request asked for `max_age`, the IdP
///   MUST emit `auth_time`, and `auth_time + max_age + clock_skew_sec`
///   must be >= `now`.
/// - `expected_acr`: pin the authentication-context class.
/// - `allowed_algorithms`: pin the JWS alg (OIDC §16.18: e.g., reject
///   HS-based ID tokens when the relying party expects RS-only).
pub(all) struct OidcIdTokenVerifyOptions {
  now : Int64
  clock_skew_sec : Int64
  issuer : String
  client_id : String
  expected_nonce : String?
  access_token : String?
  authorization_code : String?
  max_age_sec : Int64?
  expected_acr : String?
  allowed_algorithms : Array[Algorithm]?
}

///|
pub fn OidcIdTokenVerifyOptions::default(
  now : Int64,
  issuer : String,
  client_id : String,
) -> OidcIdTokenVerifyOptions {
  {
    now,
    clock_skew_sec: 0L,
    issuer,
    client_id,
    expected_nonce: None,
    access_token: None,
    authorization_code: None,
    max_age_sec: None,
    expected_acr: None,
    allowed_algorithms: None,
  }
}

///|
pub fn OidcIdTokenVerifyOptions::strict(
  now : Int64,
  issuer : String,
  client_id : String,
  expected_nonce : String,
) -> OidcIdTokenVerifyOptions {
  {
    ..OidcIdTokenVerifyOptions::default(now, issuer, client_id),
    expected_nonce: Some(expected_nonce),
  }
}

///|
/// Structured ID token. Required OIDC claims are hoisted to top-level
/// fields; optional standard claims (auth_time, acr, amr, nonce, at_hash,
/// c_hash, azp, plus the OIDC §5.1 profile shorthand for email / name /
/// preferred_username) are exposed as `Option`. The full verified JWS
/// (header, claims, alg, kid) remains accessible via `jwt`.
pub(all) struct OidcIdToken {
  iss : String
  sub : String
  aud : Array[String]
  exp : Int64
  iat : Int64
  azp : String?
  auth_time : Int64?
  nonce : String?
  acr : String?
  amr : Array[String]?
  at_hash : String?
  c_hash : String?
  email : String?
  email_verified : Bool?
  name : String?
  preferred_username : String?
  // RFC 7800 confirmation claim (rare on ID tokens, common on
  // OAuth access tokens). Exposed for symmetry with Rfc9068Token.
  cnf : Cnf?
  jwt : VerifiedJwt
}

///|
pub fn verify_oidc_id_token(
  token : String,
  key : VerifyKey,
  opts : OidcIdTokenVerifyOptions,
) -> OidcIdToken raise JwtError {
  let base : VerifyOptions = {
    now: opts.now,
    clock_skew_sec: opts.clock_skew_sec,
    require_exp: true,
    issuer: Some(opts.issuer),
    audience: Some(opts.client_id),
    typ_allowed: None,
  }
  let v = verify(token, key, base)
  finalise_oidc_id_token(v, opts)
}

///|
pub fn verify_oidc_id_token_jwks(
  token : String,
  set : Array[@jwk.JwkSetEntry],
  opts : OidcIdTokenVerifyOptions,
) -> OidcIdToken raise JwtError {
  let header = peek_header(token)
  let key = select_verify_key(set, header)
  verify_oidc_id_token(token, key, opts)
}

///|
fn finalise_oidc_id_token(
  v : VerifiedJwt,
  opts : OidcIdTokenVerifyOptions,
) -> OidcIdToken raise JwtError {
  match opts.allowed_algorithms {
    Some(allowed) => {
      let mut ok = false
      for a in allowed {
        if a == v.alg {
          ok = true
          break
        }
      }
      if !ok {
        raise AlgorithmNotAllowed(alg_to_str(v.alg))
      }
    }
    None => ()
  }
  let iss = require_string_claim(v.claims, "iss")
  let sub = require_string_claim(v.claims, "sub")
  let aud = extract_aud(v.claims)
  let exp = require_numeric_claim(v.claims, "exp")
  let iat = require_numeric_claim(v.claims, "iat")
  // OIDC §3.1.3.7 step 4–5: if aud has multiple entries, azp MUST be
  // present and equal the relying party's client_id.
  let azp = extract_string(v.claims, "azp")
  if aud.length() > 1 {
    match azp {
      Some(s) => if s != opts.client_id { raise InvalidAudience }
      None => raise InvalidAudience
    }
  } else {
    match azp {
      Some(s) => if s != opts.client_id { raise InvalidAudience }
      None => ()
    }
  }
  // OIDC §3.1.3.7 step 11: nonce replay defence.
  let nonce = extract_string(v.claims, "nonce")
  match opts.expected_nonce {
    Some(want) =>
      match nonce {
        Some(got) => if want != got { raise NonceMismatch }
        None => raise NonceMismatch
      }
    None => ()
  }
  // OIDC §3.1.3.6 / §3.3.2.11: at_hash / c_hash bind the ID token to a
  // specific access_token / authorization_code.
  let at_hash = extract_string(v.claims, "at_hash")
  match opts.access_token {
    Some(at) =>
      match at_hash {
        Some(claimed) => {
          let expected = compute_x_hash(v.alg, at)
          if claimed != expected {
            raise AtHashMismatch
          }
        }
        None => raise AtHashMismatch
      }
    None => ()
  }
  let c_hash = extract_string(v.claims, "c_hash")
  match opts.authorization_code {
    Some(code) =>
      match c_hash {
        Some(claimed) => {
          let expected = compute_x_hash(v.alg, code)
          if claimed != expected {
            raise CHashMismatch
          }
        }
        None => raise CHashMismatch
      }
    None => ()
  }
  // OIDC §3.1.2.1 / §3.1.3.7 step 13: max_age requires auth_time and
  // bounds its age.
  let auth_time = get_numeric_date(v.claims, "auth_time")
  match opts.max_age_sec {
    Some(max) =>
      match auth_time {
        Some(at) =>
          if at + max + opts.clock_skew_sec < opts.now {
            raise AuthTimeTooOld
          }
        None => raise AuthTimeTooOld
      }
    None => ()
  }
  let acr = extract_string(v.claims, "acr")
  match opts.expected_acr {
    Some(want) =>
      match acr {
        Some(got) => if got != want { raise AcrMismatch }
        None => raise AcrMismatch
      }
    None => ()
  }
  {
    iss,
    sub,
    aud,
    exp,
    iat,
    azp,
    auth_time,
    nonce,
    acr,
    amr: extract_string_array(v.claims, "amr"),
    at_hash,
    c_hash,
    email: extract_string(v.claims, "email"),
    email_verified: get_bool(v.claims, "email_verified"),
    name: extract_string(v.claims, "name"),
    preferred_username: extract_string(v.claims, "preferred_username"),
    cnf: extract_cnf(v.claims),
    jwt: v,
  }
}

///|
fn get_bool(m : Map[String, Json], key : String) -> Bool? raise JwtError {
  match m.get(key) {
    Some(True) => Some(true)
    Some(False) => Some(false)
    Some(_) => raise ClaimsParseError(key + " is not a boolean")
    None => None
  }
}

///|
/// Compute the OIDC `at_hash` / `c_hash` value: hash the input UTF-8
/// bytes with the digest matching the JWS alg (§3.1.3.6), take the
/// left half, base64url-encode (no padding).
///
/// Per OIDC §3.1.3.6 the hash function follows the JWS alg's family:
///   RS256/ES256/HS256/PS256 → SHA-256
///   RS384/ES384/HS384/PS384 → SHA-384
///   RS512/ES512/HS512/PS512 → SHA-512
///   EdDSA                   → SHA-512 (matches Ed25519's internal hash)
///
/// Exposed for issuers that need to embed `at_hash` / `c_hash` in the
/// ID token they emit, and for callers that want to compare a hash
/// without round-tripping through `verify_oidc_id_token`.
pub fn compute_x_hash(alg : Algorithm, value : String) -> String {
  let bytes = @utf8.encode(value[:])
  let h = match alg {
    HS256 | RS256 | ES256 | PS256 | ES256K => @hash.sha256(bytes)
    HS384 | RS384 | ES384 | PS384 => @hash.sha384(bytes)
    HS512 | RS512 | ES512 | PS512 | EdDSA => @hash.sha512(bytes)
  }
  let half = h.length() / 2
  let left = Bytes::makei(half, fn(i) { h[i] })
  base64url_encode(left)
}

// -----------------------------------------------------------------------------
// RFC 7523 — JWT Profile for OAuth 2.0 Client Authentication
// -----------------------------------------------------------------------------
//
// §3 client_assertion shape:
//   iss = sub = client_id
//   aud = the AS's token endpoint URL (the verifier's identifier)
//   exp REQUIRED; jti SHOULD; iat MAY
//
// This is the assertion the *client* presents to the *authorization server*
// when using client_assertion_type=
// "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".

///|
pub(all) struct ClientAssertionVerifyOptions {
  now : Int64
  clock_skew_sec : Int64
  // The client_id the AS believes is making the assertion. Both `iss`
  // and `sub` MUST equal this value (RFC 7523 §3 step 2 + 3).
  expected_client_id : String
  // The AS's token endpoint URL (or another AS-chosen identifier).
  // The assertion's `aud` claim must contain this value.
  token_endpoint : String
  allowed_algorithms : Array[Algorithm]?
  // Strict AS profiles should reject replay-friendly assertions. The default
  // constructor requires a replay cache key (`jti`), recent `iat`, and a short
  // exp lifetime.
  require_jti : Bool
  max_iat_age_sec : Int64?
  max_exp_lifetime_sec : Int64?
} derive(Eq, Debug)

///|
pub fn ClientAssertionVerifyOptions::default(
  now : Int64,
  expected_client_id : String,
  token_endpoint : String,
) -> ClientAssertionVerifyOptions {
  {
    now,
    clock_skew_sec: 0L,
    expected_client_id,
    token_endpoint,
    allowed_algorithms: None,
    require_jti: true,
    max_iat_age_sec: Some(300L),
    max_exp_lifetime_sec: Some(300L),
  }
}

///|
pub(all) struct ClientAssertion {
  client_id : String
  aud : Array[String]
  exp : Int64
  iat : Int64?
  jti : String?
  jwt : VerifiedJwt
}

///|
pub fn verify_client_assertion(
  token : String,
  key : VerifyKey,
  opts : ClientAssertionVerifyOptions,
) -> ClientAssertion raise JwtError {
  let base : VerifyOptions = {
    now: opts.now,
    clock_skew_sec: opts.clock_skew_sec,
    require_exp: true,
    issuer: Some(opts.expected_client_id),
    audience: Some(opts.token_endpoint),
    typ_allowed: None,
  }
  let v = verify(token, key, base)
  match opts.allowed_algorithms {
    Some(allowed) => {
      let mut ok = false
      for a in allowed {
        if a == v.alg {
          ok = true
          break
        }
      }
      if !ok {
        raise AlgorithmNotAllowed(alg_to_str(v.alg))
      }
    }
    None => ()
  }
  let sub = require_string_claim(v.claims, "sub")
  if sub != opts.expected_client_id {
    raise SubjectMismatch
  }
  let aud = extract_aud(v.claims)
  let exp = require_numeric_claim(v.claims, "exp")
  let iat = get_numeric_date(v.claims, "iat")
  match opts.max_iat_age_sec {
    Some(max) => {
      let issued = match iat {
        Some(n) => n
        None => raise MissingRequiredClaim("iat")
      }
      if issued + max + opts.clock_skew_sec < opts.now {
        raise IssuedInFuture
      }
    }
    None => ()
  }
  match opts.max_exp_lifetime_sec {
    Some(max) => {
      let issued = match iat {
        Some(n) => n
        None => raise MissingRequiredClaim("iat")
      }
      if exp > issued + max {
        raise ClaimsParseError("client assertion exp lifetime too long")
      }
    }
    None => ()
  }
  let jti = extract_string(v.claims, "jti")
  if opts.require_jti && jti is None {
    raise MissingRequiredClaim("jti")
  }
  { client_id: opts.expected_client_id, aud, exp, iat, jti, jwt: v }
}

///|
pub fn verify_client_assertion_jwks(
  token : String,
  set : Array[@jwk.JwkSetEntry],
  opts : ClientAssertionVerifyOptions,
) -> ClientAssertion raise JwtError {
  let header = peek_header(token)
  let key = select_verify_key(set, header)
  verify_client_assertion(token, key, opts)
}

// -----------------------------------------------------------------------------
// RFC 7800 — Proof-of-Possession Key Semantics (cnf claim)
// -----------------------------------------------------------------------------
//
// `cnf` is a JSON object whose members encode how the holder proves
// possession of an asymmetric key (or a shared secret) bound to the
// token. The three forms we recognise:
//   * jwk          — full JWK of the holder's key
//   * jkt          — base64url(SHA-256(canonical JWK)) thumbprint
//                    (used by DPoP, RFC 9449)
//   * x5t#S256     — base64url(SHA-256(client cert)) thumbprint
//                    (used by OAuth mTLS client auth, RFC 8705)

///|
fn extract_cnf(claims : Map[String, Json]) -> Cnf? raise JwtError {
  match claims.get("cnf") {
    None => None
    Some(Object(m)) => {
      for key, _ in m {
        if key != "jwk" && key != "jkt" && key != "x5t#S256" {
          raise ClaimsParseError("unsupported cnf member '" + key + "'")
        }
      }
      let jwk = match m.get("jwk") {
        Some(Object(inner)) => Some(inner)
        Some(_) => raise ClaimsParseError("cnf.jwk is not an object")
        None => None
      }
      let jkt = match m.get("jkt") {
        Some(String(s)) => Some(s)
        Some(_) => raise ClaimsParseError("cnf.jkt is not a string")
        None => None
      }
      let x5t_s256 = match m.get("x5t#S256") {
        Some(String(s)) => Some(s)
        Some(_) => raise ClaimsParseError("cnf.x5t#S256 is not a string")
        None => None
      }
      if jwk is None && jkt is None && x5t_s256 is None {
        raise ClaimsParseError("cnf has no supported confirmation method")
      }
      Some({ jwk, jkt, x5t_s256 })
    }
    Some(_) => raise ClaimsParseError("claim 'cnf' is not an object")
  }
}

// -----------------------------------------------------------------------------
// RFC 9449 — Demonstrating Proof of Possession (DPoP)
// -----------------------------------------------------------------------------
//
// A DPoP proof JWT is a small companion JWS that travels alongside an
// OAuth access token. The resource server validates the proof against
// the request and against the access token's `cnf.jkt` to confirm the
// caller controls the private key paired with the access token.
//
// Proof shape (§4):
//   header.typ  = "dpop+jwt"
//   header.alg  ∈ {ES256, ES256K, ES384, ES512, EdDSA, RS256, PS256, …}
//                 — no symmetric algs, no "none"
//   header.jwk  = the holder's JWK (public part only)
//   claims.jti  = unique per-request nonce (replay defence, RS state)
//   claims.htm  = HTTP method, e.g., "GET"
//   claims.htu  = HTTP URI without query/fragment
//   claims.iat  = issued-at, recent
//   claims.ath  = base64url(SHA-256(access_token))  — when bound
//   claims.nonce = optional, supplied by the server for nonce protocol

///|
pub(all) struct DpopVerifyOptions {
  now : Int64
  // How recently the proof must have been issued. RFC 9449 §4.3 step 11
  // recommends short windows (e.g., a few seconds to a minute). We
  // accept iat ∈ (now - max_iat_age_sec, now + clock_skew_sec).
  max_iat_age_sec : Int64
  clock_skew_sec : Int64
  // HTTP method the request is using ("GET", "POST", …). MUST match
  // the proof's `htm` exactly. RFC 9449 §4.3 step 9.
  http_method : String
  // HTTP URI without query string or fragment. MUST match `htu`. §4.3
  // step 10.
  http_uri : String
  // If `Some(at)`, the proof MUST carry `ath` = base64url(SHA-256(at)).
  // Pass `expected_jkt` too when the access token is sender-constrained.
  bound_access_token : String?
  // If `Some(jkt)`, the proof's embedded jwk thumbprint MUST equal jkt.
  // Use this when the access token's cnf is unwrapped already.
  expected_jkt : String?
  // If `Some(n)`, the proof MUST carry `nonce` = n (server-issued).
  expected_nonce : String?
  // Algorithm allow-list. None permits any asymmetric alg `verify`
  // accepts. Symmetric algs are blocked at the typed VerifyKey layer.
  allowed_algorithms : Array[Algorithm]?
} derive(Eq, Debug)

///|
pub(all) struct VerifiedDpop {
  htm : String
  htu : String
  iat : Int64
  jti : String
  ath : String?
  nonce : String?
  // Holder's JWK from the proof header. The thumbprint (jkt) below is
  // what binds the proof to a cnf-carrying access token.
  jwk : Map[String, Json]
  jkt : String
  jwt : VerifiedJwt
}

///|
/// Verify a DPoP proof JWT (§4.3). Returns the structured result if
/// every check passes; raises `InvalidDpopProof(reason)` otherwise.
///
/// The verifying key is extracted from the proof's `jwk` header rather
/// than from a JWKS — DPoP keys are caller-supplied per request, not
/// IdP-rotated. Callers MUST still gate on `expected_jkt` (or pass an
/// access token via `bound_access_token`) to ensure the proof's key
/// is the one the resource server authorised.
pub fn verify_dpop_proof(
  token : String,
  opts : DpopVerifyOptions,
) -> VerifiedDpop raise JwtError {
  let header = peek_header(token)
  // typ MUST be "dpop+jwt" (§4.3 step 3).
  let typ = match get_string(header, "typ") {
    Some(s) => s
    None => raise InvalidDpopProof("missing typ header")
  }
  if typ != "dpop+jwt" {
    raise InvalidDpopProof("typ must be 'dpop+jwt', got '" + typ + "'")
  }
  // Pull the embedded JWK and derive a VerifyKey from it. The IdP / RS
  // never sees this key in advance; it's the holder's per-session
  // ephemeral public key.
  let jwk_obj = match header.get("jwk") {
    Some(Object(m)) => m
    _ => raise InvalidDpopProof("missing jwk header")
  }
  let alg_str = match get_string(header, "alg") {
    Some(s) => s
    None => raise InvalidDpopProof("missing alg header")
  }
  let alg = alg_from_str(alg_str) catch {
    e => raise InvalidDpopProof("unknown alg: " + @debug.to_string(e))
  }
  // Block symmetric algs — DPoP is asymmetric only (§4.2).
  match alg {
    HS256 | HS384 | HS512 =>
      raise InvalidDpopProof("HMAC alg not allowed for DPoP")
    _ => ()
  }
  match opts.allowed_algorithms {
    Some(allowed) => {
      let mut ok = false
      for a in allowed {
        if a == alg {
          ok = true
          break
        }
      }
      if !ok {
        raise InvalidDpopProof(
          "alg '" + alg_to_str(alg) + "' not in allow-list",
        )
      }
    }
    None => ()
  }
  // Build a JWKS entry from the inline jwk so we can reuse the existing
  // resolver path; round-trip through @jwk.parse_set ensures the same
  // strict shape (n/e/x/y constraints, kty matching alg).
  let jwk = parse_inline_jwk(jwk_obj, alg)
  let jkt = jwk_thumbprint_base64url(jwk_obj)
  let vk = jwk_to_verify_key(jwk, alg)
  // Pass typ_allowed=Some(["dpop+jwt"]) explicitly so verify()'s
  // default typ-denylist (which rejects specialised classes when no
  // allow-list is given) lets the proof through. The typ check above
  // already ruled out anything else.
  let base : VerifyOptions = {
    now: opts.now,
    clock_skew_sec: opts.clock_skew_sec,
    require_exp: false,
    issuer: None,
    audience: None,
    typ_allowed: Some(["dpop+jwt"]),
  }
  let v = verify(token, vk, base) catch {
    _ => raise InvalidDpopProof("signature verify failed")
  }
  let htm = match extract_dpop_string(v.claims, "htm") {
    Some(s) => s
    None => raise InvalidDpopProof("missing htm claim")
  }
  if htm != opts.http_method {
    raise InvalidDpopProof("htm '" + htm + "' does not match HTTP method")
  }
  let htu = match extract_dpop_string(v.claims, "htu") {
    Some(s) => s
    None => raise InvalidDpopProof("missing htu claim")
  }
  if htu != opts.http_uri {
    raise InvalidDpopProof("htu does not match HTTP URI")
  }
  let iat = match get_numeric_date(v.claims, "iat") {
    Some(n) => n
    None => raise InvalidDpopProof("missing iat claim")
  }
  if iat + opts.max_iat_age_sec + opts.clock_skew_sec < opts.now {
    raise InvalidDpopProof("iat too old")
  }
  if iat > opts.now + opts.clock_skew_sec {
    raise InvalidDpopProof("iat in the future")
  }
  let jti = match extract_dpop_string(v.claims, "jti") {
    Some(s) => s
    None => raise InvalidDpopProof("missing jti claim")
  }
  let nonce = extract_dpop_string(v.claims, "nonce")
  match opts.expected_nonce {
    Some(want) =>
      match nonce {
        Some(got) => if want != got { raise InvalidDpopProof("nonce mismatch") }
        None => raise InvalidDpopProof("nonce required but absent")
      }
    None => ()
  }
  let ath = extract_dpop_string(v.claims, "ath")
  match opts.bound_access_token {
    Some(at) => {
      let expected_ath = sha256_base64url(at)
      match ath {
        Some(got) =>
          if got != expected_ath {
            raise InvalidDpopProof("ath does not match access_token hash")
          }
        None => raise InvalidDpopProof("ath required but absent")
      }
      if opts.expected_jkt is None {
        raise InvalidDpopProof(
          "expected_jkt required when bound_access_token is set",
        )
      }
    }
    None => ()
  }
  match opts.expected_jkt {
    Some(want) => if want != jkt { raise CnfJktMismatch }
    None => ()
  }
  { htm, htu, iat, jti, ath, nonce, jwk: jwk_obj, jkt, jwt: v }
}

///|
fn extract_dpop_string(
  claims : Map[String, Json],
  key : String,
) -> String? raise JwtError {
  extract_string(claims, key) catch {
    _ => raise InvalidDpopProof(key + " claim is not a string")
  }
}

///|
/// Build a `@jwk.Jwk` from an inline JWK map for the DPoP `jwk` header.
/// Re-uses the strict parser (`@jwk.parse_public`) so the same shape
/// constraints apply (kty must match alg, no private fields tolerated
/// inside a DPoP header).
fn parse_inline_jwk(
  jwk_obj : Map[String, Json],
  alg : Algorithm,
) -> @jwk.Jwk raise JwtError {
  reject_inline_jwk_private_material(jwk_obj)
  // Stringify the JWK map so we can hand it to @jwk.parse_public. The
  // round-trip costs a JSON encode/decode but keeps the validation
  // logic centralised.
  let s = Json::object(jwk_obj).stringify()
  let parsed = @jwk.parse_public(s) catch {
    e => raise InvalidDpopProof("invalid jwk: " + @debug.to_string(e))
  }
  // Cross-check kty against alg so a DPoP header that says alg=ES256
  // but supplies an RSA key gets rejected before signature work.
  match (alg, parsed) {
    (ES256, EcP256(..))
    | (ES384, EcP384(..))
    | (ES512, EcP521(..))
    | (ES256K, EcSecp256k1(..))
    | (EdDSA, OkpEd25519(..))
    | (RS256, Rsa(..))
    | (RS384, Rsa(..))
    | (RS512, Rsa(..))
    | (PS256, Rsa(..))
    | (PS384, Rsa(..))
    | (PS512, Rsa(..)) => parsed
    _ => raise InvalidDpopProof("jwk kty does not match alg")
  }
}

///|
fn reject_inline_jwk_private_material(
  jwk_obj : Map[String, Json],
) -> Unit raise JwtError {
  let private_fields = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
  for name in private_fields {
    match jwk_obj.get(name) {
      Some(_) =>
        raise InvalidDpopProof("inline jwk must not contain private material")
      None => ()
    }
  }
}

///|
fn jwk_thumbprint_base64url(
  jwk_obj : Map[String, Json],
) -> String raise JwtError {
  let s = Json::object(jwk_obj).stringify()
  let parsed = @jwk.parse_public(s) catch {
    e => raise InvalidDpopProof("invalid jwk: " + @debug.to_string(e))
  }
  @jwk.thumbprint_base64url(parsed) catch {
    e => raise InvalidDpopProof("thumbprint failed: " + @debug.to_string(e))
  }
}

///|
fn sha256_base64url(s : String) -> String {
  let h = @hash.sha256(@utf8.encode(s[:]))
  base64url_encode(h)
}

// -----------------------------------------------------------------------------
// OIDC Back-Channel Logout 1.0 — Logout Token
// -----------------------------------------------------------------------------
//
// Logout tokens are a separate JWT class an IdP pushes to RPs to tell
// them to terminate a session. Per §2.4 the token MUST have:
//   typ      = "logout+jwt"
//   events   = { "http://schemas.openid.net/event/backchannel-logout": {} }
//   iss, aud, iat, jti
//   at least one of sub, sid
//   MUST NOT contain a nonce claim (it's not an ID token)
//   MUST NOT contain exp (a recipient SHOULD reject exp if present —
//                        we permit it but don't require it)

///|
pub(all) struct LogoutTokenVerifyOptions {
  now : Int64
  clock_skew_sec : Int64
  issuer : String
  client_id : String
  // If `Some(s)`, reject logout tokens whose `iat` is more than `s`
  // seconds in the past. OIDC §2.7 recommends short windows because
  // logout tokens are unauthenticated by exp.
  max_iat_age_sec : Int64?
  allowed_algorithms : Array[Algorithm]?
} derive(Eq, Debug)

///|
pub fn LogoutTokenVerifyOptions::default(
  now : Int64,
  issuer : String,
  client_id : String,
) -> LogoutTokenVerifyOptions {
  // OIDC Back-Channel Logout 1.0 §2.7 — logout tokens carry no exp
  // claim, so without an iat freshness gate a captured logout token
  // can be replayed indefinitely. Default to a 5-minute window so the
  // RP gets a useful baseline; callers that need a different
  // tolerance (or jti tracking in lieu) override the field.
  {
    now,
    clock_skew_sec: 0L,
    issuer,
    client_id,
    max_iat_age_sec: Some(300L),
    allowed_algorithms: None,
  }
}

///|
pub(all) struct LogoutToken {
  iss : String
  aud : Array[String]
  iat : Int64
  jti : String
  // OIDC §2.4 — at least one of sub, sid is REQUIRED. Verification
  // already enforced at least one is Some; both can be Some.
  sub : String?
  sid : String?
  jwt : VerifiedJwt
}

///|
pub fn verify_logout_token(
  token : String,
  key : VerifyKey,
  opts : LogoutTokenVerifyOptions,
) -> LogoutToken raise JwtError {
  let base : VerifyOptions = {
    now: opts.now,
    clock_skew_sec: opts.clock_skew_sec,
    require_exp: false,
    issuer: Some(opts.issuer),
    audience: Some(opts.client_id),
    typ_allowed: Some(["logout+jwt"]),
  }
  let v = verify(token, key, base)
  match opts.allowed_algorithms {
    Some(allowed) => {
      let mut ok = false
      for a in allowed {
        if a == v.alg {
          ok = true
          break
        }
      }
      if !ok {
        raise AlgorithmNotAllowed(alg_to_str(v.alg))
      }
    }
    None => ()
  }
  // OIDC §2.4: nonce MUST NOT be present (logout token != ID token).
  match v.claims.get("nonce") {
    Some(_) => raise LogoutTokenForbiddenNonce
    None => ()
  }
  // events MUST be an object containing the backchannel-logout member.
  match v.claims.get("events") {
    Some(Object(m)) =>
      match m.get("http://schemas.openid.net/event/backchannel-logout") {
        Some(Object(_)) => ()
        None => raise MissingLogoutEvent
        _ => raise MissingLogoutEvent
      }
    _ => raise MissingLogoutEvent
  }
  let iss = require_string_claim(v.claims, "iss")
  let aud = extract_aud(v.claims)
  let iat = require_numeric_claim(v.claims, "iat")
  match opts.max_iat_age_sec {
    Some(max) =>
      if iat + max + opts.clock_skew_sec < opts.now {
        raise IssuedInFuture // semantically "iat too old"; reuse code
      }
    None => ()
  }
  let jti = require_string_claim(v.claims, "jti")
  let sub = extract_string(v.claims, "sub")
  let sid = extract_string(v.claims, "sid")
  if sub is None && sid is None {
    raise LogoutSubAndSidMissing
  }
  { iss, aud, iat, jti, sub, sid, jwt: v }
}

///|
pub fn verify_logout_token_jwks(
  token : String,
  set : Array[@jwk.JwkSetEntry],
  opts : LogoutTokenVerifyOptions,
) -> LogoutToken raise JwtError {
  let header = peek_header(token)
  let key = select_verify_key(set, header)
  verify_logout_token(token, key, opts)
}

// -----------------------------------------------------------------------------
// OIDC Core §5.3.2 — UserInfo signed-JWT response
// -----------------------------------------------------------------------------

///|
pub(all) struct UserInfoVerifyOptions {
  now : Int64
  clock_skew_sec : Int64
  issuer : String
  client_id : String
  // The `sub` value from the paired ID token. UserInfo's `sub` MUST
  // equal this; otherwise the response was substituted between the
  // /userinfo endpoint and the relying party.
  expected_sub : String
  allowed_algorithms : Array[Algorithm]?
} derive(Eq, Debug)

///|
pub(all) struct UserInfo {
  sub : String
  iss : String
  aud : Array[String]
  email : String?
  email_verified : Bool?
  name : String?
  preferred_username : String?
  // Anything else the IdP put in.
  claims : Map[String, Json]
  jwt : VerifiedJwt
}

///|
pub fn verify_userinfo_jws(
  token : String,
  key : VerifyKey,
  opts : UserInfoVerifyOptions,
) -> UserInfo raise JwtError {
  // OIDC §5.3.2: when signed, the UserInfo response MUST include `iss`
  // and `aud`. exp is not required.
  let base : VerifyOptions = {
    now: opts.now,
    clock_skew_sec: opts.clock_skew_sec,
    require_exp: false,
    issuer: Some(opts.issuer),
    audience: Some(opts.client_id),
    typ_allowed: None,
  }
  let v = verify(token, key, base)
  match opts.allowed_algorithms {
    Some(allowed) => {
      let mut ok = false
      for a in allowed {
        if a == v.alg {
          ok = true
          break
        }
      }
      if !ok {
        raise AlgorithmNotAllowed(alg_to_str(v.alg))
      }
    }
    None => ()
  }
  let sub = require_string_claim(v.claims, "sub")
  if sub != opts.expected_sub {
    raise UserInfoSubMismatch
  }
  let iss = require_string_claim(v.claims, "iss")
  let aud = extract_aud(v.claims)
  {
    sub,
    iss,
    aud,
    email: extract_string(v.claims, "email"),
    email_verified: get_bool(v.claims, "email_verified"),
    name: extract_string(v.claims, "name"),
    preferred_username: extract_string(v.claims, "preferred_username"),
    claims: v.claims,
    jwt: v,
  }
}

///|
pub fn verify_userinfo_jws_jwks(
  token : String,
  set : Array[@jwk.JwkSetEntry],
  opts : UserInfoVerifyOptions,
) -> UserInfo raise JwtError {
  let header = peek_header(token)
  let key = select_verify_key(set, header)
  verify_userinfo_jws(token, key, opts)
}

// -----------------------------------------------------------------------------
// RFC 9101 — JWT-Secured Authorization Request (JAR)
// -----------------------------------------------------------------------------
//
// A JAR is the client's authorization request encoded as a JWT, presented
// to the AS via the `request` parameter. The AS validates it and pulls
// the OAuth parameters out of the claims.

///|
pub(all) struct RequestObjectVerifyOptions {
  now : Int64
  clock_skew_sec : Int64
  expected_client_id : String
  // The AS's own issuer URL (also its `aud` in client-issued JARs).
  expected_aud : String
  // Strict callers should require exp and a fresh iat. The default
  // constructor below enables both so long-lived signed request objects
  // cannot be replayed indefinitely.
  require_exp : Bool
  max_iat_age_sec : Int64?
  allowed_algorithms : Array[Algorithm]?
  // RFC 8725 explicit typing for JAR request objects. The default constructor
  // requires a request-object typ; set None only for legacy interop tests.
  typ_allowed : Array[String]?
} derive(Eq, Debug)

///|
pub fn RequestObjectVerifyOptions::default(
  now : Int64,
  expected_client_id : String,
  expected_aud : String,
) -> RequestObjectVerifyOptions {
  {
    now,
    clock_skew_sec: 0L,
    expected_client_id,
    expected_aud,
    require_exp: true,
    max_iat_age_sec: Some(300L),
    allowed_algorithms: None,
    typ_allowed: Some(["oauth-authz-req+jwt", "application/oauth-authz-req+jwt"]),
  }
}

///|
pub(all) struct RequestObject {
  client_id : String
  iss : String
  aud : Array[String]
  // OAuth authorization parameters extracted from the claims.
  // Common keys: response_type, redirect_uri, scope, state, nonce,
  // code_challenge, code_challenge_method, prompt, etc.
  params : Map[String, Json]
  jwt : VerifiedJwt
}

///|
pub fn verify_request_object(
  token : String,
  key : VerifyKey,
  opts : RequestObjectVerifyOptions,
) -> RequestObject raise JwtError {
  let base : VerifyOptions = {
    now: opts.now,
    clock_skew_sec: opts.clock_skew_sec,
    require_exp: opts.require_exp,
    issuer: Some(opts.expected_client_id),
    audience: Some(opts.expected_aud),
    typ_allowed: opts.typ_allowed,
  }
  let v = verify(token, key, base)
  match opts.allowed_algorithms {
    Some(allowed) => {
      let mut ok = false
      for a in allowed {
        if a == v.alg {
          ok = true
          break
        }
      }
      if !ok {
        raise AlgorithmNotAllowed(alg_to_str(v.alg))
      }
    }
    None => ()
  }
  match opts.max_iat_age_sec {
    Some(max) => {
      let iat = require_numeric_claim(v.claims, "iat")
      if iat + max + opts.clock_skew_sec < opts.now {
        raise IssuedInFuture
      }
    }
    None => ()
  }
  // RFC 9101 §10.2.4: client_id in the request object MUST equal the
  // client_id parameter (which we pinned via opts).
  let client_id_claim = extract_string(v.claims, "client_id")
  match client_id_claim {
    Some(s) => if s != opts.expected_client_id { raise ClientIdMismatch }
    None => ()
  }
  {
    client_id: opts.expected_client_id,
    iss: opts.expected_client_id,
    aud: extract_aud(v.claims),
    params: v.claims,
    jwt: v,
  }
}

// -----------------------------------------------------------------------------
// JARM — JWT-Secured Authorization Response Mode (OAuth + OIDC)
// -----------------------------------------------------------------------------
//
// The AS returns the authorization response (code, state, etc.) wrapped
// in a signed JWT instead of plain query parameters. The RP verifies it.

///|
pub(all) struct JarmVerifyOptions {
  now : Int64
  clock_skew_sec : Int64
  // The AS's expected issuer URL.
  expected_issuer : String
  // The RP's client_id (the JARM `aud`).
  client_id : String
  // If `Some(s)`, the JARM `state` claim must equal this. The RP must
  // remember the `state` it sent and confirm it round-trips.
  expected_state : String?
  allowed_algorithms : Array[Algorithm]?
  // RFC 8725 explicit typing for JARM authorization responses.
  typ_allowed : Array[String]?
} derive(Eq, Debug)

///|
pub fn JarmVerifyOptions::strict(
  now : Int64,
  expected_issuer : String,
  client_id : String,
  expected_state : String,
) -> JarmVerifyOptions {
  {
    now,
    clock_skew_sec: 0L,
    expected_issuer,
    client_id,
    expected_state: Some(expected_state),
    allowed_algorithms: None,
    typ_allowed: Some([
      "oauth-authz-resp+jwt", "application/oauth-authz-resp+jwt",
    ]),
  }
}

///|
pub(all) struct JarmResponse {
  iss : String
  aud : Array[String]
  exp : Int64
  // Authorization response params: code, state, id_token, access_token,
  // token_type, expires_in, scope, iss (again), error, etc.
  params : Map[String, Json]
  jwt : VerifiedJwt
}

///|
pub fn verify_jarm(
  token : String,
  key : VerifyKey,
  opts : JarmVerifyOptions,
) -> JarmResponse raise JwtError {
  let base : VerifyOptions = {
    now: opts.now,
    clock_skew_sec: opts.clock_skew_sec,
    require_exp: true,
    issuer: Some(opts.expected_issuer),
    audience: Some(opts.client_id),
    typ_allowed: opts.typ_allowed,
  }
  let v = verify(token, key, base)
  match opts.allowed_algorithms {
    Some(allowed) => {
      let mut ok = false
      for a in allowed {
        if a == v.alg {
          ok = true
          break
        }
      }
      if !ok {
        raise AlgorithmNotAllowed(alg_to_str(v.alg))
      }
    }
    None => ()
  }
  let state = extract_string(v.claims, "state")
  match opts.expected_state {
    Some(want) =>
      match state {
        Some(got) =>
          if want != got {
            raise ClaimsParseError("JARM state does not round-trip")
          }
        None => raise MissingRequiredClaim("state")
      }
    None => ()
  }
  {
    iss: require_string_claim(v.claims, "iss"),
    aud: extract_aud(v.claims),
    exp: require_numeric_claim(v.claims, "exp"),
    params: v.claims,
    jwt: v,
  }
}

// -----------------------------------------------------------------------------
// OIDC Self-Issued OP v2
// -----------------------------------------------------------------------------
//
// Self-Issued OPs let a holder mint their own ID token. The signature
// key comes from the token itself (sub_jwk claim) and the subject is
// the SHA-256 thumbprint of that key. Used in DID and decentralised
// identity flows.

///|
pub(all) struct SelfIssuedVerifyOptions {
  now : Int64
  clock_skew_sec : Int64
  // RP's redirect URI; the SIOP v2 spec uses this in place of client_id
  // for unregistered relying parties. Optional — when None we accept
  // any `aud`.
  expected_aud : String?
  // Expected nonce from the authorization request.
  expected_nonce : String?
  allowed_algorithms : Array[Algorithm]?
}

///|
pub(all) struct SelfIssuedToken {
  iss : String
  sub : String // SHA-256 thumbprint of sub_jwk
  aud : Array[String]
  exp : Int64
  iat : Int64
  nonce : String?
  // The holder's self-asserted JWK, base for the signature.
  sub_jwk : Map[String, Json]
  jwt : VerifiedJwt
}

///|
/// Verify a Self-Issued OP v2 ID token. The verifying key is extracted
/// from the token's own `sub_jwk` claim, and `sub` MUST equal the
/// thumbprint of that key. Use only for SIOP v2 flows; the issuer
/// constraint differs from regular OIDC.
pub fn verify_self_issued_id_token(
  token : String,
  opts : SelfIssuedVerifyOptions,
) -> SelfIssuedToken raise JwtError {
  // Pre-parse the payload so we can grab sub_jwk before signature work.
  let parts = token.split(".").to_array()
  if parts.length() != 3 {
    raise InvalidToken("expected 3 segments")
  }
  let payload_bytes = base64url_decode(parts[1].to_owned())
  let payload_str = @utf8.decode(payload_bytes[:]) catch {
    _ => raise ClaimsParseError("payload not UTF-8")
  }
  reject_duplicate_top_level_json_keys(payload_str, false)
  let claims = parse_json_object(payload_str)
  let sub_jwk_obj = match claims.get("sub_jwk") {
    Some(Object(m)) => m
    _ => raise MissingRequiredClaim("sub_jwk")
  }
  // Derive VerifyKey from sub_jwk.
  let alg = match get_string(claims, "iss") {
    Some(s) =>
      if s != "https://self-issued.me/v2" {
        raise InvalidIssuer
      } else {
        // alg comes from the header, but we need it for the kty/alg
        // pairing. Read the header to extract alg.
        let header_bytes = base64url_decode(parts[0].to_owned())
        let header_str = @utf8.decode(header_bytes[:]) catch {
          _ => raise InvalidHeader("not UTF-8")
        }
        reject_duplicate_top_level_json_keys(header_str, true)
        let header = parse_json_object(header_str)
        let alg_str = match get_string(header, "alg") {
          Some(s) => s
          None => raise InvalidHeader("missing alg")
        }
        alg_from_str(alg_str)
      }
    None => raise MissingRequiredClaim("iss")
  }
  let jwk = parse_inline_jwk(sub_jwk_obj, alg)
  let vk = jwk_to_verify_key(jwk, alg)
  // sub MUST equal the SHA-256 thumbprint of sub_jwk.
  let expected_sub = jwk_thumbprint_base64url(sub_jwk_obj)
  let sub = require_string_claim(claims, "sub")
  if sub != expected_sub {
    raise SelfIssuedSubMismatch
  }
  // Now do the standard verify pipeline.
  let base : VerifyOptions = {
    now: opts.now,
    clock_skew_sec: opts.clock_skew_sec,
    require_exp: true,
    issuer: Some("https://self-issued.me/v2"),
    audience: opts.expected_aud,
    typ_allowed: None,
  }
  let v = verify(token, vk, base)
  match opts.allowed_algorithms {
    Some(allowed) => {
      let mut ok = false
      for a in allowed {
        if a == v.alg {
          ok = true
          break
        }
      }
      if !ok {
        raise AlgorithmNotAllowed(alg_to_str(v.alg))
      }
    }
    None => ()
  }
  let nonce = extract_string(v.claims, "nonce")
  match opts.expected_nonce {
    Some(want) =>
      match nonce {
        Some(got) => if want != got { raise NonceMismatch }
        None => raise NonceMismatch
      }
    None => ()
  }
  {
    iss: require_string_claim(v.claims, "iss"),
    sub,
    aud: extract_aud(v.claims),
    exp: require_numeric_claim(v.claims, "exp"),
    iat: require_numeric_claim(v.claims, "iat"),
    nonce,
    sub_jwk: sub_jwk_obj,
    jwt: v,
  }
}

// -----------------------------------------------------------------------------
// OIDC Core §10.2 — Encrypted ID Tokens (nested JWE-wrapping-JWS)
// -----------------------------------------------------------------------------

///|
/// Verify an encrypted OIDC ID token: decrypt the outer JWE with
/// `decryption_key`, then run the standard ID-token verify on the
/// inner JWS using `verify_key` and `opts`. The decryption key and
/// verify key come from different IdP material in general — the JWE
/// is typically encrypted to the RP, and the inner JWS is signed by
/// the IdP.
pub fn verify_oidc_id_token_encrypted(
  jwe_token : String,
  decryption_key : @jwe.DecryptionKey,
  verify_key : VerifyKey,
  opts : OidcIdTokenVerifyOptions,
) -> OidcIdToken raise JwtError {
  // RFC 7519 §11.2: a Nested JWT (JWE encapsulating a JWS) MUST have the
  // outer JWE's `cty` header set to "JWT" or "application/jwt" so the
  // recipient is told to verify the decrypted bytes as a JWS, not parse
  // them as something else. We pre-peek the outer header before
  // decrypting; the `cty` value is integrity-protected by the JWE AEAD,
  // so an attacker can't substitute it. (Pre-decryption read here is for
  // shape validation only — we do not act on any other header value
  // before verification.)
  let outer_parts = jwe_token.split(".").to_array()
  if outer_parts.length() != 5 {
    raise InvalidToken("encrypted ID token is not a compact JWE")
  }
  let outer_header_bytes = base64url_decode(outer_parts[0].to_owned())
  let outer_header_str = @utf8.decode(outer_header_bytes[:]) catch {
    _ => raise InvalidHeader("JWE header not UTF-8")
  }
  reject_duplicate_top_level_json_keys(outer_header_str, true)
  let outer_header = parse_json_object(outer_header_str)
  match get_string(outer_header, "cty") {
    Some(s) =>
      if s != "JWT" && s != "application/jwt" {
        raise InvalidType(
          "JWE cty must be 'JWT' for a nested ID token, got '" + s + "'",
        )
      }
    None =>
      raise InvalidType("JWE missing cty='JWT' header for nested ID token")
  }
  let inner_bytes = @jwe.decrypt(jwe_token, decryption_key) catch {
    e => raise InvalidToken("JWE decrypt failed: " + @debug.to_string(e))
  }
  let inner = @utf8.decode(inner_bytes[:]) catch {
    _ => raise InvalidToken("inner ID token not UTF-8")
  }
  verify_oidc_id_token(inner, verify_key, opts)
}

// -----------------------------------------------------------------------------
// OIDC Core §5.6.2 — Aggregated / Distributed Claims
// -----------------------------------------------------------------------------
//
// An ID token may delegate some claims to external sources via
// `_claim_sources` and `_claim_names`. The library exposes the
// parsed structure; following the URLs / verifying embedded JWTs is
// the caller's job.

///|
pub(all) enum ClaimSource {
  // Aggregated: the claim value is itself a signed JWT embedded inline.
  Aggregated(jwt~ : String)
  // Distributed: the caller must fetch the claim from `endpoint`,
  // optionally bearing `access_token`.
  Distributed(endpoint~ : String, access_token~ : String?)
}

///|
pub(all) struct AggregatedDistributedClaims {
  // Map from source id (an arbitrary string) → claim source descriptor.
  sources : Map[String, ClaimSource]
  // Map from claim name → source id, telling the RP where to look up
  // each individual claim value.
  names : Map[String, String]
}

///|
/// Extract the aggregated / distributed claim metadata from a parsed
/// claim set. Returns None if neither `_claim_sources` nor
/// `_claim_names` is present. If either metadata member is present, malformed
/// entries are rejected instead of being silently dropped.
pub fn extract_aggregated_distributed_claims(
  claims : Map[String, Json],
) -> AggregatedDistributedClaims? raise JwtError {
  let sources_obj = match claims.get("_claim_sources") {
    Some(Object(m)) => Some(m)
    Some(_) => raise ClaimsParseError("_claim_sources is not an object")
    None => None
  }
  let names_obj = match claims.get("_claim_names") {
    Some(Object(m)) => Some(m)
    Some(_) => raise ClaimsParseError("_claim_names is not an object")
    None => None
  }
  if sources_obj is None && names_obj is None {
    return None
  }
  let sources : Map[String, ClaimSource] = Map([])
  match sources_obj {
    Some(m) =>
      for k, v in m {
        match v {
          Object(inner) => {
            let jwt_claim = match inner.get("JWT") {
              Some(String(s)) => Some(s)
              Some(_) =>
                raise ClaimsParseError(
                  "_claim_sources." + k + ".JWT is not a string",
                )
              None => None
            }
            let endpoint = match inner.get("endpoint") {
              Some(String(s)) => Some(s)
              Some(_) =>
                raise ClaimsParseError(
                  "_claim_sources." + k + ".endpoint is not a string",
                )
              None => None
            }
            match (jwt_claim, endpoint) {
              (Some(jwt_str), None) =>
                sources[k] = ClaimSource::Aggregated(jwt=jwt_str)
              (None, Some(ep)) => {
                let at = match inner.get("access_token") {
                  Some(String(s)) => Some(s)
                  Some(_) =>
                    raise ClaimsParseError(
                      "_claim_sources." + k + ".access_token is not a string",
                    )
                  None => None
                }
                sources[k] = ClaimSource::Distributed(
                  endpoint=ep,
                  access_token=at,
                )
              }
              (Some(_), Some(_)) =>
                raise ClaimsParseError(
                  "_claim_sources." + k + " has both JWT and endpoint",
                )
              (None, None) =>
                raise ClaimsParseError(
                  "_claim_sources." + k + " has neither JWT nor endpoint",
                )
            }
          }
          _ =>
            raise ClaimsParseError("_claim_sources." + k + " is not an object")
        }
      }
    None => ()
  }
  let names : Map[String, String] = Map([])
  match names_obj {
    Some(m) =>
      for k, v in m {
        match v {
          String(src) => {
            if sources.get(src) is None {
              raise ClaimsParseError(
                "_claim_names." + k + " references missing source",
              )
            }
            names[k] = src
          }
          _ => raise ClaimsParseError("_claim_names." + k + " is not a string")
        }
      }
    None => ()
  }
  Some({ sources, names })
}

// -----------------------------------------------------------------------------
// OIDC Discovery 1.0 — Provider Metadata parser (no HTTP)
// -----------------------------------------------------------------------------
//
// `.well-known/openid-configuration` is a JSON document describing the
// IdP's endpoints, supported algorithms, and JWKS URL. We expose a
// parser so callers can fetch the document over whatever HTTP client
// they have and hand the body here.

///|
pub(all) struct ProviderMetadata {
  issuer : String
  authorization_endpoint : String?
  token_endpoint : String?
  userinfo_endpoint : String?
  jwks_uri : String?
  registration_endpoint : String?
  end_session_endpoint : String?
  introspection_endpoint : String?
  revocation_endpoint : String?
  device_authorization_endpoint : String?
  backchannel_authentication_endpoint : String?
  pushed_authorization_request_endpoint : String?
  response_types_supported : Array[String]
  subject_types_supported : Array[String]
  id_token_signing_alg_values_supported : Array[String]
  token_endpoint_auth_methods_supported : Array[String]?
  scopes_supported : Array[String]?
  claims_supported : Array[String]?
  // Everything else the IdP put in — keep the raw map for forward-
  // compatibility with future spec extensions.
  raw : Map[String, Json]
}

///|
pub fn parse_provider_metadata(
  json : String,
) -> ProviderMetadata raise JwtError {
  reject_duplicate_top_level_json_keys(json, false)
  let m = parse_json_object(json)
  let issuer = match extract_string(m, "issuer") {
    Some(s) => s
    None => raise MissingRequiredClaim("issuer")
  }
  let resp_types = string_array_or_empty(m, "response_types_supported")
  if resp_types.length() == 0 {
    raise MissingRequiredClaim("response_types_supported")
  }
  let subject_types = string_array_or_empty(m, "subject_types_supported")
  if subject_types.length() == 0 {
    raise MissingRequiredClaim("subject_types_supported")
  }
  let alg_values = string_array_or_empty(
    m, "id_token_signing_alg_values_supported",
  )
  if alg_values.length() == 0 {
    raise MissingRequiredClaim("id_token_signing_alg_values_supported")
  }
  {
    issuer,
    authorization_endpoint: extract_string(m, "authorization_endpoint"),
    token_endpoint: extract_string(m, "token_endpoint"),
    userinfo_endpoint: extract_string(m, "userinfo_endpoint"),
    jwks_uri: extract_string(m, "jwks_uri"),
    registration_endpoint: extract_string(m, "registration_endpoint"),
    end_session_endpoint: extract_string(m, "end_session_endpoint"),
    introspection_endpoint: extract_string(m, "introspection_endpoint"),
    revocation_endpoint: extract_string(m, "revocation_endpoint"),
    device_authorization_endpoint: extract_string(
      m, "device_authorization_endpoint",
    ),
    backchannel_authentication_endpoint: extract_string(
      m, "backchannel_authentication_endpoint",
    ),
    pushed_authorization_request_endpoint: extract_string(
      m, "pushed_authorization_request_endpoint",
    ),
    response_types_supported: resp_types,
    subject_types_supported: subject_types,
    id_token_signing_alg_values_supported: alg_values,
    token_endpoint_auth_methods_supported: extract_string_array(
      m, "token_endpoint_auth_methods_supported",
    ),
    scopes_supported: extract_string_array(m, "scopes_supported"),
    claims_supported: extract_string_array(m, "claims_supported"),
    raw: m,
  }
}

///|
fn extract_string(
  m : Map[String, Json],
  key : String,
) -> String? raise JwtError {
  match m.get(key) {
    Some(String(s)) => Some(s)
    Some(_) => raise ClaimsParseError(key + " is not a string")
    None => None
  }
}

///|
fn string_array_or_empty(
  m : Map[String, Json],
  key : String,
) -> Array[String] raise JwtError {
  match extract_string_array(m, key) {
    Some(a) => a
    None => []
  }
}

// -----------------------------------------------------------------------------
// OIDC Federation 1.0 — Entity Statement verify
// -----------------------------------------------------------------------------
//
// An Entity Statement is a signed JWT describing a federation
// participant. Two flavours:
//   * Entity Configuration: iss == sub, the entity describes itself.
//   * Subordinate Statement: iss is the superior, sub is the
//     subordinate; encodes the superior's view of the subordinate's
//     metadata, policy, constraints, etc.
//
// In both cases the JWT carries `jwks` (the entity's keys), `metadata`
// (per entity-type claim sets), and `authority_hints` / `source_endpoint`
// for chain traversal.

///|
pub(all) enum EntityStatementKind {
  // iss == sub. Self-issued entity description.
  Configuration
  // iss != sub. Superior's statement about a subordinate.
  Subordinate
} derive(Eq, Debug)

///|
pub(all) struct EntityStatementVerifyOptions {
  now : Int64
  clock_skew_sec : Int64
  // The entity identifier the statement is about. For Configuration
  // this MUST equal both `iss` and `sub`; for Subordinate, equal to
  // `sub`.
  subject : String
  // If `Some(s)`, the issuer MUST equal `s`. For Configuration this
  // is normally the same as `subject`; for Subordinate it's the
  // superior's identifier.
  expected_issuer : String?
  // Restrict the statement kind. None accepts either.
  expected_kind : EntityStatementKind?
  allowed_algorithms : Array[Algorithm]?
} derive(Eq, Debug)

///|
pub(all) struct EntityStatement {
  iss : String
  sub : String
  exp : Int64
  iat : Int64
  kind : EntityStatementKind
  // The entity's own keys (an inline JWKS). Callers feed this into
  // `@jwk.parse_set` when they want to use the keys.
  jwks : Map[String, Json]
  // Per entity-type metadata: openid_provider, openid_relying_party,
  // federation_entity, oauth_authorization_server, etc. Raw JSON map
  // keyed by entity-type name.
  metadata : Map[String, Json]?
  // Trust-chain pointers.
  authority_hints : Array[String]?
  source_endpoint : String?
  // Trust marks the entity claims; each is itself a signed JWT.
  trust_marks : Array[Json]?
  // Constraints and policy as raw maps for the caller to interpret.
  constraints : Map[String, Json]?
  policy : Map[String, Json]?
  jwt : VerifiedJwt
}

///|
pub fn verify_entity_statement(
  token : String,
  key : VerifyKey,
  opts : EntityStatementVerifyOptions,
) -> EntityStatement raise JwtError {
  let base : VerifyOptions = {
    now: opts.now,
    clock_skew_sec: opts.clock_skew_sec,
    require_exp: true,
    issuer: opts.expected_issuer,
    audience: None,
    typ_allowed: Some(["entity-statement+jwt"]),
  }
  let v = verify(token, key, base)
  match opts.allowed_algorithms {
    Some(allowed) => {
      let mut ok = false
      for a in allowed {
        if a == v.alg {
          ok = true
          break
        }
      }
      if !ok {
        raise AlgorithmNotAllowed(alg_to_str(v.alg))
      }
    }
    None => ()
  }
  let iss = require_string_claim(v.claims, "iss")
  let sub = require_string_claim(v.claims, "sub")
  if sub != opts.subject {
    raise InvalidEntityStatement("sub does not match expected subject")
  }
  let kind = if iss == sub {
    EntityStatementKind::Configuration
  } else {
    EntityStatementKind::Subordinate
  }
  match opts.expected_kind {
    Some(want) =>
      if want != kind {
        raise InvalidEntityStatement(
          "expected " +
          (match want {
            Configuration => "Configuration"
            Subordinate => "Subordinate"
          }) +
          " statement",
        )
      }
    None => ()
  }
  let exp = require_numeric_claim(v.claims, "exp")
  let iat = require_numeric_claim(v.claims, "iat")
  let jwks = match v.claims.get("jwks") {
    Some(Object(m)) => m
    _ => raise InvalidEntityStatement("jwks missing or not an object")
  }
  let metadata = match v.claims.get("metadata") {
    Some(Object(m)) => Some(m)
    Some(_) => raise InvalidEntityStatement("metadata is not an object")
    None => None
  }
  let authority_hints = extract_string_array(v.claims, "authority_hints")
  let source_endpoint = extract_string(v.claims, "source_endpoint")
  let trust_marks = match v.claims.get("trust_marks") {
    Some(Array(items)) => Some(items)
    Some(_) => raise InvalidEntityStatement("trust_marks is not an array")
    None => None
  }
  let constraints = match v.claims.get("constraints") {
    Some(Object(m)) => Some(m)
    Some(_) => raise InvalidEntityStatement("constraints is not an object")
    None => None
  }
  let policy = match v.claims.get("metadata_policy") {
    Some(Object(m)) => Some(m)
    Some(_) => raise InvalidEntityStatement("metadata_policy is not an object")
    None => None
  }
  {
    iss,
    sub,
    exp,
    iat,
    kind,
    jwks,
    metadata,
    authority_hints,
    source_endpoint,
    trust_marks,
    constraints,
    policy,
    jwt: v,
  }
}

// -----------------------------------------------------------------------------
// OIDC CIBA — auth_req_id and rt_hash binding on the ID token
// -----------------------------------------------------------------------------
//
// CIBA's ID token includes two extra claims:
//   urn:openid:params:jwt:claim:auth_req_id   — the auth_req_id the
//     IdP returned earlier, binding this token to the back-channel
//     authentication request.
//   urn:openid:params:jwt:claim:rt_hash       — half-hash of the
//     refresh token, analogous to at_hash but for refresh tokens
//     (CIBA Push / Ping flows).
//
// Verify uses the standard OIDC ID-token pipeline plus these two
// optional binding checks.

///|
pub(all) struct CibaVerifyOptions {
  oidc : OidcIdTokenVerifyOptions
  // If `Some(id)`, the token's auth_req_id claim MUST equal `id`.
  expected_auth_req_id : String?
  // If `Some(rt)`, the token's rt_hash claim MUST equal
  // base64url(SHA-256(rt) leftmost-half) per the same construction
  // as at_hash.
  refresh_token : String?
}

///|
pub(all) struct CibaIdToken {
  // The parsed standard OIDC ID token.
  id_token : OidcIdToken
  // The auth_req_id from the matching claim, if present.
  auth_req_id : String?
  // The rt_hash from the matching claim, if present.
  rt_hash : String?
}

///|
pub fn verify_ciba_id_token(
  token : String,
  key : VerifyKey,
  opts : CibaVerifyOptions,
) -> CibaIdToken raise JwtError {
  let id = verify_oidc_id_token(token, key, opts.oidc)
  let auth_req_id = extract_string(
    id.jwt.claims,
    "urn:openid:params:jwt:claim:auth_req_id",
  )
  match opts.expected_auth_req_id {
    Some(want) =>
      match auth_req_id {
        Some(got) => if got != want { raise AuthReqIdMismatch }
        None => raise AuthReqIdMismatch
      }
    None => ()
  }
  let rt_hash = extract_string(
    id.jwt.claims,
    "urn:openid:params:jwt:claim:rt_hash",
  )
  match opts.refresh_token {
    Some(rt) => {
      let expected = compute_x_hash(id.jwt.alg, rt)
      match rt_hash {
        Some(claimed) => if claimed != expected { raise RtHashMismatch }
        None => raise RtHashMismatch
      }
    }
    None => ()
  }
  { id_token: id, auth_req_id, rt_hash }
}

// -----------------------------------------------------------------------------
// FAPI 2.0 profile guard
// -----------------------------------------------------------------------------
//
// FAPI 2.0 Security Profile pins a strict subset of OIDC / OAuth
// behaviours. The library cannot enforce HTTP-level requirements
// (PAR, mTLS, push-style authentication), but it can pre-build
// strict verification options the caller hands to `verify_oidc_id_token`
// or `verify_rfc9068`.
//
// FAPI 2.0 §4.2 requires:
//   * alg ∈ {PS256, ES256, EdDSA}
//   * iss / aud / exp / iat / jti / sub all required (we already gate
//     these via OIDC + RFC 9068 verify)
//   * nonce required for ID tokens issued from interactive auth
//   * short clock skew tolerance (we default to 60s)
//   * DPoP or mTLS sender-constrained binding (caller's job to wire
//     opts.bound_access_token / opts.expected_jkt on the DPoP layer)

///|
let fapi_allowed_algorithms : Array[Algorithm] = [PS256, ES256, EdDSA]

///|
/// Build OIDC ID Token verify options pre-populated with the FAPI 2.0
/// strict defaults: algorithm allow-list locked to PS256/ES256/EdDSA,
/// 60s clock skew, nonce required (caller supplies the expected value
/// from the authorization request).
///
/// Returns an `OidcIdTokenVerifyOptions` that the caller passes
/// through to `verify_oidc_id_token`. A FapiPolicyViolation is raised
/// if `expected_nonce` is None — FAPI requires the relying party send
/// a fresh nonce on every login.
pub fn fapi_oidc_options(
  now : Int64,
  issuer : String,
  client_id : String,
  expected_nonce : String,
) -> OidcIdTokenVerifyOptions {
  {
    now,
    clock_skew_sec: 60L,
    issuer,
    client_id,
    expected_nonce: Some(expected_nonce),
    access_token: None,
    authorization_code: None,
    max_age_sec: None,
    expected_acr: None,
    allowed_algorithms: Some(fapi_allowed_algorithms),
  }
}

///|
/// Build RFC 9068 access-token verify options with FAPI defaults.
/// Same algorithm pin and short clock skew; the caller still supplies
/// the resource indicator (`audience`).
pub fn fapi_rfc9068_options(
  now : Int64,
  issuer : String,
  audience : String,
  expected_client_id : String,
) -> Rfc9068VerifyOptions {
  {
    now,
    clock_skew_sec: 60L,
    issuer,
    audience,
    expected_client_id: Some(expected_client_id),
    required_scopes: None,
    allowed_algorithms: Some(fapi_allowed_algorithms),
  }
}

///|
/// Reject the token's algorithm if it falls outside the FAPI list.
/// Useful when you already have a `VerifiedJwt` (e.g., from a custom
/// pipeline) and want to apply the FAPI alg policy after the fact.
pub fn fapi_check_alg(v : VerifiedJwt) -> Unit raise JwtError {
  let mut ok = false
  for a in fapi_allowed_algorithms {
    if a == v.alg {
      ok = true
      break
    }
  }
  if !ok {
    raise FapiPolicyViolation(
      "alg '" + alg_to_str(v.alg) + "' not permitted by FAPI 2.0",
    )
  }
}
