// JSON Web Key (RFC 7517) parse + serialise.
//
// Bridges JOSE JSON keys to the workspace's existing key types
// (`mizchi/rsa`, `mizchi/p256`, `mizchi/p384`, `mizchi/p521`,
// `mizchi/secp256k1`, `mizchi/ed25519`). Algorithm-specific encodings follow RFC 7518 §6
// (RSA / EC / oct) and RFC 8037 §2 (OKP / Ed25519). The RFC 7638
// canonical-form JWK thumbprint is implemented in this module.
//
// Scope and caveats:
//
//   * RSA `RsaPrivateKey` in `mizchi/rsa` only carries `(n, e, d)`, not
//     the CRT parameters (`p`, `q`, `dp`, `dq`, `qi`). Parsing a JWK
//     with CRT parameters keeps the fields readable inside the JSON we
//     just decoded but the resulting `Jwk::Rsa` keeps only what the
//     workspace can hold. Round-tripping a private RSA JWK therefore
//     emits `n`, `e`, `d` but NOT the CRT parameters.
//   * `oct` keys are symmetric secrets. `parse_public` rejects them and
//     `serialise_public` deliberately omits `k`.
//   * `serialise_public` never emits private fields (RFC 7517 §6).
//   * `serialise_private` emits the private fields and requires that the
//     `privkey~` slot is populated.
//   * Thumbprint canonical-form per RFC 7638 §3 picks only the
//     required fields for the key type, lexicographically orders the
//     member names, and produces compact JSON with no whitespace.
//
// We use `moonbitlang/core/json` for parsing and emit JSON via either
// the same library's `stringify` (for the friendly serialisations) or
// our own canonical writer (for the thumbprint, where byte-exact output
// matters).

///|
pub(all) enum Jwk {
  Rsa(pubkey~ : @rsa.RsaPublicKey, privkey~ : @rsa.RsaPrivateKey?)
  EcP256(pubkey~ : @p256.PublicKey, privkey~ : @p256.PrivateKey?)
  EcP384(pubkey~ : @p384.PublicKey, privkey~ : @p384.PrivateKey?)
  EcP521(pubkey~ : @p521.PublicKey, privkey~ : @p521.PrivateKey?)
  EcSecp256k1(pubkey~ : @secp256k1.PublicKey, privkey~ : @secp256k1.PrivateKey?)
  OkpEd25519(pubkey~ : @ed25519.PublicKey, privkey~ : @ed25519.PrivateKey?)
  Hmac(secret~ : Bytes)
}

///|
pub suberror JwkError {
  // Top-level JSON parse failure or a value with the wrong shape (e.g.
  // a JSON array where an object was required).
  InvalidJson(String)
  // Required field missing for the declared `kty` (e.g. RSA without `n`).
  MissingField(String)
  // base64url decode failed for one of the value fields.
  InvalidBase64Url(String)
  // `kty` was absent or contained an unrecognized value.
  UnsupportedKty(String)
  // `crv` was unsupported for the declared `kty`.
  UnsupportedCurve(String)
  // Field passed base64url decode but the wrong number of bytes for the
  // declared key shape (e.g. Ed25519 `x` was not 32 bytes).
  InvalidFieldLength(String)
  // Cryptographic check inside the underlying key module failed
  // (PointNotOnCurve, RSA modulus zero, etc).
  CryptoError(String)
  // `serialise_private` asked for but the private slot was None.
  PrivateKeyMissing
} derive(Debug)

// -----------------------------------------------------------------------------
// base64url helpers (no padding, '-'/'_' substitutions per RFC 4648 §5)
// -----------------------------------------------------------------------------

///|
fn b64url_encode(b : Bytes) -> String {
  let s = @base64.encode(b[:], padding=false)
  let buf = StringBuilder::new()
  for c in s {
    let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
    buf.write_char(c2)
  }
  buf.to_string()
}

///|
fn b64url_decode(s : String) -> Bytes raise JwkError {
  let buf = StringBuilder::new()
  let mut n = 0
  for c in s {
    let is_valid = (c >= 'A' && c <= 'Z') ||
      (c >= 'a' && c <= 'z') ||
      (c >= '0' && c <= '9') ||
      c == '-' ||
      c == '_'
    if !is_valid {
      raise InvalidBase64Url("non-alphabet character")
    }
    let c2 = if c == '-' { '+' } else if c == '_' { '/' } else { c }
    buf.write_char(c2)
    n = n + 1
  }
  if n % 4 == 1 {
    raise InvalidBase64Url("invalid base64url length")
  }
  let pad = (4 - n % 4) % 4
  for _ in 0..<pad {
    buf.write_char('=')
  }
  @base64.decode(buf.to_string()) catch {
    _ => raise InvalidBase64Url("malformed base64url segment")
  }
}

// -----------------------------------------------------------------------------
// JSON helpers
// -----------------------------------------------------------------------------

///|
fn parse_object(json : String) -> Map[String, Json] raise JwkError {
  reject_duplicate_json_keys(json)
  let parsed = @json.parse(json[:]) catch {
    _ => raise InvalidJson("not valid JSON")
  }
  match parsed {
    Object(m) => m
    _ => raise InvalidJson("top-level value is not an object")
  }
}

///|
fn json_ws_skip(s : String, start : Int) -> Int {
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
fn json_read_key(s : String, start : Int) -> (String, Int) raise JwkError {
  let buf = StringBuilder::new()
  let mut i = start + 1
  while i < s.length() {
    let c = s.get_char(i).unwrap()
    if c == '"' {
      return (buf.to_string(), i + 1)
    }
    if c == '\\' {
      raise InvalidJson("escaped JSON member names are not supported")
    }
    buf.write_char(c)
    i = i + 1
  }
  raise InvalidJson("unterminated JSON member name")
}

///|
fn json_skip_string(s : String, start : Int) -> Int raise JwkError {
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
  raise InvalidJson("unterminated JSON string")
}

///|
fn json_scan_array(s : String, start : Int) -> Int raise JwkError {
  let mut i = start + 1
  while true {
    i = json_ws_skip(s, i)
    if i >= s.length() {
      raise InvalidJson("unterminated JSON array")
    }
    if s.get_char(i).unwrap() == ']' {
      return i + 1
    }
    i = json_scan_value(s, i)
    i = json_ws_skip(s, i)
    if i >= s.length() {
      raise InvalidJson("unterminated JSON array")
    }
    let sep = s.get_char(i).unwrap()
    if sep == ',' {
      i = i + 1
    } else if sep == ']' {
      return i + 1
    } else {
      raise InvalidJson("expected ',' or ']'")
    }
  }
  i
}

///|
fn json_scan_object(s : String, start : Int) -> Int raise JwkError {
  let keys : Array[String] = []
  let mut i = start + 1
  while true {
    i = json_ws_skip(s, i)
    if i >= s.length() {
      raise InvalidJson("unterminated JSON object")
    }
    if s.get_char(i).unwrap() == '}' {
      return i + 1
    }
    if s.get_char(i).unwrap() != '"' {
      raise InvalidJson("expected JSON member name")
    }
    let (key, next) = json_read_key(s, i)
    for prev in keys {
      if prev == key {
        raise InvalidJson("duplicate JSON member '" + key + "'")
      }
    }
    keys.push(key)
    i = json_ws_skip(s, next)
    if i >= s.length() || s.get_char(i).unwrap() != ':' {
      raise InvalidJson("expected ':' after JSON member")
    }
    i = json_scan_value(s, i + 1)
    i = json_ws_skip(s, i)
    if i >= s.length() {
      raise InvalidJson("unterminated JSON object")
    }
    let sep = s.get_char(i).unwrap()
    if sep == ',' {
      i = i + 1
    } else if sep == '}' {
      return i + 1
    } else {
      raise InvalidJson("expected ',' or '}'")
    }
  }
  i
}

///|
fn json_scan_value(s : String, start : Int) -> Int raise JwkError {
  let i = json_ws_skip(s, start)
  if i >= s.length() {
    raise InvalidJson("missing JSON value")
  }
  let c = s.get_char(i).unwrap()
  if c == '"' {
    json_skip_string(s, i)
  } else if c == '{' {
    json_scan_object(s, i)
  } else if c == '[' {
    json_scan_array(s, i)
  } else {
    let mut j = i
    while j < s.length() {
      let x = s.get_char(j).unwrap()
      if x == ',' || x == '}' || x == ']' {
        return j
      }
      j = j + 1
    }
    j
  }
}

///|
fn reject_duplicate_json_keys(json : String) -> Unit raise JwkError {
  let i = json_scan_value(json, 0)
  let rest = json_ws_skip(json, i)
  if rest != json.length() {
    raise InvalidJson("trailing data after JSON value")
  }
}

///|
fn get_string(m : Map[String, Json], key : String) -> String? raise JwkError {
  match m.get(key) {
    Some(String(s)) => Some(s)
    Some(_) => raise InvalidJson(key + " must be a string")
    None => None
  }
}

///|
fn get_string_array(
  m : Map[String, Json],
  key : String,
) -> Array[String]? raise JwkError {
  match m.get(key) {
    Some(Array(items)) => {
      let out : Array[String] = []
      for item in items {
        match item {
          String(s) => out.push(s)
          _ => raise InvalidJson(key + " entries must be strings")
        }
      }
      Some(out)
    }
    Some(_) => raise InvalidJson(key + " must be an array of strings")
    None => None
  }
}

///|
fn need_string(m : Map[String, Json], key : String) -> String raise JwkError {
  match get_string(m, key) {
    Some(s) => s
    None => raise MissingField(key)
  }
}

///|
fn need_b64url(m : Map[String, Json], key : String) -> Bytes raise JwkError {
  b64url_decode(need_string(m, key))
}

///|
fn opt_b64url(m : Map[String, Json], key : String) -> Bytes? raise JwkError {
  match get_string(m, key) {
    Some(s) => Some(b64url_decode(s))
    None => None
  }
}

// -----------------------------------------------------------------------------
// helpers to lift bytes into bigint / key fields
// -----------------------------------------------------------------------------

///|
// RFC 7518 §6.3.1 says RSA n/e/d are unsigned big-endian integers encoded
// with the minimum number of octets. Reject leading zeroes instead of
// normalising them so alternate encodings cannot cross a trust boundary.
fn bytes_to_bigint(b : Bytes) -> @bigint.BigInt raise JwkError {
  if b.length() == 0 {
    raise InvalidFieldLength("expected non-empty integer field")
  }
  if b.length() > 1 && b[0] == b'\x00' {
    raise InvalidFieldLength("integer field must use minimal unsigned encoding")
  }
  @bigint.BigInt::from_octets(b[:])
}

///|
fn bigint_byte_len(n : @bigint.BigInt) -> Int {
  let oct = n.to_octets()
  let mut start = 0
  while start < oct.length() - 1 && oct[start] == b'\x00' {
    start = start + 1
  }
  oct.length() - start
}

///|
fn bigint_is_odd(n : @bigint.BigInt) -> Bool {
  let oct = n.to_octets()
  oct.length() > 0 && (oct[oct.length() - 1].to_int() & 1) == 1
}

///|
fn validate_rsa_public_params(
  n : @bigint.BigInt,
  e : @bigint.BigInt,
) -> Int raise JwkError {
  if n.compare_int(1) <= 0 {
    raise CryptoError("RSA modulus must be greater than 1")
  }
  if !bigint_is_odd(n) {
    raise CryptoError("RSA modulus must be odd")
  }
  if e.compare_int(3) < 0 || !bigint_is_odd(e) {
    raise CryptoError("RSA public exponent must be odd and >= 3")
  }
  bigint_byte_len(n)
}

///|
fn make_ec_pub_p256(x : Bytes, y : Bytes) -> @p256.PublicKey raise JwkError {
  if x.length() != 32 {
    raise InvalidFieldLength("EC P-256 x must be 32 bytes")
  }
  if y.length() != 32 {
    raise InvalidFieldLength("EC P-256 y must be 32 bytes")
  }
  let buf = FixedArray::make(65, b'\x00')
  buf.unsafe_set(0, b'\x04')
  for i = 0; i < 32; i = i + 1 {
    buf.unsafe_set(1 + i, x[i])
  }
  for i = 0; i < 32; i = i + 1 {
    buf.unsafe_set(33 + i, y[i])
  }
  let uncompressed = Bytes::makei(65, fn(j) { buf.unsafe_get(j) })
  @p256.PublicKey::from_uncompressed(uncompressed) catch {
    e => raise CryptoError("P-256 public key: " + @debug.to_string(e))
  }
}

///|
fn make_ec_pub_p384(x : Bytes, y : Bytes) -> @p384.PublicKey raise JwkError {
  if x.length() != 48 {
    raise InvalidFieldLength("EC P-384 x must be 48 bytes")
  }
  if y.length() != 48 {
    raise InvalidFieldLength("EC P-384 y must be 48 bytes")
  }
  let buf = FixedArray::make(97, b'\x00')
  buf.unsafe_set(0, b'\x04')
  for i = 0; i < 48; i = i + 1 {
    buf.unsafe_set(1 + i, x[i])
  }
  for i = 0; i < 48; i = i + 1 {
    buf.unsafe_set(49 + i, y[i])
  }
  let uncompressed = Bytes::makei(97, fn(j) { buf.unsafe_get(j) })
  @p384.PublicKey::from_uncompressed(uncompressed) catch {
    e => raise CryptoError("P-384 public key: " + @debug.to_string(e))
  }
}

///|
fn make_ec_pub_p521(x : Bytes, y : Bytes) -> @p521.PublicKey raise JwkError {
  if x.length() != 66 {
    raise InvalidFieldLength("EC P-521 x must be 66 bytes")
  }
  if y.length() != 66 {
    raise InvalidFieldLength("EC P-521 y must be 66 bytes")
  }
  let buf = FixedArray::make(133, b'\x00')
  buf.unsafe_set(0, b'\x04')
  for i = 0; i < 66; i = i + 1 {
    buf.unsafe_set(1 + i, x[i])
  }
  for i = 0; i < 66; i = i + 1 {
    buf.unsafe_set(67 + i, y[i])
  }
  let uncompressed = Bytes::makei(133, fn(j) { buf.unsafe_get(j) })
  @p521.PublicKey::from_uncompressed(uncompressed) catch {
    e => raise CryptoError("P-521 public key: " + @debug.to_string(e))
  }
}

///|
fn make_ec_pub_secp256k1(
  x : Bytes,
  y : Bytes,
) -> @secp256k1.PublicKey raise JwkError {
  if x.length() != 32 {
    raise InvalidFieldLength("secp256k1 x must be 32 bytes")
  }
  if y.length() != 32 {
    raise InvalidFieldLength("secp256k1 y must be 32 bytes")
  }
  let buf = FixedArray::make(65, b'\x00')
  buf.unsafe_set(0, b'\x04')
  for i = 0; i < 32; i = i + 1 {
    buf.unsafe_set(1 + i, x[i])
  }
  for i = 0; i < 32; i = i + 1 {
    buf.unsafe_set(33 + i, y[i])
  }
  let uncompressed = Bytes::makei(65, fn(j) { buf.unsafe_get(j) })
  @secp256k1.PublicKey::from_uncompressed(uncompressed) catch {
    e => raise CryptoError("secp256k1 public key: " + @debug.to_string(e))
  }
}

// EC private-key construction: pad the scalar to the required length before
// handing it to `from_bytes`, mirroring the workspace's PKCS#8 loaders.

///|
fn pad_left(b : Bytes, n : Int) -> Bytes raise JwkError {
  if b.length() > n {
    raise InvalidFieldLength("EC d longer than curve order")
  }
  let pad = n - b.length()
  Bytes::makei(n, fn(i) { if i < pad { b'\x00' } else { b[i - pad] } })
}

// -----------------------------------------------------------------------------
// public-key serialisation (extract x/y/n/e/etc from each key type)
// -----------------------------------------------------------------------------

// Each EC module gives us `to_uncompressed` returning
// `04 || X || Y`. We split it here for the JWK x / y fields.

///|
fn split_uncompressed(b : Bytes, coord_len : Int) -> (Bytes, Bytes) {
  let x = Bytes::makei(coord_len, fn(i) { b[1 + i] })
  let y = Bytes::makei(coord_len, fn(i) { b[1 + coord_len + i] })
  (x, y)
}

///|
fn rsa_n_e_bytes(pk : @rsa.RsaPublicKey) -> (Bytes, Bytes) {
  // Both n and e are emitted as the minimal unsigned big-endian encoding.
  // BigInt::to_octets already returns minimal-length output for positive
  // values, so we forward it directly.
  (pk.n.to_octets(), pk.e.to_octets())
}

// -----------------------------------------------------------------------------
// parse_public / parse_private
// -----------------------------------------------------------------------------

///|
fn parse_inner(
  m : Map[String, Json],
  allow_private : Bool,
) -> Jwk raise JwkError {
  let kty = need_string(m, "kty")
  match kty {
    "RSA" => {
      let n_bytes = need_b64url(m, "n")
      let e_bytes = need_b64url(m, "e")
      let n = bytes_to_bigint(n_bytes)
      let e = bytes_to_bigint(e_bytes)
      let n_bytes_len = validate_rsa_public_params(n, e)
      let pub_key : @rsa.RsaPublicKey = { n, e, n_bytes_len }
      let priv_key : @rsa.RsaPrivateKey? = if allow_private {
        match opt_b64url(m, "d") {
          Some(d_bytes) => {
            let d = bytes_to_bigint(d_bytes)
            if d.compare_int(0) <= 0 {
              raise CryptoError("RSA private exponent must be positive")
            }
            let p : @rsa.RsaPrivateKey = { n, e, d, n_bytes_len }
            Some(p)
          }
          None => None
        }
      } else {
        None
      }
      Rsa(pubkey=pub_key, privkey=priv_key)
    }
    "EC" => {
      let crv = need_string(m, "crv")
      let x_bytes = need_b64url(m, "x")
      let y_bytes = need_b64url(m, "y")
      match crv {
        "P-256" => {
          let pub_key = make_ec_pub_p256(x_bytes, y_bytes)
          let priv_key : @p256.PrivateKey? = if allow_private {
            match opt_b64url(m, "d") {
              Some(d_bytes) => {
                let d_padded = pad_left(d_bytes, 32)
                let p = @p256.PrivateKey::from_bytes(d_padded) catch {
                  e =>
                    raise CryptoError("P-256 private: " + @debug.to_string(e))
                }
                if p.public_key().to_uncompressed() != pub_key.to_uncompressed() {
                  raise CryptoError("P-256 public/private mismatch")
                }
                Some(p)
              }
              None => None
            }
          } else {
            None
          }
          EcP256(pubkey=pub_key, privkey=priv_key)
        }
        "P-384" => {
          let pub_key = make_ec_pub_p384(x_bytes, y_bytes)
          let priv_key : @p384.PrivateKey? = if allow_private {
            match opt_b64url(m, "d") {
              Some(d_bytes) => {
                let d_padded = pad_left(d_bytes, 48)
                let p = @p384.PrivateKey::from_bytes(d_padded) catch {
                  e =>
                    raise CryptoError("P-384 private: " + @debug.to_string(e))
                }
                if p.public_key().to_uncompressed() != pub_key.to_uncompressed() {
                  raise CryptoError("P-384 public/private mismatch")
                }
                Some(p)
              }
              None => None
            }
          } else {
            None
          }
          EcP384(pubkey=pub_key, privkey=priv_key)
        }
        "P-521" => {
          let pub_key = make_ec_pub_p521(x_bytes, y_bytes)
          let priv_key : @p521.PrivateKey? = if allow_private {
            match opt_b64url(m, "d") {
              Some(d_bytes) => {
                let d_padded = pad_left(d_bytes, 66)
                let p = @p521.PrivateKey::from_bytes(d_padded) catch {
                  e =>
                    raise CryptoError("P-521 private: " + @debug.to_string(e))
                }
                if p.public_key().to_uncompressed() != pub_key.to_uncompressed() {
                  raise CryptoError("P-521 public/private mismatch")
                }
                Some(p)
              }
              None => None
            }
          } else {
            None
          }
          EcP521(pubkey=pub_key, privkey=priv_key)
        }
        "secp256k1" => {
          let pub_key = make_ec_pub_secp256k1(x_bytes, y_bytes)
          let priv_key : @secp256k1.PrivateKey? = if allow_private {
            match opt_b64url(m, "d") {
              Some(d_bytes) => {
                let d_padded = pad_left(d_bytes, 32)
                let p = @secp256k1.PrivateKey::from_bytes(d_padded) catch {
                  e =>
                    raise CryptoError(
                      "secp256k1 private: " + @debug.to_string(e),
                    )
                }
                if p.public_key().to_uncompressed() != pub_key.to_uncompressed() {
                  raise CryptoError("secp256k1 public/private mismatch")
                }
                Some(p)
              }
              None => None
            }
          } else {
            None
          }
          EcSecp256k1(pubkey=pub_key, privkey=priv_key)
        }
        _ => raise UnsupportedCurve(crv)
      }
    }
    "OKP" => {
      let crv = need_string(m, "crv")
      match crv {
        "Ed25519" => {
          let x_bytes = need_b64url(m, "x")
          if x_bytes.length() != 32 {
            raise InvalidFieldLength("Ed25519 x must be 32 bytes")
          }
          let pub_key = @ed25519.PublicKey::from_bytes(x_bytes) catch {
            e => raise CryptoError("Ed25519 public: " + @debug.to_string(e))
          }
          let priv_key : @ed25519.PrivateKey? = if allow_private {
            match opt_b64url(m, "d") {
              Some(d_bytes) => {
                if d_bytes.length() != 32 {
                  raise InvalidFieldLength("Ed25519 d (seed) must be 32 bytes")
                }
                let p = @ed25519.PrivateKey::from_seed(d_bytes) catch {
                  e => raise CryptoError("Ed25519 seed: " + @debug.to_string(e))
                }
                if p.public_key().to_bytes() != pub_key.to_bytes() {
                  raise CryptoError("Ed25519 public/private mismatch")
                }
                Some(p)
              }
              None => None
            }
          } else {
            None
          }
          OkpEd25519(pubkey=pub_key, privkey=priv_key)
        }
        _ => raise UnsupportedCurve(crv)
      }
    }
    "oct" => {
      if !allow_private {
        raise CryptoError("oct is a symmetric key; use parse_private")
      }
      let k = need_b64url(m, "k")
      Hmac(secret=k)
    }
    _ => raise UnsupportedKty(kty)
  }
}

///|
pub fn parse_public(json : String) -> Jwk raise JwkError {
  let m = parse_object(json)
  parse_inner(m, false)
}

///|
pub fn parse_private(json : String) -> Jwk raise JwkError {
  // `parse_private` is permissive: it pulls the private field if present,
  // but a pub-only JWK still parses to a `Jwk` with `privkey = None`.
  let m = parse_object(json)
  parse_inner(m, true)
}

///|
/// A single entry inside an RFC 7517 §5 JWK Set, carrying both the parsed
/// key material and the JOSE metadata callers need to dispatch on (`kid`,
/// `alg`, `use`, `key_ops`). Returned by `parse_set`.
pub(all) struct JwkSetEntry {
  jwk : Jwk
  kid : String?
  alg : String?
  use_ : String?
  key_ops : Array[String]?
}

///|
/// Parse an RFC 7517 §5 JWK Set document of the form
/// `{ "keys": [ <jwk>, <jwk>, ... ] }`. Each entry is parsed as a public
/// JWK; private fields are tolerated but not required. The metadata
/// fields (`kid`, `alg`, `use`, `key_ops`) are extracted alongside so callers
/// (e.g. `@jwt.select_verify_key`) can select a key by header `kid` + `alg`
/// without re-parsing the JSON.
pub fn parse_set(json : String) -> Array[JwkSetEntry] raise JwkError {
  let m = parse_object(json)
  let keys = match m.get("keys") {
    Some(Array(items)) => items
    Some(_) => raise InvalidJson("JWK Set 'keys' field must be an array")
    None => raise MissingField("keys")
  }
  let out : Array[JwkSetEntry] = []
  let seen_kids : Array[String] = []
  for k in keys {
    let inner = match k {
      Object(o) => o
      _ => raise InvalidJson("JWK Set entry must be an object")
    }
    // Use the same parse_inner path as parse_public, accepting private
    // material when present so a JWK Set with sign-side keys still loads.
    let jwk = parse_inner(inner, true)
    let kid = get_string(inner, "kid")
    match kid {
      Some(kid_value) => {
        for seen in seen_kids {
          if seen == kid_value {
            raise InvalidJson("duplicate JWK Set kid '" + kid_value + "'")
          }
        }
        seen_kids.push(kid_value)
      }
      None => ()
    }
    out.push({
      jwk,
      kid,
      alg: get_string(inner, "alg"),
      use_: get_string(inner, "use"),
      key_ops: get_string_array(inner, "key_ops"),
    })
  }
  out
}

// -----------------------------------------------------------------------------
// serialise_public / serialise_private
// -----------------------------------------------------------------------------

///|
fn jwk_to_public_map(jwk : Jwk) -> Map[String, Json] {
  let m : Map[String, Json] = Map([])
  match jwk {
    Rsa(pubkey~, ..) => {
      let (n, e) = rsa_n_e_bytes(pubkey)
      m["kty"] = Json::string("RSA")
      m["n"] = Json::string(b64url_encode(n))
      m["e"] = Json::string(b64url_encode(e))
    }
    EcP256(pubkey~, ..) => {
      let (x, y) = split_uncompressed(pubkey.to_uncompressed(), 32)
      m["kty"] = Json::string("EC")
      m["crv"] = Json::string("P-256")
      m["x"] = Json::string(b64url_encode(x))
      m["y"] = Json::string(b64url_encode(y))
    }
    EcP384(pubkey~, ..) => {
      let (x, y) = split_uncompressed(pubkey.to_uncompressed(), 48)
      m["kty"] = Json::string("EC")
      m["crv"] = Json::string("P-384")
      m["x"] = Json::string(b64url_encode(x))
      m["y"] = Json::string(b64url_encode(y))
    }
    EcP521(pubkey~, ..) => {
      let (x, y) = split_uncompressed(pubkey.to_uncompressed(), 66)
      m["kty"] = Json::string("EC")
      m["crv"] = Json::string("P-521")
      m["x"] = Json::string(b64url_encode(x))
      m["y"] = Json::string(b64url_encode(y))
    }
    EcSecp256k1(pubkey~, ..) => {
      let (x, y) = split_uncompressed(pubkey.to_uncompressed(), 32)
      m["kty"] = Json::string("EC")
      m["crv"] = Json::string("secp256k1")
      m["x"] = Json::string(b64url_encode(x))
      m["y"] = Json::string(b64url_encode(y))
    }
    OkpEd25519(pubkey~, ..) => {
      m["kty"] = Json::string("OKP")
      m["crv"] = Json::string("Ed25519")
      m["x"] = Json::string(b64url_encode(pubkey.to_bytes()))
    }
    Hmac(_) => m["kty"] = Json::string("oct")
  }
  m
}

///|
pub fn serialise_public(jwk : Jwk) -> String {
  let m = jwk_to_public_map(jwk)
  Json::object(m).stringify()
}

///|
pub fn serialise_private(jwk : Jwk) -> String raise JwkError {
  let m = jwk_to_public_map(jwk)
  match jwk {
    Rsa(privkey~, ..) =>
      match privkey {
        Some(p) => m["d"] = Json::string(b64url_encode(p.d.to_octets()))
        // CRT params not held in @rsa.RsaPrivateKey; omitted intentionally.
        None => raise PrivateKeyMissing
      }
    EcP256(privkey~, ..) =>
      match privkey {
        Some(p) =>
          m["d"] = Json::string(b64url_encode(p.d.to_octets(length=32)))
        None => raise PrivateKeyMissing
      }
    EcP384(privkey~, ..) =>
      match privkey {
        Some(p) =>
          m["d"] = Json::string(b64url_encode(p.d.to_octets(length=48)))
        None => raise PrivateKeyMissing
      }
    EcP521(privkey~, ..) =>
      match privkey {
        Some(p) =>
          m["d"] = Json::string(b64url_encode(p.d.to_octets(length=66)))
        None => raise PrivateKeyMissing
      }
    EcSecp256k1(privkey~, ..) =>
      match privkey {
        Some(p) =>
          m["d"] = Json::string(b64url_encode(p.d.to_octets(length=32)))
        None => raise PrivateKeyMissing
      }
    OkpEd25519(privkey~, ..) =>
      match privkey {
        Some(p) => m["d"] = Json::string(b64url_encode(p.seed_bytes()))
        None => raise PrivateKeyMissing
      }
    Hmac(secret~) =>
      // For `oct` the secret IS the whole key — no separate private field.
      m["k"] = Json::string(b64url_encode(secret))
  }
  Json::object(m).stringify()
}

// -----------------------------------------------------------------------------
// RFC 7638 thumbprint
//
// "The construction of the hash input is the SHA-256 hash of the UTF-8
//  representation of a JSON object containing the *required* members of
//  the JWK [...] with no whitespace or line breaks, and in
//  lexicographic order of the member names."
// -----------------------------------------------------------------------------

///|
fn json_string_escape(s : String) -> String {
  // The JWK fields we emit through the canonical form are all base64url
  // (no escapable characters) or fixed-vocabulary `kty`/`crv` strings.
  // We still implement the minimal JSON string escape required by RFC 8259
  // §7 so this function is safe for arbitrary values too.
  let buf = StringBuilder::new()
  buf.write_char('"')
  for c in s {
    if c == '"' {
      buf.write_string("\\\"")
    } else if c == '\\' {
      buf.write_string("\\\\")
    } else if c == '\n' {
      buf.write_string("\\n")
    } else if c == '\r' {
      buf.write_string("\\r")
    } else if c == '\t' {
      buf.write_string("\\t")
    } else if c.to_int() < 0x20 {
      // Emit a \u00XX escape for any control character; the codepoints
      // used in RFC 7638 inputs never enter this branch.
      let n = c.to_int()
      buf.write_string("\\u00")
      let hex_chars = "0123456789abcdef"
      let hi = n / 16 % 16
      let lo = n % 16
      buf.write_char(hex_chars.get_char(hi).unwrap())
      buf.write_char(hex_chars.get_char(lo).unwrap())
    } else {
      buf.write_char(c)
    }
  }
  buf.write_char('"')
  buf.to_string()
}

///|
// Emit `{"k1":"v1","k2":"v2",...}` with keys sorted lexicographically and
// no whitespace. Used only for RFC 7638 thumbprint input construction.
//
// We sort by hand-rolled lexicographic comparison over the key strings'
// UTF-8 byte sequences (RFC 7638 §3 is unambiguous: "the order
// recommended by ECMA-262 [...] lexicographic order of the JSON member
// names" and all our keys are ASCII), rather than trusting
// `Array::sort_by_key` for tuples — the latter was observed to leave
// elements out of order in this MoonBit version.
fn canonical_object(pairs : Array[(String, String)]) -> String {
  pairs.sort_by(fn(a, b) {
    let ak = a.0
    let bk = b.0
    let la = ak.length()
    let lb = bk.length()
    let n = if la < lb { la } else { lb }
    let mut i = 0
    let mut result = 0
    while i < n {
      let ca = ak.get_char(i).unwrap().to_int()
      let cb = bk.get_char(i).unwrap().to_int()
      if ca != cb {
        result = ca - cb
        break
      }
      i = i + 1
    }
    if result == 0 {
      la - lb
    } else {
      result
    }
  })
  let buf = StringBuilder::new()
  buf.write_char('{')
  let mut first = true
  for p in pairs {
    if !first {
      buf.write_char(',')
    }
    first = false
    buf.write_string(json_string_escape(p.0))
    buf.write_char(':')
    buf.write_string(json_string_escape(p.1))
  }
  buf.write_char('}')
  buf.to_string()
}

///|
fn canonical_form(jwk : Jwk) -> String {
  let pairs : Array[(String, String)] = []
  match jwk {
    Rsa(pubkey~, ..) => {
      let (n, e) = rsa_n_e_bytes(pubkey)
      pairs.push(("e", b64url_encode(e)))
      pairs.push(("kty", "RSA"))
      pairs.push(("n", b64url_encode(n)))
    }
    EcP256(pubkey~, ..) => {
      let (x, y) = split_uncompressed(pubkey.to_uncompressed(), 32)
      pairs.push(("crv", "P-256"))
      pairs.push(("kty", "EC"))
      pairs.push(("x", b64url_encode(x)))
      pairs.push(("y", b64url_encode(y)))
    }
    EcP384(pubkey~, ..) => {
      let (x, y) = split_uncompressed(pubkey.to_uncompressed(), 48)
      pairs.push(("crv", "P-384"))
      pairs.push(("kty", "EC"))
      pairs.push(("x", b64url_encode(x)))
      pairs.push(("y", b64url_encode(y)))
    }
    EcP521(pubkey~, ..) => {
      let (x, y) = split_uncompressed(pubkey.to_uncompressed(), 66)
      pairs.push(("crv", "P-521"))
      pairs.push(("kty", "EC"))
      pairs.push(("x", b64url_encode(x)))
      pairs.push(("y", b64url_encode(y)))
    }
    EcSecp256k1(pubkey~, ..) => {
      let (x, y) = split_uncompressed(pubkey.to_uncompressed(), 32)
      pairs.push(("crv", "secp256k1"))
      pairs.push(("kty", "EC"))
      pairs.push(("x", b64url_encode(x)))
      pairs.push(("y", b64url_encode(y)))
    }
    OkpEd25519(pubkey~, ..) => {
      pairs.push(("crv", "Ed25519"))
      pairs.push(("kty", "OKP"))
      pairs.push(("x", b64url_encode(pubkey.to_bytes())))
    }
    Hmac(secret~) => {
      pairs.push(("k", b64url_encode(secret)))
      pairs.push(("kty", "oct"))
    }
  }
  canonical_object(pairs)
}

// Internal debug helper — exposed so tests can pin the canonical JSON
// form for RFC 7638 fixtures without re-deriving it.

///|
pub fn debug_canonical_form(jwk : Jwk) -> String {
  canonical_form(jwk)
}

///|
pub fn thumbprint(jwk : Jwk) -> Bytes raise JwkError {
  let canonical = canonical_form(jwk)
  // SHA-256 over the UTF-8 octets of the canonical form. The canonical
  // form only contains ASCII (base64url alphabet, fixed kty/crv strings),
  // so we can lift each Char's low byte directly.
  let chars : Array[Char] = []
  for c in canonical {
    if c.to_int() > 0x7f {
      raise CryptoError("canonical JSON unexpectedly contained non-ASCII")
    }
    chars.push(c)
  }
  let raw = Bytes::makei(chars.length(), fn(j) { chars[j].to_int().to_byte() })
  @hash.sha256(raw)
}

///|
pub fn thumbprint_base64url(jwk : Jwk) -> String raise JwkError {
  b64url_encode(thumbprint(jwk))
}
