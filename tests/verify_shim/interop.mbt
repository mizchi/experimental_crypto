// Reverse-direction interop shim (Node produces, MoonBit verifies/decrypts).
//
// Exposes, to a Node.js host (see driver.mjs), flat functions that exercise the
// VERIFY / DECRYPT side of the library against artifacts a reference stack
// produced: `jwt_verify` checks a JWS Node signed, `aead_open` decrypts +
// authenticates a ciphertext Node sealed. Both are non-raising (return a
// status / sentinel) so the JS boundary stays plain.

///|
fn hexval(c : Char) -> Int {
  let v = c.to_int()
  if v >= '0'.to_int() && v <= '9'.to_int() {
    v - '0'.to_int()
  } else if v >= 'a'.to_int() && v <= 'f'.to_int() {
    v - 'a'.to_int() + 10
  } else if v >= 'A'.to_int() && v <= 'F'.to_int() {
    v - 'A'.to_int() + 10
  } else {
    abort("non-hex char")
  }
}

///|
fn from_hex(s : String) -> Bytes {
  let n = s.length() / 2
  Bytes::makei(n, fn(i) {
    ((hexval(s.get_char(i * 2).unwrap()) << 4) |
    hexval(s.get_char(i * 2 + 1).unwrap())).to_byte()
  })
}

///|
fn nib(n : Int) -> Char {
  "0123456789abcdef".get_char(n & 0xf).unwrap()
}

///|
fn to_hex(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i in 0..<b.length() {
    let v = b[i].to_int()
    sb.write_char(nib(v >> 4))
    sb.write_char(nib(v))
  }
  sb.to_string()
}

///|
fn token_alg(token : String) -> String {
  let hdr = @jwt.peek_header(token) catch { _ => return "" }
  match hdr.get("alg") {
    Some(Json::String(s)) => s
    _ => ""
  }
}

///|
fn verify_key_for(
  alg : String,
  jwk_json : String,
  secret_hex : String,
) -> @jwt.VerifyKey? {
  match alg {
    "HS256" => return Some(@jwt.VerifyKey::Hs256(secret=from_hex(secret_hex)))
    "HS384" => return Some(@jwt.VerifyKey::Hs384(secret=from_hex(secret_hex)))
    "HS512" => return Some(@jwt.VerifyKey::Hs512(secret=from_hex(secret_hex)))
    _ => ()
  }
  let jwk = @jwk.parse_public(jwk_json) catch { _ => return None }
  match (alg, jwk) {
    ("EdDSA", @jwk.Jwk::OkpEd25519(pubkey~, ..)) =>
      Some(@jwt.VerifyKey::EdDsa(pubkey~))
    ("ES256", @jwk.Jwk::EcP256(pubkey~, ..)) =>
      Some(@jwt.VerifyKey::Es256(pubkey~))
    ("ES384", @jwk.Jwk::EcP384(pubkey~, ..)) =>
      Some(@jwt.VerifyKey::Es384(pubkey~))
    ("RS256", @jwk.Jwk::Rsa(pubkey~, ..)) =>
      Some(@jwt.VerifyKey::Rs256(pubkey~))
    ("RS384", @jwk.Jwk::Rsa(pubkey~, ..)) =>
      Some(@jwt.VerifyKey::Rs384(pubkey~))
    ("RS512", @jwk.Jwk::Rsa(pubkey~, ..)) =>
      Some(@jwt.VerifyKey::Rs512(pubkey~))
    ("PS256", @jwk.Jwk::Rsa(pubkey~, ..)) =>
      Some(@jwt.VerifyKey::Ps256(pubkey~))
    ("PS384", @jwk.Jwk::Rsa(pubkey~, ..)) =>
      Some(@jwt.VerifyKey::Ps384(pubkey~))
    ("PS512", @jwk.Jwk::Rsa(pubkey~, ..)) =>
      Some(@jwt.VerifyKey::Ps512(pubkey~))
    _ => None
  }
}

///|
/// Verify a JWS produced elsewhere. For HMAC pass `secret_hex` (and "" for
/// `jwk_json`); for asymmetric algs pass the public key as a JWK. Returns 1 if
/// the signature (and standard time checks) verify, else 0.
pub fn jwt_verify(
  token : String,
  jwk_json : String,
  secret_hex : String,
) -> Int {
  let alg = token_alg(token)
  if alg == "" {
    return 0
  }
  let vk = match verify_key_for(alg, jwk_json, secret_hex) {
    Some(k) => k
    None => return 0
  }
  // Fixed evaluation instant inside the fixture token's validity window.
  let _ = @jwt.verify(token, vk, @jwt.VerifyOptions::default(2000000000L)) catch {
    _ => return 0
  }
  1
}

///|
/// Decrypt + authenticate a ciphertext (ct||tag) sealed elsewhere. `alg_id`:
/// 0 = ChaCha20-Poly1305, 1 = AES-128-GCM, 2 = AES-256-GCM. Returns the
/// plaintext as hex, or "ERR" if authentication fails.
pub fn aead_open(
  alg_id : Int,
  key_hex : String,
  nonce_hex : String,
  aad_hex : String,
  ct_hex : String,
) -> String {
  let alg = match alg_id {
    0 => @aead.Algorithm::ChaCha20Poly1305
    1 => @aead.Algorithm::Aes128Gcm
    2 => @aead.Algorithm::Aes256Gcm
    _ => return "ERR"
  }
  let pt = @aead.open(
    alg,
    from_hex(key_hex),
    from_hex(nonce_hex),
    from_hex(aad_hex),
    from_hex(ct_hex),
  ) catch {
    _ => return "ERR"
  }
  to_hex(pt)
}
