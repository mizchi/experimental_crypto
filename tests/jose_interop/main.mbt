// JOSE (JWS) interop fixture emitter.
//
// Signs a JWT with each asymmetric / symmetric algorithm and prints the token
// plus the public key (as a JWK via the `jwk` module, or the shared secret for
// HMAC). `verify.mjs` imports the key into Node's built-in `crypto` and
// verifies the JWS signature, proving `jwt.sign` + the underlying signing
// primitives + `jwk.serialise_public` interoperate with a reference JOSE
// verifier. Keys are derived deterministically so the fixture is reproducible.

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
fn payload() -> Json {
  Json::object(
    Map([
      ("iss", Json::string("moonbit-interop")),
      ("sub", Json::string("alice")),
      ("aud", Json::string("verifier")),
      ("iat", Json::number(1700000000)),
      ("exp", Json::number(4070908800)),
    ]),
  )
}

///|
fn emit_pub(name : String, token : String, jwk_json : String) -> Unit {
  println("-----BEGIN JOSE " + name + "-----")
  println("TOKEN=" + token)
  println("JWK=" + jwk_json)
  println("-----END JOSE " + name + "-----")
}

///|
fn emit_hmac(name : String, token : String, secret : Bytes) -> Unit {
  println("-----BEGIN JOSE " + name + "-----")
  println("TOKEN=" + token)
  println("SECRET=" + to_hex(secret))
  println("-----END JOSE " + name + "-----")
}

///|
fn main {
  let pl = payload()

  // EdDSA (Ed25519)
  let ed_sk = @ed25519.PrivateKey::from_seed(
    Bytes::makei(32, fn(i) { (i + 3).to_byte() }),
  ) catch {
    _ => abort("ed25519 seed")
  }
  let ed_tok = @jwt.sign(pl, @jwt.Key::EdDsa(privkey=ed_sk)) catch {
    _ => abort("EdDSA sign")
  }
  let ed_jwk = @jwk.serialise_public(
    @jwk.Jwk::OkpEd25519(pubkey=ed_sk.public_key(), privkey=None),
  )
  emit_pub("EDDSA", ed_tok, ed_jwk)

  // ES256 (ECDSA P-256, SHA-256)
  let p_sk = @p256.PrivateKey::from_bytes(
    Bytes::makei(32, fn(i) { (i + 1).to_byte() }),
  ) catch {
    _ => abort("p256 scalar")
  }
  let es_tok = @jwt.sign(pl, @jwt.Key::Es256(privkey=p_sk)) catch {
    _ => abort("ES256 sign")
  }
  let es_jwk = @jwk.serialise_public(
    @jwk.Jwk::EcP256(pubkey=p_sk.public_key(), privkey=None),
  )
  emit_pub("ES256", es_tok, es_jwk)

  // HS256 (HMAC-SHA-256)
  let secret : Bytes = b"experimental_crypto interop shared HMAC secret"
  let hs_tok = @jwt.sign(pl, @jwt.Key::Hs256(secret~)) catch {
    _ => abort("HS256 sign")
  }
  emit_hmac("HS256", hs_tok, secret)
}
