// PKCS#8 key-loading interop shim.
//
// openssl generates a PKCS#8 private key (RSA / EC P-256 / EC P-384 / Ed25519);
// this shim loads it via the key modules' `from_pkcs8_pem` loaders, signs a
// fixed JWT, and returns the token. The Node driver derives the public key from
// the same PEM and verifies the JWS — proving MoonBit decoded openssl's PKCS#8
// key material correctly and signed with it.

///|
fn fixed_payload() -> Json {
  Json::object(
    Map([
      ("iss", Json::string("pkcs8-interop")),
      ("sub", Json::string("openssl-loaded-key")),
      ("iat", Json::number(1700000000)),
      ("exp", Json::number(4070908800)),
    ]),
  )
}

///|
/// Load a PKCS#8 PEM private key for `alg` and sign a fixed JWT with it.
/// `alg` is one of "RS256", "ES256", "ES384", "EdDSA".
pub fn pkcs8_sign_jws(alg : String, pkcs8_pem : String) -> String {
  let key : @jwt.Key = match alg {
    "RS256" =>
      @jwt.Key::Rs256(
        privkey=@rsa.RsaPrivateKey::from_pkcs8_pem(pkcs8_pem) catch {
          e => abort("RS256 load: " + @debug.to_string(e))
        },
      )
    "ES256" =>
      @jwt.Key::Es256(
        privkey=@p256.PrivateKey::from_pkcs8_pem(pkcs8_pem) catch {
          e => abort("ES256 load: " + @debug.to_string(e))
        },
      )
    "ES384" =>
      @jwt.Key::Es384(
        privkey=@p384.PrivateKey::from_pkcs8_pem(pkcs8_pem) catch {
          e => abort("ES384 load: " + @debug.to_string(e))
        },
      )
    "EdDSA" =>
      @jwt.Key::EdDsa(
        privkey=@ed25519.PrivateKey::from_pkcs8_pem(pkcs8_pem) catch {
          e => abort("EdDSA load: " + @debug.to_string(e))
        },
      )
    _ => abort("unsupported alg " + alg)
  }
  @jwt.sign(fixed_payload(), key) catch {
    e => abort("sign: " + @debug.to_string(e))
  }
}
