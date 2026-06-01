// JWE (RFC 7516) interop shim — both directions, verified against Node's
// built-in crypto (RSA-OAEP-256 + AES-GCM), no npm.
//
//   jwe_encrypt_dir / jwe_encrypt_rsa : MoonBit encrypts, Node decrypts.
//   jwe_decrypt_dir / jwe_decrypt_rsa : Node encrypts, MoonBit decrypts.
//
// `enc_id`: 0 = A128GCM, 1 = A256GCM. Hex in/out at the JS boundary.

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
fn enc_of(id : Int) -> @jwe.JweEnc {
  match id {
    0 => @jwe.JweEnc::A128gcm
    1 => @jwe.JweEnc::A256gcm
    _ => abort("bad enc id")
  }
}

///|
/// dir mode: MoonBit encrypts with a caller-supplied CEK + IV.
pub fn jwe_encrypt_dir(
  enc_id : Int,
  cek_hex : String,
  iv_hex : String,
  pt_hex : String,
) -> String {
  @jwe.encrypt(
    from_hex(pt_hex),
    @jwe.JweAlg::Dir,
    enc_of(enc_id),
    @jwe.EncryptionKey::EncDir(cek=from_hex(cek_hex)),
    iv=from_hex(iv_hex),
  ) catch {
    e => abort("jwe_encrypt_dir: " + @debug.to_string(e))
  }
}

///|
/// dir mode: MoonBit decrypts a compact JWE. Returns plaintext hex or "ERR".
pub fn jwe_decrypt_dir(cek_hex : String, token : String) -> String {
  let pt = @jwe.decrypt(
    token,
    @jwe.DecryptionKey::DecDir(cek=from_hex(cek_hex)),
  ) catch {
    _ => return "ERR"
  }
  to_hex(pt)
}

///|
/// RSA-OAEP-256: MoonBit encrypts to an RSA public key (n, e).
pub fn jwe_encrypt_rsa(
  enc_id : Int,
  n_hex : String,
  e_hex : String,
  cek_hex : String,
  iv_hex : String,
  seed_hex : String,
  pt_hex : String,
) -> String {
  let pk = @rsa.RsaPublicKey::from_components(from_hex(n_hex), from_hex(e_hex)) catch {
    e => abort("jwe_encrypt_rsa(key): " + @debug.to_string(e))
  }
  @jwe.encrypt(
    from_hex(pt_hex),
    @jwe.JweAlg::Rsa_oaep_256,
    enc_of(enc_id),
    @jwe.EncryptionKey::EncRsa(pubkey=pk),
    cek=from_hex(cek_hex),
    iv=from_hex(iv_hex),
    oaep_seed=from_hex(seed_hex),
  ) catch {
    e => abort("jwe_encrypt_rsa: " + @debug.to_string(e))
  }
}

///|
/// RSA-OAEP-256: MoonBit decrypts a compact JWE with a PKCS#8 PEM private key.
pub fn jwe_decrypt_rsa(pkcs8_pem : String, token : String) -> String {
  let sk = @rsa.RsaPrivateKey::from_pkcs8_pem(pkcs8_pem) catch {
    _ => return "ERR"
  }
  let pt = @jwe.decrypt(token, @jwe.DecryptionKey::DecRsa(privkey=sk)) catch {
    _ => return "ERR"
  }
  to_hex(pt)
}
