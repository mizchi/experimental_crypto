// JS-export shim over `mizchi/experimental_crypto/tls12` for the live TLS 1.2
// interop harness (client.mjs drives the socket; this provides the crypto).
//
// All exports are non-raising: a MoonBit function declared `raise` compiles to
// a JS Result wrapper, so every shim catches internally and returns a sentinel
// (empty Bytes / 0) on failure. The driver treats empty output as an error.

///|
fn suite_of(u16 : Int) -> @tls12.CipherSuite {
  match @tls12.CipherSuite::from_u16(u16) {
    Some(s) => s
    None => abort("unknown cipher suite")
  }
}

///|
fn empty() -> Bytes {
  Bytes::makei(0, fn(_i) { b'\x00' })
}

///|
fn concat2(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
/// Build a full handshake-wrapped ClientHello. Offers the four ECDHE-AEAD
/// suites and the x25519 / secp256r1 / secp384r1 groups, SNI = "localhost".
pub fn client_hello(client_random : Bytes) -> Bytes {
  let body = @tls12.build_client_hello(
    client_random,
    [
      @tls12.CipherSuite::EcdheEcdsaAes128GcmSha256,
      @tls12.CipherSuite::EcdheRsaAes128GcmSha256,
      @tls12.CipherSuite::EcdheEcdsaAes256GcmSha384,
      @tls12.CipherSuite::EcdheRsaAes256GcmSha384,
    ],
    [@tls12.group_x25519, @tls12.group_secp256r1, @tls12.group_secp384r1],
    "localhost",
  ) catch {
    _ => return empty()
  }
  @tls12.handshake_message(@tls12.HandshakeType::ClientHello, body)
}

///|
/// Parse a ServerHello body; returns `server_random(32) || cipher_suite(2)`,
/// or empty on failure.
pub fn parse_server_hello(sh_body : Bytes) -> Bytes {
  let sh = @tls12.parse_server_hello(sh_body) catch { _ => return empty() }
  let suite = sh.cipher_suite().to_u16()
  concat2(
    sh.random(),
    Bytes::makei(2, fn(i) {
      if i == 0 {
        ((suite >> 8) & 0xff).to_byte()
      } else {
        (suite & 0xff).to_byte()
      }
    }),
  )
}

///|
/// Parse a Certificate body; returns the leaf (first) DER, or empty.
pub fn parse_certificate_leaf(cert_body : Bytes) -> Bytes {
  let certs = @tls12.parse_certificate(cert_body) catch { _ => return empty() }
  if certs.length() == 0 {
    return empty()
  }
  certs[0]
}

///|
/// Parse a ServerKeyExchange body; returns `named_group(2) || server_public`,
/// or empty. (The signature is verified separately via `verify_ske`.)
pub fn parse_ske(ske_body : Bytes) -> Bytes {
  let ske = @tls12.parse_server_key_exchange(ske_body) catch {
    _ => return empty()
  }
  let g = ske.named_group()
  concat2(
    Bytes::makei(2, fn(i) {
      if i == 0 {
        ((g >> 8) & 0xff).to_byte()
      } else {
        (g & 0xff).to_byte()
      }
    }),
    ske.public_key(),
  )
}

///|
/// Verify the ServerKeyExchange signature against the leaf cert. Returns 1 if
/// valid, 0 otherwise.
pub fn verify_ske(
  leaf : Bytes,
  ske_body : Bytes,
  client_random : Bytes,
  server_random : Bytes,
) -> Int {
  let ske = @tls12.parse_server_key_exchange(ske_body) catch { _ => return 0 }
  let ok = @tls12.verify_server_key_exchange(
    leaf, ske, client_random, server_random,
  ) catch {
    _ => return 0
  }
  if ok {
    1
  } else {
    0
  }
}

///|
/// Client ephemeral ECDHE public key for `group`, or empty on failure.
pub fn ecdhe_public(group : Int, eph_priv : Bytes) -> Bytes {
  @tls12.ecdhe_client_public(group, eph_priv) catch {
    _ => empty()
  }
}

///|
/// ECDHE pre_master_secret, or empty on failure.
pub fn ecdhe_pms(group : Int, eph_priv : Bytes, server_pub : Bytes) -> Bytes {
  @tls12.ecdhe_pre_master_secret(group, eph_priv, server_pub) catch {
    _ => empty()
  }
}

///|
/// Handshake-wrapped ClientKeyExchange carrying the client ECDHE public key.
pub fn client_key_exchange(client_pub : Bytes) -> Bytes {
  @tls12.handshake_message(
    @tls12.HandshakeType::ClientKeyExchange,
    @tls12.build_client_key_exchange(client_pub),
  )
}

///|
/// master_secret = PRF(pms, "master secret", client_random || server_random).
pub fn master_secret(
  suite_u16 : Int,
  pms : Bytes,
  client_random : Bytes,
  server_random : Bytes,
) -> Bytes {
  suite_of(suite_u16)
  .prf_hash()
  .master_secret(pms, client_random, server_random)
}

///|
/// key_block = PRF(master_secret, "key expansion", server_random ||
/// client_random), sliced to `client_key || server_key || client_iv(4) ||
/// server_iv(4)` for the AEAD suite. The caller slices by key length (16 for
/// the AES-128 suites, 32 for AES-256).
pub fn key_block(
  suite_u16 : Int,
  ms : Bytes,
  client_random : Bytes,
  server_random : Bytes,
) -> Bytes {
  let suite = suite_of(suite_u16)
  let key_len = suite.aead().key_size()
  suite.prf_hash().key_block(ms, client_random, server_random, 2 * key_len + 8)
}

///|
/// Handshake-wrapped Finished. `is_client` selects the "client finished" /
/// "server finished" label. `transcript` is the concatenation of all framed
/// handshake messages so far.
pub fn finished_verify_data(
  suite_u16 : Int,
  ms : Bytes,
  is_client : Int,
  transcript : Bytes,
) -> Bytes {
  let label = if is_client == 1 { "client finished" } else { "server finished" }
  let vd = suite_of(suite_u16)
    .prf_hash()
    .finished_verify_data(ms, label, transcript)
  @tls12.handshake_message(@tls12.HandshakeType::Finished, vd)
}

///|
fn gcm_keys(
  suite_u16 : Int,
  key : Bytes,
  iv : Bytes,
) -> @tls12.GcmKeys raise @tls12.RecordError {
  @tls12.GcmKeys::new(suite_of(suite_u16).aead(), key, iv)
}

///|
/// Seal one TLS 1.2 GCM record. `ctype` is the content-type byte (22 handshake,
/// 23 application_data, etc.). Returns the on-wire record or empty.
pub fn seal_record(
  suite_u16 : Int,
  key : Bytes,
  iv : Bytes,
  seq : Int,
  ctype : Int,
  plaintext : Bytes,
) -> Bytes {
  let ct = match @tls12.ContentType::from_int(ctype) {
    Some(c) => c
    None => return empty()
  }
  let keys = gcm_keys(suite_u16, key, iv) catch { _ => return empty() }
  @tls12.seal_gcm_record(keys, seq.to_uint64(), ct, plaintext) catch {
    _ => empty()
  }
}

///|
/// Open one TLS 1.2 GCM record; returns the decrypted content (without the
/// content-type — the caller knows it), or empty on auth failure.
pub fn open_record(
  suite_u16 : Int,
  key : Bytes,
  iv : Bytes,
  seq : Int,
  record : Bytes,
) -> Bytes {
  let keys = gcm_keys(suite_u16, key, iv) catch { _ => return empty() }
  let (_ct, pt) = @tls12.open_gcm_record(keys, seq.to_uint64(), record) catch {
    _ => return empty()
  }
  pt
}

///|
/// Generic handshake-message wrapper (`type(1) || len(3) || body`).
pub fn handshake_wrap(msg_type : Int, body : Bytes) -> Bytes {
  let ty = match @tls12.HandshakeType::from_int(msg_type) {
    Some(t) => t
    None => return empty()
  }
  @tls12.handshake_message(ty, body)
}
