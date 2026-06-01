// Interop shim for live TLS 1.3 handshakes.
//
// Exposes a flat (Bytes / Int / String) API over the `tls13` client building
// blocks so a Node.js host can drive a real 1-RTT handshake over a TCP socket
// (see `interop/tls_client/client.mjs`). `Bytes` maps to `Uint8Array` at the
// JS boundary; structs / tuples are NOT crossed — every value returned to JS
// is a flat `Bytes` (length-prefixed where several fields are bundled).
//
// All exports are intentionally non-raising: on any internal error they
// `abort`, which surfaces as a thrown JS exception the host can report. This
// keeps the JS return values plain `Uint8Array` (a `raise` signature would
// wrap them in a MoonBit `Result` object instead).
//
// This is a test/interop harness, not part of the library surface: secret key
// material (handshake / application traffic keys) is returned to the caller on
// purpose so the Node side can frame records.

///|
fn suite_of(suite_u16 : Int) -> @tls13.CipherSuite {
  match @tls13.CipherSuite::from_u16(suite_u16) {
    Some(s) => s
    None => abort("unsupported cipher suite " + suite_u16.to_string())
  }
}

///|
fn concat(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for p in parts {
    total = total + p.length()
  }
  let out = FixedArray::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i in 0..<p.length() {
      out[off + i] = p[i]
    }
    off = off + p.length()
  }
  Bytes::makei(total, fn(i) { out[i] })
}

///|
// Bundle several Bytes fields into one blob, each prefixed with a 4-byte
// big-endian length. The Node side unpacks them back in order.
fn pack(fields : Array[Bytes]) -> Bytes {
  let chunks : Array[Bytes] = []
  for f in fields {
    let n = f.length()
    chunks.push(
      Bytes::makei(4, fn(i) { ((n >> ((3 - i) * 8)) & 0xff).to_byte() }),
    )
    chunks.push(f)
  }
  concat(chunks)
}

///|
/// Clamp a 32-byte scalar into an X25519 public key.
pub fn x25519_public(priv32 : Bytes) -> Bytes {
  let sk = @x25519.PrivateKey::from_bytes(priv32) catch {
    e => abort("x25519_public: " + @debug.to_string(e))
  }
  sk.public_key().to_bytes()
}

///|
/// X25519(priv, peer_pub) raw shared secret (aborts on a small-order peer key).
pub fn x25519_shared(priv32 : Bytes, peer_pub : Bytes) -> Bytes {
  let sk = @x25519.PrivateKey::from_bytes(priv32) catch {
    e => abort("x25519_shared(sk): " + @debug.to_string(e))
  }
  let pk = @x25519.PublicKey::from_bytes(peer_pub) catch {
    e => abort("x25519_shared(pk): " + @debug.to_string(e))
  }
  let ss = @x25519.diffie_hellman(sk, pk) catch {
    e => abort("x25519_shared(dh): " + @debug.to_string(e))
  }
  ss.to_bytes()
}

///|
/// Build a ClientHello handshake message (with its 4-byte header) offering a
/// single cipher suite, X25519 key share, and a small signature-scheme set.
pub fn client_hello(
  suite_u16 : Int,
  random32 : Bytes,
  session_id : Bytes,
  x25519_pub : Bytes,
  server_name : String,
) -> Bytes {
  let suite = suite_of(suite_u16)
  let offer : @tls13.KeyShareOffer = {
    group: @tls13.NamedGroup::X25519,
    key_exchange: x25519_pub,
  }
  let sni : String? = if server_name == "" { None } else { Some(server_name) }
  @tls13.build_client_hello(
    random32,
    session_id,
    [suite],
    [@tls13.NamedGroup::X25519],
    [offer],
    [
      @tls13.SignatureScheme::EcdsaSecp256r1Sha256,
      @tls13.SignatureScheme::Ed25519,
      @tls13.SignatureScheme::RsaPssRsaeSha256,
      @tls13.SignatureScheme::EcdsaSecp384r1Sha384,
    ],
    server_name=sni,
  ) catch {
    e => abort("client_hello: " + @debug.to_string(e))
  }
}

///|
/// Extract the server's X25519 key-share public key from a ServerHello
/// handshake message (with its 4-byte header).
pub fn server_key_share(server_hello_msg : Bytes) -> Bytes {
  let (_, body, _) = @tls13.parse_handshake(server_hello_msg) catch {
    e => abort("server_key_share(parse): " + @debug.to_string(e))
  }
  let sh = @tls13.parse_server_hello(body) catch {
    e => abort("server_key_share(sh): " + @debug.to_string(e))
  }
  match sh.key_share {
    Some(ks) => ks
    None => abort("ServerHello carried no key_share")
  }
}

///|
/// Server handshake-traffic write_key || write_iv, so the host can decrypt the
/// server's encrypted handshake flight before `run_handshake` re-derives and
/// verifies everything. `client_hello` / `server_hello` are the handshake
/// messages (with their 4-byte headers).
pub fn server_hs_keyiv(
  suite_u16 : Int,
  client_hello : Bytes,
  server_hello : Bytes,
  shared : Bytes,
) -> Bytes {
  let suite = suite_of(suite_u16)
  let h = suite.hash()
  let th = h.transcript_hash(concat([client_hello, server_hello]))
  let early = h.early_secret(b"")
  let hs = h.handshake_secret(early, shared)
  let s_hs = h.server_handshake_traffic_secret(hs, th)
  concat([h.write_key(s_hs, suite.key_len()), h.write_iv(s_hs)])
}

///|
/// AEAD key length (bytes) for the suite, so the host can split key||iv.
pub fn key_len(suite_u16 : Int) -> Int {
  suite_of(suite_u16).key_len()
}

///|
/// Open one TLS 1.3 record. Returns `content_type_byte || plaintext`.
pub fn open_record(
  suite_u16 : Int,
  key : Bytes,
  iv : Bytes,
  seq : Int,
  record : Bytes,
) -> Bytes {
  let suite = suite_of(suite_u16)
  let (ct, content) = @tls13.open_record(
    suite,
    key,
    iv,
    seq.to_uint64(),
    record,
  ) catch {
    e => abort("open_record: " + @debug.to_string(e))
  }
  concat([Bytes::makei(1, fn(_) { ct.to_byte() }), content])
}

///|
/// Seal one TLS 1.3 record. `content_type` is the wire byte (22 handshake, 23
/// application_data, …). Returns the full on-wire record (5-byte header + ct).
pub fn seal_record(
  suite_u16 : Int,
  key : Bytes,
  iv : Bytes,
  seq : Int,
  content_type : Int,
  content : Bytes,
) -> Bytes {
  let suite = suite_of(suite_u16)
  let ct = match content_type {
    20 => @tls13.ContentType::ChangeCipherSpec
    21 => @tls13.ContentType::Alert
    22 => @tls13.ContentType::Handshake
    23 => @tls13.ContentType::ApplicationData
    _ => abort("bad content type " + content_type.to_string())
  }
  @tls13.seal_record(suite, key, iv, seq.to_uint64(), ct, content) catch {
    e => abort("seal_record: " + @debug.to_string(e))
  }
}

///|
/// Drive the 1-RTT handshake: verifies the server CertificateVerify + Finished
/// over the transcript and returns a packed blob of, in order:
///   client_finished, client_handshake_key, client_handshake_iv,
///   client_application_key, client_application_iv,
///   server_application_key, server_application_iv.
pub fn run_handshake(
  suite_u16 : Int,
  client_hello : Bytes,
  server_hello : Bytes,
  shared : Bytes,
  server_flight : Bytes,
) -> Bytes {
  let suite = suite_of(suite_u16)
  let res = @tls13.client_handshake_1rtt(
    suite, client_hello, server_hello, shared, server_flight,
  ) catch {
    e => abort("run_handshake: " + @debug.to_string(e))
  }
  let k = res.keys
  pack([
    res.client_finished,
    k.client_handshake_key,
    k.client_handshake_iv,
    k.client_application_key,
    k.client_application_iv,
    k.server_application_key,
    k.server_application_iv,
  ])
}
