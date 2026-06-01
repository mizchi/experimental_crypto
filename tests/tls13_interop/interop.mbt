// Interop shim for live TLS 1.3 handshakes.
//
// Exposes a flat (Bytes / Int / String) API over the `tls13` client building
// blocks so a Node.js host can drive a real 1-RTT handshake over a TCP socket
// (see `tests/tls13_interop/client.mjs`). `Bytes` maps to `Uint8Array` at the
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
/// P-256 ECDHE public key (65-byte uncompressed SEC1 point) from a 32-byte
/// scalar, for a TLS 1.3 secp256r1 key share.
pub fn p256_public(priv32 : Bytes) -> Bytes {
  let sk = @p256.PrivateKey::from_bytes(priv32) catch {
    e => abort("p256_public: " + @debug.to_string(e))
  }
  sk.public_key().to_uncompressed()
}

///|
/// P-256 ECDHE shared secret: the 32-byte X coordinate of priv·peer
/// (RFC 8446 §7.4.2 — the TLS 1.3 (EC)DHE secret for secp256r1).
pub fn p256_shared(priv32 : Bytes, peer_pub : Bytes) -> Bytes {
  let sk = @p256.PrivateKey::from_bytes(priv32) catch {
    e => abort("p256_shared(sk): " + @debug.to_string(e))
  }
  let pk = @p256.PublicKey::from_uncompressed(peer_pub) catch {
    e => abort("p256_shared(pk): " + @debug.to_string(e))
  }
  sk.ecdh(pk)
}

///|
/// P-384 ECDHE public key (97-byte uncompressed point) from a 48-byte scalar.
pub fn p384_public(priv48 : Bytes) -> Bytes {
  let sk = @p384.PrivateKey::from_bytes(priv48) catch {
    e => abort("p384_public: " + @debug.to_string(e))
  }
  sk.public_key().to_uncompressed()
}

///|
/// P-384 ECDHE shared secret: the 48-byte X coordinate of priv·peer.
pub fn p384_shared(priv48 : Bytes, peer_pub : Bytes) -> Bytes {
  let sk = @p384.PrivateKey::from_bytes(priv48) catch {
    e => abort("p384_shared(sk): " + @debug.to_string(e))
  }
  let pk = @p384.PublicKey::from_uncompressed(peer_pub) catch {
    e => abort("p384_shared(pk): " + @debug.to_string(e))
  }
  sk.ecdh(pk)
}

///|
fn group_of(group_u16 : Int) -> @tls13.NamedGroup {
  match group_u16 {
    0x0017 => @tls13.NamedGroup::Secp256r1
    0x0018 => @tls13.NamedGroup::Secp384r1
    0x001d => @tls13.NamedGroup::X25519
    _ => abort("unsupported key-share group " + group_u16.to_string())
  }
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
  client_hello_group(
    0x001d, suite_u16, random32, session_id, x25519_pub, server_name,
  )
}

///|
/// Like `client_hello`, but offers the key share for an arbitrary `group_u16`
/// (0x0017 secp256r1 / 0x0018 secp384r1 / 0x001d x25519). `key_exchange` is the
/// group's wire public key (X25519: 32 bytes; NIST: uncompressed point).
pub fn client_hello_group(
  group_u16 : Int,
  suite_u16 : Int,
  random32 : Bytes,
  session_id : Bytes,
  key_exchange : Bytes,
  server_name : String,
) -> Bytes {
  let suite = suite_of(suite_u16)
  let group = group_of(group_u16)
  let offer : @tls13.KeyShareOffer = { group, key_exchange }
  let sni : String? = if server_name == "" { None } else { Some(server_name) }
  @tls13.build_client_hello(
    random32,
    session_id,
    [suite],
    [group],
    [offer],
    [
      @tls13.SignatureScheme::EcdsaSecp256r1Sha256,
      @tls13.SignatureScheme::Ed25519,
      @tls13.SignatureScheme::RsaPssRsaeSha256,
      @tls13.SignatureScheme::EcdsaSecp384r1Sha384,
    ],
    server_name=sni,
  ) catch {
    e => abort("client_hello_group: " + @debug.to_string(e))
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
  pack_keys(res)
}

///|
fn pack_keys(res : @tls13.ClientHandshakeResult) -> Bytes {
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

///|
/// Like `run_handshake`, but additionally validates the server's certificate
/// chain to `anchor_der` (a single trust-anchor CA certificate, DER) at time
/// `now` (GeneralizedTime "YYYYMMDDHHMMSSZ") and checks `hostname` against the
/// leaf's dNSName SANs. Aborts (→ JS throw) if the chain or identity fails.
pub fn run_handshake_verified(
  suite_u16 : Int,
  client_hello : Bytes,
  server_hello : Bytes,
  shared : Bytes,
  server_flight : Bytes,
  anchor_der : Bytes,
  now : String,
  hostname : String,
) -> Bytes {
  let suite = suite_of(suite_u16)
  let anchor = @pkix.parse_certificate(anchor_der) catch {
    e => abort("run_handshake_verified(anchor): " + @debug.to_string(e))
  }
  let res = @tls13.client_handshake_1rtt_verified(
    suite, client_hello, server_hello, shared, server_flight, anchor, now, hostname,
  ) catch {
    e => abort("run_handshake_verified: " + @debug.to_string(e))
  }
  pack_keys(res)
}

///|
/// Parse the server's Certificate message out of the decrypted handshake
/// `server_flight` and return the chain (leaf first) as a packed blob of DER
/// certificates. Lets the host pick the matching trust anchor from a system CA
/// bundle before calling `run_handshake_verified`.
pub fn server_chain(server_flight : Bytes) -> Bytes {
  let msgs = @tls13.parse_handshake_flight(server_flight) catch {
    e => abort("server_chain(flight): " + @debug.to_string(e))
  }
  for m in msgs {
    let (t, body) = m
    if t == @tls13.HandshakeType::Certificate {
      let chain = @tls13.parse_certificate(body) catch {
        e => abort("server_chain(cert): " + @debug.to_string(e))
      }
      return pack(chain)
    }
  }
  abort("server_chain: no Certificate message in flight")
}
