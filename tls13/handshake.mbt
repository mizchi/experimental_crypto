// TLS 1.3 handshake message framing and the authentication-critical Finished /
// CertificateVerify helpers (RFC 8446 §4). Parsing the individual message
// bodies (ClientHello/ServerHello extensions, the certificate list, …) and the
// client state machine build on these; this file provides the framing plus the
// two verify-side primitives that actually authenticate the peer.

///|
/// Handshake message type (RFC 8446 §4, HandshakeType).
pub(all) enum HandshakeType {
  ClientHello
  ServerHello
  NewSessionTicket
  EndOfEarlyData
  EncryptedExtensions
  Certificate
  CertificateRequest
  CertificateVerify
  Finished
  KeyUpdate
  MessageHash
} derive(Eq, Debug)

///|
pub fn HandshakeType::to_int(self : HandshakeType) -> Int {
  match self {
    ClientHello => 1
    ServerHello => 2
    NewSessionTicket => 4
    EndOfEarlyData => 5
    EncryptedExtensions => 8
    Certificate => 11
    CertificateRequest => 13
    CertificateVerify => 15
    Finished => 20
    KeyUpdate => 24
    MessageHash => 254
  }
}

///|
fn HandshakeType::from_int(v : Int) -> HandshakeType? {
  match v {
    1 => Some(ClientHello)
    2 => Some(ServerHello)
    4 => Some(NewSessionTicket)
    5 => Some(EndOfEarlyData)
    8 => Some(EncryptedExtensions)
    11 => Some(Certificate)
    13 => Some(CertificateRequest)
    15 => Some(CertificateVerify)
    20 => Some(Finished)
    24 => Some(KeyUpdate)
    254 => Some(MessageHash)
    _ => None
  }
}

///|
pub suberror HandshakeError {
  // Buffer ended inside a handshake header or body.
  Truncated
  // msg_type byte is not a known HandshakeType.
  UnknownType(Int)
  // verify_finished was given a message that is not a Finished, or whose MAC
  // length does not match the suite hash.
  NotFinished
} derive(Debug)

///|
/// Wrap a handshake body in its framing: `msg_type(1) || uint24(length) || body`.
pub fn handshake_message(msg_type : HandshakeType, body : Bytes) -> Bytes {
  let len = body.length()
  Bytes::makei(4 + len, fn(i) {
    match i {
      0 => msg_type.to_int().to_byte()
      1 => ((len >> 16) & 0xff).to_byte()
      2 => ((len >> 8) & 0xff).to_byte()
      3 => (len & 0xff).to_byte()
      _ => body[i - 4]
    }
  })
}

///|
/// Parse one handshake message from the front of `buf`. Returns the type, the
/// body, and the number of bytes consumed (4 + body length). Use the returned
/// offset to walk a coalesced flight of several messages.
pub fn parse_handshake(
  buf : Bytes,
  offset? : Int = 0,
) -> (HandshakeType, Bytes, Int) raise HandshakeError {
  if offset < 0 || buf.length() - offset < 4 {
    raise Truncated
  }
  let msg_type = match HandshakeType::from_int(buf[offset].to_int()) {
    Some(t) => t
    None => raise UnknownType(buf[offset].to_int())
  }
  let len = (buf[offset + 1].to_int() << 16) |
    (buf[offset + 2].to_int() << 8) |
    buf[offset + 3].to_int()
  if buf.length() - offset - 4 < len {
    raise Truncated
  }
  let body = Bytes::makei(len, fn(i) { buf[offset + 4 + i] })
  (msg_type, body, 4 + len)
}

///|
/// Parse a coalesced flight of handshake messages, consuming the whole buffer.
pub fn parse_handshake_flight(
  buf : Bytes,
) -> Array[(HandshakeType, Bytes)] raise HandshakeError {
  let out : Array[(HandshakeType, Bytes)] = []
  let mut off = 0
  while off < buf.length() {
    let (t, body, consumed) = parse_handshake(buf, offset=off)
    out.push((t, body))
    off = off + consumed
  }
  out
}

// ─── Finished (RFC 8446 §4.4.4) ──────────────────────────────────────────

///|
/// Finished verify_data = HMAC(finished_key, Transcript-Hash(handshake context)),
/// where finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length)
/// and `base_key` is the {client,server} handshake traffic secret. `transcript`
/// is the already-computed Transcript-Hash over the messages up to (but not
/// including) this Finished.
pub fn finished_mac(
  suite : CipherSuite,
  base_key : Bytes,
  transcript : Bytes,
) -> Bytes {
  let h = suite.hash()
  h.hmac(h.finished_key(base_key), transcript)
}

///|
/// Build a Finished handshake message (framing + verify_data) for `base_key`.
pub fn build_finished(
  suite : CipherSuite,
  base_key : Bytes,
  transcript : Bytes,
) -> Bytes {
  handshake_message(Finished, finished_mac(suite, base_key, transcript))
}

///|
/// Verify a peer's Finished message. Recomputes the expected verify_data and
/// compares it to the message body in constant time. Returns `true` iff the
/// message is a well-formed Finished whose MAC matches; raises `NotFinished`
/// for a non-Finished message or a body of the wrong length.
pub fn verify_finished(
  suite : CipherSuite,
  base_key : Bytes,
  transcript : Bytes,
  finished_msg : Bytes,
) -> Bool raise HandshakeError {
  let (msg_type, body, consumed) = parse_handshake(finished_msg) catch {
    _ => raise NotFinished
  }
  if msg_type != Finished || consumed != finished_msg.length() {
    raise NotFinished
  }
  let expected = finished_mac(suite, base_key, transcript)
  if body.length() != expected.length() {
    raise NotFinished
  }
  @hash.ct_eq(body, expected)
}

// ─── CertificateVerify (RFC 8446 §4.4.3) ─────────────────────────────────

///|
/// Context string signed in the server's CertificateVerify.
pub let server_certificate_verify_context : String = "TLS 1.3, server CertificateVerify"

///|
/// Context string signed in the client's CertificateVerify.
pub let client_certificate_verify_context : String = "TLS 1.3, client CertificateVerify"

///|
/// The content covered by a CertificateVerify signature (RFC 8446 §4.4.3):
///
/// ```text
/// 0x20 repeated 64 times || context_string || 0x00 || Transcript-Hash
/// ```
///
/// `transcript` is the Transcript-Hash over the handshake messages up to (but
/// not including) this CertificateVerify. Pass `transcript` already hashed; the
/// returned bytes are what the peer's signature must verify over.
pub fn certificate_verify_content(
  context : String,
  transcript : Bytes,
) -> Bytes {
  let ctx = Buffer()
  for c in context {
    ctx.write_byte((c.to_int() & 0xff).to_byte())
  }
  let ctx_bytes = ctx.to_bytes()
  let prefix_len = 64
  let total = prefix_len + ctx_bytes.length() + 1 + transcript.length()
  Bytes::makei(total, fn(i) {
    if i < prefix_len {
      b'\x20'
    } else if i < prefix_len + ctx_bytes.length() {
      ctx_bytes[i - prefix_len]
    } else if i == prefix_len + ctx_bytes.length() {
      b'\x00'
    } else {
      transcript[i - prefix_len - ctx_bytes.length() - 1]
    }
  })
}
