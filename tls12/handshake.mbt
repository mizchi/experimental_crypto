// TLS 1.2 handshake message framing and types (RFC 5246 §7.4).
//
// Every handshake message is `msg_type(1) || length(3) || body`. Messages are
// carried inside Handshake-type records; the transcript fed into Finished and
// the ServerKeyExchange signature is the concatenation of these framed
// messages (header included).

///|
pub(all) enum HandshakeType {
  ClientHello
  ServerHello
  NewSessionTicket
  Certificate
  ServerKeyExchange
  CertificateRequest
  ServerHelloDone
  CertificateVerify
  ClientKeyExchange
  Finished
} derive(Eq, Debug)

///|
pub fn HandshakeType::to_int(self : HandshakeType) -> Int {
  match self {
    ClientHello => 1
    ServerHello => 2
    NewSessionTicket => 4
    Certificate => 11
    ServerKeyExchange => 12
    CertificateRequest => 13
    ServerHelloDone => 14
    CertificateVerify => 15
    ClientKeyExchange => 16
    Finished => 20
  }
}

///|
pub fn HandshakeType::from_int(v : Int) -> HandshakeType? {
  match v {
    1 => Some(ClientHello)
    2 => Some(ServerHello)
    4 => Some(NewSessionTicket)
    11 => Some(Certificate)
    12 => Some(ServerKeyExchange)
    13 => Some(CertificateRequest)
    14 => Some(ServerHelloDone)
    15 => Some(CertificateVerify)
    16 => Some(ClientKeyExchange)
    20 => Some(Finished)
    _ => None
  }
}

///|
pub suberror MessageError {
  Truncated(String)
  UnknownHandshakeType(Int)
  Malformed(String)
} derive(Debug)

///|
/// Wrap a handshake `body` in its `type(1) || length(3)` header.
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
/// Parse one framed handshake message, returning its type and body. Raises if
/// the 4-byte header is missing or the declared length overruns `data`.
pub fn parse_handshake(
  data : Bytes,
) -> (HandshakeType, Bytes) raise MessageError {
  if data.length() < 4 {
    raise Truncated("handshake header")
  }
  let ty = match HandshakeType::from_int(data[0].to_int()) {
    Some(t) => t
    None => raise UnknownHandshakeType(data[0].to_int())
  }
  let len = (data[1].to_int() << 16) |
    (data[2].to_int() << 8) |
    data[3].to_int()
  if data.length() < 4 + len {
    raise Truncated("handshake body")
  }
  let body = Bytes::makei(len, fn(i) { data[4 + i] })
  (ty, body)
}
