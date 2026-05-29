// Parsers for the TLS 1.3 server flight messages (RFC 8446 §4): ServerHello,
// Certificate, and CertificateVerify. These extract exactly the fields a client
// needs to continue the handshake (selected suite, server key share, the
// certificate chain, the CertificateVerify signature) and fail closed on any
// length mismatch, trailing data, or unsupported shape.

///|
pub suberror MessageError {
  // Ran off the end of a length-prefixed field or the buffer.
  Truncated(String)
  // A length prefix did not match the bytes that followed / trailing data.
  LengthMismatch(String)
  // A required field had an unexpected fixed value (e.g. compression != 0).
  Malformed(String)
} derive(Debug)

// ─── byte reader ─────────────────────────────────────────────────────────

///|
priv struct Reader {
  buf : Bytes
  mut pos : Int
}

///|
fn Reader::new(buf : Bytes) -> Reader {
  { buf, pos: 0 }
}

///|
fn Reader::remaining(self : Reader) -> Int {
  self.buf.length() - self.pos
}

///|
fn Reader::is_empty(self : Reader) -> Bool {
  self.pos >= self.buf.length()
}

///|
fn Reader::u8(self : Reader, what : String) -> Int raise MessageError {
  if self.remaining() < 1 {
    raise Truncated(what)
  }
  let v = self.buf[self.pos].to_int()
  self.pos = self.pos + 1
  v
}

///|
fn Reader::u16(self : Reader, what : String) -> Int raise MessageError {
  if self.remaining() < 2 {
    raise Truncated(what)
  }
  let v = (self.buf[self.pos].to_int() << 8) | self.buf[self.pos + 1].to_int()
  self.pos = self.pos + 2
  v
}

///|
fn Reader::u24(self : Reader, what : String) -> Int raise MessageError {
  if self.remaining() < 3 {
    raise Truncated(what)
  }
  let v = (self.buf[self.pos].to_int() << 16) |
    (self.buf[self.pos + 1].to_int() << 8) |
    self.buf[self.pos + 2].to_int()
  self.pos = self.pos + 3
  v
}

///|
fn Reader::take(
  self : Reader,
  n : Int,
  what : String,
) -> Bytes raise MessageError {
  if n < 0 || self.remaining() < n {
    raise Truncated(what)
  }
  let start = self.pos
  let out = Bytes::makei(n, fn(i) { self.buf[start + i] })
  self.pos = self.pos + n
  out
}

// ─── named groups / signature schemes ────────────────────────────────────

///|
/// TLS 1.3 `NamedGroup` (RFC 8446 §4.2.7) for key shares.
pub(all) enum NamedGroup {
  Secp256r1
  Secp384r1
  Secp521r1
  X25519
  X448
  Unknown(Int)
} derive(Eq, Debug)

///|
fn NamedGroup::from_u16(v : Int) -> NamedGroup {
  match v {
    0x0017 => Secp256r1
    0x0018 => Secp384r1
    0x0019 => Secp521r1
    0x001d => X25519
    0x001e => X448
    _ => Unknown(v)
  }
}

///|
/// TLS 1.3 `SignatureScheme` (RFC 8446 §4.2.3) used in CertificateVerify.
pub(all) enum SignatureScheme {
  RsaPkcs1Sha256
  RsaPkcs1Sha384
  RsaPkcs1Sha512
  EcdsaSecp256r1Sha256
  EcdsaSecp384r1Sha384
  EcdsaSecp521r1Sha512
  RsaPssRsaeSha256
  RsaPssRsaeSha384
  RsaPssRsaeSha512
  Ed25519
  Ed448
  Unknown(Int)
} derive(Eq, Debug)

///|
fn SignatureScheme::from_u16(v : Int) -> SignatureScheme {
  match v {
    0x0401 => RsaPkcs1Sha256
    0x0501 => RsaPkcs1Sha384
    0x0601 => RsaPkcs1Sha512
    0x0403 => EcdsaSecp256r1Sha256
    0x0503 => EcdsaSecp384r1Sha384
    0x0603 => EcdsaSecp521r1Sha512
    0x0804 => RsaPssRsaeSha256
    0x0805 => RsaPssRsaeSha384
    0x0806 => RsaPssRsaeSha512
    0x0807 => Ed25519
    0x0808 => Ed448
    _ => Unknown(v)
  }
}

// ─── ServerHello (RFC 8446 §4.1.3) ───────────────────────────────────────

///|
// HelloRetryRequest is signalled by this special ServerHello.random value
// (RFC 8446 §4.1.3); we surface it rather than treating it as a normal SH.
let hello_retry_request_random : Bytes = b"\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c"

///|
/// Parsed ServerHello fields a client needs (RFC 8446 §4.1.3).
pub(all) struct ServerHello {
  legacy_version : Int
  random : Bytes
  is_hello_retry_request : Bool
  cipher_suite : Int
  // selected_version from the supported_versions extension (0x0304 for 1.3).
  selected_version : Int?
  // The server's key_share: chosen group + its key_exchange bytes.
  key_share_group : NamedGroup?
  key_share : Bytes?
}

///|
/// Parse a ServerHello body (the bytes after the 4-byte handshake header).
pub fn parse_server_hello(body : Bytes) -> ServerHello raise MessageError {
  let r = Reader::new(body)
  let legacy_version = r.u16("SH.legacy_version")
  let random = r.take(32, "SH.random")
  let is_hrr = random == hello_retry_request_random
  let sid_len = r.u8("SH.legacy_session_id_echo length")
  let _ = r.take(sid_len, "SH.legacy_session_id_echo")
  let cipher_suite = r.u16("SH.cipher_suite")
  let compression = r.u8("SH.legacy_compression_method")
  if compression != 0 {
    raise Malformed("SH.legacy_compression_method must be 0")
  }
  let ext_total = r.u16("SH.extensions length")
  if r.remaining() != ext_total {
    raise LengthMismatch("SH.extensions")
  }
  let mut selected_version : Int? = None
  let mut key_share_group : NamedGroup? = None
  let mut key_share : Bytes? = None
  while !r.is_empty() {
    let ext_type = r.u16("SH.extension type")
    let ext_len = r.u16("SH.extension length")
    let ext_data = r.take(ext_len, "SH.extension data")
    match ext_type {
      // supported_versions: selected_version (2 bytes) in a ServerHello.
      0x002b => {
        let er = Reader::new(ext_data)
        selected_version = Some(er.u16("supported_versions.selected"))
        if !er.is_empty() {
          raise LengthMismatch("supported_versions")
        }
      }
      // key_share: a single KeyShareEntry { group, key_exchange<1..2^16-1> }.
      0x0033 => {
        let er = Reader::new(ext_data)
        let group = NamedGroup::from_u16(er.u16("key_share.group"))
        let ke_len = er.u16("key_share.key_exchange length")
        let ke = er.take(ke_len, "key_share.key_exchange")
        if !er.is_empty() {
          raise LengthMismatch("key_share")
        }
        key_share_group = Some(group)
        key_share = Some(ke)
      }
      _ => ()
    }
  }
  {
    legacy_version,
    random,
    is_hello_retry_request: is_hrr,
    cipher_suite,
    selected_version,
    key_share_group,
    key_share,
  }
}

// ─── Certificate (RFC 8446 §4.4.2) ───────────────────────────────────────

///|
/// Parse a Certificate body and return the chain as a list of DER blobs, leaf
/// first. The per-entry extensions are skipped. Raises if the
/// certificate_request_context is non-empty (unexpected in a server
/// Certificate for a full handshake).
pub fn parse_certificate(body : Bytes) -> Array[Bytes] raise MessageError {
  let r = Reader::new(body)
  let ctx_len = r.u8("Certificate.certificate_request_context length")
  // RFC 8446 §4.4.2: in server authentication this context SHALL be empty.
  if ctx_len != 0 {
    raise Malformed("Certificate.certificate_request_context must be empty")
  }
  let list_len = r.u24("Certificate.certificate_list length")
  if r.remaining() != list_len {
    raise LengthMismatch("Certificate.certificate_list")
  }
  let certs : Array[Bytes] = []
  while !r.is_empty() {
    let cert_len = r.u24("CertificateEntry.cert_data length")
    let cert = r.take(cert_len, "CertificateEntry.cert_data")
    let ext_len = r.u16("CertificateEntry.extensions length")
    let _ = r.take(ext_len, "CertificateEntry.extensions")
    certs.push(cert)
  }
  certs
}

// ─── CertificateVerify (RFC 8446 §4.4.3) ─────────────────────────────────

///|
/// Parsed CertificateVerify: the signature scheme and the raw signature.
pub(all) struct CertificateVerify {
  scheme : SignatureScheme
  signature : Bytes
}

///|
/// Parse a CertificateVerify body: SignatureScheme(2) || signature<0..2^16-1>.
pub fn parse_certificate_verify(
  body : Bytes,
) -> CertificateVerify raise MessageError {
  let r = Reader::new(body)
  let scheme = SignatureScheme::from_u16(r.u16("CertificateVerify.algorithm"))
  let sig_len = r.u16("CertificateVerify.signature length")
  let signature = r.take(sig_len, "CertificateVerify.signature")
  if !r.is_empty() {
    raise LengthMismatch("CertificateVerify trailing data")
  }
  { scheme, signature }
}
