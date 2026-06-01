// TLS 1.2 handshake message bodies (RFC 5246 §7.4, RFC 4492 / RFC 8422 for the
// ECC extensions and ServerKeyExchange). Covers the messages a 1-RTT ECDHE
// client needs: ClientHello (build), ServerHello / Certificate /
// ServerKeyExchange / ServerHelloDone (parse), ClientKeyExchange (build).

// ─── named constants ───────────────────────────────────────────────────────

///|
/// Cipher suites this client offers / understands (all ECDHE + AEAD).
pub(all) enum CipherSuite {
  EcdheEcdsaAes128GcmSha256
  EcdheRsaAes128GcmSha256
  EcdheEcdsaAes256GcmSha384
  EcdheRsaAes256GcmSha384
} derive(Eq, Debug)

///|
pub fn CipherSuite::to_u16(self : CipherSuite) -> Int {
  match self {
    EcdheEcdsaAes128GcmSha256 => 0xc02b
    EcdheRsaAes128GcmSha256 => 0xc02f
    EcdheEcdsaAes256GcmSha384 => 0xc02c
    EcdheRsaAes256GcmSha384 => 0xc030
  }
}

///|
pub fn CipherSuite::from_u16(v : Int) -> CipherSuite? {
  match v {
    0xc02b => Some(EcdheEcdsaAes128GcmSha256)
    0xc02f => Some(EcdheRsaAes128GcmSha256)
    0xc02c => Some(EcdheEcdsaAes256GcmSha384)
    0xc030 => Some(EcdheRsaAes256GcmSha384)
    _ => None
  }
}

///|
/// The PRF / transcript hash this suite uses.
pub fn CipherSuite::prf_hash(self : CipherSuite) -> PrfHash {
  match self {
    EcdheEcdsaAes128GcmSha256 | EcdheRsaAes128GcmSha256 => Sha256
    EcdheEcdsaAes256GcmSha384 | EcdheRsaAes256GcmSha384 => Sha384
  }
}

///|
/// The AEAD this suite uses for the record layer.
pub fn CipherSuite::aead(self : CipherSuite) -> @aead.Algorithm {
  match self {
    EcdheEcdsaAes128GcmSha256 | EcdheRsaAes128GcmSha256 => @aead.Aes128Gcm
    EcdheEcdsaAes256GcmSha384 | EcdheRsaAes256GcmSha384 => @aead.Aes256Gcm
  }
}

///|
/// Named groups (supported_groups / ECDHE). Values per the IANA registry.
pub let group_x25519 : Int = 0x001d

///|
pub let group_secp256r1 : Int = 0x0017

///|
pub let group_secp384r1 : Int = 0x0018

///|
/// SignatureAndHashAlgorithm code points used in signature_algorithms and in
/// the ServerKeyExchange signature (RFC 5246 §7.4.1.4.1, RFC 8422).
pub let sig_ecdsa_secp256r1_sha256 : Int = 0x0403

///|
pub let sig_ecdsa_secp384r1_sha384 : Int = 0x0503

///|
pub let sig_rsa_pkcs1_sha256 : Int = 0x0401

///|
pub let sig_rsa_pkcs1_sha384 : Int = 0x0501

///|
pub let sig_ed25519 : Int = 0x0807

// ─── byte reader ────────────────────────────────────────────────────────────

///|
priv struct Reader {
  data : Bytes
  mut pos : Int
}

///|
fn Reader::new(data : Bytes) -> Reader {
  { data, pos: 0 }
}

///|
fn Reader::remaining(self : Reader) -> Int {
  self.data.length() - self.pos
}

///|
fn Reader::u8(self : Reader, what : String) -> Int raise MessageError {
  if self.remaining() < 1 {
    raise Truncated(what)
  }
  let v = self.data[self.pos].to_int()
  self.pos += 1
  v
}

///|
fn Reader::u16(self : Reader, what : String) -> Int raise MessageError {
  (self.u8(what) << 8) | self.u8(what)
}

///|
fn Reader::u24(self : Reader, what : String) -> Int raise MessageError {
  (self.u8(what) << 16) | (self.u8(what) << 8) | self.u8(what)
}

///|
fn Reader::take(
  self : Reader,
  n : Int,
  what : String,
) -> Bytes raise MessageError {
  if self.remaining() < n {
    raise Truncated(what)
  }
  let start = self.pos
  self.pos += n
  Bytes::makei(n, fn(i) { self.data[start + i] })
}

// ─── byte writer helpers ─────────────────────────────────────────────────────

///|
fn concat_all(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for p in parts {
    total += p.length()
  }
  let out = FixedArray::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i = 0; i < p.length(); i = i + 1 {
      out[off + i] = p[i]
    }
    off += p.length()
  }
  Bytes::makei(total, fn(i) { out[i] })
}

///|
fn u16b(v : Int) -> Bytes {
  Bytes::makei(2, fn(i) {
    if i == 0 {
      ((v >> 8) & 0xff).to_byte()
    } else {
      (v & 0xff).to_byte()
    }
  })
}

// ─── ClientHello ─────────────────────────────────────────────────────────────

///|
/// Build the ClientHello body (without the handshake header — wrap with
/// `handshake_message(ClientHello, ...)`). Offers the given cipher suites and
/// supported groups, advertises a fixed set of signature algorithms, and sets
/// SNI to `server_name` when non-empty.
///
/// `client_random` must be 32 bytes; `session_id` may be empty.
pub fn build_client_hello(
  client_random : Bytes,
  cipher_suites : Array[CipherSuite],
  groups : Array[Int],
  server_name : String,
) -> Bytes raise MessageError {
  if client_random.length() != 32 {
    raise Malformed("client_random must be 32 bytes")
  }
  let cs_bytes = concat_all(cipher_suites.map(fn(c) { u16b(c.to_u16()) }))
  let groups_list = concat_all(groups.map(fn(g) { u16b(g) }))
  // extensions ----------------------------------------------------------------
  let exts : Array[Bytes] = []
  // supported_groups (10)
  exts.push(
    concat_all([
      u16b(10),
      u16b(groups_list.length() + 2),
      u16b(groups_list.length()),
      groups_list,
    ]),
  )
  // ec_point_formats (11): uncompressed only
  exts.push(concat_all([u16b(11), u16b(2), b"\x01\x00"]))
  // signature_algorithms (13)
  let sigs = concat_all(
    [
      sig_ecdsa_secp256r1_sha256, sig_ecdsa_secp384r1_sha384, sig_rsa_pkcs1_sha256,
      sig_rsa_pkcs1_sha384, sig_ed25519,
    ].map(fn(s) { u16b(s) }),
  )
  exts.push(
    concat_all([u16b(13), u16b(sigs.length() + 2), u16b(sigs.length()), sigs]),
  )
  // server_name (0)
  if server_name.length() > 0 {
    let host = Bytes::makei(server_name.length(), fn(i) {
      (server_name.get_char(i).unwrap().to_int() & 0xff).to_byte()
    })
    let sni_list = concat_all([b"\x00", u16b(host.length()), host])
    exts.push(
      concat_all([
        u16b(0),
        u16b(sni_list.length() + 2),
        u16b(sni_list.length()),
        sni_list,
      ]),
    )
  }
  let ext_bytes = concat_all(exts)
  concat_all([
    b"\x03\x03", // client_version = TLS 1.2
    client_random,
    b"\x00", // session_id length 0
    u16b(cs_bytes.length()),
    cs_bytes,
    b"\x01\x00", // compression_methods: 1 method, null
    u16b(ext_bytes.length()),
    ext_bytes,
  ])
}

// ─── ServerHello ─────────────────────────────────────────────────────────────

///|
pub struct ServerHello {
  server_random : Bytes
  session_id : Bytes
  cipher_suite : CipherSuite
}

///|
pub fn ServerHello::random(self : ServerHello) -> Bytes {
  self.server_random
}

///|
pub fn ServerHello::cipher_suite(self : ServerHello) -> CipherSuite {
  self.cipher_suite
}

///|
/// Parse a ServerHello body. Rejects a non-TLS-1.2 version or an unsupported
/// cipher suite.
pub fn parse_server_hello(body : Bytes) -> ServerHello raise MessageError {
  let r = Reader::new(body)
  let ver = r.u16("server_version")
  if ver != 0x0303 {
    raise Malformed("ServerHello version is not TLS 1.2")
  }
  let server_random = r.take(32, "server_random")
  let sid_len = r.u8("session_id length")
  let session_id = r.take(sid_len, "session_id")
  let cs = r.u16("cipher_suite")
  let cipher_suite = match CipherSuite::from_u16(cs) {
    Some(s) => s
    None => raise Malformed("unsupported cipher suite 0x" + cs.to_string())
  }
  let _compression = r.u8("compression_method")
  // Trailing extensions are ignored for our 1-RTT ECDHE needs.
  { server_random, session_id, cipher_suite }
}

// ─── Certificate ─────────────────────────────────────────────────────────────

///|
/// Parse a Certificate body into the ordered list of DER certificates
/// (leaf first), per RFC 5246 §7.4.2.
pub fn parse_certificate(body : Bytes) -> Array[Bytes] raise MessageError {
  let r = Reader::new(body)
  let total = r.u24("certificate_list length")
  if total != r.remaining() {
    raise Malformed("Certificate list length mismatch")
  }
  let certs : Array[Bytes] = []
  while r.remaining() > 0 {
    let clen = r.u24("certificate length")
    certs.push(r.take(clen, "certificate"))
  }
  certs
}

// ─── ServerKeyExchange ───────────────────────────────────────────────────────

///|
/// Parsed ECDHE ServerKeyExchange (RFC 4492 §5.4). `params_raw` is the
/// ServerECDHParams byte range (curve_type .. public_key) exactly as it
/// appeared on the wire; the signature covers
/// `client_random || server_random || params_raw`.
pub struct ServerKeyExchange {
  named_group : Int
  public_key : Bytes
  sig_scheme : Int
  signature : Bytes
  params_raw : Bytes
}

///|
pub fn ServerKeyExchange::named_group(self : ServerKeyExchange) -> Int {
  self.named_group
}

///|
pub fn ServerKeyExchange::public_key(self : ServerKeyExchange) -> Bytes {
  self.public_key
}

///|
pub fn ServerKeyExchange::sig_scheme(self : ServerKeyExchange) -> Int {
  self.sig_scheme
}

///|
pub fn ServerKeyExchange::signature(self : ServerKeyExchange) -> Bytes {
  self.signature
}

///|
/// The exact bytes the server signed, given the two 32-byte randoms:
/// `client_random || server_random || ServerECDHParams`.
pub fn ServerKeyExchange::signed_material(
  self : ServerKeyExchange,
  client_random : Bytes,
  server_random : Bytes,
) -> Bytes {
  concat_all([client_random, server_random, self.params_raw])
}

///|
/// Parse an ECDHE ServerKeyExchange body. Only `curve_type == named_curve (3)`
/// is supported.
pub fn parse_server_key_exchange(
  body : Bytes,
) -> ServerKeyExchange raise MessageError {
  let r = Reader::new(body)
  let curve_type = r.u8("ECParameters curve_type")
  if curve_type != 3 {
    raise Malformed("only named_curve ServerKeyExchange is supported")
  }
  let named_group = r.u16("named_curve")
  let pk_len = r.u8("ECPoint length")
  let public_key = r.take(pk_len, "ECPoint")
  // ServerECDHParams = the bytes consumed so far (curve_type .. public_key).
  let params_len = 1 + 2 + 1 + pk_len
  let params_raw = Bytes::makei(params_len, fn(i) { body[i] })
  let sig_scheme = r.u16("SignatureAndHashAlgorithm")
  let sig_len = r.u16("signature length")
  let signature = r.take(sig_len, "signature")
  { named_group, public_key, sig_scheme, signature, params_raw }
}

// ─── ServerHelloDone ─────────────────────────────────────────────────────────

///|
/// Validate a ServerHelloDone body (must be empty).
pub fn parse_server_hello_done(body : Bytes) -> Unit raise MessageError {
  if body.length() != 0 {
    raise Malformed("ServerHelloDone must be empty")
  }
}

// ─── ClientKeyExchange ───────────────────────────────────────────────────────

///|
/// Build an ECDHE ClientKeyExchange body: `len(1) || ECPoint`. Wrap with
/// `handshake_message(ClientKeyExchange, ...)`.
pub fn build_client_key_exchange(public_key : Bytes) -> Bytes {
  concat_all([
    Bytes::makei(1, fn(_i) { public_key.length().to_byte() }),
    public_key,
  ])
}
