// TLS 1.3 ClientHello builder (RFC 8446 §4.1.2) and a symmetric parser. The
// builder emits a spec-compliant first flight with the mandatory TLS 1.3
// extensions (supported_versions, supported_groups, signature_algorithms,
// key_share) and an optional SNI. The caller supplies the random, the session
// id, and the key-share public keys (generated with its own ECDHE module).

// ─── little encoding helpers ─────────────────────────────────────────────

///|
fn u16_bytes(v : Int) -> Bytes {
  Bytes::makei(2, fn(i) {
    if i == 0 {
      ((v >> 8) & 0xff).to_byte()
    } else {
      (v & 0xff).to_byte()
    }
  })
}

///|
fn concat_bytes(parts : Array[Bytes]) -> Bytes {
  let total = parts.fold(init=0, fn(acc, b) { acc + b.length() })
  let out = FixedArray::make(total, b'\x00')
  let mut o = 0
  for b in parts {
    for i in 0..<b.length() {
      out[o + i] = b[i]
    }
    o = o + b.length()
  }
  Bytes::makei(total, fn(i) { out[i] })
}

///|
fn with_u8_len(body : Bytes) -> Bytes raise MessageError {
  if body.length() > 0xff {
    raise LengthMismatch("u8-length field overflow")
  }
  concat_bytes([Bytes::makei(1, fn(_) { body.length().to_byte() }), body])
}

///|
fn with_u16_len(body : Bytes) -> Bytes raise MessageError {
  if body.length() > 0xffff {
    raise LengthMismatch("u16-length field overflow")
  }
  concat_bytes([u16_bytes(body.length()), body])
}

///|
fn extension(ext_type : Int, data : Bytes) -> Bytes raise MessageError {
  concat_bytes([u16_bytes(ext_type), with_u16_len(data)])
}

// ─── builder ─────────────────────────────────────────────────────────────

///|
/// A key_share offer: the chosen group and the client's public key bytes.
pub(all) struct KeyShareOffer {
  group : NamedGroup
  key_exchange : Bytes
}

///|
/// Build a TLS 1.3 ClientHello handshake message (with its 4-byte handshake
/// header). `random` must be 32 bytes; `legacy_session_id` is 0 or 32 bytes
/// (modern clients echo a 32-byte value for middlebox compatibility).
pub fn build_client_hello(
  random : Bytes,
  legacy_session_id : Bytes,
  cipher_suites : Array[CipherSuite],
  supported_groups : Array[NamedGroup],
  key_shares : Array[KeyShareOffer],
  signature_algorithms : Array[SignatureScheme],
  server_name? : String? = None,
) -> Bytes raise MessageError {
  if random.length() != 32 {
    raise Malformed("ClientHello.random must be 32 bytes")
  }
  if legacy_session_id.length() != 0 && legacy_session_id.length() != 32 {
    raise Malformed("ClientHello.legacy_session_id must be 0 or 32 bytes")
  }

  // cipher_suites<2..2^16-2>
  let cs = concat_bytes(cipher_suites.map(fn(c) { u16_bytes(c.to_u16()) }))

  // extensions (order is not significant to a conformant server).
  let exts : Array[Bytes] = []
  match server_name {
    Some(name) => {
      let host = Bytes::makei(name.length(), fn(i) {
        (name.get_char(i).unwrap().to_int() & 0xff).to_byte()
      })
      // ServerNameList { NameType host_name(0); HostName<1..2^16-1> }
      let entry = concat_bytes([b"\x00", with_u16_len(host)])
      exts.push(extension(0x0000, with_u16_len(entry)))
    }
    None => ()
  }
  // supported_versions: list of one (TLS 1.3 = 0x0304).
  exts.push(extension(0x002b, with_u8_len(u16_bytes(0x0304))))
  // supported_groups: NamedGroupList<2..2^16-1>.
  exts.push(
    extension(
      0x000a,
      with_u16_len(
        concat_bytes(supported_groups.map(fn(g) { u16_bytes(g.to_u16()) })),
      ),
    ),
  )
  // signature_algorithms: SignatureSchemeList<2..2^16-2>.
  exts.push(
    extension(
      0x000d,
      with_u16_len(
        concat_bytes(signature_algorithms.map(fn(s) { u16_bytes(s.to_u16()) })),
      ),
    ),
  )
  // key_share: KeyShareClientHello { KeyShareEntry client_shares<0..2^16-1> }.
  let entries = concat_bytes(
    key_shares.map(fn(ks) {
      concat_bytes([u16_bytes(ks.group.to_u16()), with_u16_len(ks.key_exchange)]) catch {
        _ => abort("key_share entry overflow")
      }
    }),
  )
  exts.push(extension(0x0033, with_u16_len(entries)))

  // Assemble the body.
  let body = concat_bytes([
    u16_bytes(0x0303), // legacy_version
    random,
    with_u8_len(legacy_session_id),
    with_u16_len(cs),
    with_u8_len(b"\x00"), // legacy_compression_methods = { null }
    with_u16_len(concat_bytes(exts)),
  ])
  handshake_message(ClientHello, body)
}

// ─── parser (symmetric, for tests and a future server side) ──────────────

///|
/// The fields of a parsed ClientHello a peer cares about.
pub(all) struct ClientHello {
  legacy_version : Int
  random : Bytes
  legacy_session_id : Bytes
  cipher_suites : Array[Int]
  supported_versions : Array[Int]
  key_shares : Array[KeyShareOffer]
}

///|
/// Parse a ClientHello body (the bytes after the 4-byte handshake header).
pub fn parse_client_hello(body : Bytes) -> ClientHello raise MessageError {
  let r = Reader::new(body)
  let legacy_version = r.u16("CH.legacy_version")
  let random = r.take(32, "CH.random")
  let sid_len = r.u8("CH.legacy_session_id length")
  let legacy_session_id = r.take(sid_len, "CH.legacy_session_id")
  let cs_len = r.u16("CH.cipher_suites length")
  if cs_len % 2 != 0 {
    raise Malformed("CH.cipher_suites length not even")
  }
  let cs_data = r.take(cs_len, "CH.cipher_suites")
  let cipher_suites : Array[Int] = []
  let csr = Reader::new(cs_data)
  while !csr.is_empty() {
    cipher_suites.push(csr.u16("CH.cipher_suite"))
  }
  let comp_len = r.u8("CH.legacy_compression_methods length")
  let _ = r.take(comp_len, "CH.legacy_compression_methods")
  let ext_total = r.u16("CH.extensions length")
  if r.remaining() != ext_total {
    raise LengthMismatch("CH.extensions")
  }
  let supported_versions : Array[Int] = []
  let key_shares : Array[KeyShareOffer] = []
  while !r.is_empty() {
    let ext_type = r.u16("CH.extension type")
    let ext_len = r.u16("CH.extension length")
    let ext_data = r.take(ext_len, "CH.extension data")
    match ext_type {
      0x002b => {
        let er = Reader::new(ext_data)
        let list_len = er.u8("supported_versions list length")
        let lr = Reader::new(er.take(list_len, "supported_versions list"))
        while !lr.is_empty() {
          supported_versions.push(lr.u16("supported_versions entry"))
        }
      }
      0x0033 => {
        let er = Reader::new(ext_data)
        let list_len = er.u16("key_share list length")
        let lr = Reader::new(er.take(list_len, "key_share list"))
        while !lr.is_empty() {
          let group = NamedGroup::from_u16(lr.u16("key_share.group"))
          let ke_len = lr.u16("key_share.key_exchange length")
          let ke = lr.take(ke_len, "key_share.key_exchange")
          key_shares.push({ group, key_exchange: ke })
        }
      }
      _ => ()
    }
  }
  {
    legacy_version,
    random,
    legacy_session_id,
    cipher_suites,
    supported_versions,
    key_shares,
  }
}
