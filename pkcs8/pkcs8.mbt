// PKCS#8 (RFC 5208 / RFC 5958) PrivateKeyInfo and EncryptedPrivateKeyInfo.
// Depends on @asn1 for primitives, @pkix for AlgorithmIdentifier, @pem for PEM I/O.

///|
pub(all) struct PrivateKeyInfo {
  version : Int // 0 (v1) or 1 (v2)
  algorithm : @pkix.AlgorithmIdentifier
  private_key : Bytes // contents of the OCTET STRING privateKey (algorithm-specific)
  attributes : Array[@asn1.Element] // [0] IMPLICIT Attributes OPTIONAL
  public_key : @asn1.BitString? // [1] IMPLICIT PublicKey, v2 only
} derive(Show)

///|
pub(all) struct EncryptedPrivateKeyInfo {
  algorithm : @pkix.AlgorithmIdentifier
  encrypted_data : Bytes
} derive(Eq, Show)

///|
pub suberror Pkcs8Error {
  Asn1(@asn1.Asn1Error)
  Pkix(@pkix.PkixError)
  Pem(@pem.PemError)
  InvalidVersion(Int)
  UnexpectedStructure(String)
} derive(Show)

///|
let label_private_key : String = "PRIVATE KEY"

///|
let label_encrypted_private_key : String = "ENCRYPTED PRIVATE KEY"

// ─── helpers ─────────────────────────────────────────────────────────────

///|
fn expect_sequence(
  elem : @asn1.Element,
) -> Array[@asn1.Element] raise Pkcs8Error {
  match elem.value {
    Sequence(items) =>
      if elem.tag == @asn1.tag_sequence {
        items
      } else {
        raise UnexpectedStructure("expected universal SEQUENCE tag")
      }
    _ => raise UnexpectedStructure("expected SEQUENCE")
  }
}

///|
fn expect_integer_small(elem : @asn1.Element) -> Int raise Pkcs8Error {
  match elem.value {
    Integer(bytes) => {
      if bytes.length() == 0 || bytes.length() > 4 {
        raise UnexpectedStructure("INTEGER out of small range")
      }
      let mut value = 0
      for i in 0..<bytes.length() {
        value = (value << 8) | bytes[i].to_int()
      }
      value
    }
    _ => raise UnexpectedStructure("expected INTEGER")
  }
}

///|
fn expect_octet_string(elem : @asn1.Element) -> Bytes raise Pkcs8Error {
  match elem.value {
    OctetString(b) => b
    _ => raise UnexpectedStructure("expected OCTET STRING")
  }
}

///|
fn parse_algorithm_identifier_elem(
  elem : @asn1.Element,
) -> @pkix.AlgorithmIdentifier raise Pkcs8Error {
  @pkix.parse_algorithm_identifier_elem(elem) catch {
    e => raise Pkix(e)
  }
}

///|
fn algorithm_identifier_to_element(
  alg : @pkix.AlgorithmIdentifier,
) -> @asn1.Element raise Pkcs8Error {
  @pkix.algorithm_identifier_to_element(alg) catch {
    e => raise Pkix(e)
  }
}

///|
fn decode_der(bytes : Bytes) -> @asn1.Element raise Pkcs8Error {
  @asn1.decode_der(bytes) catch {
    e => raise Asn1(e)
  }
}

///|
fn match_context_implicit_set(
  elem : @asn1.Element,
  number : UInt,
) -> Array[@asn1.Element]? raise Pkcs8Error {
  if elem.tag.class_ != ContextSpecific || elem.tag.number != number {
    return None
  }
  // [n] IMPLICIT SET OF Attribute: tag bits 0x80 | constructed | n.
  // The implicit replacement loses the SET tag, but the constructed bit is preserved.
  if not(elem.tag.constructed) {
    raise UnexpectedStructure(
      "[" + number.to_string() + "] IMPLICIT SET must be constructed",
    )
  }
  match elem.value {
    Unknown(raw) => {
      let inner = @asn1.Decoder::new(raw)
      let items : Array[@asn1.Element] = []
      while not(inner.is_empty()) {
        items.push(inner.read_element() catch { e => raise Asn1(e) })
      }
      Some(items)
    }
    _ =>
      raise UnexpectedStructure(
        "[" + number.to_string() + "] IMPLICIT SET missing raw payload",
      )
  }
}

///|
fn match_context_implicit_bit_string(
  elem : @asn1.Element,
  number : UInt,
) -> @asn1.BitString? raise Pkcs8Error {
  if elem.tag.class_ != ContextSpecific || elem.tag.number != number {
    return None
  }
  if elem.tag.constructed {
    raise UnexpectedStructure(
      "[" + number.to_string() + "] IMPLICIT BIT STRING must be primitive",
    )
  }
  match elem.value {
    Unknown(raw) => Some(decode_bit_string_content(raw))
    _ =>
      raise UnexpectedStructure(
        "[" + number.to_string() + "] IMPLICIT BIT STRING missing payload",
      )
  }
}

///|
fn decode_bit_string_content(b : Bytes) -> @asn1.BitString raise Pkcs8Error {
  if b.length() < 1 {
    raise UnexpectedStructure("BIT STRING content empty")
  }
  let unused_bits = b[0].to_int()
  if unused_bits > 7 {
    raise UnexpectedStructure("BIT STRING unused_bits > 7")
  }
  let bytes = Bytes::makei(b.length() - 1, fn(i) { b[i + 1] })
  { bytes, unused_bits }
}

///|
fn wrap_context_implicit_set(
  number : UInt,
  items : Array[@asn1.Element],
) -> @asn1.Element {
  // Re-serialize the items in SET order and present the raw bytes under the
  // context tag. We do NOT enforce DER SET ordering here; attributes round-trip
  // bit-for-bit because we preserve the input order.
  let enc = @asn1.Encoder::new()
  for item in items {
    enc.write_element(item)
  }
  @asn1.Element::new(
    @asn1.Tag::context(number, constructed=true),
    Unknown(enc.finish()),
  )
}

///|
fn wrap_context_implicit_bit_string(
  number : UInt,
  bs : @asn1.BitString,
) -> @asn1.Element {
  let buf = Buffer()
  buf.write_byte(bs.unused_bits.to_byte())
  buf.write_bytes(bs.bytes)
  @asn1.Element::new(@asn1.Tag::context(number), Unknown(buf.to_bytes()))
}

// ─── PrivateKeyInfo ──────────────────────────────────────────────────────

///|
pub fn parse_der(der : Bytes) -> PrivateKeyInfo raise Pkcs8Error {
  let elem = decode_der(der)
  let items = expect_sequence(elem)
  if items.length() < 3 {
    raise UnexpectedStructure("PrivateKeyInfo: too few fields")
  }
  let version = expect_integer_small(items[0])
  if version != 0 && version != 1 {
    raise InvalidVersion(version)
  }
  let algorithm = parse_algorithm_identifier_elem(items[1])
  let private_key = expect_octet_string(items[2])
  let mut attributes : Array[@asn1.Element] = []
  let mut public_key : @asn1.BitString? = None
  let mut i = 3
  while i < items.length() {
    let item = items[i]
    match match_context_implicit_set(item, 0U) {
      Some(attrs) => {
        attributes = attrs
        i = i + 1
        continue
      }
      None => ()
    }
    match match_context_implicit_bit_string(item, 1U) {
      Some(bs) => {
        if version < 1 {
          raise UnexpectedStructure("[1] publicKey requires v2 (version=1)")
        }
        public_key = Some(bs)
        i = i + 1
        continue
      }
      None => ()
    }
    raise UnexpectedStructure("unrecognized PrivateKeyInfo field")
  }
  { version, algorithm, private_key, attributes, public_key }
}

///|
pub fn serialize_der(info : PrivateKeyInfo) -> Bytes {
  serialize_der_checked(info) catch {
    _ => abort("serialize_der: invalid AlgorithmIdentifier")
  }
}

///|
fn serialize_der_checked(info : PrivateKeyInfo) -> Bytes raise Pkcs8Error {
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(
      @asn1.tag_integer,
      Integer(int_to_be_minimal(info.version)),
    ),
    algorithm_identifier_to_element(info.algorithm),
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(info.private_key)),
  ]
  if info.attributes.length() > 0 {
    items.push(wrap_context_implicit_set(0U, info.attributes))
  }
  match info.public_key {
    Some(bs) => items.push(wrap_context_implicit_bit_string(1U, bs))
    None => ()
  }
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence(items)))
}

///|
fn int_to_be_minimal(value : Int) -> Bytes {
  if value == 0 {
    return b"\x00"
  }
  let bytes_be : Array[Int] = []
  let mut tmp = value
  while tmp != 0 && tmp != -1 {
    bytes_be.push(tmp & 0xFF)
    tmp = tmp >> 8
  }
  if bytes_be.length() == 0 {
    bytes_be.push(if value < 0 { 0xFF } else { 0x00 })
  }
  let top = bytes_be[bytes_be.length() - 1]
  if value >= 0 && (top & 0x80) != 0 {
    bytes_be.push(0)
  } else if value < 0 && (top & 0x80) == 0 {
    bytes_be.push(0xFF)
  }
  let buf = Buffer()
  for i = bytes_be.length() - 1; i >= 0; i = i - 1 {
    buf.write_byte(bytes_be[i].to_byte())
  }
  buf.to_bytes()
}

// ─── EncryptedPrivateKeyInfo ─────────────────────────────────────────────

///|
pub fn parse_encrypted_der(
  der : Bytes,
) -> EncryptedPrivateKeyInfo raise Pkcs8Error {
  let elem = decode_der(der)
  let items = expect_sequence(elem)
  if items.length() != 2 {
    raise UnexpectedStructure("EncryptedPrivateKeyInfo arity")
  }
  {
    algorithm: parse_algorithm_identifier_elem(items[0]),
    encrypted_data: expect_octet_string(items[1]),
  }
}

///|
pub fn serialize_encrypted_der(enc : EncryptedPrivateKeyInfo) -> Bytes {
  serialize_encrypted_der_checked(enc) catch {
    _ => abort("serialize_encrypted_der: invalid AlgorithmIdentifier")
  }
}

///|
fn serialize_encrypted_der_checked(
  enc : EncryptedPrivateKeyInfo,
) -> Bytes raise Pkcs8Error {
  let items : Array[@asn1.Element] = [
    algorithm_identifier_to_element(enc.algorithm),
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(enc.encrypted_data)),
  ]
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence(items)))
}

// ─── PEM convenience wrappers ────────────────────────────────────────────

///|
pub fn parse_pem(pem_str : String) -> PrivateKeyInfo raise Pkcs8Error {
  let block = @pem.decode(pem_str) catch { e => raise Pem(e) }
  if block.label != label_private_key {
    raise UnexpectedStructure(
      "expected '" +
      label_private_key +
      "' PEM label, got '" +
      block.label +
      "'",
    )
  }
  parse_der(block.data)
}

///|
pub fn serialize_pem(info : PrivateKeyInfo) -> String {
  @pem.encode_simple(label_private_key, serialize_der(info))
}

///|
pub fn parse_encrypted_pem(
  pem_str : String,
) -> EncryptedPrivateKeyInfo raise Pkcs8Error {
  let block = @pem.decode(pem_str) catch { e => raise Pem(e) }
  if block.label != label_encrypted_private_key {
    raise UnexpectedStructure(
      "expected '" +
      label_encrypted_private_key +
      "' PEM label, got '" +
      block.label +
      "'",
    )
  }
  parse_encrypted_der(block.data)
}

///|
pub fn serialize_encrypted_pem(enc : EncryptedPrivateKeyInfo) -> String {
  @pem.encode_simple(label_encrypted_private_key, serialize_encrypted_der(enc))
}
