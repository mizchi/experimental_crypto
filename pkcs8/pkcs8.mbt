// PKCS#8 (RFC 5208 / RFC 5958) PrivateKeyInfo and EncryptedPrivateKeyInfo.
// Depends on @asn1 for primitives, @pkix for AlgorithmIdentifier, @pem for PEM I/O.

///|
pub(all) struct PrivateKeyInfo {
  version : Int // 0 (v1) or 1 (v2)
  algorithm : @pkix.AlgorithmIdentifier
  private_key : Bytes // contents of the OCTET STRING privateKey (algorithm-specific)
  attributes : Array[@asn1.Element] // [0] IMPLICIT Attributes OPTIONAL
  public_key : @asn1.BitString? // [1] IMPLICIT PublicKey, v2 only
} derive(Debug)

///|
pub(all) struct EncryptedPrivateKeyInfo {
  algorithm : @pkix.AlgorithmIdentifier
  encrypted_data : Bytes
} derive(Eq, Debug)

///|
pub suberror Pkcs8Error {
  Asn1(@asn1.Asn1Error)
  Pkix(@pkix.PkixError)
  Pem(@pem.PemError)
  InvalidVersion(Int)
  UnexpectedStructure(String)
  // PBES2 (RFC 8018) decryption errors. See pbes2.mbt.
  UnsupportedKdf(@asn1.ObjectIdentifier)
  UnsupportedCipher(@asn1.ObjectIdentifier)
  InvalidPadding
  Pbkdf2(@pbkdf2.Pbkdf2Error)
  Scrypt(@scrypt.ScryptError)
  Aead(@aead.AeadError)
} derive(Debug)

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
      if (bytes[0].to_int() & 0x80) != 0 {
        raise UnexpectedStructure("INTEGER is negative; expected non-negative")
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
fn reject_pem_headers(block : @pem.PemBlock) -> Unit raise Pkcs8Error {
  if block.headers.length() > 0 {
    raise UnexpectedStructure("PKCS#8 PEM must not contain legacy headers")
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
  if !elem.tag.constructed {
    raise UnexpectedStructure(
      "[" + number.to_string() + "] IMPLICIT SET must be constructed",
    )
  }
  match elem.value {
    Unknown(raw) => {
      let inner = @asn1.Decoder::new(raw)
      let items : Array[@asn1.Element] = []
      let mut prev : Bytes? = None
      while !inner.is_empty() {
        let item = inner.read_element() catch { e => raise Asn1(e) }
        let current = @asn1.encode_der(item)
        match prev {
          Some(p) =>
            if bytes_lex_compare(p, current) > 0 {
              raise UnexpectedStructure(
                "[" +
                number.to_string() +
                "] IMPLICIT SET items not in DER order",
              )
            }
          None => ()
        }
        prev = Some(current)
        items.push(item)
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
  validate_bit_string_tail(bytes, unused_bits)
  { bytes, unused_bits }
}

///|
fn validate_bit_string_tail(
  bytes : Bytes,
  unused_bits : Int,
) -> Unit raise Pkcs8Error {
  if unused_bits < 0 || unused_bits > 7 {
    raise UnexpectedStructure("BIT STRING unused_bits out of range")
  }
  if bytes.length() == 0 {
    if unused_bits != 0 {
      raise UnexpectedStructure(
        "BIT STRING unused_bits non-zero with empty data",
      )
    }
    return
  }
  if unused_bits > 0 {
    let mask = (1 << unused_bits) - 1
    let last = bytes[bytes.length() - 1].to_int()
    if (last & mask) != 0 {
      raise UnexpectedStructure("BIT STRING unused tail bits must be zero")
    }
  }
}

///|
fn wrap_context_implicit_set(
  number : UInt,
  items : Array[@asn1.Element],
) -> @asn1.Element {
  // DER SET OF (X.690 §11.6) requires components to be ordered by their
  // encoded byte sequence. Sort the encoded forms lexicographically before
  // emitting the [n] IMPLICIT SET so a round-trip from a non-canonical input
  // produces canonical output (closes review #1 finding 18).
  let encoded : Array[Bytes] = []
  for item in items {
    encoded.push(@asn1.encode_der(item))
  }
  encoded.sort_by(fn(a, b) { bytes_lex_compare(a, b) })
  let enc = @asn1.Encoder::new()
  for e in encoded {
    enc.buf.write_bytes(e)
  }
  @asn1.Element::new(
    @asn1.Tag::context(number, constructed=true),
    Unknown(enc.finish()),
  )
}

///|
fn bytes_lex_compare(a : Bytes, b : Bytes) -> Int {
  // Shorter-then-byte ordering matches DER SET OF semantics: pad the shorter
  // value with trailing zeros for the comparison so that, e.g.,
  // `0x30 0x00` (empty SEQUENCE) precedes `0x30 0x02 0x05 0x00`.
  let la = a.length()
  let lb = b.length()
  let mut i = 0
  let n = if la < lb { la } else { lb }
  while i < n {
    let av = a[i].to_int()
    let bv = b[i].to_int()
    if av != bv {
      return av - bv
    }
    i = i + 1
  }
  la - lb
}

///|
fn wrap_context_implicit_bit_string(
  number : UInt,
  bs : @asn1.BitString,
) -> @asn1.Element {
  validate_bit_string_tail(bs.bytes, bs.unused_bits) catch {
    e => abort("invalid context BIT STRING: " + @debug.to_string(e))
  }
  let buf = Buffer()
  buf.write_byte(bs.unused_bits.to_byte())
  buf.write_bytes(bs.bytes)
  @asn1.Element::new(@asn1.Tag::context(number), Unknown(buf.to_bytes()))
}

///|
fn validate_public_key_shape(
  algorithm : @pkix.AlgorithmIdentifier,
  public_key : @asn1.BitString?,
) -> Unit raise Pkcs8Error {
  match public_key {
    None => ()
    Some(bs) => {
      let alg = algorithm.algorithm.to_string()
      if alg == "1.2.840.113549.1.1.1" {
        validate_rsa_public_key_shape(bs)
      } else if alg == "1.2.840.10045.2.1" {
        validate_ec_public_key_shape(algorithm, bs)
      } else if alg == "1.3.101.110" || alg == "1.3.101.112" {
        require_raw_public_key_shape(bs, 32, alg)
      } else if alg == "1.3.101.111" {
        require_raw_public_key_shape(bs, 56, alg)
      } else if alg == "1.3.101.113" {
        require_raw_public_key_shape(bs, 57, alg)
      }
    }
  }
}

///|
fn require_raw_public_key_shape(
  bs : @asn1.BitString,
  len : Int,
  alg : String,
) -> Unit raise Pkcs8Error {
  if bs.unused_bits != 0 {
    raise UnexpectedStructure("publicKey unused_bits must be zero for " + alg)
  }
  if bs.bytes.length() != len {
    raise UnexpectedStructure(
      "publicKey length mismatch for " +
      alg +
      ": expected " +
      len.to_string() +
      ", got " +
      bs.bytes.length().to_string(),
    )
  }
}

///|
fn validate_rsa_public_key_shape(bs : @asn1.BitString) -> Unit raise Pkcs8Error {
  if bs.unused_bits != 0 {
    raise UnexpectedStructure("RSA publicKey unused_bits must be zero")
  }
  let elem = decode_der(bs.bytes)
  let items = expect_sequence(elem)
  if items.length() != 2 {
    raise UnexpectedStructure("RSA publicKey must be RSAPublicKey SEQUENCE")
  }
  expect_positive_integer(items[0], "RSA modulus")
  expect_positive_integer(items[1], "RSA publicExponent")
}

///|
fn expect_positive_integer(
  elem : @asn1.Element,
  name : String,
) -> Unit raise Pkcs8Error {
  match elem.value {
    Integer(bytes) => {
      if bytes.length() == 0 {
        raise UnexpectedStructure(name + " INTEGER is empty")
      }
      if (bytes[0].to_int() & 0x80) != 0 {
        raise UnexpectedStructure(name + " INTEGER is negative")
      }
    }
    _ => raise UnexpectedStructure(name + " must be INTEGER")
  }
}

///|
fn validate_ec_public_key_shape(
  algorithm : @pkix.AlgorithmIdentifier,
  bs : @asn1.BitString,
) -> Unit raise Pkcs8Error {
  match algorithm_parameter_oid_string(algorithm) {
    Some("1.2.840.10045.3.1.7") =>
      require_uncompressed_ec_public_key(bs, 32, "secp256r1")
    Some("1.3.132.0.34") =>
      require_uncompressed_ec_public_key(bs, 48, "secp384r1")
    Some("1.3.132.0.10") =>
      require_uncompressed_ec_public_key(bs, 32, "secp256k1")
    _ => ()
  }
}

///|
fn algorithm_parameter_oid_string(
  algorithm : @pkix.AlgorithmIdentifier,
) -> String? raise Pkcs8Error {
  match algorithm.parameters {
    Some(param_bytes) => {
      let elem = decode_der(param_bytes)
      match elem.value {
        Oid(o) => Some(o.to_string())
        _ => None
      }
    }
    None => None
  }
}

///|
fn require_uncompressed_ec_public_key(
  bs : @asn1.BitString,
  coordinate_len : Int,
  curve : String,
) -> Unit raise Pkcs8Error {
  if bs.unused_bits != 0 {
    raise UnexpectedStructure("EC publicKey unused_bits must be zero")
  }
  let expected_len = 1 + coordinate_len * 2
  if bs.bytes.length() != expected_len {
    raise UnexpectedStructure(
      "EC publicKey length mismatch for " +
      curve +
      ": expected " +
      expected_len.to_string() +
      ", got " +
      bs.bytes.length().to_string(),
    )
  }
  if bs.bytes[0] != b'\x04' {
    raise UnexpectedStructure("EC publicKey must be uncompressed for " + curve)
  }
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
  let mut saw_attributes = false
  let mut i = 3
  while i < items.length() {
    let item = items[i]
    match match_context_implicit_set(item, 0U) {
      Some(attrs) => {
        if saw_attributes {
          raise UnexpectedStructure("duplicate attributes")
        }
        attributes = attrs
        saw_attributes = true
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
        match public_key {
          Some(_) => raise UnexpectedStructure("duplicate publicKey")
          None => ()
        }
        public_key = Some(bs)
        i = i + 1
        continue
      }
      None => ()
    }
    raise UnexpectedStructure("unrecognized PrivateKeyInfo field")
  }
  validate_public_key_shape(algorithm, public_key)
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
  reject_pem_headers(block)
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
  reject_pem_headers(block)
  parse_encrypted_der(block.data)
}

///|
pub fn serialize_encrypted_pem(enc : EncryptedPrivateKeyInfo) -> String {
  @pem.encode_simple(label_encrypted_private_key, serialize_encrypted_der(enc))
}
