// X.509 v3 (RFC 5280) data structures and DER (de)serialization.
// Depends on @asn1 for tag / element primitives.

///|
pub(all) struct AlgorithmIdentifier {
  algorithm : @asn1.ObjectIdentifier
  parameters : Bytes? // DER-encoded ANY DEFINED BY algorithm; None means absent
} derive(Eq, Show)

///|
pub(all) struct AttributeTypeAndValue {
  oid : @asn1.ObjectIdentifier
  value : @asn1.Element // ANY
} derive(Show)

///|
pub(all) struct Name {
  rdns : Array[Array[AttributeTypeAndValue]]
} derive(Show)

///|
pub(all) struct Validity {
  not_before : String // UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime
  not_after : String
  not_before_tag : @asn1.Tag // remember which CHOICE branch we parsed
  not_after_tag : @asn1.Tag
} derive(Eq, Show)

///|
pub(all) struct SubjectPublicKeyInfo {
  algorithm : AlgorithmIdentifier
  subject_public_key : @asn1.BitString
} derive(Show)

///|
pub(all) struct Extension {
  oid : @asn1.ObjectIdentifier
  critical : Bool
  value : Bytes // DER-encoded extnValue OCTET STRING content
} derive(Show)

///|
pub(all) struct TbsCertificate {
  version : Int // 0 = v1, 1 = v2, 2 = v3
  serial_number : Bytes // INTEGER, big-endian two's complement
  signature : AlgorithmIdentifier
  issuer : Name
  validity : Validity
  subject : Name
  subject_public_key_info : SubjectPublicKeyInfo
  issuer_unique_id : @asn1.BitString? // v2+
  subject_unique_id : @asn1.BitString? // v2+
  extensions : Array[Extension] // v3 only
} derive(Show)

///|
pub(all) struct Certificate {
  tbs : TbsCertificate
  signature_algorithm : AlgorithmIdentifier
  signature : @asn1.BitString
} derive(Show)

///|
pub suberror PkixError {
  Asn1(@asn1.Asn1Error)
  UnexpectedStructure(String)
  UnsupportedVersion(Int)
  UnsupportedAlgorithm(@asn1.ObjectIdentifier)
  InvalidTime(String)
} derive(Show)

// ─── helpers ─────────────────────────────────────────────────────────────

///|
fn expect_sequence(elem : @asn1.Element) -> Array[@asn1.Element] raise PkixError {
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
fn expect_set(elem : @asn1.Element) -> Array[@asn1.Element] raise PkixError {
  match elem.value {
    Set(items) =>
      if elem.tag == @asn1.tag_set {
        items
      } else {
        raise UnexpectedStructure("expected universal SET tag")
      }
    _ => raise UnexpectedStructure("expected SET")
  }
}

///|
fn expect_integer_bytes(elem : @asn1.Element) -> Bytes raise PkixError {
  match elem.value {
    Integer(b) => b
    _ => raise UnexpectedStructure("expected INTEGER")
  }
}

///|
fn expect_integer_small(elem : @asn1.Element) -> Int raise PkixError {
  let bytes = expect_integer_bytes(elem)
  if bytes.length() == 0 || bytes.length() > 4 {
    raise UnexpectedStructure("INTEGER out of small range")
  }
  let mut value = 0
  for i in 0..<bytes.length() {
    value = (value << 8) | bytes[i].to_int()
  }
  value
}

///|
fn expect_oid(elem : @asn1.Element) -> @asn1.ObjectIdentifier raise PkixError {
  match elem.value {
    Oid(o) => o
    _ => raise UnexpectedStructure("expected OBJECT IDENTIFIER")
  }
}

///|
fn expect_bit_string(elem : @asn1.Element) -> @asn1.BitString raise PkixError {
  match elem.value {
    BitString(bs) => bs
    _ => raise UnexpectedStructure("expected BIT STRING")
  }
}

///|
fn expect_octet_string(elem : @asn1.Element) -> Bytes raise PkixError {
  match elem.value {
    OctetString(b) => b
    _ => raise UnexpectedStructure("expected OCTET STRING")
  }
}

///|
fn expect_bool(elem : @asn1.Element) -> Bool raise PkixError {
  match elem.value {
    Boolean(b) => b
    _ => raise UnexpectedStructure("expected BOOLEAN")
  }
}

///|
fn expect_time(elem : @asn1.Element) -> (String, @asn1.Tag) raise PkixError {
  match elem.value {
    UtcTime(s) => (s, @asn1.tag_utc_time)
    GeneralizedTime(s) => (s, @asn1.tag_generalized_time)
    _ => raise UnexpectedStructure("expected UTCTime / GeneralizedTime")
  }
}

// Context [n] EXPLICIT: outer tag = ContextSpecific n constructed,
// content = a single nested TLV.
///|
fn match_context_explicit(
  elem : @asn1.Element,
  number : UInt,
) -> @asn1.Element? raise PkixError {
  if elem.tag.class_ != ContextSpecific || elem.tag.number != number {
    return None
  }
  if not(elem.tag.constructed) {
    raise UnexpectedStructure("context [" + number.to_string() + "] not constructed")
  }
  match elem.value {
    Unknown(raw) =>
      Some(@asn1.decode_der(raw) catch { e => raise Asn1(e) })
    Sequence(_) | Set(_) =>
      // asn1 decode_value never gives us Sequence/Set for context tags, but
      // be defensive.
      raise UnexpectedStructure("context [" + number.to_string() + "] unexpected value kind")
    _ =>
      raise UnexpectedStructure("context [" + number.to_string() + "] missing raw payload")
  }
}

// Context [n] IMPLICIT BIT STRING: tag = ContextSpecific n primitive,
// content = standard BIT STRING content (unused_bits prefix + data).
///|
fn match_context_implicit_bit_string(
  elem : @asn1.Element,
  number : UInt,
) -> @asn1.BitString? raise PkixError {
  if elem.tag.class_ != ContextSpecific || elem.tag.number != number {
    return None
  }
  if elem.tag.constructed {
    raise UnexpectedStructure("[" + number.to_string() + "] IMPLICIT BIT STRING must be primitive")
  }
  match elem.value {
    Unknown(raw) => Some(decode_bit_string_content(raw))
    _ => raise UnexpectedStructure("[" + number.to_string() + "] missing raw payload")
  }
}

///|
fn decode_bit_string_content(b : Bytes) -> @asn1.BitString raise PkixError {
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

// ─── low-level structure parsers ─────────────────────────────────────────

///|
fn parse_algorithm_identifier_elem(
  elem : @asn1.Element,
) -> AlgorithmIdentifier raise PkixError {
  let items = expect_sequence(elem)
  if items.length() < 1 || items.length() > 2 {
    raise UnexpectedStructure("AlgorithmIdentifier arity")
  }
  let algorithm = expect_oid(items[0])
  let parameters = if items.length() == 2 {
    Some(@asn1.encode_der(items[1]))
  } else {
    None
  }
  { algorithm, parameters }
}

///|
fn parse_validity_elem(elem : @asn1.Element) -> Validity raise PkixError {
  let items = expect_sequence(elem)
  if items.length() != 2 {
    raise UnexpectedStructure("Validity must have 2 entries")
  }
  let (nb, nb_tag) = expect_time(items[0])
  let (na, na_tag) = expect_time(items[1])
  { not_before: nb, not_after: na, not_before_tag: nb_tag, not_after_tag: na_tag }
}

///|
fn parse_attribute_type_and_value(
  elem : @asn1.Element,
) -> AttributeTypeAndValue raise PkixError {
  let items = expect_sequence(elem)
  if items.length() != 2 {
    raise UnexpectedStructure("AttributeTypeAndValue must have 2 entries")
  }
  { oid: expect_oid(items[0]), value: items[1] }
}

///|
fn parse_rdn(elem : @asn1.Element) -> Array[AttributeTypeAndValue] raise PkixError {
  let items = expect_set(elem)
  if items.length() == 0 {
    raise UnexpectedStructure("RelativeDistinguishedName must be non-empty")
  }
  let out : Array[AttributeTypeAndValue] = []
  for item in items {
    out.push(parse_attribute_type_and_value(item))
  }
  out
}

///|
fn parse_name_elem(elem : @asn1.Element) -> Name raise PkixError {
  let items = expect_sequence(elem)
  let rdns : Array[Array[AttributeTypeAndValue]] = []
  for item in items {
    rdns.push(parse_rdn(item))
  }
  { rdns, }
}

///|
fn parse_spki_elem(
  elem : @asn1.Element,
) -> SubjectPublicKeyInfo raise PkixError {
  let items = expect_sequence(elem)
  if items.length() != 2 {
    raise UnexpectedStructure("SubjectPublicKeyInfo must have 2 entries")
  }
  {
    algorithm: parse_algorithm_identifier_elem(items[0]),
    subject_public_key: expect_bit_string(items[1]),
  }
}

///|
fn parse_extension(elem : @asn1.Element) -> Extension raise PkixError {
  let items = expect_sequence(elem)
  if items.length() < 2 || items.length() > 3 {
    raise UnexpectedStructure("Extension arity")
  }
  let oid = expect_oid(items[0])
  let mut critical = false
  let value_index = if items.length() == 3 {
    critical = expect_bool(items[1])
    2
  } else {
    1
  }
  let value = expect_octet_string(items[value_index])
  { oid, critical, value }
}

///|
fn parse_extensions_seq(elem : @asn1.Element) -> Array[Extension] raise PkixError {
  let items = expect_sequence(elem)
  let out : Array[Extension] = []
  for item in items {
    out.push(parse_extension(item))
  }
  out
}

// ─── TBSCertificate / Certificate ────────────────────────────────────────

///|
fn parse_tbs_certificate_elem(
  elem : @asn1.Element,
) -> TbsCertificate raise PkixError {
  let items = expect_sequence(elem)
  let mut idx = 0
  let mut version = 0
  if idx < items.length() {
    match match_context_explicit(items[idx], 0U) {
      Some(inner) => {
        version = expect_integer_small(inner)
        if version < 0 || version > 2 {
          raise UnsupportedVersion(version)
        }
        idx = idx + 1
      }
      None => () // DEFAULT v1 → version stays 0
    }
  }
  if items.length() - idx < 6 {
    raise UnexpectedStructure("TBSCertificate too few fields")
  }
  let serial_number = expect_integer_bytes(items[idx])
  let signature = parse_algorithm_identifier_elem(items[idx + 1])
  let issuer = parse_name_elem(items[idx + 2])
  let validity = parse_validity_elem(items[idx + 3])
  let subject = parse_name_elem(items[idx + 4])
  let spki = parse_spki_elem(items[idx + 5])
  idx = idx + 6
  let mut issuer_unique_id : @asn1.BitString? = None
  let mut subject_unique_id : @asn1.BitString? = None
  let mut extensions : Array[Extension] = []
  while idx < items.length() {
    let item = items[idx]
    match match_context_implicit_bit_string(item, 1U) {
      Some(bs) => {
        if version < 1 {
          raise UnexpectedStructure("issuerUniqueID requires v2 or v3")
        }
        issuer_unique_id = Some(bs)
        idx = idx + 1
        continue
      }
      None => ()
    }
    match match_context_implicit_bit_string(item, 2U) {
      Some(bs) => {
        if version < 1 {
          raise UnexpectedStructure("subjectUniqueID requires v2 or v3")
        }
        subject_unique_id = Some(bs)
        idx = idx + 1
        continue
      }
      None => ()
    }
    match match_context_explicit(item, 3U) {
      Some(inner) => {
        if version < 2 {
          raise UnexpectedStructure("extensions requires v3")
        }
        extensions = parse_extensions_seq(inner)
        idx = idx + 1
        continue
      }
      None => ()
    }
    raise UnexpectedStructure("unrecognized TBSCertificate field")
  }
  {
    version,
    serial_number,
    signature,
    issuer,
    validity,
    subject,
    subject_public_key_info: spki,
    issuer_unique_id,
    subject_unique_id,
    extensions,
  }
}

///|
pub fn parse_certificate(der : Bytes) -> Certificate raise PkixError {
  let elem = @asn1.decode_der(der) catch { e => raise Asn1(e) }
  let items = expect_sequence(elem)
  if items.length() != 3 {
    raise UnexpectedStructure("Certificate must have 3 fields")
  }
  let tbs = parse_tbs_certificate_elem(items[0])
  let sig_alg = parse_algorithm_identifier_elem(items[1])
  let sig = expect_bit_string(items[2])
  { tbs, signature_algorithm: sig_alg, signature: sig }
}

///|
pub fn parse_subject_public_key_info(
  der : Bytes,
) -> SubjectPublicKeyInfo raise PkixError {
  let elem = @asn1.decode_der(der) catch { e => raise Asn1(e) }
  parse_spki_elem(elem)
}

///|
pub fn parse_name(der : Bytes) -> Name raise PkixError {
  let elem = @asn1.decode_der(der) catch { e => raise Asn1(e) }
  parse_name_elem(elem)
}

// ─── serializers ─────────────────────────────────────────────────────────

///|
fn algorithm_identifier_to_element(alg : AlgorithmIdentifier) -> @asn1.Element raise PkixError {
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_oid, Oid(alg.algorithm)),
  ]
  match alg.parameters {
    Some(bytes) =>
      items.push(@asn1.decode_der(bytes) catch { e => raise Asn1(e) })
    None => ()
  }
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn attribute_type_and_value_to_element(av : AttributeTypeAndValue) -> @asn1.Element {
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_oid, Oid(av.oid)),
    av.value,
  ]
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn rdn_to_element(rdn : Array[AttributeTypeAndValue]) -> @asn1.Element {
  let items : Array[@asn1.Element] = []
  for av in rdn {
    items.push(attribute_type_and_value_to_element(av))
  }
  @asn1.Element::new(@asn1.tag_set, Set(items))
}

///|
fn name_to_element(name : Name) -> @asn1.Element {
  let items : Array[@asn1.Element] = []
  for rdn in name.rdns {
    items.push(rdn_to_element(rdn))
  }
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn validity_to_element(v : Validity) -> @asn1.Element {
  let nb_value = if v.not_before_tag == @asn1.tag_utc_time {
    @asn1.Value::UtcTime(v.not_before)
  } else {
    @asn1.Value::GeneralizedTime(v.not_before)
  }
  let na_value = if v.not_after_tag == @asn1.tag_utc_time {
    @asn1.Value::UtcTime(v.not_after)
  } else {
    @asn1.Value::GeneralizedTime(v.not_after)
  }
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(v.not_before_tag, nb_value),
    @asn1.Element::new(v.not_after_tag, na_value),
  ]
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn spki_to_element(spki : SubjectPublicKeyInfo) -> @asn1.Element raise PkixError {
  let items : Array[@asn1.Element] = [
    algorithm_identifier_to_element(spki.algorithm),
    @asn1.Element::new(@asn1.tag_bit_string, BitString(spki.subject_public_key)),
  ]
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn extension_to_element(ext : Extension) -> @asn1.Element {
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_oid, Oid(ext.oid)),
  ]
  if ext.critical {
    items.push(@asn1.Element::new(@asn1.tag_boolean, Boolean(true)))
  }
  items.push(@asn1.Element::new(@asn1.tag_octet_string, OctetString(ext.value)))
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn extensions_to_element(exts : Array[Extension]) -> @asn1.Element {
  let items : Array[@asn1.Element] = []
  for ext in exts {
    items.push(extension_to_element(ext))
  }
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn wrap_context_explicit(number : UInt, inner : @asn1.Element) -> @asn1.Element {
  let payload = @asn1.encode_der(inner)
  @asn1.Element::new(
    @asn1.Tag::context(number, constructed=true),
    Unknown(payload),
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
  @asn1.Element::new(
    @asn1.Tag::context(number),
    Unknown(buf.to_bytes()),
  )
}

///|
fn tbs_certificate_to_element(tbs : TbsCertificate) -> @asn1.Element raise PkixError {
  let items : Array[@asn1.Element] = []
  if tbs.version != 0 {
    items.push(wrap_context_explicit(
      0U,
      @asn1.Element::new(
        @asn1.tag_integer,
        Integer(int_to_be_minimal(tbs.version)),
      ),
    ))
  }
  items.push(@asn1.Element::new(@asn1.tag_integer, Integer(tbs.serial_number)))
  items.push(algorithm_identifier_to_element(tbs.signature))
  items.push(name_to_element(tbs.issuer))
  items.push(validity_to_element(tbs.validity))
  items.push(name_to_element(tbs.subject))
  items.push(spki_to_element(tbs.subject_public_key_info))
  match tbs.issuer_unique_id {
    Some(bs) => items.push(wrap_context_implicit_bit_string(1U, bs))
    None => ()
  }
  match tbs.subject_unique_id {
    Some(bs) => items.push(wrap_context_implicit_bit_string(2U, bs))
    None => ()
  }
  if tbs.extensions.length() > 0 {
    items.push(wrap_context_explicit(3U, extensions_to_element(tbs.extensions)))
  }
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn int_to_be_minimal(value : Int) -> Bytes {
  if value == 0 {
    return b"\x00"
  }
  let buf = Buffer()
  let mut tmp = value
  let bytes_be : Array[Int] = []
  while tmp != 0 && tmp != -1 {
    bytes_be.push(tmp & 0xFF)
    tmp = tmp >> 8
  }
  if bytes_be.length() == 0 {
    bytes_be.push(if value < 0 { 0xFF } else { 0x00 })
  }
  // Add sign-extension byte if needed.
  let top = bytes_be[bytes_be.length() - 1]
  if value >= 0 && (top & 0x80) != 0 {
    bytes_be.push(0)
  } else if value < 0 && (top & 0x80) == 0 {
    bytes_be.push(0xFF)
  }
  for i = bytes_be.length() - 1; i >= 0; i = i - 1 {
    buf.write_byte(bytes_be[i].to_byte())
  }
  buf.to_bytes()
}

///|
pub fn serialize_certificate(cert : Certificate) -> Bytes {
  serialize_certificate_checked(cert) catch { _ => abort("serialize_certificate: invalid algorithm parameters") }
}

///|
fn serialize_certificate_checked(cert : Certificate) -> Bytes raise PkixError {
  let items : Array[@asn1.Element] = [
    tbs_certificate_to_element(cert.tbs),
    algorithm_identifier_to_element(cert.signature_algorithm),
    @asn1.Element::new(@asn1.tag_bit_string, BitString(cert.signature)),
  ]
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence(items)))
}

///|
pub fn serialize_subject_public_key_info(spki : SubjectPublicKeyInfo) -> Bytes {
  serialize_spki_checked(spki) catch { _ => abort("serialize_spki: invalid algorithm parameters") }
}

///|
fn serialize_spki_checked(spki : SubjectPublicKeyInfo) -> Bytes raise PkixError {
  @asn1.encode_der(spki_to_element(spki))
}

///|
pub fn serialize_name(name : Name) -> Bytes {
  @asn1.encode_der(name_to_element(name))
}
