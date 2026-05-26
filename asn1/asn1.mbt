///|
pub(all) enum TagClass {
  Universal
  Application
  ContextSpecific
  Private
} derive(Eq, Debug, Hash)

///|
pub struct Tag {
  class_ : TagClass
  number : UInt
  constructed : Bool
} derive(Eq, Debug, Hash)

///|
pub fn Tag::universal(number : UInt, constructed? : Bool = false) -> Tag {
  { class_: TagClass::Universal, number, constructed }
}

///|
pub fn Tag::context(number : UInt, constructed? : Bool = false) -> Tag {
  { class_: TagClass::ContextSpecific, number, constructed }
}

///|
pub let tag_boolean : Tag = Tag::universal(1)

///|
pub let tag_integer : Tag = Tag::universal(2)

///|
pub let tag_bit_string : Tag = Tag::universal(3)

///|
pub let tag_octet_string : Tag = Tag::universal(4)

///|
pub let tag_null : Tag = Tag::universal(5)

///|
pub let tag_oid : Tag = Tag::universal(6)

///|
pub let tag_utf8_string : Tag = Tag::universal(12)

///|
pub let tag_sequence : Tag = Tag::universal(16, constructed=true)

///|
pub let tag_set : Tag = Tag::universal(17, constructed=true)

///|
pub let tag_printable_string : Tag = Tag::universal(19)

///|
pub let tag_ia5_string : Tag = Tag::universal(22)

///|
pub let tag_utc_time : Tag = Tag::universal(23)

///|
pub let tag_generalized_time : Tag = Tag::universal(24)

///|
pub struct ObjectIdentifier {
  arcs : Array[UInt]
} derive(Eq, Debug, Hash)

///|
/// Construct an OID from its arc sequence. Validates that the first two
/// arcs follow X.660 §3.5 (arcs[0] ∈ {0, 1, 2}, and if arcs[0] < 2 then
/// arcs[1] < 40). Without this check, `from_arcs([5, 10])` would DER-
/// encode to the same single byte (`40*5+10 = 210`, but the encoder also
/// happens to drop the first arc's upper bits) as `from_arcs([2, 130])`,
/// while `derive(Eq)` would say the two values differ — yielding two
/// distinct OIDs in MoonBit that round-trip to the same DER on the wire.
pub fn ObjectIdentifier::from_arcs(arcs : Array[UInt]) -> ObjectIdentifier {
  match oid_arc_validation_error(arcs) {
    Some(msg) => abort(msg)
    None => ()
  }
  { arcs, }
}

///|
/// Same as `from_arcs` but raises `Asn1Error::InvalidEncoding` on the
/// validation failures instead of aborting the process. Use this when
/// the arcs come from untrusted input that you'd rather not crash on.
pub fn ObjectIdentifier::from_arcs_checked(
  arcs : Array[UInt],
) -> ObjectIdentifier raise Asn1Error {
  match oid_arc_validation_error(arcs) {
    Some(msg) => raise InvalidEncoding(msg)
    None => ()
  }
  { arcs, }
}

///|
pub fn ObjectIdentifier::from_string(
  s : String,
) -> ObjectIdentifier raise Asn1Error {
  if s.length() == 0 {
    raise InvalidEncoding("empty OID string")
  }
  let arcs : Array[UInt] = []
  let mut current : UInt = 0U
  let mut has_digit = false
  for c in s {
    if c == '.' {
      if !has_digit {
        raise InvalidEncoding("empty arc in OID")
      }
      arcs.push(current)
      current = 0U
      has_digit = false
    } else if c >= '0' && c <= '9' {
      let d = (c.to_int() - '0'.to_int()).reinterpret_as_uint()
      if current > (0xFFFFFFFFU - d) / 10U {
        raise InvalidEncoding("OID arc overflows UInt")
      }
      current = current * 10U + d
      has_digit = true
    } else {
      raise InvalidEncoding("non-digit in OID string")
    }
  }
  if !has_digit {
    raise InvalidEncoding("trailing dot in OID")
  }
  arcs.push(current)
  match oid_arc_validation_error(arcs) {
    Some(msg) => raise InvalidEncoding(msg)
    None => ()
  }
  { arcs, }
}

///|
fn oid_arc_validation_error(arcs : Array[UInt]) -> String? {
  if arcs.length() < 2 {
    return Some("OID must have at least 2 arcs")
  }
  if arcs[0] > 2U {
    return Some("OID arcs[0] must be 0, 1, or 2")
  }
  if arcs[0] < 2U && arcs[1] >= 40U {
    return Some("OID arcs[1] must be < 40 when arcs[0] is 0 or 1")
  }
  if arcs[0] == 2U && arcs[1] > 0xFFFFFFFFU - 80U {
    return Some("OID arcs[1] too large for DER first subidentifier")
  }
  None
}

///|
pub fn ObjectIdentifier::to_string(self : ObjectIdentifier) -> String {
  let buf = StringBuilder::new()
  let mut first = true
  for a in self.arcs {
    if !first {
      buf.write_char('.')
    }
    buf.write_string(a.to_string())
    first = false
  }
  buf.to_string()
}

///|
fn encode_oid(enc : Encoder, oid : ObjectIdentifier) -> Unit {
  // Caller is expected to provide a validated OID; we still guard a bit.
  match oid_arc_validation_error(oid.arcs) {
    Some(msg) => abort("encode_oid: " + msg)
    None => ()
  }
  let first = oid_first_subidentifier(oid)
  write_base128(enc, first)
  for i in 2..<oid.arcs.length() {
    write_base128(enc, oid.arcs[i])
  }
}

///|
fn oid_first_subidentifier(oid : ObjectIdentifier) -> UInt {
  if oid.arcs[0] < 2U {
    oid.arcs[0] * 40U + oid.arcs[1]
  } else {
    80U + oid.arcs[1]
  }
}

///|
fn write_base128(enc : Encoder, value : UInt) -> Unit {
  if value == 0U {
    enc.buf.write_byte(b'\x00')
    return
  }
  let mut tmp = value
  let mut nbytes = 0
  while tmp > 0U {
    nbytes = nbytes + 1
    tmp = tmp >> 7
  }
  for i = nbytes - 1; i >= 0; i = i - 1 {
    let chunk = ((value >> (i * 7)) & 0x7FU).reinterpret_as_int()
    let cont = if i > 0 { 0x80 } else { 0x00 }
    enc.buf.write_byte((chunk | cont).to_byte())
  }
}

///|
fn decode_oid(bytes : Bytes) -> ObjectIdentifier raise Asn1Error {
  if bytes.length() == 0 {
    raise InvalidEncoding("OID payload empty")
  }
  let arcs : Array[UInt] = []
  let (first, next) = read_base128_from_bytes(bytes, 0)
  if first < 40U {
    arcs.push(0U)
    arcs.push(first)
  } else if first < 80U {
    arcs.push(1U)
    arcs.push(first - 40U)
  } else {
    arcs.push(2U)
    arcs.push(first - 80U)
  }
  let mut i = next
  while i < bytes.length() {
    let (value, j) = read_base128_from_bytes(bytes, i)
    arcs.push(value)
    i = j
  }
  match oid_arc_validation_error(arcs) {
    Some(msg) => raise InvalidEncoding(msg)
    None => ()
  }
  { arcs, }
}

///|
fn read_base128_from_bytes(
  bytes : Bytes,
  start : Int,
) -> (UInt, Int) raise Asn1Error {
  let mut i = start
  let mut value : UInt = 0U
  let mut first_in_arc = true
  // UInt overflow guard: if value already exceeds this, shifting left by 7
  // would lose high bits. UInt::max_value >> 7 == 0x01FFFFFF on 32-bit UInt.
  let shift_overflow_threshold : UInt = 0xFFFFFFFFU >> 7
  while true {
    if i >= bytes.length() {
      raise InvalidEncoding("truncated OID arc")
    }
    let b = bytes[i].to_int()
    // X.690 §8.19.2: each base-128 sub-identifier must be minimally encoded.
    // The first continuation byte of an arc cannot be 0x80 because that
    // would mean a leading zero (continuation set but value bits all zero).
    if first_in_arc && b == 0x80 {
      raise InvalidEncoding("non-minimal OID base-128 encoding")
    }
    if value > shift_overflow_threshold {
      raise InvalidEncoding("OID arc overflows UInt")
    }
    value = (value << 7) | (b & 0x7F).reinterpret_as_uint()
    i = i + 1
    first_in_arc = false
    if (b & 0x80) == 0 {
      break
    }
  }
  (value, i)
}

///|
pub(all) struct BitString {
  bytes : Bytes
  unused_bits : Int
} derive(Eq, Debug)

///|
pub(all) enum Value {
  Boolean(Bool)
  Integer(Bytes) // big-endian, two's complement
  BitString(BitString)
  OctetString(Bytes)
  Null
  Oid(ObjectIdentifier)
  Utf8String(String)
  PrintableString(String)
  Ia5String(String)
  UtcTime(String)
  GeneralizedTime(String)
  Sequence(Array[Element])
  Set(Array[Element])
  Unknown(Bytes) // raw content for tags this module does not interpret
} derive(Debug)

///|
pub struct Element {
  tag : Tag
  value : Value
} derive(Debug)

///|
pub fn Element::new(tag : Tag, value : Value) -> Element {
  { tag, value }
}

///|
pub suberror Asn1Error {
  TruncatedInput
  UnexpectedTag(expected~ : Tag, got~ : Tag)
  InvalidLength
  InvalidEncoding(String)
  Unsupported(String)
  TrailingBytes(Int)
} derive(Debug)

///|
pub fn decode_der(input : Bytes) -> Element raise Asn1Error {
  let dec = Decoder::new(input)
  let elem = dec.read_element()
  if !dec.is_empty() {
    raise TrailingBytes(dec.remaining())
  }
  elem
}

///|
pub fn decode_der_all(input : Bytes) -> Array[Element] raise Asn1Error {
  let dec = Decoder::new(input)
  let items = []
  while !dec.is_empty() {
    items.push(dec.read_element())
  }
  items
}

///|
pub fn encode_der(element : Element) -> Bytes {
  let enc = Encoder::new()
  enc.write_element(element)
  enc.finish()
}

///|
fn class_bits(cls : TagClass) -> Int {
  match cls {
    Universal => 0x00
    Application => 0x40
    ContextSpecific => 0x80
    Private => 0xC0
  }
}

///|
fn bits_to_class(byte : Int) -> TagClass {
  match byte & 0xC0 {
    0x00 => Universal
    0x40 => Application
    0x80 => ContextSpecific
    _ => Private
  }
}

///|
pub fn write_tag(enc : Encoder, tag : Tag) -> Unit {
  let cls = class_bits(tag.class_)
  let cons = if tag.constructed { 0x20 } else { 0x00 }
  let number = tag.number
  if number < 31U {
    let first = cls | cons | number.reinterpret_as_int()
    enc.buf.write_byte(first.to_byte())
  } else {
    enc.buf.write_byte((cls | cons | 0x1F).to_byte())
    let mut tmp = number
    let mut nbytes = 0
    while tmp > 0U {
      nbytes = nbytes + 1
      tmp = tmp >> 7
    }
    for i = nbytes - 1; i >= 0; i = i - 1 {
      let shift = i * 7
      let chunk = ((number >> shift) & 0x7FU).reinterpret_as_int()
      let cont = if i > 0 { 0x80 } else { 0x00 }
      enc.buf.write_byte((chunk | cont).to_byte())
    }
  }
}

///|
pub fn read_tag(dec : Decoder) -> Tag raise Asn1Error {
  if dec.remaining() < 1 {
    raise TruncatedInput
  }
  let first = dec.input[dec.pos].to_int()
  dec.pos = dec.pos + 1
  let class_ = bits_to_class(first)
  let constructed = (first & 0x20) != 0
  let low5 = first & 0x1F
  let number = if low5 != 0x1F {
    low5.reinterpret_as_uint()
  } else {
    let mut n : UInt = 0U
    let mut done = false
    let mut first_in_number = true
    let shift_overflow_threshold : UInt = 0xFFFFFFFFU >> 7
    while !done {
      if dec.remaining() < 1 {
        raise TruncatedInput
      }
      let b = dec.input[dec.pos].to_int()
      dec.pos = dec.pos + 1
      if first_in_number && b == 0x80 {
        raise InvalidEncoding("non-minimal high-tag-number encoding")
      }
      if n > shift_overflow_threshold {
        raise InvalidEncoding("tag number overflows UInt")
      }
      n = (n << 7) | (b & 0x7F).reinterpret_as_uint()
      first_in_number = false
      if (b & 0x80) == 0 {
        done = true
      }
    }
    if n < 31U {
      raise InvalidEncoding("high-tag-number form used for tag < 31")
    }
    n
  }
  { class_, number, constructed }
}

///|
pub fn write_length(enc : Encoder, length : Int) -> Unit {
  if length < 0 {
    abort("write_length: negative length")
  }
  if length < 128 {
    enc.buf.write_byte(length.to_byte())
  } else {
    let mut tmp = length
    let mut nbytes = 0
    while tmp > 0 {
      nbytes = nbytes + 1
      tmp = tmp >> 8
    }
    enc.buf.write_byte((0x80 | nbytes).to_byte())
    for i = nbytes - 1; i >= 0; i = i - 1 {
      enc.buf.write_byte(((length >> (i * 8)) & 0xFF).to_byte())
    }
  }
}

///|
/// DER length cap. 16 MiB is well above any realistic certificate / CMS
/// blob and keeps a single TLV from forcing a multi-hundred-MB allocation.
/// Hit on decode -> `Unsupported("length exceeds max_input_size")`.
const MAX_INPUT_SIZE : Int = 16 * 1024 * 1024

///|
pub fn read_length(dec : Decoder) -> Int raise Asn1Error {
  if dec.remaining() < 1 {
    raise TruncatedInput
  }
  let first = dec.input[dec.pos].to_int()
  dec.pos = dec.pos + 1
  if first < 0x80 {
    return first
  }
  if first == 0x80 {
    raise InvalidEncoding("indefinite length not allowed in DER")
  }
  let nbytes = first & 0x7F
  if nbytes > 4 {
    raise InvalidLength
  }
  if dec.remaining() < nbytes {
    raise TruncatedInput
  }
  let mut value = 0
  // X.690 §10.1: minimal encoding required
  let first_byte = dec.input[dec.pos].to_int()
  if first_byte == 0 && nbytes > 1 {
    raise InvalidEncoding("non-minimal length encoding")
  }
  for _ in 0..<nbytes {
    value = (value << 8) | dec.input[dec.pos].to_int()
    dec.pos = dec.pos + 1
  }
  if value < 128 {
    raise InvalidEncoding("long form used for length < 128")
  }
  if value > MAX_INPUT_SIZE {
    raise Unsupported("length exceeds max_input_size")
  }
  value
}

///|
/// Hard cap on nested SEQUENCE / SET parsing depth. Real-world DER blobs
/// (certificates, CMS, PKCS#7) rarely nest more than ~10 levels. Anything
/// deeper is almost certainly a stack-overflow attempt. Hit on decode ->
/// `Unsupported("nested too deep")`.
const MAX_DEPTH : Int = 32

///|
pub struct Decoder {
  input : Bytes
  mut pos : Int
  current_depth : Int
}

///|
pub fn Decoder::new(input : Bytes) -> Decoder {
  { input, pos: 0, current_depth: 0 }
}

///|
pub fn Decoder::remaining(self : Decoder) -> Int {
  self.input.length() - self.pos
}

///|
pub fn Decoder::is_empty(self : Decoder) -> Bool {
  self.remaining() == 0
}

///|
fn read_bytes(dec : Decoder, n : Int) -> Bytes raise Asn1Error {
  if dec.remaining() < n {
    raise TruncatedInput
  }
  let start = dec.pos
  let bytes = Bytes::makei(n, fn(i) { dec.input[start + i] })
  dec.pos = dec.pos + n
  bytes
}

///|
pub fn Decoder::read_element(self : Decoder) -> Element raise Asn1Error {
  let tag = read_tag(self)
  validate_der_tag_form(tag)
  let length = read_length(self)
  if self.remaining() < length {
    raise TruncatedInput
  }
  let value = decode_value(self, tag, length)
  { tag, value }
}

///|
fn validate_der_tag_form(tag : Tag) -> Unit raise Asn1Error {
  if tag.class_ != Universal {
    return
  }
  match tag.number {
    16U | 17U =>
      if !tag.constructed {
        raise InvalidEncoding("constructed universal type encoded as primitive")
      }
    1U | 2U | 3U | 4U | 5U | 6U | 12U | 19U | 22U | 23U | 24U =>
      if tag.constructed {
        raise InvalidEncoding("primitive universal type encoded as constructed")
      }
    _ => ()
  }
}

///|
/// Construct a child decoder for a nested SEQUENCE / SET payload, inheriting
/// the parent's recursion depth + 1. Raises `Unsupported` if the new depth
/// would exceed `MAX_DEPTH`.
fn child_decoder(
  parent_depth : Int,
  payload : Bytes,
) -> Decoder raise Asn1Error {
  let next_depth = parent_depth + 1
  if next_depth > MAX_DEPTH {
    raise Unsupported("nested too deep")
  }
  { input: payload, pos: 0, current_depth: next_depth }
}

///|
fn decode_value(
  dec : Decoder,
  tag : Tag,
  length : Int,
) -> Value raise Asn1Error {
  if tag.class_ != Universal {
    return Unknown(read_bytes(dec, length))
  }
  if tag.constructed {
    // Sequence / Set handled by their universal numbers below; otherwise raw.
    match tag.number {
      16U => {
        let inner = child_decoder(dec.current_depth, read_bytes(dec, length))
        let items = []
        while !inner.is_empty() {
          items.push(inner.read_element())
        }
        Sequence(items)
      }
      17U => {
        let inner = child_decoder(dec.current_depth, read_bytes(dec, length))
        let items = []
        while !inner.is_empty() {
          items.push(inner.read_element())
        }
        validate_der_set_order(items)
        Set(items)
      }
      _ => Unknown(read_bytes(dec, length))
    }
  } else {
    match tag.number {
      1U => {
        if length != 1 {
          raise InvalidLength
        }
        let b = dec.input[dec.pos].to_int()
        dec.pos = dec.pos + 1
        if b != 0 && b != 0xFF {
          raise InvalidEncoding("DER Boolean must be 0x00 or 0xFF")
        }
        Boolean(b != 0)
      }
      2U => {
        // X.690 §8.3.2: INTEGER content must be at least one octet and the
        // most significant 9 bits cannot be all zeros or all ones (i.e. no
        // redundant 0x00 / 0xFF padding before a same-sign next byte).
        if length == 0 {
          raise InvalidLength
        }
        let bytes = read_bytes(dec, length)
        if length >= 2 {
          let b0 = bytes[0].to_int()
          let b1 = bytes[1].to_int()
          if b0 == 0x00 && (b1 & 0x80) == 0 {
            raise InvalidEncoding(
              "non-canonical INTEGER (redundant 0x00 padding)",
            )
          }
          if b0 == 0xFF && (b1 & 0x80) != 0 {
            raise InvalidEncoding(
              "non-canonical INTEGER (redundant 0xFF padding)",
            )
          }
        }
        Integer(bytes)
      }
      4U => OctetString(read_bytes(dec, length))
      5U => {
        if length != 0 {
          raise InvalidLength
        }
        Null
      }
      6U => Oid(decode_oid(read_bytes(dec, length)))
      12U => Utf8String(decode_utf8_bytes(read_bytes(dec, length)))
      19U => {
        let s = decode_ascii_bytes(read_bytes(dec, length))
        validate_printable_string(s)
        PrintableString(s)
      }
      22U => Ia5String(decode_ascii_bytes(read_bytes(dec, length)))
      23U => {
        let s = decode_ascii_bytes(read_bytes(dec, length))
        validate_time_string(s, tag_utc_time)
        UtcTime(s)
      }
      24U => {
        let s = decode_ascii_bytes(read_bytes(dec, length))
        validate_time_string(s, tag_generalized_time)
        GeneralizedTime(s)
      }
      3U => BitString(decode_bit_string(read_bytes(dec, length)))
      _ => Unknown(read_bytes(dec, length))
    }
  }
}

///|
fn decode_utf8_bytes(b : Bytes) -> String raise Asn1Error {
  @utf8.decode(b[:]) catch {
    _ => raise InvalidEncoding("invalid UTF-8")
  }
}

///|
fn decode_ascii_bytes(b : Bytes) -> String raise Asn1Error {
  // ASCII is a strict subset of UTF-8; enforce 0x00..0x7F per byte.
  for i in 0..<b.length() {
    if b[i].to_int() > 0x7F {
      raise InvalidEncoding("non-ASCII byte in ASCII string")
    }
  }
  decode_utf8_bytes(b)
}

///|
fn validate_ascii_string(s : String) -> Unit raise Asn1Error {
  for c in s {
    if c.to_int() > 0x7F {
      raise InvalidEncoding("non-ASCII character in ASCII string")
    }
  }
}

///|
fn validate_printable_string(s : String) -> Unit raise Asn1Error {
  for c in s {
    if !is_printable_string_char(c) {
      raise InvalidEncoding("character not allowed in PrintableString")
    }
  }
}

///|
fn is_printable_string_char(c : Char) -> Bool {
  let cp = c.to_int()
  (cp >= 0x41 && cp <= 0x5A) || // A-Z
  (cp >= 0x61 && cp <= 0x7A) || // a-z
  (cp >= 0x30 && cp <= 0x39) || // 0-9
  cp == 0x20 || // space
  cp == 0x27 || // apostrophe
  cp == 0x28 || // (
  cp == 0x29 || // )
  cp == 0x2B || // +
  cp == 0x2C || // ,
  cp == 0x2D || // -
  cp == 0x2E || // .
  cp == 0x2F || // /
  cp == 0x3A || // :
  cp == 0x3D || // =
  cp == 0x3F // ?
}

///|
fn validate_time_string(s : String, tag : Tag) -> Unit raise Asn1Error {
  validate_ascii_string(s)
  let (digits, year_at, month_at, day_at, hour_at, minute_at, second_at) = if tag ==
    tag_utc_time {
    (12, 0, 2, 4, 6, 8, 10)
  } else if tag == tag_generalized_time {
    (14, 0, 4, 6, 8, 10, 12)
  } else {
    raise InvalidEncoding("expected UTCTime / GeneralizedTime tag")
  }
  if s.length() != digits + 1 {
    raise InvalidEncoding("non-canonical time length")
  }
  if s.get_char(digits).unwrap() != 'Z' {
    raise InvalidEncoding("DER time must use Z timezone")
  }
  for i in 0..<digits {
    let c = s.get_char(i).unwrap()
    if c < '0' || c > '9' {
      raise InvalidEncoding("non-digit in time")
    }
  }
  let year = if tag == tag_utc_time {
    let yy = decimal2(s, year_at)
    if yy >= 50 {
      1900 + yy
    } else {
      2000 + yy
    }
  } else {
    decimal4(s, year_at)
  }
  if year <= 0 {
    raise InvalidEncoding("invalid time year")
  }
  let month = decimal2(s, month_at)
  let day = decimal2(s, day_at)
  let hour = decimal2(s, hour_at)
  let minute = decimal2(s, minute_at)
  let second = decimal2(s, second_at)
  if month < 1 || month > 12 {
    raise InvalidEncoding("invalid time month")
  }
  if day < 1 || day > days_in_month(year, month) {
    raise InvalidEncoding("invalid time day")
  }
  if hour > 23 || minute > 59 || second > 59 {
    raise InvalidEncoding("invalid time clock")
  }
}

///|
fn decimal2(s : String, offset : Int) -> Int {
  let hi = s.get_char(offset).unwrap().to_int() - '0'.to_int()
  let lo = s.get_char(offset + 1).unwrap().to_int() - '0'.to_int()
  hi * 10 + lo
}

///|
fn decimal4(s : String, offset : Int) -> Int {
  decimal2(s, offset) * 100 + decimal2(s, offset + 2)
}

///|
fn days_in_month(year : Int, month : Int) -> Int {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31
    4 | 6 | 9 | 11 => 30
    2 => if is_leap_year(year) { 29 } else { 28 }
    _ => 0
  }
}

///|
fn is_leap_year(year : Int) -> Bool {
  year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

///|
fn decode_bit_string(b : Bytes) -> BitString raise Asn1Error {
  if b.length() < 1 {
    raise InvalidEncoding("BitString missing unused-bits header")
  }
  let unused_bits = b[0].to_int()
  if unused_bits > 7 {
    raise InvalidEncoding("BitString unused_bits > 7")
  }
  if b.length() == 1 && unused_bits != 0 {
    raise InvalidEncoding("BitString unused_bits non-zero with empty data")
  }
  let bytes = Bytes::makei(b.length() - 1, fn(i) { b[i + 1] })
  validate_bit_string_tail(bytes, unused_bits) catch {
    _ => raise InvalidEncoding("BitString unused tail bits must be zero")
  }
  { bytes, unused_bits }
}

///|
fn validate_bit_string_tail(
  bytes : Bytes,
  unused_bits : Int,
) -> Unit raise Asn1Error {
  if unused_bits < 0 || unused_bits > 7 {
    raise InvalidEncoding("BitString unused_bits out of range")
  }
  if bytes.length() == 0 {
    if unused_bits != 0 {
      raise InvalidEncoding("BitString unused_bits non-zero with empty data")
    }
    return
  }
  if unused_bits > 0 {
    let mask = (1 << unused_bits) - 1
    let last = bytes[bytes.length() - 1].to_int()
    if (last & mask) != 0 {
      raise InvalidEncoding("BitString unused tail bits must be zero")
    }
  }
}

///|
fn validate_der_set_order(items : Array[Element]) -> Unit raise Asn1Error {
  let mut prev : Bytes? = None
  for item in items {
    let current = element_to_bytes_at(item, 0)
    match prev {
      Some(p) =>
        if bytes_lex_compare(p, current) > 0 {
          raise InvalidEncoding("SET items not in DER order")
        }
      None => ()
    }
    prev = Some(current)
  }
}

///|
fn bytes_lex_compare(a : Bytes, b : Bytes) -> Int {
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
pub fn Decoder::expect_tag(
  self : Decoder,
  expected : Tag,
) -> Element raise Asn1Error {
  let elem = self.read_element()
  if elem.tag != expected {
    raise UnexpectedTag(expected~, got=elem.tag)
  }
  elem
}

///|
pub struct Encoder {
  buf : Buffer
}

///|
pub fn Encoder::new() -> Encoder {
  { buf: Buffer() }
}

///|
pub fn Encoder::write_element(self : Encoder, element : Element) -> Unit {
  // Single-pass encoding: compute payload size first (alloc-free traversal),
  // then write tag + length + payload directly into the outer buffer.
  // Depth is bounded the same way the decoder bounds it (MAX_DEPTH=32);
  // without this an attacker-constructed Element with deeply nested
  // Sequence/Set could overflow the native stack via mutual recursion of
  // value_encoded_size and element_encoded_size.
  write_element_at(self, element, 0)
}

///|
fn write_element_at(enc : Encoder, element : Element, depth : Int) -> Unit {
  if depth > MAX_DEPTH {
    abort("asn1 encoder: depth exceeds MAX_DEPTH")
  }
  let payload_size = value_encoded_size_at(element.value, depth)
  write_tag(enc, element.tag)
  write_length(enc, payload_size)
  encode_value_at(enc, element.value, depth)
}

///|
fn value_encoded_size_at(value : Value, depth : Int) -> Int {
  if depth > MAX_DEPTH {
    abort("asn1 encoder: depth exceeds MAX_DEPTH")
  }
  match value {
    Null => 0
    Boolean(_) => 1
    Integer(b) => b.length()
    OctetString(b) => b.length()
    Utf8String(s) => utf8_byte_count(s)
    PrintableString(s) => {
      validate_printable_string(s) catch {
        e => abort("encode PrintableString: " + repr(e))
      }
      utf8_byte_count(s)
    }
    Ia5String(s) => {
      validate_ascii_string(s) catch {
        e => abort("encode IA5String: " + repr(e))
      }
      utf8_byte_count(s)
    }
    UtcTime(s) => {
      validate_time_string(s, tag_utc_time) catch {
        e => abort("encode UTCTime: " + repr(e))
      }
      utf8_byte_count(s)
    }
    GeneralizedTime(s) => {
      validate_time_string(s, tag_generalized_time) catch {
        e => abort("encode GeneralizedTime: " + repr(e))
      }
      utf8_byte_count(s)
    }
    BitString(bs) => {
      validate_bit_string_for_encode(bs)
      1 + bs.bytes.length()
    }
    Oid(oid) => oid_encoded_size(oid)
    Sequence(items) | Set(items) => {
      let mut total = 0
      for item in items {
        total = total + element_encoded_size_at(item, depth + 1)
      }
      total
    }
    Unknown(b) => b.length()
  }
}

///|
fn element_encoded_size_at(elem : Element, depth : Int) -> Int {
  let payload = value_encoded_size_at(elem.value, depth)
  tag_encoded_size(elem.tag) + length_encoded_size(payload) + payload
}

///|
fn element_to_bytes_at(elem : Element, depth : Int) -> Bytes {
  let enc = Encoder::new()
  write_element_at(enc, elem, depth)
  enc.finish()
}

///|
fn tag_encoded_size(tag : Tag) -> Int {
  if tag.number < 31U {
    1
  } else {
    let mut count = 1
    let mut tmp = tag.number
    while tmp > 0U {
      count = count + 1
      tmp = tmp >> 7
    }
    count
  }
}

///|
fn length_encoded_size(length : Int) -> Int {
  if length < 128 {
    1
  } else {
    let mut count = 1
    let mut tmp = length
    while tmp > 0 {
      count = count + 1
      tmp = tmp >> 8
    }
    count
  }
}

///|
fn oid_encoded_size(oid : ObjectIdentifier) -> Int {
  match oid_arc_validation_error(oid.arcs) {
    Some(msg) => abort("oid_encoded_size: " + msg)
    None => ()
  }
  let first = oid_first_subidentifier(oid)
  let mut size = base128_size(first)
  for i in 2..<oid.arcs.length() {
    size = size + base128_size(oid.arcs[i])
  }
  size
}

///|
fn base128_size(value : UInt) -> Int {
  if value == 0U {
    return 1
  }
  let mut count = 0
  let mut tmp = value
  while tmp > 0U {
    count = count + 1
    tmp = tmp >> 7
  }
  count
}

///|
fn utf8_byte_count(s : String) -> Int {
  let mut count = 0
  for c in s {
    let cp = c.to_int()
    count = count +
      (if cp < 0x80 {
        1
      } else if cp < 0x800 {
        2
      } else if cp < 0x10000 {
        3
      } else {
        4
      })
  }
  count
}

///|
fn validate_bit_string_for_encode(bs : BitString) -> Unit {
  validate_bit_string_tail(bs.bytes, bs.unused_bits) catch {
    e => abort("encode BIT STRING: " + repr(e))
  }
}

///|
fn encode_value_at(enc : Encoder, value : Value, depth : Int) -> Unit {
  match value {
    Null => ()
    Boolean(b) => enc.buf.write_byte((if b { 0xFF } else { 0 }).to_byte())
    Integer(bytes) => enc.buf.write_bytes(bytes)
    OctetString(bytes) => enc.buf.write_bytes(bytes)
    Utf8String(s) => encode_ascii_string(enc, s)
    PrintableString(s) => encode_ascii_string(enc, s)
    Ia5String(s) => encode_ascii_string(enc, s)
    UtcTime(s) => encode_ascii_string(enc, s)
    GeneralizedTime(s) => encode_ascii_string(enc, s)
    Sequence(items) =>
      for item in items {
        write_element_at(enc, item, depth + 1)
      }
    Set(items) => {
      let encoded = sorted_set_item_encodings(items, depth)
      for item in encoded {
        enc.buf.write_bytes(item)
      }
    }
    BitString(bs) => {
      enc.buf.write_byte(bs.unused_bits.to_byte())
      enc.buf.write_bytes(bs.bytes)
    }
    Oid(oid) => encode_oid(enc, oid)
    Unknown(bytes) => enc.buf.write_bytes(bytes)
  }
}

///|
fn sorted_set_item_encodings(
  items : Array[Element],
  depth : Int,
) -> Array[Bytes] {
  let encoded : Array[Bytes] = []
  for item in items {
    encoded.push(element_to_bytes_at(item, depth + 1))
  }
  encoded.sort_by(fn(a, b) { bytes_lex_compare(a, b) })
  encoded
}

///|
fn encode_ascii_string(enc : Encoder, s : String) -> Unit {
  // For Utf8String we go through the proper UTF-8 encoder; for the ASCII-only
  // string types (PrintableString / IA5String / UTCTime / GeneralizedTime) the
  // caller is expected to have provided characters in the U+0000..U+007F range,
  // which UTF-8 encodes identically to 7-bit ASCII.
  let bytes = @utf8.encode(s[:])
  enc.buf.write_bytes(bytes)
}

///|
pub fn Encoder::finish(self : Encoder) -> Bytes {
  self.buf.to_bytes()
}
