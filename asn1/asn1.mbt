///|
pub(all) enum TagClass {
  Universal
  Application
  ContextSpecific
  Private
} derive(Eq, Show, Hash)

///|
pub struct Tag {
  class_ : TagClass
  number : UInt
  constructed : Bool
} derive(Eq, Show, Hash)

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
} derive(Eq, Show, Hash)

///|
pub fn ObjectIdentifier::from_arcs(arcs : Array[UInt]) -> ObjectIdentifier {
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
      if not(has_digit) {
        raise InvalidEncoding("empty arc in OID")
      }
      arcs.push(current)
      current = 0U
      has_digit = false
    } else if c >= '0' && c <= '9' {
      let d = (c.to_int() - '0'.to_int()).reinterpret_as_uint()
      current = current * 10U + d
      has_digit = true
    } else {
      raise InvalidEncoding("non-digit in OID string")
    }
  }
  if not(has_digit) {
    raise InvalidEncoding("trailing dot in OID")
  }
  arcs.push(current)
  if arcs.length() < 2 {
    raise InvalidEncoding("OID must have at least two arcs")
  }
  if arcs[0] > 2U {
    raise InvalidEncoding("first arc must be 0, 1, or 2")
  }
  if arcs[0] < 2U && arcs[1] >= 40U {
    raise InvalidEncoding("second arc must be < 40 when first arc is 0 or 1")
  }
  { arcs, }
}

///|
pub fn ObjectIdentifier::to_string(self : ObjectIdentifier) -> String {
  let buf = StringBuilder::new()
  let mut first = true
  for a in self.arcs {
    if not(first) {
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
  if oid.arcs.length() < 2 {
    abort("encode_oid: OID has fewer than 2 arcs")
  }
  let first = oid.arcs[0] * 40U + oid.arcs[1]
  write_base128(enc, first)
  for i in 2..<oid.arcs.length() {
    write_base128(enc, oid.arcs[i])
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
  let first = bytes[0].to_int().reinterpret_as_uint()
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
  let mut i = 1
  while i < bytes.length() {
    let mut value : UInt = 0U
    while true {
      if i >= bytes.length() {
        raise InvalidEncoding("truncated OID arc")
      }
      let b = bytes[i].to_int()
      value = (value << 7) | (b & 0x7F).reinterpret_as_uint()
      i = i + 1
      if (b & 0x80) == 0 {
        break
      }
    }
    arcs.push(value)
  }
  { arcs, }
}

///|
pub(all) struct BitString {
  bytes : Bytes
  unused_bits : Int
} derive(Eq, Show)

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
} derive(Show)

///|
pub struct Element {
  tag : Tag
  value : Value
} derive(Show)

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
} derive(Show)

///|
pub fn decode_der(input : Bytes) -> Element raise Asn1Error {
  let dec = Decoder::new(input)
  let elem = dec.read_element()
  if not(dec.is_empty()) {
    raise TrailingBytes(dec.remaining())
  }
  elem
}

///|
pub fn decode_der_all(input : Bytes) -> Array[Element] raise Asn1Error {
  let dec = Decoder::new(input)
  let items = []
  while not(dec.is_empty()) {
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
    while not(done) {
      if dec.remaining() < 1 {
        raise TruncatedInput
      }
      let b = dec.input[dec.pos].to_int()
      dec.pos = dec.pos + 1
      n = (n << 7) | (b & 0x7F).reinterpret_as_uint()
      if (b & 0x80) == 0 {
        done = true
      }
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
  value
}

///|
pub struct Decoder {
  input : Bytes
  mut pos : Int
}

///|
pub fn Decoder::new(input : Bytes) -> Decoder {
  { input, pos: 0 }
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
  let length = read_length(self)
  if self.remaining() < length {
    raise TruncatedInput
  }
  let value = decode_value(self, tag, length)
  { tag, value }
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
        let inner = Decoder::new(read_bytes(dec, length))
        let items = []
        while not(inner.is_empty()) {
          items.push(inner.read_element())
        }
        Sequence(items)
      }
      17U => {
        let inner = Decoder::new(read_bytes(dec, length))
        let items = []
        while not(inner.is_empty()) {
          items.push(inner.read_element())
        }
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
      2U => Integer(read_bytes(dec, length))
      4U => OctetString(read_bytes(dec, length))
      5U => {
        if length != 0 {
          raise InvalidLength
        }
        Null
      }
      6U => Oid(decode_oid(read_bytes(dec, length)))
      12U => Utf8String(decode_utf8_bytes(read_bytes(dec, length)))
      19U => PrintableString(decode_ascii_bytes(read_bytes(dec, length)))
      22U => Ia5String(decode_ascii_bytes(read_bytes(dec, length)))
      23U => UtcTime(decode_ascii_bytes(read_bytes(dec, length)))
      24U => GeneralizedTime(decode_ascii_bytes(read_bytes(dec, length)))
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
  { bytes, unused_bits }
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
  // then write tag + length + payload directly into the outer buffer. This
  // avoids the inner Encoder + Bytes copy that the old two-pass version did.
  let payload_size = value_encoded_size(element.value)
  write_tag(self, element.tag)
  write_length(self, payload_size)
  encode_value(self, element.value)
}

///|
fn value_encoded_size(value : Value) -> Int {
  match value {
    Null => 0
    Boolean(_) => 1
    Integer(b) => b.length()
    OctetString(b) => b.length()
    Utf8String(s) => utf8_byte_count(s)
    PrintableString(s) => utf8_byte_count(s)
    Ia5String(s) => utf8_byte_count(s)
    UtcTime(s) => utf8_byte_count(s)
    GeneralizedTime(s) => utf8_byte_count(s)
    BitString(bs) => 1 + bs.bytes.length()
    Oid(oid) => oid_encoded_size(oid)
    Sequence(items) | Set(items) => {
      let mut total = 0
      for item in items {
        total = total + element_encoded_size(item)
      }
      total
    }
    Unknown(b) => b.length()
  }
}

///|
fn element_encoded_size(elem : Element) -> Int {
  let payload = value_encoded_size(elem.value)
  tag_encoded_size(elem.tag) + length_encoded_size(payload) + payload
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
  if oid.arcs.length() < 2 {
    abort("oid_encoded_size: OID has fewer than 2 arcs")
  }
  let first = oid.arcs[0] * 40U + oid.arcs[1]
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
fn encode_value(enc : Encoder, value : Value) -> Unit {
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
    Sequence(items) | Set(items) =>
      for item in items {
        enc.write_element(item)
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
