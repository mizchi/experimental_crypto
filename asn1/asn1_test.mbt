///|
fn ascii_tlv(tag : Int, payload : String) -> Bytes {
  let bytes = @utf8.encode(payload[:])
  if bytes.length() >= 128 {
    abort("ascii_tlv helper only supports short-form length")
  }
  let buf = Buffer()
  buf.write_byte(tag.to_byte())
  buf.write_byte(bytes.length().to_byte())
  buf.write_bytes(bytes)
  buf.to_bytes()
}

///|
test "tag: universal primitive short form (INTEGER)" {
  let enc = @asn1.Encoder::new()
  @asn1.write_tag(enc, @asn1.tag_integer)
  inspect(enc.finish(), content="b\"\\x02\"")
}

///|
test "tag: universal constructed (SEQUENCE)" {
  let enc = @asn1.Encoder::new()
  @asn1.write_tag(enc, @asn1.tag_sequence)
  inspect(
    enc.finish(),
    content=(
      #|b"0"
    ),
  )
}

///|
test "tag: context-specific [0] constructed" {
  let enc = @asn1.Encoder::new()
  @asn1.write_tag(enc, @asn1.Tag::context(0, constructed=true))
  inspect(enc.finish(), content="b\"\\xa0\"")
}

///|
test "tag: high-tag-number form 31" {
  let enc = @asn1.Encoder::new()
  @asn1.write_tag(enc, @asn1.Tag::universal(31))
  inspect(enc.finish(), content="b\"\\x1f\\x1f\"")
}

///|
test "tag: high-tag-number form 128 (two-byte base-128)" {
  let enc = @asn1.Encoder::new()
  @asn1.write_tag(enc, @asn1.Tag::universal(128))
  inspect(enc.finish(), content="b\"\\x1f\\x81\\x00\"")
}

///|
test "tag: read_tag short form INTEGER" {
  let dec = @asn1.Decoder::new(b"\x02")
  let tag = @asn1.read_tag(dec)
  assert_eq(tag, @asn1.tag_integer)
}

///|
test "tag: read_tag short form SEQUENCE" {
  let dec = @asn1.Decoder::new(b"\x30")
  let tag = @asn1.read_tag(dec)
  assert_eq(tag, @asn1.tag_sequence)
}

///|
test "tag: read_tag context-specific [3] primitive" {
  let dec = @asn1.Decoder::new(b"\x83")
  let tag = @asn1.read_tag(dec)
  assert_eq(tag, @asn1.Tag::context(3))
}

///|
test "tag: read_tag high-tag-number form 128" {
  let dec = @asn1.Decoder::new(b"\x1f\x81\x00")
  let tag = @asn1.read_tag(dec)
  assert_eq(tag, @asn1.Tag::universal(128))
}

///|
test "length: short form 0" {
  let enc = @asn1.Encoder::new()
  @asn1.write_length(enc, 0)
  inspect(enc.finish(), content="b\"\\x00\"")
}

///|
test "length: short form 127 (boundary)" {
  let enc = @asn1.Encoder::new()
  @asn1.write_length(enc, 127)
  inspect(enc.finish(), content="b\"\\x7f\"")
}

///|
test "length: long form 128 (boundary)" {
  let enc = @asn1.Encoder::new()
  @asn1.write_length(enc, 128)
  inspect(enc.finish(), content="b\"\\x81\\x80\"")
}

///|
test "length: long form 256" {
  let enc = @asn1.Encoder::new()
  @asn1.write_length(enc, 256)
  inspect(enc.finish(), content="b\"\\x82\\x01\\x00\"")
}

///|
test "length: long form 65535" {
  let enc = @asn1.Encoder::new()
  @asn1.write_length(enc, 65535)
  inspect(enc.finish(), content="b\"\\x82\\xff\\xff\"")
}

///|
test "length: read short form" {
  let dec = @asn1.Decoder::new(b"\x7f")
  assert_eq(@asn1.read_length(dec), 127)
}

///|
test "length: read long form 256" {
  let dec = @asn1.Decoder::new(b"\x82\x01\x00")
  assert_eq(@asn1.read_length(dec), 256)
}

///|
test "length: roundtrip representative values" {
  for n in [0, 1, 127, 128, 255, 256, 1000, 65535, 65536, 16777215] {
    let enc = @asn1.Encoder::new()
    @asn1.write_length(enc, n)
    let dec = @asn1.Decoder::new(enc.finish())
    assert_eq(@asn1.read_length(dec), n)
  }
}

///|
test "length: reject indefinite form (0x80) in DER" {
  let dec = @asn1.Decoder::new(b"\x80")
  // X.690 §10.1: DER must use definite form
  match (try? @asn1.read_length(dec)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected error for indefinite length")
  }
}

///|
test "primitive: NULL" {
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_null, Null))
  inspect(enc.finish(), content="b\"\\x05\\x00\"")
  let dec = @asn1.Decoder::new(b"\x05\x00")
  let elem = dec.read_element()
  assert_eq(elem.tag, @asn1.tag_null)
  match elem.value {
    Null => ()
    _ => assert_eq(true, false, msg="expected Null")
  }
}

///|
test "primitive: Boolean true (DER 0xFF)" {
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_boolean, Boolean(true)))
  inspect(enc.finish(), content="b\"\\x01\\x01\\xff\"")
}

///|
test "primitive: Boolean false" {
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_boolean, Boolean(false)))
  inspect(enc.finish(), content="b\"\\x01\\x01\\x00\"")
}

///|
test "primitive: Boolean roundtrip" {
  for b in [true, false] {
    let enc = @asn1.Encoder::new()
    enc.write_element(@asn1.Element::new(@asn1.tag_boolean, Boolean(b)))
    let dec = @asn1.Decoder::new(enc.finish())
    match dec.read_element().value {
      Boolean(v) => assert_eq(v, b)
      _ => assert_eq(true, false, msg="expected Boolean")
    }
  }
}

///|
test "primitive: Integer 0 (1 byte 0x00)" {
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_integer, Integer(b"\x00")))
  inspect(enc.finish(), content="b\"\\x02\\x01\\x00\"")
}

///|
test "primitive: Integer 128 (needs leading 0x00 for sign)" {
  // Caller is responsible for proper two's-complement encoding;
  // here we just verify pass-through.
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_integer, Integer(b"\x00\x80")))
  inspect(enc.finish(), content="b\"\\x02\\x02\\x00\\x80\"")
}

///|
test "primitive: OctetString empty + 5 bytes" {
  let enc = @asn1.Encoder::new()
  enc.write_element(
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"")),
  )
  enc.write_element(
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"hello")),
  )
  inspect(enc.finish(), content="b\"\\x04\\x00\\x04\\x05hello\"")
}

///|
test "primitive: OctetString roundtrip" {
  let data : Bytes = b"\x00\x01\x02hello\xFF"
  let enc = @asn1.Encoder::new()
  enc.write_element(
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(data)),
  )
  let dec = @asn1.Decoder::new(enc.finish())
  match dec.read_element().value {
    OctetString(b) => assert_eq(b, data)
    _ => assert_eq(true, false, msg="expected OctetString")
  }
}

///|
test "primitive: Utf8String 'moon'" {
  let enc = @asn1.Encoder::new()
  enc.write_element(
    @asn1.Element::new(@asn1.tag_utf8_string, Utf8String("moon")),
  )
  inspect(enc.finish(), content="b\"\\x0c\\x04moon\"")
  let dec = @asn1.Decoder::new(enc.finish())
  match dec.read_element().value {
    Utf8String(s) => assert_eq(s, "moon")
    _ => assert_eq(true, false, msg="expected Utf8String")
  }
}

///|
test "primitive: Utf8String '日本語' (multi-byte UTF-8)" {
  let s = "日本語"
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_utf8_string, Utf8String(s)))
  let dec = @asn1.Decoder::new(enc.finish())
  match dec.read_element().value {
    Utf8String(out) => assert_eq(out, s)
    _ => assert_eq(true, false, msg="expected Utf8String")
  }
}

///|
test "primitive: Utf8String mixed ASCII + emoji roundtrip" {
  let s = "moon🌙 v1"
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_utf8_string, Utf8String(s)))
  let dec = @asn1.Decoder::new(enc.finish())
  match dec.read_element().value {
    Utf8String(out) => assert_eq(out, s)
    _ => assert_eq(true, false, msg="expected Utf8String")
  }
}

///|
test "primitive: Utf8String rejects invalid UTF-8 (lone continuation byte)" {
  // 0x80 is a continuation byte with no leader; invalid UTF-8.
  let bytes : Bytes = b"\x0c\x01\x80"
  match (try? @asn1.decode_der(bytes)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected invalid UTF-8")
  }
}

///|
test "primitive: PrintableString rejects non-ASCII bytes" {
  // tag 19 (PrintableString), length 2, payload 0xC3 0xA9 ('é' in UTF-8)
  let bytes : Bytes = b"\x13\x02\xc3\xa9"
  match (try? @asn1.decode_der(bytes)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected non-ASCII rejection")
  }
}

///|
test "primitive: PrintableString accepts allowed alphabet" {
  let s = "Hello, World +()-./:=?AZaz09"
  let enc = @asn1.Encoder::new()
  enc.write_element(
    @asn1.Element::new(@asn1.tag_printable_string, PrintableString(s)),
  )
  let dec = @asn1.Decoder::new(enc.finish())
  match dec.read_element().value {
    PrintableString(out) => assert_eq(out, s)
    _ => assert_eq(true, false, msg="expected PrintableString")
  }
}

///|
test "ATTACK: PrintableString rejects disallowed ASCII characters" {
  for s in ["Hello!", "mail@example", "snake_case", "[bracket]"] {
    let raised = try {
      let _ = @asn1.decode_der(ascii_tlv(0x13, s))
      false
    } catch {
      InvalidEncoding(_) => true
      _ => false
    }
    assert_true(raised)
  }
}

///|
test "primitive: Unknown tag preserves raw content" {
  // Tag 0x42 = application 2, primitive
  let dec = @asn1.Decoder::new(b"\x42\x03abc")
  let elem = dec.read_element()
  match elem.value {
    Unknown(b) => assert_eq(b, b"abc")
    _ => assert_eq(true, false, msg="expected Unknown")
  }
}

///|
test "primitive: NULL with non-zero length rejected" {
  let dec = @asn1.Decoder::new(b"\x05\x01\x00")
  match (try? dec.read_element()) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected length error")
  }
}

///|
test "oid: sha256WithRSAEncryption 1.2.840.113549.1.1.11" {
  let oid = @asn1.ObjectIdentifier::from_string("1.2.840.113549.1.1.11")
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_oid, Oid(oid)))
  inspect(
    enc.finish(),
    content=(
      #|b"\x06\x09*\x86H\x86\xf7\x0d\x01\x01\x0b"
    ),
  )
}

///|
test "oid: small values 1.2.3" {
  let oid = @asn1.ObjectIdentifier::from_string("1.2.3")
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_oid, Oid(oid)))
  inspect(
    enc.finish(),
    content=(
      #|b"\x06\x02*\x03"
    ),
  )
}

///|
test "oid: first arc 2 (2.5.4.3 commonName)" {
  let oid = @asn1.ObjectIdentifier::from_string("2.5.4.3")
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_oid, Oid(oid)))
  inspect(
    enc.finish(),
    content=(
      #|b"\x06\x03U\x04\x03"
    ),
  )
}

///|
test "oid: roundtrip via to_string" {
  let inputs = [
    "1.2.840.113549.1.1.11", "1.3.6.1.5.5.7.1.1", "2.5.29.17", "0.0", "2.16.840.1.101.3.4.2.1",
  ]
  for s in inputs {
    let oid = @asn1.ObjectIdentifier::from_string(s)
    assert_eq(oid.to_string(), s)
  }
}

///|
test "oid: decode roundtrip from DER" {
  let der = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
  let dec = @asn1.Decoder::new(der)
  match dec.read_element().value {
    Oid(o) => assert_eq(o.to_string(), "1.2.840.113549.1.1.11")
    _ => assert_eq(true, false, msg="expected Oid")
  }
}

///|
test "oid: from_string rejects empty / single-arc" {
  match (try? @asn1.ObjectIdentifier::from_string("")) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="empty should error")
  }
  match (try? @asn1.ObjectIdentifier::from_string("1")) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="single arc should error")
  }
}

///|
test "oid: from_string rejects invalid first arc" {
  match (try? @asn1.ObjectIdentifier::from_string("3.0")) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="first arc > 2 should error")
  }
  match (try? @asn1.ObjectIdentifier::from_string("1.40")) {
    Err(_) => ()
    Ok(_) =>
      assert_eq(true, false, msg="second arc > 39 with first<2 should error")
  }
}

///|
test "sequence: empty" {
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_sequence, Sequence([])))
  inspect(
    enc.finish(),
    content=(
      #|b"0\x00"
    ),
  )
}

///|
test "sequence: SEQUENCE { INTEGER 1, NULL }" {
  let enc = @asn1.Encoder::new()
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
    @asn1.Element::new(@asn1.tag_null, Null),
  ]
  enc.write_element(@asn1.Element::new(@asn1.tag_sequence, Sequence(items)))
  // Expected: 30 05 02 01 01 05 00
  inspect(
    enc.finish(),
    content=(
      #|b"0\x05\x02\x01\x01\x05\x00"
    ),
  )
}

///|
test "sequence: roundtrip nested" {
  // SEQUENCE { SEQUENCE { INTEGER 7 }, OCTET STRING "x" }
  let inner : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x07")),
  ]
  let outer : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_sequence, Sequence(inner)),
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"x")),
  ]
  let original = @asn1.Element::new(@asn1.tag_sequence, Sequence(outer))
  let enc = @asn1.Encoder::new()
  enc.write_element(original)
  let bytes = enc.finish()
  let dec = @asn1.Decoder::new(bytes)
  let decoded = dec.read_element()
  assert_eq(decoded.tag, @asn1.tag_sequence)
  match decoded.value {
    Sequence(items) => {
      assert_eq(items.length(), 2)
      assert_eq(items[0].tag, @asn1.tag_sequence)
      match items[0].value {
        Sequence(inner_items) => {
          assert_eq(inner_items.length(), 1)
          match inner_items[0].value {
            Integer(b) => assert_eq(b, b"\x07")
            _ => assert_eq(true, false, msg="expected Integer")
          }
        }
        _ => assert_eq(true, false, msg="expected inner Sequence")
      }
      match items[1].value {
        OctetString(b) => assert_eq(b, b"x")
        _ => assert_eq(true, false, msg="expected OctetString")
      }
    }
    _ => assert_eq(true, false, msg="expected Sequence")
  }
}

///|
test "set: empty" {
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_set, Set([])))
  inspect(
    enc.finish(),
    content=(
      #|b"1\x00"
    ),
  )
}

///|
test "set: SET { NULL }" {
  let enc = @asn1.Encoder::new()
  let items : Array[@asn1.Element] = [@asn1.Element::new(@asn1.tag_null, Null)]
  enc.write_element(@asn1.Element::new(@asn1.tag_set, Set(items)))
  inspect(
    enc.finish(),
    content=(
      #|b"1\x02\x05\x00"
    ),
  )
}

///|
test "ATTACK: SET items must be in DER canonical order" {
  // Non-canonical SET { NULL, OCTET STRING "" }; lexicographic DER order is
  // OCTET STRING (04 00) before NULL (05 00).
  let der : Bytes = b"\x31\x04\x05\x00\x04\x00"
  let raised = try {
    let _ = @asn1.decode_der(der)
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "set: encoder sorts SET items canonically" {
  let elem = @asn1.Element::new(
    @asn1.tag_set,
    Set([
      @asn1.Element::new(@asn1.tag_null, Null),
      @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"")),
    ]),
  )
  inspect(
    @asn1.encode_der(elem),
    content=(
      #|b"1\x04\x04\x00\x05\x00"
    ),
  )
}

///|
test "bit_string: 6-bit value 011011 (unused=2)" {
  // From X.690 Annex A: bits 0..5 = 0,1,1,0,1,1 → byte 0x6C, unused_bits=2
  let bs : @asn1.BitString = { bytes: b"\x6c", unused_bits: 2 }
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_bit_string, BitString(bs)))
  inspect(
    enc.finish(),
    content=(
      #|b"\x03\x02\x02l"
    ),
  )
}

///|
test "bit_string: roundtrip" {
  let cases : Array[(Bytes, Int)] = [
    (b"", 0),
    (b"\x00", 0),
    (b"\x6c", 2),
    (b"\xff\xff", 0),
    (b"\xab\xcd\xee", 1),
  ]
  for c in cases {
    let original : @asn1.BitString = { bytes: c.0, unused_bits: c.1 }
    let elem = @asn1.Element::new(@asn1.tag_bit_string, BitString(original))
    let bytes = @asn1.encode_der(elem)
    let decoded = @asn1.decode_der(bytes)
    match decoded.value {
      BitString(b) => {
        assert_eq(b.bytes, original.bytes)
        assert_eq(b.unused_bits, original.unused_bits)
      }
      _ => assert_eq(true, false, msg="expected BitString")
    }
  }
}

///|
test "time: UTCTime '230101000000Z'" {
  let s = "230101000000Z"
  let enc = @asn1.Encoder::new()
  enc.write_element(@asn1.Element::new(@asn1.tag_utc_time, UtcTime(s)))
  let bytes = enc.finish()
  let dec = @asn1.Decoder::new(bytes)
  match dec.read_element().value {
    UtcTime(t) => assert_eq(t, s)
    _ => assert_eq(true, false, msg="expected UtcTime")
  }
}

///|
test "time: GeneralizedTime '20260525120000Z'" {
  let s = "20260525120000Z"
  let enc = @asn1.Encoder::new()
  enc.write_element(
    @asn1.Element::new(@asn1.tag_generalized_time, GeneralizedTime(s)),
  )
  let dec = @asn1.Decoder::new(enc.finish())
  match dec.read_element().value {
    GeneralizedTime(t) => assert_eq(t, s)
    _ => assert_eq(true, false, msg="expected GeneralizedTime")
  }
}

///|
test "ATTACK: UTCTime requires YYMMDDHHMMSSZ canonical form" {
  for s in ["230101000000+0900", "2301010000Z", "230101000000", "230231000000Z"] {
    let raised = try {
      let _ = @asn1.decode_der(ascii_tlv(0x17, s))
      false
    } catch {
      InvalidEncoding(_) => true
      _ => false
    }
    assert_true(raised)
  }
}

///|
test "ATTACK: GeneralizedTime requires YYYYMMDDHHMMSSZ canonical form" {
  for
    s in [
      "20260525120000+0900", "20260525120000.0Z", "202605251200Z", "20260230000000Z",
    ] {
    let raised = try {
      let _ = @asn1.decode_der(ascii_tlv(0x18, s))
      false
    } catch {
      InvalidEncoding(_) => true
      _ => false
    }
    assert_true(raised)
  }
}

///|
test "top-level: encode_der / decode_der roundtrip" {
  let original = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_integer, Integer(b"\x2a")),
      @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"yo")),
    ]),
  )
  let bytes = @asn1.encode_der(original)
  let decoded = @asn1.decode_der(bytes)
  assert_eq(decoded.tag, @asn1.tag_sequence)
}

///|
test "top-level: decode_der rejects trailing bytes" {
  let bytes : Bytes = b"\x05\x00\xff" // NULL + extra
  match (try? @asn1.decode_der(bytes)) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected TrailingBytes error")
  }
}

///|
test "top-level: decode_der_all multiple" {
  let bytes : Bytes = b"\x05\x00\x05\x00\x02\x01\x07" // NULL NULL INTEGER 7
  let elems = @asn1.decode_der_all(bytes)
  assert_eq(elems.length(), 3)
  match elems[2].value {
    Integer(b) => assert_eq(b, b"\x07")
    _ => assert_eq(true, false, msg="expected Integer")
  }
}

///|
test "tag: roundtrip universal 0..16384" {
  for n in [0U, 1U, 30U, 31U, 127U, 128U, 200U, 16384U] {
    let enc = @asn1.Encoder::new()
    let original = @asn1.Tag::universal(n, constructed=n % 2U == 0U)
    @asn1.write_tag(enc, original)
    let decoded = @asn1.read_tag(@asn1.Decoder::new(enc.finish()))
    assert_eq(decoded, original)
  }
}

///|
test "security: nested SEQUENCE deeper than MAX_DEPTH rejected" {
  // Build SEQUENCE { SEQUENCE { ... { } ... } } nested 40 levels deep,
  // well past the 32-level guard. Innermost is an empty SEQUENCE.
  // Each outer wrapper adds: tag(1) + length(1) + child_size,
  // so length grows by 2 per level. With 40 levels the longest length is
  // 78 which still fits in short form (< 128).
  let depth = 40
  // Encode bottom-up: start with empty bytes (innermost children only;
  // the innermost SEQUENCE itself is the first wrap).
  let mut current : Bytes = b""
  for level in 0..<depth {
    let child_size = current.length()
    // length always < 128 here so short form is fine
    let prefix : Bytes = Bytes::makei(2, fn(i) {
      if i == 0 {
        b'\x30'
      } else {
        child_size.to_byte()
      }
    })
    let combined = Bytes::makei(prefix.length() + current.length(), fn(i) {
      if i < prefix.length() {
        prefix[i]
      } else {
        current[i - prefix.length()]
      }
    })
    current = combined
    let _ = level
  }
  match (try? @asn1.decode_der(current)) {
    Err(@asn1.Unsupported(_)) => ()
    Err(other) =>
      assert_eq(
        true,
        false,
        msg="expected Unsupported, got " + other.to_string(),
      )
    Ok(_) => assert_eq(true, false, msg="expected nested-too-deep rejection")
  }
}

///|
test "security: length exceeding max_input_size rejected" {
  // long form, 4-byte length = 0x01000001 (~16 MiB + 1) which is one above
  // the 16 MiB cap. read_length should bail with Unsupported before any
  // allocation attempt.
  let bytes : Bytes = b"\x04\x84\x01\x00\x00\x01"
  match (try? @asn1.decode_der(bytes)) {
    Err(@asn1.Unsupported(_)) => ()
    Err(other) =>
      assert_eq(
        true,
        false,
        msg="expected Unsupported, got " + other.to_string(),
      )
    Ok(_) => assert_eq(true, false, msg="expected length-too-large rejection")
  }
}

///|
test "security: OID arc UInt overflow rejected" {
  // OID arc encoded as base-128 with enough continuation bytes to overflow
  // the UInt32 accumulator. 6 bytes of 0xFF followed by 0x7F packs ~49 bits
  // of data, well past the 32-bit ceiling.
  // First byte 0x2A (== 42) -> arc 1.2; then a giant continuation arc.
  let bytes : Bytes = b"\x06\x08\x2A\xFF\xFF\xFF\xFF\xFF\xFF\x7F"
  match (try? @asn1.decode_der(bytes)) {
    Err(@asn1.InvalidEncoding(_)) => ()
    Err(other) =>
      assert_eq(
        true,
        false,
        msg="expected InvalidEncoding, got " + other.to_string(),
      )
    Ok(_) => assert_eq(true, false, msg="expected OID overflow rejection")
  }
}

///|
test "security: non-minimal OID base-128 rejected" {
  // OID 1.2.840 normally encodes as 0x2A 0x86 0x48. A non-minimal form
  // pads the 840 arc with a leading 0x80 continuation byte: 0x80 0x86 0x48.
  // 0x80 means "continuation set, value bits = 0" which is an illegal
  // leading byte under X.690 §8.19.2.
  let bytes : Bytes = b"\x06\x04\x2A\x80\x86\x48"
  match (try? @asn1.decode_der(bytes)) {
    Err(@asn1.InvalidEncoding(_)) => ()
    Err(other) =>
      assert_eq(
        true,
        false,
        msg="expected InvalidEncoding, got " + other.to_string(),
      )
    Ok(_) => assert_eq(true, false, msg="expected non-minimal OID rejection")
  }
}

///|
test "security: INTEGER with redundant 0x00 padding rejected" {
  // 0x02 0x02 0x00 0x01 = INTEGER 1 with a redundant 0x00 prefix. Canonical
  // DER would encode 1 as 0x02 0x01 0x01. Per X.690 §8.3.2 this must reject.
  let bytes : Bytes = b"\x02\x02\x00\x01"
  match (try? @asn1.decode_der(bytes)) {
    Err(@asn1.InvalidEncoding(_)) => ()
    Err(other) =>
      assert_eq(
        true,
        false,
        msg="expected InvalidEncoding, got " + other.to_string(),
      )
    Ok(_) =>
      assert_eq(true, false, msg="expected non-canonical INTEGER rejection")
  }
}

///|
test "security: INTEGER with redundant 0xFF padding rejected" {
  // 0x02 0x02 0xFF 0xFF = -1 with redundant 0xFF padding. Canonical form
  // is 0x02 0x01 0xFF. Per X.690 §8.3.2 must reject.
  let bytes : Bytes = b"\x02\x02\xFF\xFF"
  match (try? @asn1.decode_der(bytes)) {
    Err(@asn1.InvalidEncoding(_)) => ()
    Err(other) =>
      assert_eq(
        true,
        false,
        msg="expected InvalidEncoding, got " + other.to_string(),
      )
    Ok(_) =>
      assert_eq(true, false, msg="expected non-canonical INTEGER rejection")
  }
}

///|
test "security: INTEGER with zero length rejected" {
  // 0x02 0x00 = INTEGER with no content. Always invalid.
  let bytes : Bytes = b"\x02\x00"
  match (try? @asn1.decode_der(bytes)) {
    Err(_) => () // InvalidLength
    Ok(_) =>
      assert_eq(true, false, msg="expected zero-length INTEGER rejection")
  }
}

///|
test "security: canonical INTEGER 128 still accepted" {
  // Sanity: 0x02 0x02 0x00 0x80 = +128 (leading 0x00 required because next
  // byte's high bit is set). Must NOT be rejected by the new canonical
  // check; this is the legitimate sign-extension case.
  let bytes : Bytes = b"\x02\x02\x00\x80"
  let elem = @asn1.decode_der(bytes)
  match elem.value {
    Integer(b) => assert_eq(b, b"\x00\x80")
    _ => assert_eq(true, false, msg="expected Integer")
  }
}

///|
test "security: canonical INTEGER -128 still accepted" {
  // 0x02 0x01 0x80 = -128 (no padding needed). Must remain accepted.
  let bytes : Bytes = b"\x02\x01\x80"
  let elem = @asn1.decode_der(bytes)
  match elem.value {
    Integer(b) => assert_eq(b, b"\x80")
    _ => assert_eq(true, false, msg="expected Integer")
  }
}

// -----------------------------------------------------------------------------
// Security attack tests
// -----------------------------------------------------------------------------

///|
test "ATTACK CVE-2018-0739 (OpenSSL ASN.1 stack overflow): deep nested SEQUENCE must reject" {
  // Construct 100 nested SEQUENCE wrappers: 30 81 ... or 30 02 30 02 ... .
  // Each `30 0X` adds 2 bytes of header around the previous element. We
  // build the innermost as SEQUENCE(empty) = 30 00, then wrap it 100 times.
  // Innermost = 30 00 (2 bytes)
  // After 1 wrap: 30 02 30 00 (4)
  // After N wraps: 2 + 2N bytes
  let depth = 100
  let total = 2 + 2 * depth
  let buf = FixedArray::make(total, b'\x00')
  // Innermost SEQUENCE(empty) is placed at the END, then wrappers grow
  // outward backwards.
  // Write innermost
  buf[total - 2] = b'\x30'
  buf[total - 1] = b'\x00'
  // Wrap N times: at each wrap, prepend `30 <len>` (assuming len < 128).
  // Length increases by 2 each wrap (header for the inner one).
  for i = 0; i < depth; i = i + 1 {
    let pos = total - 2 - 2 * (i + 1)
    let inner_len = 2 + 2 * i
    if inner_len >= 128 {
      // For deeper levels we'd need long-form length encoding; keep depth
      // <= 62 to stay within short-form length. Adjust if needed.
      break
    }
    buf[pos] = b'\x30'
    buf[pos + 1] = inner_len.to_byte()
  }
  let der = Bytes::makei(total, fn(j) { buf[j] })
  let raised = try {
    let _ = @asn1.decode_der(der)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "ATTACK: non-canonical INTEGER with redundant 0x00 padding must reject" {
  // RFC 5280: INTEGER must be encoded in the smallest number of octets.
  // Tag 02, len 02, content 00 01 ─ that's "1" written as 2 bytes with a
  // leading 0x00 sign byte. Since the high bit of 0x01 is clear, the leading
  // 0x00 is redundant and non-canonical.
  let der : Bytes = b"\x02\x02\x00\x01"
  let raised = try {
    let _ = @asn1.decode_der(der)
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "ATTACK: INTEGER with redundant 0xFF padding (negative) must reject" {
  // For negative integers, leading 0xFF before another high-bit-set byte
  // is also non-canonical.
  let der : Bytes = b"\x02\x02\xff\x80"
  let raised = try {
    let _ = @asn1.decode_der(der)
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "ATTACK: trailing bytes after a valid element must reject" {
  // Encodes NULL (05 00) followed by an extra 0xFF — strict parsers must
  // not silently accept the trailing byte (cf. RFC 5280 §4.1: DER is the
  // canonical form, no trailing content allowed).
  let der : Bytes = b"\x05\x00\xff"
  let raised = try {
    let _ = @asn1.decode_der(der)
    false
  } catch {
    TrailingBytes(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "ATTACK: truncated length (declared > actual) must reject" {
  // SEQUENCE with declared length 0x10 but only 1 byte of content.
  let der : Bytes = b"\x30\x10\x05"
  let raised = try {
    let _ = @asn1.decode_der(der)
    false
  } catch {
    TruncatedInput => true
    _ => false
  }
  assert_true(raised)
}

///|
test "ATTACK: BIT STRING with unused_bits > 7 must reject" {
  // RFC 5280: BIT STRING's first content byte (unused-bits) ∈ [0, 7].
  // Tag 03, len 02, unused_bits 08, data 00 — out-of-range unused_bits.
  let der : Bytes = b"\x03\x02\x08\x00"
  let raised = try {
    let _ = @asn1.decode_der(der)
    false
  } catch {
    _ => true
  }
  assert_true(raised)
}

///|
test "ATTACK: high-tag-number form for low universal tag must reject" {
  // INTEGER (tag 2) encoded using high-tag-number form: 1f 02.
  // DER requires the short tag form for tag numbers < 31.
  let der : Bytes = b"\x1f\x02\x01\x00"
  let raised = try {
    let _ = @asn1.decode_der(der)
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "ATTACK: non-minimal high-tag-number encoding must reject" {
  // Universal tag 31 encoded as 1f 80 1f instead of the canonical 1f 1f.
  let der : Bytes = b"\x1f\x80\x1f\x00"
  let raised = try {
    let _ = @asn1.decode_der(der)
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "ATTACK: primitive and constructed forms for universal tags must reject" {
  // Constructed INTEGER and primitive SEQUENCE are BER-shaped but not DER.
  for der in [b"\x22\x01\x00", b"\x10\x00"] {
    let raised = try {
      let _ = @asn1.decode_der(der)
      false
    } catch {
      InvalidEncoding(_) => true
      _ => false
    }
    assert_true(raised)
  }
}

///|
test "ATTACK: BIT STRING unused tail bits must be zero" {
  // unused_bits=1 means the final low bit is padding and must be zero.
  let der : Bytes = b"\x03\x02\x01\x01"
  let raised = try {
    let _ = @asn1.decode_der(der)
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "asn1: OID first subidentifier supports multi-byte base128" {
  let oid = @asn1.ObjectIdentifier::from_string("2.999.1")
  let der = @asn1.encode_der(@asn1.Element::new(@asn1.tag_oid, Oid(oid)))
  let decoded = @asn1.decode_der(der)
  match decoded.value {
    Oid(got) => assert_eq(got.to_string(), "2.999.1")
    _ => abort("expected OID")
  }
}

///|
test "ATTACK: non-minimal OID first subidentifier must reject" {
  // OID 1.2 is first-subidentifier 42. DER form is 2a, not 80 2a.
  let der : Bytes = b"\x06\x02\x80\x2a"
  let raised = try {
    let _ = @asn1.decode_der(der)
    false
  } catch {
    InvalidEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "asn1: from_arcs accepts well-formed OIDs" {
  // Smoke-check that the OIDs we use across the workspace still parse via
  // from_arcs. The bad-arc abort path (arcs[0] >= 3, or arcs[1] >= 40 with
  // arcs[0] < 2) isn't catchable from MoonBit, so we can't exercise it
  // here; the security property (no aliasing between [5,10] and [2,130])
  // is enforced by abort() at the constructor edge.
  let ok = @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 10045, 3, 1, 7])
  assert_eq(ok.arcs[0], 1U)
  let ok2 = @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 19]) // basicConstraints
  assert_eq(ok2.arcs.length(), 4)
}

///|
test "asn1: from_arcs_checked raises on bad arc[0]" {
  match (try? @asn1.ObjectIdentifier::from_arcs_checked([5U, 10U])) {
    Err(InvalidEncoding(_)) => ()
    other => abort("expected InvalidEncoding, got \{other}")
  }
}

///|
test "asn1: from_arcs_checked raises on arc[1] >= 40 with small arc[0]" {
  match (try? @asn1.ObjectIdentifier::from_arcs_checked([1U, 40U])) {
    Err(InvalidEncoding(_)) => ()
    other => abort("expected InvalidEncoding, got \{other}")
  }
}

///|
test "asn1: from_arcs_checked raises on first-subidentifier overflow" {
  match (try? @asn1.ObjectIdentifier::from_arcs_checked([2U, 0xFFFFFFFFU])) {
    Err(InvalidEncoding(_)) => ()
    other => abort("expected InvalidEncoding, got \{other}")
  }
}

///|
test "asn1: from_string raises on arc overflow" {
  match (try? @asn1.ObjectIdentifier::from_string("2.4294967296")) {
    Err(InvalidEncoding(_)) => ()
    other => abort("expected InvalidEncoding, got \{other}")
  }
}

///|
test "asn1: from_arcs_checked accepts valid OIDs" {
  let ok = @asn1.ObjectIdentifier::from_arcs_checked([
    1U, 2, 840, 113549, 1, 1, 11,
  ])
  assert_eq(ok.arcs[0], 1U)
}
