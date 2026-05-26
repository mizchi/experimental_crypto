///|
fn cn_oid() -> @asn1.ObjectIdentifier raise {
  @asn1.ObjectIdentifier::from_string("2.5.4.3")
}

///|
fn sha256_with_rsa() -> @asn1.ObjectIdentifier raise {
  @asn1.ObjectIdentifier::from_string("1.2.840.113549.1.1.11")
}

///|
fn rsa_encryption() -> @asn1.ObjectIdentifier raise {
  @asn1.ObjectIdentifier::from_string("1.2.840.113549.1.1.1")
}

///|
fn null_parameters() -> Bytes {
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_null, Null))
}

///|
fn cn(value : String) -> @pkix.AttributeTypeAndValue raise {
  {
    oid: cn_oid(),
    value: @asn1.Element::new(@asn1.tag_utf8_string, Utf8String(value)),
  }
}

///|
fn name_cn(value : String) -> @pkix.Name raise {
  { rdns: [[cn(value)]] }
}

///|
fn elem_from_der(bytes : Bytes) -> @asn1.Element {
  @asn1.decode_der(bytes) catch {
    _ => abort("test fixture DER failed")
  }
}

///|
fn concat_der(parts : Array[Bytes]) -> Bytes {
  let buf = Buffer()
  for p in parts {
    buf.write_bytes(p)
  }
  buf.to_bytes()
}

///|
fn raw_short_tlv(tag : Int, payload : Bytes) -> Bytes {
  if payload.length() >= 128 {
    abort("raw_short_tlv helper only supports short-form length")
  }
  let buf = Buffer()
  buf.write_byte(tag.to_byte())
  buf.write_byte(payload.length().to_byte())
  buf.write_bytes(payload)
  buf.to_bytes()
}

///|
fn raw_ascii_tlv(tag : Int, payload : String) -> Bytes {
  let buf = Buffer()
  for c in payload {
    let cp = c.to_int()
    if cp > 0x7F {
      abort("raw_ascii_tlv helper only supports ASCII")
    }
    buf.write_byte(cp.to_byte())
  }
  raw_short_tlv(tag, buf.to_bytes())
}

///|
fn explicit_version(version_bytes : Bytes) -> @asn1.Element {
  @asn1.Element::new(
    @asn1.Tag::context(0U, constructed=true),
    Unknown(
      @asn1.encode_der(
        @asn1.Element::new(@asn1.tag_integer, Integer(version_bytes)),
      ),
    ),
  )
}

///|
fn validity_elem(
  not_before : String,
  not_before_tag : @asn1.Tag,
  not_after : String,
  not_after_tag : @asn1.Tag,
) -> @asn1.Element {
  let nb_value = if not_before_tag == @asn1.tag_utc_time {
    @asn1.Value::UtcTime(not_before)
  } else {
    @asn1.Value::GeneralizedTime(not_before)
  }
  let na_value = if not_after_tag == @asn1.tag_utc_time {
    @asn1.Value::UtcTime(not_after)
  } else {
    @asn1.Value::GeneralizedTime(not_after)
  }
  @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(not_before_tag, nb_value),
      @asn1.Element::new(not_after_tag, na_value),
    ]),
  )
}

///|
fn base_tbs_items(
  version_bytes? : Bytes = b"\x02",
  serial? : Bytes = b"\x01",
  validity? : @asn1.Element,
) -> Array[@asn1.Element] raise {
  let cert = sample_cert()
  let validity_elem = match validity {
    Some(e) => e
    None =>
      validity_elem(
        cert.tbs.validity.not_before,
        cert.tbs.validity.not_before_tag,
        cert.tbs.validity.not_after,
        cert.tbs.validity.not_after_tag,
      )
  }
  [
    explicit_version(version_bytes),
    @asn1.Element::new(@asn1.tag_integer, Integer(serial)),
    @pkix.algorithm_identifier_to_element(cert.tbs.signature),
    elem_from_der(@pkix.serialize_name(cert.tbs.issuer)),
    validity_elem,
    elem_from_der(@pkix.serialize_name(cert.tbs.subject)),
    elem_from_der(
      @pkix.serialize_subject_public_key_info(cert.tbs.subject_public_key_info),
    ),
  ]
}

///|
fn cert_der_from_tbs_items(items : Array[@asn1.Element]) -> Bytes raise {
  let cert = sample_cert()
  @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([
        @asn1.Element::new(@asn1.tag_sequence, Sequence(items)),
        @pkix.algorithm_identifier_to_element(cert.signature_algorithm),
        @asn1.Element::new(@asn1.tag_bit_string, BitString(cert.signature)),
      ]),
    ),
  )
}

///|
fn sample_cert() -> @pkix.Certificate raise {
  let tbs : @pkix.TbsCertificate = {
    version: 2,
    serial_number: b"\x01",
    signature: {
      algorithm: sha256_with_rsa(),
      parameters: Some(null_parameters()),
    },
    issuer: name_cn("Test CA"),
    validity: {
      not_before: "230101000000Z",
      not_after: "330101000000Z",
      not_before_tag: @asn1.tag_utc_time,
      not_after_tag: @asn1.tag_utc_time,
    },
    subject: name_cn("Test Cert"),
    subject_public_key_info: {
      algorithm: {
        algorithm: rsa_encryption(),
        parameters: Some(null_parameters()),
      },
      subject_public_key: { bytes: b"\x00\x01\x02\x03", unused_bits: 0 },
    },
    issuer_unique_id: None,
    subject_unique_id: None,
    extensions: [],
  }
  {
    tbs,
    signature_algorithm: {
      algorithm: sha256_with_rsa(),
      parameters: Some(null_parameters()),
    },
    signature: { bytes: b"\xde\xad\xbe\xef", unused_bits: 0 },
  }
}

///|
test "pkix: roundtrip minimal v3 certificate" {
  let original = sample_cert()
  let bytes1 = @pkix.serialize_certificate(original)
  let parsed = @pkix.parse_certificate(bytes1)
  let bytes2 = @pkix.serialize_certificate(parsed)
  assert_eq(bytes1, bytes2)
}

///|
test "pkix: parse fields back from minimal v3 certificate" {
  let bytes = @pkix.serialize_certificate(sample_cert())
  let cert = @pkix.parse_certificate(bytes)
  assert_eq(cert.tbs.version, 2)
  assert_eq(cert.tbs.serial_number, b"\x01")
  assert_eq(cert.tbs.signature.algorithm, sha256_with_rsa())
  assert_eq(cert.tbs.validity.not_before, "230101000000Z")
  assert_eq(cert.tbs.validity.not_after, "330101000000Z")
  assert_eq(cert.tbs.extensions.length(), 0)
  assert_eq(cert.signature_algorithm.algorithm, sha256_with_rsa())
  assert_eq(cert.signature.bytes, b"\xde\xad\xbe\xef")
}

///|
test "pkix: parse subject CN" {
  let bytes = @pkix.serialize_certificate(sample_cert())
  let cert = @pkix.parse_certificate(bytes)
  assert_eq(cert.tbs.subject.rdns.length(), 1)
  assert_eq(cert.tbs.subject.rdns[0].length(), 1)
  let av = cert.tbs.subject.rdns[0][0]
  assert_eq(av.oid, cn_oid())
  match av.value.value {
    Utf8String(s) => assert_eq(s, "Test Cert")
    _ => assert_eq(true, false, msg="expected Utf8String CN")
  }
}

///|
test "pkix: roundtrip with extensions (subjectKeyIdentifier)" {
  let cert = sample_cert()
  let ski_oid = @asn1.ObjectIdentifier::from_string("2.5.29.14")
  let ski_inner = @asn1.encode_der(
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"\xab\xcd\xef\x01")),
  )
  let new_tbs : @pkix.TbsCertificate = {
    ..cert.tbs,
    extensions: [{ oid: ski_oid, critical: false, value: ski_inner }],
  }
  let new_cert : @pkix.Certificate = { ..cert, tbs: new_tbs }
  let bytes1 = @pkix.serialize_certificate(new_cert)
  let parsed = @pkix.parse_certificate(bytes1)
  let bytes2 = @pkix.serialize_certificate(parsed)
  assert_eq(bytes1, bytes2)
  assert_eq(parsed.tbs.extensions.length(), 1)
  assert_eq(parsed.tbs.extensions[0].oid, ski_oid)
  assert_eq(parsed.tbs.extensions[0].critical, false)
  assert_eq(parsed.tbs.extensions[0].value, ski_inner)
}

///|
test "pkix: v1 cert has version field elided" {
  let v1_cert : @pkix.Certificate = {
    ..sample_cert(),
    tbs: { ..sample_cert().tbs, version: 0 },
  }
  let bytes = @pkix.serialize_certificate(v1_cert)
  let parsed = @pkix.parse_certificate(bytes)
  assert_eq(parsed.tbs.version, 0)
  // v1 certs have no [0] EXPLICIT version wrapper, and no extensions allowed.
  assert_eq(parsed.tbs.extensions.length(), 0)
}

///|
test "pkix: serialize_name + parse_name roundtrip" {
  let name = name_cn("Test Cert")
  let bytes1 = @pkix.serialize_name(name)
  let parsed = @pkix.parse_name(bytes1)
  let bytes2 = @pkix.serialize_name(parsed)
  assert_eq(bytes1, bytes2)
}

///|
test "pkix: serialize_subject_public_key_info + parse roundtrip" {
  let spki : @pkix.SubjectPublicKeyInfo = {
    algorithm: {
      algorithm: rsa_encryption(),
      parameters: Some(null_parameters()),
    },
    subject_public_key: { bytes: b"\x00\x01\x02", unused_bits: 0 },
  }
  let bytes1 = @pkix.serialize_subject_public_key_info(spki)
  let parsed = @pkix.parse_subject_public_key_info(bytes1)
  let bytes2 = @pkix.serialize_subject_public_key_info(parsed)
  assert_eq(bytes1, bytes2)
}

///|
test "pkix: parse_certificate rejects non-SEQUENCE input" {
  match (try? @pkix.parse_certificate(b"\x05\x00")) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected error on NULL input")
  }
}

///|
test "pkix: parse_certificate rejects truncated input" {
  match (try? @pkix.parse_certificate(b"\x30\x82")) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected error on truncated input")
  }
}

///|
test "ATTACK pkix: explicit DEFAULT v1 version is rejected" {
  let der = cert_der_from_tbs_items(base_tbs_items(version_bytes=b"\x00"))
  match (try? @pkix.parse_certificate(der)) {
    Err(@pkix.UnexpectedStructure(_)) => ()
    other => abort("expected explicit default version rejection, got \{other}")
  }
}

///|
test "ATTACK pkix: serial number must be positive" {
  for serial in [b"\x00", b"\xff"] {
    let der = cert_der_from_tbs_items(base_tbs_items(serial~))
    match (try? @pkix.parse_certificate(der)) {
      Err(@pkix.UnexpectedStructure(_)) => ()
      other => abort("expected serial rejection, got \{other}")
    }
  }
}

///|
test "ATTACK pkix: invalid validity time syntax is rejected at parse" {
  let bad_validity = @asn1.Element::new(
    @asn1.tag_sequence,
    Unknown(
      concat_der([
        raw_ascii_tlv(0x17, "230101000000+0900"),
        raw_ascii_tlv(0x17, "330101000000Z"),
      ]),
    ),
  )
  let der = cert_der_from_tbs_items(base_tbs_items(validity=bad_validity))
  match (try? @pkix.parse_certificate(der)) {
    Err(@pkix.Asn1(@asn1.InvalidEncoding(_))) => ()
    Err(@pkix.InvalidTime(_)) => ()
    other => abort("expected InvalidTime, got \{other}")
  }
}

///|
test "ATTACK pkix: duplicate optional TBSCertificate fields are rejected" {
  let items = base_tbs_items()
  let empty_exts = @asn1.Element::new(@asn1.tag_sequence, Sequence([]))
  items.push(
    @asn1.Element::new(
      @asn1.Tag::context(3U, constructed=true),
      Unknown(@asn1.encode_der(empty_exts)),
    ),
  )
  items.push(
    @asn1.Element::new(
      @asn1.Tag::context(3U, constructed=true),
      Unknown(@asn1.encode_der(empty_exts)),
    ),
  )
  let der = cert_der_from_tbs_items(items)
  match (try? @pkix.parse_certificate(der)) {
    Err(@pkix.UnexpectedStructure(_)) => ()
    other => abort("expected duplicate extensions rejection, got \{other}")
  }
}

///|
test "ATTACK pkix: IMPLICIT uniqueID BIT STRING tail padding is checked" {
  let items = base_tbs_items(version_bytes=b"\x01")
  items.push(@asn1.Element::new(@asn1.Tag::context(1U), Unknown(b"\x01\x01")))
  let der = cert_der_from_tbs_items(items)
  match (try? @pkix.parse_certificate(der)) {
    Err(@pkix.UnexpectedStructure(_)) => ()
    other => abort("expected BIT STRING padding rejection, got \{other}")
  }
}

///|
test "ATTACK pkix: RDN SET order must be DER canonical" {
  let cn_av = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_oid, Oid(cn_oid())),
      @asn1.Element::new(@asn1.tag_utf8_string, Utf8String("b")),
    ]),
  )
  let country_av = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(
        @asn1.tag_oid,
        Oid(@asn1.ObjectIdentifier::from_string("2.5.4.6")),
      ),
      @asn1.Element::new(@asn1.tag_printable_string, PrintableString("US")),
    ]),
  )
  let noncanonical_set = raw_short_tlv(
    0x31,
    concat_der([@asn1.encode_der(country_av), @asn1.encode_der(cn_av)]),
  )
  let noncanonical_name = raw_short_tlv(0x30, noncanonical_set)
  match (try? @pkix.parse_name(noncanonical_name)) {
    Err(@pkix.Asn1(@asn1.InvalidEncoding(_))) => ()
    Err(@pkix.UnexpectedStructure(_)) => ()
    other => abort("expected RDN SET order rejection, got \{other}")
  }
}
