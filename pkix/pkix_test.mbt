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
fn sample_cert() -> @pkix.Certificate raise {
  let tbs : @pkix.TbsCertificate = {
    version: 2,
    serial_number: b"\x01",
    signature: { algorithm: sha256_with_rsa(), parameters: Some(null_parameters()) },
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
    algorithm: { algorithm: rsa_encryption(), parameters: Some(null_parameters()) },
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
