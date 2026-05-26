///|
fn ed25519_oid() -> @asn1.ObjectIdentifier raise {
  // id-Ed25519 from RFC 8410 §3.
  @asn1.ObjectIdentifier::from_string("1.3.101.112")
}

///|
fn pbes2_oid() -> @asn1.ObjectIdentifier raise {
  // id-PBES2 from RFC 8018 §A.4.
  @asn1.ObjectIdentifier::from_string("1.2.840.113549.1.5.13")
}

///|
fn sample_ed25519_key() -> @pkcs8.PrivateKeyInfo raise {
  // RFC 8410 §10.3 sample Ed25519 private key contents:
  //   privateKey OCTET STRING containing inner CurvePrivateKey OCTET STRING.
  // For PKCS#8 v1 the parameters of the algorithm are absent.
  let raw_seed : Bytes = b"\xD4\xEE\x72\xDB\xF9\x13\x58\x4A\xD5\xB6\xD8\xF1\xF7\x69\xF8\xAD\x3A\xFE\x7C\x28\xCB\xF1\xD4\xFB\xE0\x97\xA8\x8F\x44\x75\x58\x42"
  let inner = @asn1.encode_der(
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(raw_seed)),
  )
  {
    version: 0,
    algorithm: { algorithm: ed25519_oid(), parameters: None },
    private_key: inner,
    attributes: [],
    public_key: None,
  }
}

///|
fn pkcs8_base_items(version? : Bytes = b"\x00") -> Array[@asn1.Element] raise {
  let key = sample_ed25519_key()
  [
    @asn1.Element::new(@asn1.tag_integer, Integer(version)),
    @pkix.algorithm_identifier_to_element(key.algorithm),
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(key.private_key)),
  ]
}

///|
fn pkcs8_der_from_items(items : Array[@asn1.Element]) -> Bytes {
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence(items)))
}

///|
test "pkcs8: serialize/parse Ed25519 PrivateKeyInfo roundtrip" {
  let original = sample_ed25519_key()
  let bytes1 = @pkcs8.serialize_der(original)
  let parsed = @pkcs8.parse_der(bytes1)
  let bytes2 = @pkcs8.serialize_der(parsed)
  @debug.assert_eq(bytes1, bytes2)
  @debug.assert_eq(parsed.version, 0)
  @debug.assert_eq(parsed.algorithm.algorithm, ed25519_oid())
  @debug.assert_eq(parsed.algorithm.parameters, None)
  @debug.assert_eq(parsed.attributes.length(), 0)
  @debug.assert_eq(parsed.public_key, None)
}

///|
test "pkcs8: Ed25519 v2 with public_key roundtrip" {
  let v1 = sample_ed25519_key()
  let pubkey_bs : @asn1.BitString = {
    bytes: b"\x19\xBF\x44\x09\x69\x84\xCD\xFE\x85\x41\xBA\xC1\x67\xDC\x3B\x96\xC8\x50\x86\xAA\x30\xB6\xB6\xCB\x0C\x5C\x38\xAD\x70\x31\x66\xE1",
    unused_bits: 0,
  }
  let v2_key : @pkcs8.PrivateKeyInfo = {
    ..v1,
    version: 1,
    public_key: Some(pubkey_bs),
  }
  let bytes1 = @pkcs8.serialize_der(v2_key)
  let parsed = @pkcs8.parse_der(bytes1)
  let bytes2 = @pkcs8.serialize_der(parsed)
  @debug.assert_eq(bytes1, bytes2)
  @debug.assert_eq(parsed.version, 1)
  assert_true(parsed.public_key is Some(_))
  match parsed.public_key {
    Some(bs) => {
      @debug.assert_eq(bs.bytes, pubkey_bs.bytes)
      @debug.assert_eq(bs.unused_bits, 0)
    }
    None => @debug.assert_eq(true, false, msg="expected public_key")
  }
}

///|
test "pkcs8: PEM roundtrip with 'PRIVATE KEY' label" {
  let key = sample_ed25519_key()
  let pem = @pkcs8.serialize_pem(key)
  let parsed = @pkcs8.parse_pem(pem)
  @debug.assert_eq(parsed.algorithm.algorithm, ed25519_oid())
  @debug.assert_eq(parsed.private_key, key.private_key)
  // Verify the PEM body starts with the expected marker.
  assert_true(pem.length() > 30)
}

///|
test "pkcs8: parse_pem rejects wrong label" {
  let pem = @pem.encode_simple("CERTIFICATE", b"\x30\x02\x05\x00")
  try @pkcs8.parse_pem(pem) catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected label mismatch error")
  }
}

///|
test "pkcs8: parse_der rejects invalid version" {
  // SEQUENCE { INTEGER 5, SEQUENCE { OID 1.3.101.112 }, OCTET STRING "" }
  let bad_version_seq : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x05")),
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([@asn1.Element::new(@asn1.tag_oid, Oid(ed25519_oid()))]),
    ),
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"")),
  ]
  let bytes = @asn1.encode_der(
    @asn1.Element::new(@asn1.tag_sequence, Sequence(bad_version_seq)),
  )
  try @pkcs8.parse_der(bytes) catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidVersion")
  }
}

///|
test "pkcs8: parse_der rejects too few fields" {
  let truncated : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x00")),
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([@asn1.Element::new(@asn1.tag_oid, Oid(ed25519_oid()))]),
    ),
  ]
  let bytes = @asn1.encode_der(
    @asn1.Element::new(@asn1.tag_sequence, Sequence(truncated)),
  )
  try @pkcs8.parse_der(bytes) catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected too-few-fields error")
  }
}

///|
test "pkcs8: EncryptedPrivateKeyInfo roundtrip" {
  let enc : @pkcs8.EncryptedPrivateKeyInfo = {
    algorithm: { algorithm: pbes2_oid(), parameters: None },
    encrypted_data: b"\xCA\xFE\xBA\xBE\xDE\xAD\xBE\xEF",
  }
  let bytes1 = @pkcs8.serialize_encrypted_der(enc)
  let parsed = @pkcs8.parse_encrypted_der(bytes1)
  let bytes2 = @pkcs8.serialize_encrypted_der(parsed)
  @debug.assert_eq(bytes1, bytes2)
  @debug.assert_eq(parsed.algorithm.algorithm, pbes2_oid())
  @debug.assert_eq(parsed.encrypted_data, b"\xCA\xFE\xBA\xBE\xDE\xAD\xBE\xEF")
}

///|
test "pkcs8: EncryptedPrivateKeyInfo PEM roundtrip" {
  let enc : @pkcs8.EncryptedPrivateKeyInfo = {
    algorithm: { algorithm: pbes2_oid(), parameters: None },
    encrypted_data: b"\x01\x02\x03\x04\x05",
  }
  let pem = @pkcs8.serialize_encrypted_pem(enc)
  let parsed = @pkcs8.parse_encrypted_pem(pem)
  @debug.assert_eq(parsed.encrypted_data, enc.encrypted_data)
}

///|
test "pkcs8: PrivateKeyInfo with attributes (Set OF) roundtrips" {
  // Use a fake attribute: SEQUENCE { OID 2.5.29.17, SET { Utf8String "x" } }
  let attr_oid = @asn1.ObjectIdentifier::from_string("2.5.29.17")
  let attr : @asn1.Element = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_oid, Oid(attr_oid)),
      @asn1.Element::new(
        @asn1.tag_set,
        Set([@asn1.Element::new(@asn1.tag_utf8_string, Utf8String("x"))]),
      ),
    ]),
  )
  let key : @pkcs8.PrivateKeyInfo = {
    ..sample_ed25519_key(),
    attributes: [attr],
  }
  let bytes1 = @pkcs8.serialize_der(key)
  let parsed = @pkcs8.parse_der(bytes1)
  let bytes2 = @pkcs8.serialize_der(parsed)
  @debug.assert_eq(bytes1, bytes2)
  @debug.assert_eq(parsed.attributes.length(), 1)
}

///|
test "ATTACK pkcs8: duplicate publicKey fields reject" {
  let items = pkcs8_base_items(version=b"\x01")
  items.push(@asn1.Element::new(@asn1.Tag::context(1U), Unknown(b"\x00\x01")))
  items.push(@asn1.Element::new(@asn1.Tag::context(1U), Unknown(b"\x00\x02")))
  try @pkcs8.parse_der(pkcs8_der_from_items(items)) catch {
    @pkcs8.UnexpectedStructure(_) => ()
    other =>
      abort("expected duplicate publicKey rejection, got " + repr(other) + "")
  } noraise {
    other =>
      abort("expected duplicate publicKey rejection, got " + repr(other) + "")
  }
}

///|
test "ATTACK pkcs8: publicKey BIT STRING tail padding is checked" {
  let items = pkcs8_base_items(version=b"\x01")
  items.push(@asn1.Element::new(@asn1.Tag::context(1U), Unknown(b"\x01\x01")))
  try @pkcs8.parse_der(pkcs8_der_from_items(items)) catch {
    @pkcs8.UnexpectedStructure(_) => ()
    other =>
      abort("expected BIT STRING padding rejection, got " + repr(other) + "")
  } noraise {
    other =>
      abort("expected BIT STRING padding rejection, got " + repr(other) + "")
  }
}

///|
test "ATTACK pkcs8: duplicate attributes fields reject" {
  let attr_payload = @asn1.encode_der(
    @asn1.Element::new(@asn1.tag_sequence, Sequence([])),
  )
  let items = pkcs8_base_items()
  items.push(
    @asn1.Element::new(
      @asn1.Tag::context(0U, constructed=true),
      Unknown(attr_payload),
    ),
  )
  items.push(
    @asn1.Element::new(
      @asn1.Tag::context(0U, constructed=true),
      Unknown(attr_payload),
    ),
  )
  try @pkcs8.parse_der(pkcs8_der_from_items(items)) catch {
    @pkcs8.UnexpectedStructure(_) => ()
    other =>
      abort("expected duplicate attributes rejection, got " + repr(other) + "")
  } noraise {
    other =>
      abort("expected duplicate attributes rejection, got " + repr(other) + "")
  }
}

///|
test "ATTACK pkcs8: attributes SET order must be DER canonical" {
  let items = pkcs8_base_items()
  let attr_payload = Buffer()
  attr_payload.write_bytes(
    @asn1.encode_der(@asn1.Element::new(@asn1.tag_null, Null)),
  )
  attr_payload.write_bytes(
    @asn1.encode_der(
      @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"")),
    ),
  )
  items.push(
    @asn1.Element::new(
      @asn1.Tag::context(0U, constructed=true),
      Unknown(attr_payload.to_bytes()),
    ),
  )
  try @pkcs8.parse_der(pkcs8_der_from_items(items)) catch {
    @pkcs8.UnexpectedStructure(_) => ()
    other =>
      abort("expected attributes SET order rejection, got " + repr(other) + "")
  } noraise {
    other =>
      abort("expected attributes SET order rejection, got " + repr(other) + "")
  }
}
