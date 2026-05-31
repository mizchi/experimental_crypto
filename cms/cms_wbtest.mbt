// Whitebox tests for CMS signedAttrs invariants.

///|
fn hex_wb(s : String) -> Bytes {
  let n = s.length() / 2
  let arr = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble_wb(s.code_unit_at(i * 2).to_int())
    let lo = hex_nibble_wb(s.code_unit_at(i * 2 + 1).to_int())
    arr[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::makei(n, fn(i) { arr[i] })
}

///|
fn hex_nibble_wb(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    abort("bad hex")
  }
}

///|
fn concat_wb(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
fn elem_from_der_wb(der : Bytes) -> @asn1.Element raise {
  @asn1.decode_der(der)
}

///|
fn message_digest_attr_wb(digest_hex : String) -> Bytes {
  hex_wb("302f06092a864886f70d01090431220420" + digest_hex)
}

///|
fn content_type_attr_wb() -> Bytes {
  hex_wb("301806092a864886f70d010903310b06092a864886f70d010701")
}

///|
test "ATTACK cms: duplicate messageDigest attributes are malformed" {
  let digest = "000102030405060708090a0b0c0d0e0f" +
    "101112131415161718191a1b1c1d1e1f"
  let attr = message_digest_attr_wb(digest)
  let attrs = parse_attributes(concat_wb(attr, attr))
  try find_message_digest_attr(attrs) catch {
    Malformed(_) => ()
    _ => abort("unexpected error")
  } noraise {
    _ => abort("accepted duplicate messageDigest attributes")
  }
}

///|
test "ATTACK cms: duplicate contentType attributes are malformed" {
  let attr = content_type_attr_wb()
  let attrs = parse_attributes(concat_wb(attr, attr))
  try find_content_type_attr(attrs) catch {
    Malformed(_) => ()
    _ => abort("unexpected error")
  } noraise {
    _ => abort("accepted duplicate contentType attributes")
  }
}

///|
test "ATTACK cms: contentType attribute with multiple values is malformed" {
  let attr = hex_wb(
    "302306092a864886f70d010903311606092a864886f70d01070106092a864886f70d010701",
  )
  let attrs = parse_attributes(attr)
  try find_content_type_attr(attrs) catch {
    Malformed(_) => ()
    _ => abort("unexpected error")
  } noraise {
    _ => abort("accepted multi-valued contentType attribute")
  }
}

///|
test "ATTACK cms: missing contentType attribute is malformed" {
  let digest = "000102030405060708090a0b0c0d0e0f" +
    "101112131415161718191a1b1c1d1e1f"
  let attrs = parse_attributes(message_digest_attr_wb(digest))
  try find_content_type_attr(attrs) catch {
    Malformed(_) => ()
    _ => abort("unexpected error")
  } noraise {
    _ => abort("accepted signedAttrs without contentType")
  }
}

///|
test "ATTACK cms: messageDigest attribute with multiple values is malformed" {
  let digest_a = "000102030405060708090a0b0c0d0e0f" +
    "101112131415161718191a1b1c1d1e1f"
  let digest_b = "202122232425262728292a2b2c2d2e2f" +
    "303132333435363738393a3b3c3d3e3f"
  let attr = hex_wb(
    "305106092a864886f70d01090431440420" + digest_a + "0420" + digest_b,
  )
  let attrs = parse_attributes(attr)
  try find_message_digest_attr(attrs) catch {
    Malformed(_) => ()
    _ => abort("unexpected error")
  } noraise {
    _ => abort("accepted multi-valued messageDigest attribute")
  }
}

///|
test "ATTACK cms: unexpected SignerInfo trailing field is malformed" {
  let sid = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_sequence, Sequence([])),
      @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
    ]),
  )
  let signed_attrs = @asn1.Element::new(
    @asn1.Tag::context(0U, constructed=true),
    Unknown(b""),
  )
  let si = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
      sid,
      elem_from_der_wb(hex_wb("300b0609608648016503040201")),
      signed_attrs,
      elem_from_der_wb(hex_wb("300d06092a864886f70d0101010500")),
      @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"")),
      @asn1.Element::new(@asn1.tag_null, Null),
    ]),
  )
  try parse_signer_info(si) catch {
    Malformed(_) => ()
    _ => abort("unexpected error")
  } noraise {
    _ => abort("accepted SignerInfo with unexpected trailing field")
  }
}

///|
test "ATTACK cms: ECDSA signatureAlgorithm and digestAlgorithm must match" {
  let scalar = Bytes::makei(32, fn(i) {
    if i == 31 {
      b'\x01'
    } else {
      b'\x00'
    }
  })
  let sk = @p256.PrivateKey::from_bytes(scalar)
  let msg : Bytes = b"cms ecdsa digest mismatch"
  let sig = sk.sign(msg, format=@p256.SignatureFormat::Der)
  let pk : @pkix_verify.PublicKey = P256(sk.public_key())
  try
    verify_signature(id_ecdsa_with_sha256(), id_sha384(), pk, msg, sig)
  catch {
    UnsupportedSignatureAlgorithm(_) => ()
    _ => abort("unexpected error")
  } noraise {
    _ => abort("accepted ECDSA signatureAlgorithm/digestAlgorithm mismatch")
  }
}

///|
// RFC 5652 §5.3 subjectKeyIdentifier SignerIdentifier. The mizchi-test-ca
// fixture cert has no SKI of its own, so we parse it and graft an
// id-ce-subjectKeyIdentifier extension onto it via record update; this
// exercises the real cert_subject_key_id accessor and the cert_matches_sid SKI
// arm. This is the path that previously raised UnsupportedSid.
fn ski_fixture_cert_der() -> Bytes {
  hex_wb(
    "308202d8308201c0a003020102020900a77e5117403e54ff300d06092a864886f70d01010b050030193117301506035504030c0e6d697a6368692d746573742d6361301e170d3236303532363131313832335a170d3336303532333131313832335a30193117301506035504030c0e6d697a6368692d746573742d636130820122300d06092a864886f70d01010105000382010f003082010a0282010100dce2d67d96298d7d7488c43aa300c6cbd2174df92b7ce79b0abc9c212228f34acfb004deca8a6fcd3de41fba58b4ecdfb50893863733bcf394ea15eed35fc620cf3239ee61d16349dcdad1901b11ffb0237111b3557a86aa72ac02732fef4d2997fc91c9abc10c185248217a749fc560781c383be58e96703ffd24c0a9db5dda732699097fd4133a84bb862ee95ff3831cb0912347400512144cb3c733d21841dd5544a337a41d438e2ee70e6d1d71614324d1bb7058aa367645894dcccd354ce3d39b654a9d77986754cf45c82acc1549cada47603ee112ec33008a1c9c8c2b95d6d6010a4a0d2af848581c169ea64c4d098a6a7ad19d728254f029276534570203010001a3233021300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300d06092a864886f70d01010b05000382010100adaf2008e2fefa0b1e8f53f442da59aeb85c18dab3682a9e7bb6eab87ab6ecfc6a074a6628b1044b5e8abd14eee3f0e57f6291ec1b832af71625db6a775a667d55a0814e73cdc5ef0c5c076065b19e7a61d14bd62781929c2b2dadbf7df290c618782f69e6e088193dc4a0954d530f0b0ad0b7a19844adac5f4b05bdc58354c8edf214abe667b2a4f66a1ffd9c0400dfb0839b7ab9a2a08d37042a278ab9186c15ebdb87008f4522f19dba689917964a4b3ae36789515ccc5607db053b888383986ddbe8055a4e9c19d4056a48ecfee27f80e2878e71a68a5d3e2e66272fda2a9482ee62198b7d152e656a6a1ba2012a736f886a8a354649efdeef60b0cbe733",
  )
}

///|
test "cms SKI: cert_matches_sid resolves a cert by its SubjectKeyIdentifier" {
  let base = @pkix.parse_certificate(ski_fixture_cert_der())
  let key_id : Bytes = b"\x01\x02\x03\x04"
  // extnValue content for SubjectKeyIdentifier ::= OCTET STRING(01020304):
  // 0x04 (OCTET STRING) 0x04 (len) then the KeyIdentifier bytes.
  let ski_ext : @pkix.Extension = {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 14]),
    critical: false,
    value: b"\x04\x04\x01\x02\x03\x04",
  }
  let cert : @pkix.Certificate = {
    ..base,
    tbs: { ..base.tbs, extensions: [ski_ext] },
  }
  match cert_subject_key_id(cert) {
    Some(b) => assert_eq(b, key_id)
    None => abort("expected to read back the grafted SKI extension")
  }
  assert_eq(cert_matches_sid(cert, SubjectKeyId(key_id)), true)
  assert_eq(cert_matches_sid(cert, SubjectKeyId(b"\xde\xad\xbe\xef")), false)
  // A cert with no SKI extension never matches an SKI sid.
  assert_eq(cert_matches_sid(base, SubjectKeyId(key_id)), false)
}

///|
test "cms SKI: parse_signer_identifier decodes [0] subjectKeyIdentifier" {
  // [0] IMPLICIT OCTET STRING with a 4-byte KeyIdentifier: 80 04 01020304.
  let elem = @asn1.Element::new(
    @asn1.Tag::context(0U),
    Unknown(b"\x01\x02\x03\x04"),
  )
  match parse_signer_identifier(elem) {
    SubjectKeyId(b) => assert_eq(b, b"\x01\x02\x03\x04")
    IssuerAndSerial(_, _) => abort("expected SubjectKeyId from a [0] sid")
  }
}

///|
// Build a minimal but structurally valid SignerInfo Element with the given
// version and sid, so the version/sid coupling can be exercised through the
// full parse_signer_info path (not just parse_signer_identifier).
fn signer_info_with(version : Int, sid : @asn1.Element) -> @asn1.Element raise {
  let signed_attrs = @asn1.Element::new(
    @asn1.Tag::context(0U, constructed=true),
    Unknown(b""),
  )
  @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_integer, Integer(b_one(version.to_byte()))),
      sid,
      // digestAlgorithm: SEQUENCE { OID sha256 }
      elem_from_der_wb(hex_wb("300b0609608648016503040201")),
      signed_attrs,
      // signatureAlgorithm: SEQUENCE { OID rsaEncryption, NULL }
      elem_from_der_wb(hex_wb("300d06092a864886f70d0101010500")),
      @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"")),
    ]),
  )
}

///|
fn b_one(byte : Byte) -> Bytes {
  Bytes::makei(1, fn(_) { byte })
}

///|
// A [0] IMPLICIT subjectKeyIdentifier sid element carrying a 4-byte
// KeyIdentifier.
fn ski_sid_elem() -> @asn1.Element {
  @asn1.Element::new(@asn1.Tag::context(0U), Unknown(b"\x01\x02\x03\x04"))
}

///|
// An issuerAndSerialNumber sid element (empty issuer Name, serial 0x01).
fn ian_sid_elem() -> @asn1.Element {
  @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_sequence, Sequence([])),
      @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
    ]),
  )
}

///|
test "cms SKI: parse_signer_info accepts a v3 subjectKeyIdentifier SignerInfo" {
  // RFC 5652 §5.3: a subjectKeyIdentifier sid requires SignerInfo.version 3.
  let si = parse_signer_info(signer_info_with(3, ski_sid_elem()))
  match si.sid {
    SubjectKeyId(b) => assert_eq(b, b"\x01\x02\x03\x04")
    IssuerAndSerial(_, _) => abort("expected SubjectKeyId from a v3 SKI sid")
  }
}

///|
test "ATTACK cms: SKI sid with SignerInfo version 1 is rejected" {
  // subjectKeyIdentifier must be paired with version 3, not 1.
  try parse_signer_info(signer_info_with(1, ski_sid_elem())) catch {
    Malformed(_) => ()
    _ => abort("unexpected error")
  } noraise {
    _ => abort("accepted SKI sid with SignerInfo version 1")
  }
}

///|
test "ATTACK cms: issuerAndSerial sid with SignerInfo version 3 is rejected" {
  // issuerAndSerialNumber must be paired with version 1, not 3.
  try parse_signer_info(signer_info_with(3, ian_sid_elem())) catch {
    Malformed(_) => ()
    _ => abort("unexpected error")
  } noraise {
    _ => abort("accepted issuerAndSerial sid with SignerInfo version 3")
  }
}
