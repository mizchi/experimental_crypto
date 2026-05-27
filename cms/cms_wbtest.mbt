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
