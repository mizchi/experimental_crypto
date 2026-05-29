// Blackbox tests for mizchi/p521. Use `@p521` to import.
//
// Vectors generated locally with openssl secp521r1 and SHA-512.

///|
fn hex(s : String) -> Bytes {
  fn nibble(c : Char) -> Int {
    let n = c.to_int()
    if n >= 0x30 && n <= 0x39 {
      n - 0x30
    } else if n >= 0x61 && n <= 0x66 {
      n - 0x61 + 10
    } else if n >= 0x41 && n <= 0x46 {
      n - 0x41 + 10
    } else {
      abort("bad hex")
    }
  }

  let len = s.length() / 2
  let out = FixedArray::make(len, b'\x00')
  let mut i = 0
  while i < len {
    let hi = nibble(s.get_char(i * 2).unwrap())
    let lo = nibble(s.get_char(i * 2 + 1).unwrap())
    out.unsafe_set(i, (hi * 16 + lo).to_byte())
    i = i + 1
  }
  Bytes::makei(len, fn(j) { out.unsafe_get(j) })
}

///|
// SPKI DER, namedCurve form (158 bytes). secp521r1.
fn vec_spki() -> Bytes {
  hex(
    "30819b301006072a8648ce3d020106052b81040023038186000400ec6fb8a65ce4fd6a23921b5ae8735a42df399ff0ac1aeaf2e7d8c858872f10e60bda513e80075ee18d74cb02fd8dc1c7db746987efb7ca255fff7956874cc71ebb00badd91cffc9a1671cf15a9fb0c7c1728af82b858eed68b3a688e15a7c8208c1a231e511f9f095a7fa9ee0de2b521d6c51fab93786412436b7786a2051ae5ffab4b",
  )
}

///|
// 04 || X(66) || Y(66).
fn vec_uncompressed() -> Bytes {
  hex(
    "0400ec6fb8a65ce4fd6a23921b5ae8735a42df399ff0ac1aeaf2e7d8c858872f10e60bda513e80075ee18d74cb02fd8dc1c7db746987efb7ca255fff7956874cc71ebb00badd91cffc9a1671cf15a9fb0c7c1728af82b858eed68b3a688e15a7c8208c1a231e511f9f095a7fa9ee0de2b521d6c51fab93786412436b7786a2051ae5ffab4b",
  )
}

///|
fn vec_msg() -> Bytes {
  // "hello mizchi"
  hex("68656c6c6f206d697a636869")
}

///|
// ASN.1 DER SEQUENCE { INTEGER r, INTEGER s } emitted by `openssl dgst -sha512 -sign`.
fn vec_sig_der() -> Bytes {
  hex(
    "308188024201b5cc90ee7d2463b3de643282b0eb65a24afc3be5ab37c23752b22c695cbe2b0aa1e21f80ab0a6759b8d270133110011909cf379c57d9b886f6cf78785f10c4f3e1024201e9302c9c514ff21f2b71deae547510f526e92d4baa82bd2a6873687f930ab05b20f7bd372095e49c5d975c307735dc8f04058448f4d74d2111b799e622c95907d2",
  )
}

///|
// JOSE form: r || s, 66+66 = 132 bytes BE. Extracted from the DER above by
// stripping the SEQUENCE/INTEGER tags and the leading 0x00 sign byte on r.
fn vec_sig_raw() -> Bytes {
  hex(
    "01b5cc90ee7d2463b3de643282b0eb65a24afc3be5ab37c23752b22c695cbe2b0aa1e21f80ab0a6759b8d270133110011909cf379c57d9b886f6cf78785f10c4f3e1" +
    "01e9302c9c514ff21f2b71deae547510f526e92d4baa82bd2a6873687f930ab05b20f7bd372095e49c5d975c307735dc8f04058448f4d74d2111b799e622c95907d2",
  )
}

///|
test "p521: verify openssl-generated DER signature" {
  let pk = @p521.PublicKey::from_spki_der(vec_spki())
  assert_true(@p521.verify(pk, vec_msg(), vec_sig_der(), Der))
}

///|
test "p521: verify openssl-generated raw r||s signature" {
  let pk = @p521.PublicKey::from_uncompressed(vec_uncompressed())
  assert_true(@p521.verify(pk, vec_msg(), vec_sig_raw(), Raw))
}

///|
test "p521: SPKI and uncompressed agree" {
  let a = @p521.PublicKey::from_spki_der(vec_spki())
  let b = @p521.PublicKey::from_uncompressed(vec_uncompressed())
  @debug.assert_eq(a.to_uncompressed(), b.to_uncompressed())
}

///|
test "p521: tampered message fails" {
  let pk = @p521.PublicKey::from_uncompressed(vec_uncompressed())
  let msg = vec_msg()
  let bad = Bytes::makei(msg.length(), fn(i) {
    if i == 0 {
      (msg[i].to_int() ^ 0x01).to_byte()
    } else {
      msg[i]
    }
  })
  assert_false(@p521.verify(pk, bad, vec_sig_der(), Der))
}

///|
test "p521: tampered signature fails" {
  let pk = @p521.PublicKey::from_uncompressed(vec_uncompressed())
  let sig = vec_sig_raw()
  let bad = Bytes::makei(132, fn(i) {
    if i == 0 {
      (sig[i].to_int() ^ 0x01).to_byte()
    } else {
      sig[i]
    }
  })
  assert_false(@p521.verify(pk, vec_msg(), bad, Raw))
}

///|
test "p521: r=0 rejected" {
  let pk = @p521.PublicKey::from_uncompressed(vec_uncompressed())
  let sig = vec_sig_raw()
  let zero_r = Bytes::makei(132, fn(i) { if i < 66 { b'\x00' } else { sig[i] } })
  assert_false(@p521.verify(pk, vec_msg(), zero_r, Raw))
}

///|
test "p521: wrong signature length rejected (Raw)" {
  let pk = @p521.PublicKey::from_uncompressed(vec_uncompressed())
  let short_sig = Bytes::makei(131, fn(_i) { b'\x00' })
  let raised = try {
    let _ = @p521.verify(pk, vec_msg(), short_sig, Raw)
    false
  } catch {
    InvalidSignatureLength(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p521: from_uncompressed rejects off-curve point" {
  let bad = Bytes::makei(133, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i == 132 {
      b'\x01'
    } else {
      b'\x00'
    }
  })
  let raised = try {
    let _ = @p521.PublicKey::from_uncompressed(bad)
    false
  } catch {
    PointNotOnCurve => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p521: from_uncompressed rejects compressed tag byte" {
  let unc = vec_uncompressed()
  let bad = Bytes::makei(133, fn(i) { if i == 0 { b'\x02' } else { unc[i] } })
  let raised = try {
    let _ = @p521.PublicKey::from_uncompressed(bad)
    false
  } catch {
    InvalidPointEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p521: from_uncompressed rejects non-canonical field coordinates" {
  let p = hex(
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  )
  let gy = hex(
    "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
  )
  fn assert_invalid(point : Bytes) -> Unit raise {
    let raised = try {
      let _ = @p521.PublicKey::from_uncompressed(point)
      false
    } catch {
      InvalidPointEncoding(_) => true
      _ => false
    }
    assert_true(raised)
  }
  let bad_x = Bytes::makei(133, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i < 67 {
      p[i - 1]
    } else {
      gy[i - 67]
    }
  })
  assert_invalid(bad_x)
  let gx = vec_uncompressed()[1:67]
  let bad_y = Bytes::makei(133, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i < 67 {
      gx[i - 1]
    } else {
      p[i - 67]
    }
  })
  assert_invalid(bad_y)
}

///|
test "p521: SPKI rejects wrong namedCurve" {
  // Hand-craft an SPKI with secp384r1 OID instead of secp521r1. The OID at
  // bytes 16..20 are `2b81040023` (= 1.3.132.0.35). Flip the last byte to
  // `22` (= P-384) and make sure the P-521 loader fails closed.
  let s = vec_spki()
  let bad = Bytes::makei(s.length(), fn(i) {
    if i == 20 {
      b'\x22'
    } else {
      s[i]
    }
  })
  let raised = try {
    let _ = @p521.PublicKey::from_spki_der(bad)
    false
  } catch {
    UnexpectedSpkiOid(_) => true
    Asn1(_) => true
    InvalidPointEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p521: SignatureFormat Debug" {
  @debug.assert_eq(@debug.to_string(@p521.SignatureFormat::Raw), "Raw")
  @debug.assert_eq(@debug.to_string(@p521.SignatureFormat::Der), "Der")
}

// -----------------------------------------------------------------------------
// Security attack tests
// -----------------------------------------------------------------------------

///|
test "ATTACK CVE-2022-21449 (Psychic Signatures): s=0 must be rejected" {
  let pk = @p521.PublicKey::from_uncompressed(vec_uncompressed())
  let sig = vec_sig_raw()
  let bad = Bytes::makei(132, fn(i) { if i < 66 { sig[i] } else { b'\x00' } })
  assert_false(@p521.verify(pk, vec_msg(), bad, Raw))
}

///|
test "ATTACK CVE-2022-21449: r=s=0 must be rejected" {
  let pk = @p521.PublicKey::from_uncompressed(vec_uncompressed())
  let bad = Bytes::makei(132, fn(_i) { b'\x00' })
  assert_false(@p521.verify(pk, vec_msg(), bad, Raw))
}

///|
test "ATTACK: s = n (P-521 order, boundary) must reject" {
  let pk = @p521.PublicKey::from_uncompressed(vec_uncompressed())
  // P-521 group order n.
  let n_hex = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
  let n = hex(n_hex)
  let r = vec_sig_raw()
  let bad = Bytes::makei(132, fn(i) { if i < 66 { r[i] } else { n[i - 66] } })
  assert_false(@p521.verify(pk, vec_msg(), bad, Raw))
}

///|
test "ATTACK CVE-2020-0601 (Curveball)-style on P-521: off-curve pubkey rejected" {
  let off_curve = Bytes::makei(133, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i == 66 {
      b'\x01'
    } else if i == 132 {
      b'\x02'
    } else {
      b'\x00'
    }
  })
  let raised = try {
    let _ = @p521.PublicKey::from_uncompressed(off_curve)
    false
  } catch {
    PointNotOnCurve => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p521: sign+verify roundtrip is deterministic" {
  let scalar = hex(
    "01026f3296840cb512d4ddf291aefb09399d7ba6a87ed08d058afb300a5bf0b983e5162efe6bc0e042073a29f8307a13ee9ecda8d1a8b7538845a504da0d6d4b92a2",
  )
  let sk = @p521.PrivateKey::from_bytes(scalar)
  let pk = sk.public_key()
  let msg : Bytes = b"hello p521 sign"
  let sig1 = sk.sign(msg)
  let sig2 = sk.sign(msg)
  @debug.assert_eq(sig1, sig2)
  assert_true(@p521.verify(pk, msg, sig1, Raw))
}

///|
test "p521: sign emits DER" {
  let scalar = hex(
    "01026f3296840cb512d4ddf291aefb09399d7ba6a87ed08d058afb300a5bf0b983e5162efe6bc0e042073a29f8307a13ee9ecda8d1a8b7538845a504da0d6d4b92a2",
  )
  let sk = @p521.PrivateKey::from_bytes(scalar)
  let pk = sk.public_key()
  let der = sk.sign(b"hello p521 sign", format=Der)
  @debug.assert_eq(der[0], b'\x30')
  assert_true(@p521.verify(pk, b"hello p521 sign", der, Der))
}

///|
test "ATTACK: p521.from_pkcs8_pem rejects legacy PEM headers" {
  let scalar = hex(
    "01026f3296840cb512d4ddf291aefb09399d7ba6a87ed08d058afb300a5bf0b983e5162efe6bc0e042073a29f8307a13ee9ecda8d1a8b7538845a504da0d6d4b92a2",
  )
  let sec1 = @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([
        @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
        @asn1.Element::new(@asn1.tag_octet_string, OctetString(scalar)),
      ]),
    ),
  )
  let info : @pkcs8.PrivateKeyInfo = {
    version: 0,
    algorithm: {
      algorithm: @asn1.ObjectIdentifier::from_string("1.2.840.10045.2.1"),
      parameters: Some(
        @asn1.encode_der(
          @asn1.Element::new(
            @asn1.tag_oid,
            Oid(@asn1.ObjectIdentifier::from_string("1.3.132.0.35")),
          ),
        ),
      ),
    },
    private_key: sec1,
    attributes: [],
    public_key: None,
  }
  let pem = @pem.encode({
    label: "PRIVATE KEY",
    data: @pkcs8.serialize_der(info),
    headers: [("Proc-Type", "4,ENCRYPTED")],
  })
  try @p521.PrivateKey::from_pkcs8_pem(pem) catch {
    InvalidPrivateKey(_) => ()
    other => abort("expected InvalidPrivateKey, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted P-521 PKCS#8 PEM with legacy headers")
  }
}

///|
test "ATTACK: p521.from_pkcs8_der rejects mismatched v2 publicKey" {
  let scalar = hex(
    "01026f3296840cb512d4ddf291aefb09399d7ba6a87ed08d058afb300a5bf0b983e5162efe6bc0e042073a29f8307a13ee9ecda8d1a8b7538845a504da0d6d4b92a2",
  )
  let sec1 = @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([
        @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
        @asn1.Element::new(@asn1.tag_octet_string, OctetString(scalar)),
      ]),
    ),
  )
  let wrong_public = Bytes::makei(133, fn(i) {
    if i == 0 {
      b'\x04'
    } else {
      b'\x00'
    }
  })
  let info : @pkcs8.PrivateKeyInfo = {
    version: 1,
    algorithm: {
      algorithm: @asn1.ObjectIdentifier::from_string("1.2.840.10045.2.1"),
      parameters: Some(
        @asn1.encode_der(
          @asn1.Element::new(
            @asn1.tag_oid,
            Oid(@asn1.ObjectIdentifier::from_string("1.3.132.0.35")),
          ),
        ),
      ),
    },
    private_key: sec1,
    attributes: [],
    public_key: Some({ bytes: wrong_public, unused_bits: 0 }),
  }
  try @p521.PrivateKey::from_pkcs8_der(@pkcs8.serialize_der(info)) catch {
    InvalidPrivateKey(_) => ()
    other => abort("expected InvalidPrivateKey, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted P-521 PKCS#8 with mismatched publicKey")
  }
}

///|
test "ATTACK: p521.from_pkcs8_der rejects unsupported SEC1 ECPrivateKey version" {
  let scalar = hex(
    "01026f3296840cb512d4ddf291aefb09399d7ba6a87ed08d058afb300a5bf0b983e5162efe6bc0e042073a29f8307a13ee9ecda8d1a8b7538845a504da0d6d4b92a2",
  )
  let sec1 = @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([
        @asn1.Element::new(@asn1.tag_integer, Integer(b"\x02")),
        @asn1.Element::new(@asn1.tag_octet_string, OctetString(scalar)),
      ]),
    ),
  )
  let info : @pkcs8.PrivateKeyInfo = {
    version: 0,
    algorithm: {
      algorithm: @asn1.ObjectIdentifier::from_string("1.2.840.10045.2.1"),
      parameters: Some(
        @asn1.encode_der(
          @asn1.Element::new(
            @asn1.tag_oid,
            Oid(@asn1.ObjectIdentifier::from_string("1.3.132.0.35")),
          ),
        ),
      ),
    },
    private_key: sec1,
    attributes: [],
    public_key: None,
  }
  try @p521.PrivateKey::from_pkcs8_der(@pkcs8.serialize_der(info)) catch {
    InvalidPrivateKey(_) => ()
    other => abort("expected InvalidPrivateKey, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted P-521 SEC1 ECPrivateKey version != 1")
  }
}

///|
test "ATTACK: p521.from_pkcs8_der rejects mismatched inner SEC1 publicKey" {
  let scalar = hex(
    "01026f3296840cb512d4ddf291aefb09399d7ba6a87ed08d058afb300a5bf0b983e5162efe6bc0e042073a29f8307a13ee9ecda8d1a8b7538845a504da0d6d4b92a2",
  )
  let wrong_public = Bytes::makei(133, fn(i) {
    if i == 0 {
      b'\x04'
    } else {
      b'\x00'
    }
  })
  let wrong_public_bit_string = @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_bit_string,
      BitString({ bytes: wrong_public, unused_bits: 0 }),
    ),
  )
  let sec1 = @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([
        @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
        @asn1.Element::new(@asn1.tag_octet_string, OctetString(scalar)),
        @asn1.Element::new(
          @asn1.Tag::context(1U, constructed=true),
          Unknown(wrong_public_bit_string),
        ),
      ]),
    ),
  )
  let info : @pkcs8.PrivateKeyInfo = {
    version: 0,
    algorithm: {
      algorithm: @asn1.ObjectIdentifier::from_string("1.2.840.10045.2.1"),
      parameters: Some(
        @asn1.encode_der(
          @asn1.Element::new(
            @asn1.tag_oid,
            Oid(@asn1.ObjectIdentifier::from_string("1.3.132.0.35")),
          ),
        ),
      ),
    },
    private_key: sec1,
    attributes: [],
    public_key: None,
  }
  try @p521.PrivateKey::from_pkcs8_der(@pkcs8.serialize_der(info)) catch {
    InvalidPrivateKey(_) => ()
    other => abort("expected InvalidPrivateKey, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted P-521 SEC1 ECPrivateKey with mismatched publicKey")
  }
}

///|
test "ATTACK: p521.from_pkcs8_der rejects unexpected SEC1 trailing fields" {
  let scalar = hex(
    "01026f3296840cb512d4ddf291aefb09399d7ba6a87ed08d058afb300a5bf0b983e5162efe6bc0e042073a29f8307a13ee9ecda8d1a8b7538845a504da0d6d4b92a2",
  )
  let sec1 = @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([
        @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
        @asn1.Element::new(@asn1.tag_octet_string, OctetString(scalar)),
        @asn1.Element::new(@asn1.tag_null, Null),
      ]),
    ),
  )
  let info : @pkcs8.PrivateKeyInfo = {
    version: 0,
    algorithm: {
      algorithm: @asn1.ObjectIdentifier::from_string("1.2.840.10045.2.1"),
      parameters: Some(
        @asn1.encode_der(
          @asn1.Element::new(
            @asn1.tag_oid,
            Oid(@asn1.ObjectIdentifier::from_string("1.3.132.0.35")),
          ),
        ),
      ),
    },
    private_key: sec1,
    attributes: [],
    public_key: None,
  }
  try @p521.PrivateKey::from_pkcs8_der(@pkcs8.serialize_der(info)) catch {
    InvalidPrivateKey(_) => ()
    other => abort("expected InvalidPrivateKey, got " + repr(other) + "")
  } noraise {
    _ =>
      abort("accepted P-521 SEC1 ECPrivateKey with unexpected trailing field")
  }
}
