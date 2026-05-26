// Blackbox tests for mizchi/p384. Use `@p384` to import.
//
// Vectors generated locally with openssl secp384r1 and SHA-384.

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
// SPKI DER, namedCurve form (120 bytes). secp384r1.
fn vec_spki() -> Bytes {
  hex(
    "3076301006072a8648ce3d020106052b8104002203620004fa918c3751c0b9adcd761351c9852ff7635ee3b696150bca4655a37583b5fc3f7c2e3aeb55eb4bc5d94e04e6ccc577f7cfab8c58bc51062ab204523d6e065fe54352340f069d5a395ededcbf1a363178b035a281dd2ee60369317f985a654b05",
  )
}

///|
// 04 || X(48) || Y(48).
fn vec_uncompressed() -> Bytes {
  hex(
    "04fa918c3751c0b9adcd761351c9852ff7635ee3b696150bca4655a37583b5fc3f7c2e3aeb55eb4bc5d94e04e6ccc577f7cfab8c58bc51062ab204523d6e065fe54352340f069d5a395ededcbf1a363178b035a281dd2ee60369317f985a654b05",
  )
}

///|
fn vec_msg() -> Bytes {
  // "hello mizchi"
  hex("68656c6c6f206d697a636869")
}

///|
// ASN.1 DER SEQUENCE { INTEGER r, INTEGER s } emitted by `openssl dgst -sha384 -sign`.
fn vec_sig_der() -> Bytes {
  hex(
    "3065023100b83dab4d89a85867caaa062b7f88ec9284ee66bb1fad9dd2eca96e9dc00bb1bd8d303023012d914e62672f44d126196f02302197dc01f9cc0c2838451e99b61a55fa58f4e7d9697afefa7c2daacf8c871113e5c76b0dbf73f41ab0045dc8d442560b",
  )
}

///|
// JOSE form: r || s, 48+48 = 96 bytes BE. Extracted from the DER above by
// stripping the SEQUENCE/INTEGER tags and the leading 0x00 sign byte on r.
fn vec_sig_raw() -> Bytes {
  hex(
    "b83dab4d89a85867caaa062b7f88ec9284ee66bb1fad9dd2eca96e9dc00bb1bd8d303023012d914e62672f44d126196f" +
    "2197dc01f9cc0c2838451e99b61a55fa58f4e7d9697afefa7c2daacf8c871113e5c76b0dbf73f41ab0045dc8d442560b",
  )
}

///|
test "p384: verify openssl-generated DER signature" {
  let pk = @p384.PublicKey::from_spki_der(vec_spki())
  assert_true(@p384.verify(pk, vec_msg(), vec_sig_der(), Der))
}

///|
test "p384: verify openssl-generated raw r||s signature" {
  let pk = @p384.PublicKey::from_uncompressed(vec_uncompressed())
  assert_true(@p384.verify(pk, vec_msg(), vec_sig_raw(), Raw))
}

///|
test "p384: SPKI and uncompressed agree" {
  let a = @p384.PublicKey::from_spki_der(vec_spki())
  let b = @p384.PublicKey::from_uncompressed(vec_uncompressed())
  @debug.assert_eq(a.to_uncompressed(), b.to_uncompressed())
}

///|
test "p384: tampered message fails" {
  let pk = @p384.PublicKey::from_uncompressed(vec_uncompressed())
  let msg = vec_msg()
  let bad = Bytes::makei(msg.length(), fn(i) {
    if i == 0 {
      (msg[i].to_int() ^ 0x01).to_byte()
    } else {
      msg[i]
    }
  })
  assert_false(@p384.verify(pk, bad, vec_sig_der(), Der))
}

///|
test "p384: tampered signature fails" {
  let pk = @p384.PublicKey::from_uncompressed(vec_uncompressed())
  let sig = vec_sig_raw()
  let bad = Bytes::makei(96, fn(i) {
    if i == 0 {
      (sig[i].to_int() ^ 0x01).to_byte()
    } else {
      sig[i]
    }
  })
  assert_false(@p384.verify(pk, vec_msg(), bad, Raw))
}

///|
test "p384: r=0 rejected" {
  let pk = @p384.PublicKey::from_uncompressed(vec_uncompressed())
  let sig = vec_sig_raw()
  let zero_r = Bytes::makei(96, fn(i) { if i < 48 { b'\x00' } else { sig[i] } })
  assert_false(@p384.verify(pk, vec_msg(), zero_r, Raw))
}

///|
test "p384: wrong signature length rejected (Raw)" {
  let pk = @p384.PublicKey::from_uncompressed(vec_uncompressed())
  let short_sig = Bytes::makei(95, fn(_i) { b'\x00' })
  let raised = try {
    let _ = @p384.verify(pk, vec_msg(), short_sig, Raw)
    false
  } catch {
    InvalidSignatureLength(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p384: from_uncompressed rejects off-curve point" {
  let bad = Bytes::makei(97, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i == 96 {
      b'\x01'
    } else {
      b'\x00'
    }
  })
  let raised = try {
    let _ = @p384.PublicKey::from_uncompressed(bad)
    false
  } catch {
    PointNotOnCurve => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p384: from_uncompressed rejects compressed tag byte" {
  let unc = vec_uncompressed()
  let bad = Bytes::makei(97, fn(i) { if i == 0 { b'\x02' } else { unc[i] } })
  let raised = try {
    let _ = @p384.PublicKey::from_uncompressed(bad)
    false
  } catch {
    InvalidPointEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p384: SPKI rejects wrong namedCurve" {
  // Hand-craft an SPKI with secp256r1 OID instead of secp384r1. The OID at
  // bytes 18..23 is `2b8104002203` (= 1.3.132.0.34); we replace it with
  // `2a8648ce3d030107` (= 1.2.840.10045.3.1.7 = secp256r1). Since the OID
  // length differs (5 vs 8) we'd have to rebuild the whole SEQUENCE; for the
  // test it's simpler to just flip the OID length byte from 5 → 4 to cause
  // an OID parse mismatch.
  let s = vec_spki()
  // Byte 17 is the OID length (0x05). Change to 0x06 — the OID then reads
  // one byte further and becomes a different OID.
  let bad = Bytes::makei(s.length(), fn(i) {
    if i == 17 {
      b'\x06'
    } else {
      s[i]
    }
  })
  let raised = try {
    let _ = @p384.PublicKey::from_spki_der(bad)
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
test "p384: SignatureFormat Debug" {
  @debug.assert_eq(@debug.to_string(@p384.SignatureFormat::Raw), "Raw")
  @debug.assert_eq(@debug.to_string(@p384.SignatureFormat::Der), "Der")
}

// -----------------------------------------------------------------------------
// Security attack tests
// -----------------------------------------------------------------------------

///|
test "ATTACK CVE-2022-21449 (Psychic Signatures): s=0 must be rejected" {
  let pk = @p384.PublicKey::from_uncompressed(vec_uncompressed())
  let sig = vec_sig_raw()
  let bad = Bytes::makei(96, fn(i) { if i < 48 { sig[i] } else { b'\x00' } })
  assert_false(@p384.verify(pk, vec_msg(), bad, Raw))
}

///|
test "ATTACK CVE-2022-21449: r=s=0 must be rejected" {
  let pk = @p384.PublicKey::from_uncompressed(vec_uncompressed())
  let bad = Bytes::makei(96, fn(_i) { b'\x00' })
  assert_false(@p384.verify(pk, vec_msg(), bad, Raw))
}

///|
test "ATTACK: s = n (P-384 order, boundary) must reject" {
  let pk = @p384.PublicKey::from_uncompressed(vec_uncompressed())
  // P-384 group order n.
  let n_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
  let n = hex(n_hex)
  let r = vec_sig_raw()
  let bad = Bytes::makei(96, fn(i) { if i < 48 { r[i] } else { n[i - 48] } })
  assert_false(@p384.verify(pk, vec_msg(), bad, Raw))
}

///|
test "ATTACK CVE-2020-0601 (Curveball)-style on P-384: off-curve pubkey rejected" {
  let off_curve = Bytes::makei(97, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i == 48 {
      b'\x01'
    } else if i == 96 {
      b'\x02'
    } else {
      b'\x00'
    }
  })
  let raised = try {
    let _ = @p384.PublicKey::from_uncompressed(off_curve)
    false
  } catch {
    PointNotOnCurve => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p384: sign+verify roundtrip is deterministic" {
  let scalar = hex(
    "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
  )
  let sk = @p384.PrivateKey::from_bytes(scalar)
  let pk = sk.public_key()
  let msg : Bytes = b"hello p384 sign"
  let sig1 = sk.sign(msg)
  let sig2 = sk.sign(msg)
  @debug.assert_eq(sig1, sig2)
  assert_true(@p384.verify(pk, msg, sig1, Raw))
}

///|
test "p384: sign emits DER" {
  let scalar = hex(
    "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
  )
  let sk = @p384.PrivateKey::from_bytes(scalar)
  let pk = sk.public_key()
  let der = sk.sign(b"hello p384 sign", format=Der)
  @debug.assert_eq(der[0], b'\x30')
  assert_true(@p384.verify(pk, b"hello p384 sign", der, Der))
}
