// Blackbox tests for mizchi/p256. Use `@p256` to import.

///|
// Helper: pack a hex string into Bytes. Assumes even-length, lowercase.
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
    out.unsafe_set(i, ((hi * 16) + lo).to_byte())
    i = i + 1
  }
  Bytes::makei(len, fn(j) { out.unsafe_get(j) })
}

///|
// RFC 7515 Appendix A.3 ES256 verification vector.
// Public key X / Y are taken from the JWK in §A.3.1, signature from §A.3.3,
// signing input from §A.3.4. base64url-decoded to hex once and embedded here
// so this test stays self-contained.
fn rfc7515_a3_pubkey() -> @p256.PublicKey raise {
  let x = hex("7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445")
  let y = hex("c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad")
  let bytes = Bytes::makei(65, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i < 33 {
      x[i - 1]
    } else {
      y[i - 33]
    }
  })
  @p256.PublicKey::from_uncompressed(bytes)
}

///|
fn rfc7515_a3_signing_input() -> Bytes {
  // ASCII bytes of the JWS Signing Input from RFC 7515 §A.3.1.
  let s = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
  Bytes::makei(s.length(), fn(i) { s.get_char(i).unwrap().to_int().to_byte() })
}

///|
fn rfc7515_a3_signature() -> Bytes {
  hex(
    "0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665" +
    "c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5",
  )
}

///|
test "p256: RFC 7515 A.3 ES256 verify (Raw)" {
  let pk = rfc7515_a3_pubkey()
  let msg = rfc7515_a3_signing_input()
  let sig = rfc7515_a3_signature()
  assert_true(@p256.verify(pk, msg, sig, Raw))
}

///|
test "p256: tampered message fails" {
  let pk = rfc7515_a3_pubkey()
  let msg_arr = FixedArray::make(115, b'\x00')
  let msg = rfc7515_a3_signing_input()
  for i = 0; i < 115; i = i + 1 {
    msg_arr.unsafe_set(i, msg[i])
  }
  // Flip a byte.
  msg_arr.unsafe_set(0, (msg_arr.unsafe_get(0).to_int() ^ 0x01).to_byte())
  let tampered = Bytes::makei(115, fn(i) { msg_arr.unsafe_get(i) })
  let sig = rfc7515_a3_signature()
  assert_false(@p256.verify(pk, tampered, sig, Raw))
}

///|
test "p256: tampered signature fails" {
  let pk = rfc7515_a3_pubkey()
  let msg = rfc7515_a3_signing_input()
  let sig = rfc7515_a3_signature()
  let bad = Bytes::makei(64, fn(i) {
    if i == 0 {
      (sig[i].to_int() ^ 0x01).to_byte()
    } else {
      sig[i]
    }
  })
  assert_false(@p256.verify(pk, msg, bad, Raw))
}

///|
test "p256: r out of range (zero) rejected" {
  let pk = rfc7515_a3_pubkey()
  let msg = rfc7515_a3_signing_input()
  // r = 0 → invalid.
  let bad_sig = Bytes::makei(64, fn(i) {
    if i < 32 {
      b'\x00'
    } else {
      rfc7515_a3_signature()[i]
    }
  })
  assert_false(@p256.verify(pk, msg, bad_sig, Raw))
}

///|
test "p256: wrong signature length rejected (Raw)" {
  let pk = rfc7515_a3_pubkey()
  let msg = rfc7515_a3_signing_input()
  let short_sig = Bytes::makei(63, fn(_i) { b'\x00' })
  let raised = try {
    let _ = @p256.verify(pk, msg, short_sig, Raw)
    false
  } catch {
    InvalidSignatureLength(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p256: SignatureFormat Show" {
  inspect(@p256.SignatureFormat::Raw, content="Raw")
  inspect(@p256.SignatureFormat::Der, content="Der")
}

///|
test "p256: roundtrip uncompressed" {
  let pk = rfc7515_a3_pubkey()
  let bytes = pk.to_uncompressed()
  assert_eq(bytes.length(), 65)
  assert_eq(bytes[0], b'\x04')
  let pk2 = @p256.PublicKey::from_uncompressed(bytes)
  assert_true(@p256.verify(pk2, rfc7515_a3_signing_input(), rfc7515_a3_signature(), Raw))
}

///|
test "p256: from_uncompressed rejects off-curve point" {
  let bad = Bytes::makei(65, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i == 64 {
      b'\x01'
    } else {
      b'\x00'
    }
  })
  let raised = try {
    let _ = @p256.PublicKey::from_uncompressed(bad)
    false
  } catch {
    PointNotOnCurve => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p256: from_uncompressed rejects bad tag byte" {
  // Compressed form 0x02 should be rejected (we only accept 0x04).
  let bad = Bytes::makei(65, fn(i) {
    if i == 0 {
      b'\x02'
    } else if i < 33 {
      hex("7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445")[i - 1]
    } else {
      hex("c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad")[i - 33]
    }
  })
  let raised = try {
    let _ = @p256.PublicKey::from_uncompressed(bad)
    false
  } catch {
    InvalidPointEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "p256: DER signature round (re-encode A.3 r/s as SEQUENCE)" {
  // Manually wrap the A.3 r,s into ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }
  // and verify the Der format path. r and s both have high bit set in some
  // bytes — we add a 0x00 sign byte when the top bit of the first byte is 1.
  let r = hex("0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665")
  let s = hex("c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5")
  fn der_int(b : Bytes) -> Bytes {
    let needs_pad = (b[0].to_int() & 0x80) != 0
    let body_len = b.length() + (if needs_pad { 1 } else { 0 })
    let head = Bytes::makei(2, fn(i) { if i == 0 { b'\x02' } else { body_len.to_byte() } })
    let body = if needs_pad {
      Bytes::makei(body_len, fn(i) { if i == 0 { b'\x00' } else { b[i - 1] } })
    } else {
      b
    }
    Bytes::makei(head.length() + body.length(), fn(i) {
      if i < head.length() {
        head[i]
      } else {
        body[i - head.length()]
      }
    })
  }

  let r_der = der_int(r)
  let s_der = der_int(s)
  let inner_len = r_der.length() + s_der.length()
  let seq = Bytes::makei(2 + inner_len, fn(i) {
    if i == 0 {
      b'\x30'
    } else if i == 1 {
      inner_len.to_byte()
    } else if i - 2 < r_der.length() {
      r_der[i - 2]
    } else {
      s_der[i - 2 - r_der.length()]
    }
  })
  let pk = rfc7515_a3_pubkey()
  let msg = rfc7515_a3_signing_input()
  assert_true(@p256.verify(pk, msg, seq, Der))
}

// -----------------------------------------------------------------------------
// Security attack tests
// -----------------------------------------------------------------------------

///|
test "ATTACK CVE-2022-21449 (Psychic Signatures): s=0 must be rejected" {
  let pk = rfc7515_a3_pubkey()
  let msg = rfc7515_a3_signing_input()
  // r = original r, s = 0. The Java vulnerability accepted this because the
  // verifier skipped the `1 <= s < n` range check.
  let sig = rfc7515_a3_signature()
  let bad = Bytes::makei(64, fn(i) {
    if i < 32 {
      sig[i]
    } else {
      b'\x00'
    }
  })
  assert_false(@p256.verify(pk, msg, bad, Raw))
}

///|
test "ATTACK CVE-2022-21449: r=s=0 must be rejected" {
  let pk = rfc7515_a3_pubkey()
  let msg = rfc7515_a3_signing_input()
  let bad = Bytes::makei(64, fn(_i) { b'\x00' })
  assert_false(@p256.verify(pk, msg, bad, Raw))
}

///|
test "ATTACK: s = n (boundary, must reject)" {
  let pk = rfc7515_a3_pubkey()
  let msg = rfc7515_a3_signing_input()
  // n (P-256 order) as 32-byte BE. Spec says 1 <= s < n, so s = n is invalid.
  let n_hex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
  let r = rfc7515_a3_signature()
  let s_eq_n = hex(n_hex)
  let bad = Bytes::makei(64, fn(i) {
    if i < 32 {
      r[i]
    } else {
      s_eq_n[i - 32]
    }
  })
  assert_false(@p256.verify(pk, msg, bad, Raw))
}

///|
test "ATTACK CVE-2020-0601 (Curveball)-style: off-curve pubkey rejected at parse" {
  // Curveball relied on accepting an attacker-supplied EC point that's NOT
  // on the named curve. We assert from_uncompressed catches this.
  let off_curve = Bytes::makei(65, fn(i) {
    if i == 0 {
      b'\x04'
    } else if i == 32 {
      b'\x01'
    } else if i == 64 {
      b'\x02'
    } else {
      b'\x00'
    }
  })
  let raised = try {
    let _ = @p256.PublicKey::from_uncompressed(off_curve)
    false
  } catch {
    PointNotOnCurve => true
    _ => false
  }
  assert_true(raised)
}
