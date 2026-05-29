// Blackbox tests for mizchi/secp256k1. Use `@secp256k1` to import.

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

// -----------------------------------------------------------------------------
// Generator-point sanity (deriving the public key from d = 1 must yield G).
// -----------------------------------------------------------------------------

///|
test "secp256k1: PrivateKey(1).public_key == G" {
  let one = Bytes::makei(32, fn(i) { if i == 31 { b'\x01' } else { b'\x00' } })
  let sk = @secp256k1.PrivateKey::from_bytes(one)
  let pk = sk.public_key()
  let bytes = pk.to_uncompressed()
  @debug.assert_eq(bytes.length(), 65)
  @debug.assert_eq(bytes[0], b'\x04')
  // SEC 2 §2.4.1 Gx / Gy.
  let gx = hex(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
  )
  let gy = hex(
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
  )
  for i = 0; i < 32; i = i + 1 {
    @debug.assert_eq(bytes[1 + i], gx[i])
  }
  for i = 0; i < 32; i = i + 1 {
    @debug.assert_eq(bytes[33 + i], gy[i])
  }
}

///|
test "secp256k1: public generator tweak matches private scalar addition" {
  let one = Bytes::makei(32, fn(i) { if i == 31 { b'\x01' } else { b'\x00' } })
  let two = Bytes::makei(32, fn(i) { if i == 31 { b'\x02' } else { b'\x00' } })
  let pk1 = @secp256k1.PrivateKey::from_bytes(one).public_key()
  let pk2 = @secp256k1.PrivateKey::from_bytes(two).public_key()
  let tweaked = pk1.add_generator_mul(one)
  @debug.assert_eq(tweaked.to_compressed(), pk2.to_compressed())

  let zero = Bytes::makei(32, fn(_) { b'\x00' })
  let unchanged = pk1.add_generator_mul(zero)
  @debug.assert_eq(unchanged.to_compressed(), pk1.to_compressed())
}

///|
test "ATTACK secp256k1: public generator tweak rejects invalid child points" {
  let one = Bytes::makei(32, fn(i) { if i == 31 { b'\x01' } else { b'\x00' } })
  let pk1 = @secp256k1.PrivateKey::from_bytes(one).public_key()
  let n = hex(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
  )
  try pk1.add_generator_mul(n) catch {
    @secp256k1.InvalidPrivateKey(_) => ()
    e => abort("expected invalid scalar rejection, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted generator tweak scalar >= n")
  }

  let n_minus_one = hex(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
  )
  try pk1.add_generator_mul(n_minus_one) catch {
    @secp256k1.InvalidPointEncoding(_) => ()
    e => abort("expected infinity rejection, got " + @debug.to_string(e))
  } noraise {
    _ => abort("accepted generator tweak that produced infinity")
  }
}

// -----------------------------------------------------------------------------
// Sign + verify roundtrip (RFC 6979 deterministic ECDSA, BIP-62 low-s).
// -----------------------------------------------------------------------------

// Bitcoin-style test scalar — same value used by the p256 tests, comfortably
// inside [1, n) for secp256k1 as well.

///|
let test_scalar : String = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"

///|
test "secp256k1: sign+verify roundtrip is deterministic" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let msg : Bytes = b"sample"
  let sig1 = sk.sign(msg)
  let sig2 = sk.sign(msg)
  // Determinism: same input ⇒ same signature.
  @debug.assert_eq(sig1, sig2)
  assert_true(@secp256k1.verify(pk, msg, sig1, Raw))
}

///|
test "secp256k1: sign tampered message produces a different signature" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let sig_a = sk.sign(b"sample")
  let sig_b = sk.sign(b"test")
  assert_false(sig_a == sig_b)
  assert_false(@secp256k1.verify(pk, b"sample", sig_b, Raw))
  assert_false(@secp256k1.verify(pk, b"test", sig_a, Raw))
}

///|
test "secp256k1: tampered signature fails verify" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let msg : Bytes = b"sample"
  let sig = sk.sign(msg)
  let bad = Bytes::makei(64, fn(i) {
    if i == 0 {
      (sig[i].to_int() ^ 0x01).to_byte()
    } else {
      sig[i]
    }
  })
  assert_false(@secp256k1.verify(pk, msg, bad, Raw))
}

///|
test "secp256k1: sign emits a DER signature when requested" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let der_sig = sk.sign(b"sample", format=Der)
  @debug.assert_eq(der_sig[0], b'\x30')
  assert_true(@secp256k1.verify(pk, b"sample", der_sig, Der))
}

///|
test "secp256k1: roundtrip uncompressed" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let bytes = pk.to_uncompressed()
  @debug.assert_eq(bytes.length(), 65)
  @debug.assert_eq(bytes[0], b'\x04')
  let pk2 = @secp256k1.PublicKey::from_uncompressed(bytes)
  let msg : Bytes = b"sample"
  let sig = sk.sign(msg)
  assert_true(@secp256k1.verify(pk2, msg, sig, Raw))
}

// -----------------------------------------------------------------------------
// BIP-62 §3 low-s normalisation.
// -----------------------------------------------------------------------------

// n / 2 as 32-byte BE — bytes 32..64 of a signature ≤ this iff low-s.

///|
let half_n_hex : String = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"

///|
// Compare two 32-byte big-endian numbers as unsigned. Returns -1 / 0 / 1.
fn cmp_be32(a : Bytes, b : Bytes) -> Int {
  for i = 0; i < 32; i = i + 1 {
    let ai = a[i].to_int()
    let bi = b[i].to_int()
    if ai < bi {
      return -1
    }
    if ai > bi {
      return 1
    }
  }
  0
}

///|
// Probe many messages so we exercise both halves of the s space without
// having to compute n - s ourselves.
fn try_messages() -> Array[Bytes] {
  let msgs : Array[Bytes] = [
    b"sample", b"test", b"bitcoin", b"ethereum", b"low-s probe 0", b"low-s probe 1",
    b"low-s probe 2", b"low-s probe 3", b"low-s probe 4", b"low-s probe 5", b"low-s probe 6",
    b"low-s probe 7", b"low-s probe 8", b"low-s probe 9", b"low-s probe 10", b"low-s probe 11",
  ]
  msgs
}

///|
test "secp256k1: sign always emits low-s (s ≤ n/2)" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let half_n = hex(half_n_hex)
  for msg in try_messages() {
    let sig = sk.sign(msg)
    let s_bytes = Bytes::makei(32, fn(i) { sig[i + 32] })
    // s_bytes must be ≤ half_n.
    assert_true(cmp_be32(s_bytes, half_n) <= 0)
  }
}

///|
test "secp256k1: sign_no_low_s can produce a high-s signature" {
  // We search for at least one message that yields a high-s raw signature.
  // Statistically half of RFC 6979 nonces produce s > n/2.
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let half_n = hex(half_n_hex)
  let mut saw_high_s = false
  let mut saw_low_s = false
  for msg in try_messages() {
    let sig = sk.sign_no_low_s(msg)
    let s_bytes = Bytes::makei(32, fn(i) { sig[i + 32] })
    if cmp_be32(s_bytes, half_n) > 0 {
      saw_high_s = true
    } else {
      saw_low_s = true
    }
  }
  assert_true(saw_high_s)
  assert_true(saw_low_s)
}

///|
test "secp256k1: sign and sign_no_low_s share r; s differs only by low-s flip" {
  // For a fixed message, RFC 6979 picks the same nonce regardless of the
  // low-s flag, so r must match. s is either equal (already low-s) or
  // s_low = n - s_high.
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
  let n = BigInt::from_string(n_hex, radix=16)
  for msg in try_messages() {
    let sig_low = sk.sign(msg)
    let sig_raw = sk.sign_no_low_s(msg)
    // r is the first 32 bytes — should be identical.
    for i = 0; i < 32; i = i + 1 {
      @debug.assert_eq(sig_low[i], sig_raw[i])
    }
    let s_low_bytes = Bytes::makei(32, fn(i) { sig_low[i + 32] })
    let s_raw_bytes = Bytes::makei(32, fn(i) { sig_raw[i + 32] })
    let s_low = BigInt::from_octets(s_low_bytes[:])
    let s_raw = BigInt::from_octets(s_raw_bytes[:])
    let same = s_low == s_raw
    let flipped = s_low == n - s_raw
    assert_true(same || flipped)
  }
}

///|
test "secp256k1: verify accepts both low-s and high-s signatures" {
  // The library's verify is permissive (BIP-66/EIP-2 is application-layer).
  // Confirm a high-s signature still verifies.
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let half_n = hex(half_n_hex)
  let mut tested_high_s = false
  for msg in try_messages() {
    let sig = sk.sign_no_low_s(msg)
    let s_bytes = Bytes::makei(32, fn(i) { sig[i + 32] })
    if cmp_be32(s_bytes, half_n) > 0 {
      assert_true(@secp256k1.verify(pk, msg, sig, Raw))
      tested_high_s = true
    }
  }
  assert_true(tested_high_s)
}

// -----------------------------------------------------------------------------
// Private-key range tests.
// -----------------------------------------------------------------------------

///|
test "secp256k1: from_bytes rejects all-zero scalar" {
  let zero = Bytes::makei(32, fn(_) { b'\x00' })
  try @secp256k1.PrivateKey::from_bytes(zero) catch {
    InvalidPrivateKey(_) => ()
    other => abort("expected InvalidPrivateKey, got " + repr(other) + "")
  } noraise {
    _ => abort("expected raise on zero scalar, got Ok")
  }
}

///|
test "secp256k1: from_bytes rejects scalar = n" {
  // n itself is out of range (must be < n).
  let scalar_eq_n = hex(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
  )
  try @secp256k1.PrivateKey::from_bytes(scalar_eq_n) catch {
    InvalidPrivateKey(_) => ()
    other => abort("expected InvalidPrivateKey, got " + repr(other) + "")
  } noraise {
    _ => abort("expected raise on scalar = n, got Ok")
  }
}

///|
test "secp256k1: from_bytes rejects scalar > n" {
  // 0xFF..FF (32 bytes) is > n.
  let scalar = Bytes::makei(32, fn(_) { b'\xff' })
  try @secp256k1.PrivateKey::from_bytes(scalar) catch {
    InvalidPrivateKey(_) => ()
    other => abort("expected InvalidPrivateKey, got " + repr(other) + "")
  } noraise {
    _ => abort("expected raise on scalar > n, got Ok")
  }
}

///|
test "secp256k1: from_bytes rejects wrong-length input" {
  let short = Bytes::makei(31, fn(_) { b'\x01' })
  try @secp256k1.PrivateKey::from_bytes(short) catch {
    InvalidPrivateKey(_) => ()
    other => abort("expected InvalidPrivateKey, got " + repr(other) + "")
  } noraise {
    _ => abort("expected raise on short input, got Ok")
  }
}

// -----------------------------------------------------------------------------
// Public-key parsing.
// -----------------------------------------------------------------------------

///|
test "secp256k1: from_uncompressed rejects off-curve point" {
  // (0, 1) is not on y² = x³ + 7.
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
    let _ = @secp256k1.PublicKey::from_uncompressed(bad)
    false
  } catch {
    PointNotOnCurve => true
    _ => false
  }
  assert_true(raised)
}

///|
test "secp256k1: from_uncompressed rejects bad tag byte (compressed 0x02)" {
  // Real Gx coords with tag 0x02 should be rejected (only 0x04 accepted).
  let gx = hex(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
  )
  let gy = hex(
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
  )
  let bad = Bytes::makei(65, fn(i) {
    if i == 0 {
      b'\x02'
    } else if i < 33 {
      gx[i - 1]
    } else {
      gy[i - 33]
    }
  })
  let raised = try {
    let _ = @secp256k1.PublicKey::from_uncompressed(bad)
    false
  } catch {
    InvalidPointEncoding(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
test "secp256k1: from_uncompressed rejects wrong-length input" {
  let bad = Bytes::makei(64, fn(_) { b'\x00' })
  let raised = try {
    let _ = @secp256k1.PublicKey::from_uncompressed(bad)
    false
  } catch {
    InvalidPublicKeyLength(_) => true
    _ => false
  }
  assert_true(raised)
}

// -----------------------------------------------------------------------------
// Signature parsing edge cases.
// -----------------------------------------------------------------------------

///|
test "secp256k1: wrong signature length rejected (Raw)" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let short_sig = Bytes::makei(63, fn(_i) { b'\x00' })
  let raised = try {
    let _ = @secp256k1.verify(pk, b"sample", short_sig, Raw)
    false
  } catch {
    InvalidSignatureLength(_) => true
    _ => false
  }
  assert_true(raised)
}

///|
fn add_extra_zero_to_first_der_integer(sig : Bytes) -> Bytes {
  // Test helper for signatures emitted by this module: SEQUENCE short len,
  // INTEGER short len for r, INTEGER short len for s.
  let seq_len = sig[1].to_int()
  let r_len = sig[3].to_int()
  Bytes::makei(sig.length() + 1, fn(i) {
    if i == 1 {
      (seq_len + 1).to_byte()
    } else if i == 3 {
      (r_len + 1).to_byte()
    } else if i == 4 {
      b'\x00'
    } else if i < 4 {
      sig[i]
    } else {
      sig[i - 1]
    }
  })
}

///|
test "ATTACK secp256k1: DER INTEGER with redundant leading zero is rejected" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let der_sig = sk.sign(b"sample", format=Der)
  let non_minimal = add_extra_zero_to_first_der_integer(der_sig)
  try @secp256k1.verify(pk, b"sample", non_minimal, Der) catch {
    InvalidDerSignature(_) => ()
    other => abort("expected InvalidDerSignature, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted non-minimal DER INTEGER")
  }
}

///|
test "secp256k1: SignatureFormat Debug" {
  @debug.assert_eq(@debug.to_string(@secp256k1.SignatureFormat::Raw), "Raw")
  @debug.assert_eq(@debug.to_string(@secp256k1.SignatureFormat::Der), "Der")
}

// -----------------------------------------------------------------------------
// Security attack tests (mirror p256).
// -----------------------------------------------------------------------------

///|
test "ATTACK CVE-2022-21449 (Psychic Signatures): s=0 must be rejected" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let sig = sk.sign(b"sample")
  let bad = Bytes::makei(64, fn(i) { if i < 32 { sig[i] } else { b'\x00' } })
  assert_false(@secp256k1.verify(pk, b"sample", bad, Raw))
}

///|
test "ATTACK CVE-2022-21449: r=0 must be rejected" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let sig = sk.sign(b"sample")
  let bad = Bytes::makei(64, fn(i) { if i < 32 { b'\x00' } else { sig[i] } })
  assert_false(@secp256k1.verify(pk, b"sample", bad, Raw))
}

///|
test "ATTACK CVE-2022-21449: r=s=0 must be rejected" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let bad = Bytes::makei(64, fn(_i) { b'\x00' })
  assert_false(@secp256k1.verify(pk, b"sample", bad, Raw))
}

///|
test "ATTACK: s = n (boundary, must reject)" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let sig = sk.sign(b"sample")
  let n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
  let s_eq_n = hex(n_hex)
  let bad = Bytes::makei(64, fn(i) {
    if i < 32 {
      sig[i]
    } else {
      s_eq_n[i - 32]
    }
  })
  assert_false(@secp256k1.verify(pk, b"sample", bad, Raw))
}

///|
test "ATTACK: r = n (boundary, must reject)" {
  let sk = @secp256k1.PrivateKey::from_bytes(hex(test_scalar))
  let pk = sk.public_key()
  let sig = sk.sign(b"sample")
  let n_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
  let r_eq_n = hex(n_hex)
  let bad = Bytes::makei(64, fn(i) { if i < 32 { r_eq_n[i] } else { sig[i] } })
  assert_false(@secp256k1.verify(pk, b"sample", bad, Raw))
}

///|
test "ATTACK CVE-2020-0601 (Curveball)-style: off-curve pubkey rejected at parse" {
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
    let _ = @secp256k1.PublicKey::from_uncompressed(off_curve)
    false
  } catch {
    PointNotOnCurve => true
    _ => false
  }
  assert_true(raised)
}
