// Blackbox tests for `mizchi/cose`. Test vectors are hand-built end-to-end
// so the assertions only depend on this workspace (no external curl).

///|
fn hex_to_bytes(s : String) -> Bytes {
  let n = s.length() / 2
  let arr = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble(s.code_unit_at(i * 2).to_int())
    let lo = hex_nibble(s.code_unit_at(i * 2 + 1).to_int())
    arr[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::makei(n, fn(i) { arr[i] })
}

///|
fn hex_nibble(c : Int) -> Int {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    0
  }
}

///|
fn ed25519_test_private_key() -> @ed25519.PrivateKey raise {
  @ed25519.PrivateKey::from_seed(
    hex_to_bytes(
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    ),
  )
}

///|
fn build_ed25519_sign1(
  protected_bytes : Bytes,
  unprotected : @cbor.CborValue,
  embedded_payload : @cbor.CborValue,
  signed_payload : Bytes,
) -> Bytes raise {
  let sk = ed25519_test_private_key()
  let sig_struct = @cbor.encode(
    Array([
      Text("Signature1"),
      Bytes(protected_bytes),
      Bytes(b""),
      Bytes(signed_payload),
    ]),
  )
  let signature = sk.sign(sig_struct)
  @cbor.encode(
    Array([
      Bytes(protected_bytes),
      unprotected,
      embedded_payload,
      Bytes(signature),
    ]),
  )
}

// --- COSE_Sign1 verify (Ed25519) -----------------------------------------

///|
// End-to-end test: build a COSE_Sign1 with our own ed25519 signer, then
// verify it via the COSE API. Uses RFC 8032 §7.1 TEST 2 seed so the
// underlying primitive is exercised at known-good vectors as a side
// benefit.
test "verify_sign1: Ed25519 round-trip succeeds" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()

  // Build the protected header: { 1: -8 } meaning alg=EdDSA.
  let protected_map : @cbor.CborValue = Map([(Uint(1UL), Nint(7UL))])
  let protected_bytes = @cbor.encode(protected_map)
  let unprotected_map : @cbor.CborValue = Map([])
  let payload = b"hello cose"

  // Sig_structure = ["Signature1", protected, external_aad(b""), payload]
  let sig_struct = @cbor.encode(
    Array([
      Text("Signature1"),
      Bytes(protected_bytes),
      Bytes(b""),
      Bytes(payload),
    ]),
  )
  let signature = sk.sign(sig_struct)

  // Build the COSE_Sign1 array (no outer tag).
  let cose_sign1 = @cbor.encode(
    Array([
      Bytes(protected_bytes),
      unprotected_map,
      Bytes(payload),
      Bytes(signature),
    ]),
  )

  let key : @cose.CoseKey = OkpEd25519(pubkey=pk)
  assert_true(@cose.verify_sign1(cose_sign1, payload, key))
}

///|
test "verify_sign1: Ed25519 with outer tag 18" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let protected_bytes = @cbor.encode(Map([(Uint(1UL), Nint(7UL))]))
  let payload = b"tagged"
  let sig_struct = @cbor.encode(
    Array([
      Text("Signature1"),
      Bytes(protected_bytes),
      Bytes(b""),
      Bytes(payload),
    ]),
  )
  let signature = sk.sign(sig_struct)
  let inner_array : @cbor.CborValue = Array([
    Bytes(protected_bytes),
    Map([]),
    Bytes(payload),
    Bytes(signature),
  ])
  // Wrap in tag 18 = COSE_Sign1.
  let cose_sign1 = @cbor.encode(Tag(18UL, inner_array))
  let key : @cose.CoseKey = OkpEd25519(pubkey=pk)
  assert_true(@cose.verify_sign1(cose_sign1, payload, key))
}

///|
test "verify_sign1: tampered signature is rejected" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let protected_bytes = @cbor.encode(Map([(Uint(1UL), Nint(7UL))]))
  let payload = b"hello cose"
  let sig_struct = @cbor.encode(
    Array([
      Text("Signature1"),
      Bytes(protected_bytes),
      Bytes(b""),
      Bytes(payload),
    ]),
  )
  let signature = sk.sign(sig_struct)
  // Flip the last byte of the signature.
  let tampered = FixedArray::make(signature.length(), b'\x00')
  for i = 0; i < signature.length(); i = i + 1 {
    tampered[i] = signature[i]
  }
  tampered[tampered.length() - 1] = (tampered[tampered.length() - 1].to_int() ^
  0x01).to_byte()
  let bad_sig = Bytes::from_array(tampered)
  let cose_sign1 = @cbor.encode(
    Array([Bytes(protected_bytes), Map([]), Bytes(payload), Bytes(bad_sig)]),
  )
  let key : @cose.CoseKey = OkpEd25519(pubkey=pk)
  assert_false(@cose.verify_sign1(cose_sign1, payload, key))
}

///|
test "verify_sign1: tampered payload is rejected" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let protected_bytes = @cbor.encode(Map([(Uint(1UL), Nint(7UL))]))
  let payload = b"hello cose"
  let sig_struct = @cbor.encode(
    Array([
      Text("Signature1"),
      Bytes(protected_bytes),
      Bytes(b""),
      Bytes(payload),
    ]),
  )
  let signature = sk.sign(sig_struct)
  // Use a different payload than what was signed.
  let cose_sign1 = @cbor.encode(
    Array([
      Bytes(protected_bytes),
      Map([]),
      Bytes(b"goodbye cose"),
      Bytes(signature),
    ]),
  )
  let key : @cose.CoseKey = OkpEd25519(pubkey=pk)
  assert_false(@cose.verify_sign1(cose_sign1, b"goodbye cose", key))
}

///|
test "verify_sign1: external_aad is bound into the signature" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let protected_bytes = @cbor.encode(Map([(Uint(1UL), Nint(7UL))]))
  let payload = b"x"
  let external_aad = b"context-A"
  // Sign with one AAD, verify with another — must fail.
  let sig_struct = @cbor.encode(
    Array([
      Text("Signature1"),
      Bytes(protected_bytes),
      Bytes(external_aad),
      Bytes(payload),
    ]),
  )
  let signature = sk.sign(sig_struct)
  let cose_sign1 = @cbor.encode(
    Array([Bytes(protected_bytes), Map([]), Bytes(payload), Bytes(signature)]),
  )
  let key : @cose.CoseKey = OkpEd25519(pubkey=pk)
  // Correct AAD verifies.
  assert_true(@cose.verify_sign1(cose_sign1, payload, key, external_aad~))
  // Wrong AAD does not.
  assert_false(
    @cose.verify_sign1(cose_sign1, payload, key, external_aad=b"context-B"),
  )
  // Default empty AAD does not.
  assert_false(@cose.verify_sign1(cose_sign1, payload, key))
}

///|
test "ATTACK verify_sign1: unsupported protected alg does not fail open" {
  let sk = ed25519_test_private_key()
  let key : @cose.CoseKey = OkpEd25519(pubkey=sk.public_key())
  let protected_bytes = @cbor.encode(Map([(Uint(1UL), Nint(998UL))])) // -999
  let payload = b"alg confusion"
  let cose_sign1 = build_ed25519_sign1(
    protected_bytes,
    Map([]),
    Bytes(payload),
    payload,
  )
  try @cose.verify_sign1(cose_sign1, payload, key) catch {
    UnsupportedAlgorithm(-999L) => ()
    InvalidStructure(_) => ()
    other => abort("expected alg rejection, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted unsupported protected alg")
  }
}

///|
test "ATTACK verify_sign1: alg in unprotected header is rejected" {
  let sk = ed25519_test_private_key()
  let key : @cose.CoseKey = OkpEd25519(pubkey=sk.public_key())
  let protected_bytes = b""
  let payload = b"unprotected alg"
  let cose_sign1 = build_ed25519_sign1(
    protected_bytes,
    Map([(Uint(1UL), Nint(7UL))]),
    Bytes(payload),
    payload,
  )
  try @cose.verify_sign1(cose_sign1, payload, key) catch {
    InvalidStructure(_) => ()
    other =>
      abort("expected protected alg requirement, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted alg only in unprotected header")
  }
}

///|
test "ATTACK verify_sign1: duplicate protected alg labels are rejected" {
  let sk = ed25519_test_private_key()
  let key : @cose.CoseKey = OkpEd25519(pubkey=sk.public_key())
  let protected_bytes = @cbor.encode(
    Map([(Uint(1UL), Nint(7UL)), (Uint(1UL), Nint(6UL))]),
  )
  let payload = b"duplicate alg"
  let cose_sign1 = build_ed25519_sign1(
    protected_bytes,
    Map([]),
    Bytes(payload),
    payload,
  )
  try @cose.verify_sign1(cose_sign1, payload, key) catch {
    InvalidStructure(_) => ()
    other => abort("expected duplicate alg rejection, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted duplicate protected alg labels")
  }
}

///|
test "ATTACK verify_sign1: protected header must use preferred CBOR encoding" {
  let sk = ed25519_test_private_key()
  let key : @cose.CoseKey = OkpEd25519(pubkey=sk.public_key())
  // { 1: -8 }, but -8 is encoded in non-preferred two-byte form 0x38 0x07
  // instead of the canonical single-byte 0x27.
  let protected_bytes = hex_to_bytes("a1013807")
  let payload = b"non-minimal protected"
  let cose_sign1 = build_ed25519_sign1(
    protected_bytes,
    Map([]),
    Bytes(payload),
    payload,
  )
  try @cose.verify_sign1(cose_sign1, payload, key) catch {
    InvalidStructure(_) => ()
    other =>
      abort("expected preferred-encoding rejection, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted non-preferred protected header encoding")
  }
}

///|
test "ATTACK verify_sign1: embedded payload must match supplied payload" {
  let sk = ed25519_test_private_key()
  let key : @cose.CoseKey = OkpEd25519(pubkey=sk.public_key())
  let protected_bytes = @cbor.encode(Map([(Uint(1UL), Nint(7UL))]))
  let signed_payload = b"payload actually signed"
  let cose_sign1 = build_ed25519_sign1(
    protected_bytes,
    Map([]),
    Bytes(b"payload displayed elsewhere"),
    signed_payload,
  )
  try @cose.verify_sign1(cose_sign1, signed_payload, key) catch {
    InvalidStructure(_) => ()
    other =>
      abort("expected embedded payload mismatch, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted mismatched embedded payload")
  }
}

// --- COSE_Key parsing ----------------------------------------------------

///|
test "parse_cose_key: Ed25519 OKP" {
  // Build a COSE_Key map: { 1: 1 (kty=OKP), 3: -8 (alg=EdDSA),
  //                         -1: 6 (crv=Ed25519), -2: <x bytes> }
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk_bytes = sk.public_key().to_bytes()
  let cose_key = @cbor.encode(
    Map([
      (Uint(1UL), Uint(1UL)), // kty = OKP
      (Uint(3UL), Nint(7UL)), // alg = EdDSA (-8)
      (Nint(0UL), Uint(6UL)), // crv = Ed25519 (6); Nint(0) is -1
      (Nint(1UL), Bytes(pk_bytes)), // x = public-key bytes; Nint(1) is -2
    ]),
  )
  let key = @cose.parse_cose_key(cose_key)
  match key {
    OkpEd25519(pubkey=_) => ()
    _ => abort("expected OkpEd25519")
  }
}

///|
test "parse_cose_key: ES256 EC2" {
  // SEC1 generator point as the test public key. The fact that it's the
  // generator doesn't affect the parse path; we just need an on-curve point.
  let gx = hex_to_bytes(
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  )
  let gy = hex_to_bytes(
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  )
  let cose_key = @cbor.encode(
    Map([
      (Uint(1UL), Uint(2UL)), // kty = EC2
      (Uint(3UL), Nint(6UL)), // alg = ES256 (-7); Nint(6) is -7
      (Nint(0UL), Uint(1UL)), // crv = P-256
      (Nint(1UL), Bytes(gx)), // x
      (Nint(2UL), Bytes(gy)), // y
    ]),
  )
  let key = @cose.parse_cose_key(cose_key)
  match key {
    Ec2P256(pubkey=_) => ()
    _ => abort("expected Ec2P256")
  }
}

///|
test "parse_cose_key: RSA with small modulus" {
  // Use a tiny known-bad-but-DER-valid modulus + e=65537. The point is to
  // exercise the parser, not actually verify. Pick a fake 64-byte modulus
  // (so it's >> e but small enough to keep the test fast).
  let n = hex_to_bytes(
    "0cdb9c2e7e1c5fb9876c5d8c4af1ad6ad9bb6c44423c5f4afe7c93bb71f6c8df16ee5cf2c4f4b7e3ab9a9e9c1d3c8a5f2e1d4c3b2a1908070605040302010001",
  )
  let e = b"\x01\x00\x01"
  let cose_key = @cbor.encode(
    Map([
      (Uint(1UL), Uint(3UL)), // kty = RSA
      (Uint(3UL), Nint(256UL)), // alg = RS256 (-257); Nint(256) is -257
      (Nint(0UL), Bytes(n)), // n
      (Nint(1UL), Bytes(e)), // e
    ]),
  )
  let key = @cose.parse_cose_key(cose_key)
  match key {
    Rsa(pubkey=_) => ()
    _ => abort("expected Rsa")
  }
}

///|
test "parse_cose_key: missing kty rejected" {
  let cose_key = @cbor.encode(
    Map([(Uint(3UL), Nint(7UL))]), // only alg, no kty
  )
  let r = try? @cose.parse_cose_key(cose_key)
  match r {
    Err(InvalidKey(_)) => ()
    _ => abort("expected InvalidKey")
  }
}

///|
test "parse_cose_key: unknown OKP curve rejected" {
  let cose_key = @cbor.encode(
    Map([
      (Uint(1UL), Uint(1UL)), // kty = OKP
      (Nint(0UL), Uint(99UL)), // crv = 99 (bogus)
      (Nint(1UL), Bytes(b"\x00")), // x (placeholder)
    ]),
  )
  let r = try? @cose.parse_cose_key(cose_key)
  match r {
    Err(InvalidKey(_)) => ()
    _ => abort("expected InvalidKey")
  }
}

///|
test "ATTACK parse_cose_key: duplicate integer labels are rejected" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let pk_bytes = @ed25519.PrivateKey::from_seed(seed).public_key().to_bytes()
  let cose_key = @cbor.encode(
    Map([
      (Uint(1UL), Uint(1UL)),
      (Uint(1UL), Uint(1UL)),
      (Nint(0UL), Uint(6UL)),
      (Nint(1UL), Bytes(pk_bytes)),
    ]),
  )
  let r = try? @cose.parse_cose_key(cose_key)
  match r {
    Err(InvalidKey(_)) => ()
    Ok(_) => abort("accepted duplicate COSE_Key integer label")
    Err(e) => abort("expected InvalidKey, got " + repr(e))
  }
}

///|
test "ATTACK parse_cose_key: mismatched OKP alg label is rejected" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let pk_bytes = @ed25519.PrivateKey::from_seed(seed).public_key().to_bytes()
  let cose_key = @cbor.encode(
    Map([
      (Uint(1UL), Uint(1UL)), // kty = OKP
      (Uint(3UL), Nint(6UL)), // alg = ES256, not EdDSA
      (Nint(0UL), Uint(6UL)), // crv = Ed25519
      (Nint(1UL), Bytes(pk_bytes)),
    ]),
  )
  let r = try? @cose.parse_cose_key(cose_key)
  match r {
    Err(InvalidKey(_)) => ()
    Ok(_) => abort("accepted Ed25519 COSE_Key with ES256 alg")
    Err(e) => abort("expected InvalidKey, got " + repr(e))
  }
}

///|
test "ATTACK parse_cose_key: mismatched EC2 alg label is rejected" {
  let gx = hex_to_bytes(
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  )
  let gy = hex_to_bytes(
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  )
  let cose_key = @cbor.encode(
    Map([
      (Uint(1UL), Uint(2UL)), // kty = EC2
      (Uint(3UL), Nint(7UL)), // alg = EdDSA, not ES256
      (Nint(0UL), Uint(1UL)), // crv = P-256
      (Nint(1UL), Bytes(gx)),
      (Nint(2UL), Bytes(gy)),
    ]),
  )
  let r = try? @cose.parse_cose_key(cose_key)
  match r {
    Err(InvalidKey(_)) => ()
    Ok(_) => abort("accepted P-256 COSE_Key with EdDSA alg")
    Err(e) => abort("expected InvalidKey, got " + repr(e))
  }
}

///|
test "ATTACK parse_cose_key: unsupported RSA alg label is rejected" {
  let n = hex_to_bytes(
    "0cdb9c2e7e1c5fb9876c5d8c4af1ad6ad9bb6c44423c5f4afe7c93bb71f6c8df16ee5cf2c4f4b7e3ab9a9e9c1d3c8a5f2e1d4c3b2a1908070605040302010001",
  )
  let e = b"\x01\x00\x01"
  let cose_key = @cbor.encode(
    Map([
      (Uint(1UL), Uint(3UL)), // kty = RSA
      (Uint(3UL), Nint(36UL)), // alg = PS256 (-37), not supported here
      (Nint(0UL), Bytes(n)),
      (Nint(1UL), Bytes(e)),
    ]),
  )
  let r = try? @cose.parse_cose_key(cose_key)
  match r {
    Err(InvalidKey(_)) => ()
    Ok(_) => abort("accepted RSA COSE_Key with unsupported alg")
    Err(e) => abort("expected InvalidKey, got " + repr(e))
  }
}

///|
test "ATTACK parse_attestation_object: duplicate text labels are rejected" {
  let att_obj = @cbor.encode(
    Map([
      (Text("fmt"), Text("packed")),
      (Text("fmt"), Text("none")),
      (Text("authData"), Bytes(b"auth")),
      (Text("attStmt"), Map([])),
    ]),
  )
  let r = try? @cose.parse_attestation_object(att_obj)
  match r {
    Err(InvalidStructure(_)) => ()
    Ok(_) => abort("accepted duplicate attestationObject text label")
    Err(e) => abort("expected InvalidStructure, got " + repr(e))
  }
}

// --- COSE_Key + COSE_Sign1 end-to-end -----------------------------------

///|
test "end-to-end: parse COSE_Key + verify COSE_Sign1 (Ed25519)" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()

  // 1. Encode the public key as a COSE_Key.
  let cose_key_bytes = @cbor.encode(
    Map([
      (Uint(1UL), Uint(1UL)),
      (Uint(3UL), Nint(7UL)),
      (Nint(0UL), Uint(6UL)),
      (Nint(1UL), Bytes(pk.to_bytes())),
    ]),
  )

  // 2. Build the COSE_Sign1.
  let protected_bytes = @cbor.encode(Map([(Uint(1UL), Nint(7UL))]))
  let payload = b"webauthn-style payload"
  let sig_struct = @cbor.encode(
    Array([
      Text("Signature1"),
      Bytes(protected_bytes),
      Bytes(b""),
      Bytes(payload),
    ]),
  )
  let signature = sk.sign(sig_struct)
  let cose_sign1 = @cbor.encode(
    Array([Bytes(protected_bytes), Map([]), Bytes(payload), Bytes(signature)]),
  )

  // 3. Parse + verify.
  let key = @cose.parse_cose_key(cose_key_bytes)
  assert_true(@cose.verify_sign1(cose_sign1, payload, key))
}
