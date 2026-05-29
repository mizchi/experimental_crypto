// Blackbox tests for `mizchi/pkix_verify`.
//
// We deliberately build the self-signed Ed25519 certificate in-test rather
// than rely on a fixture: the `mizchi/pkix` round-trip is byte-stable so
// re-encoding a parsed cert produces the same bytes, and signing those bytes
// with our `mizchi/ed25519` gives us a cert that pkix_verify can verify
// end-to-end — no external openssl dependency in CI.

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

// ─── builders ────────────────────────────────────────────────────────────

///|
fn ed25519_alg_id() -> @pkix.AlgorithmIdentifier {
  // RFC 8410: id-Ed25519, no parameters.
  {
    algorithm: @asn1.ObjectIdentifier::from_arcs([1U, 3, 101, 112]),
    parameters: None,
  }
}

///|
fn rsa_encryption_alg_id(params : Bytes?) -> @pkix.AlgorithmIdentifier {
  {
    algorithm: @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 113549, 1, 1, 1]),
    parameters: params,
  }
}

///|
fn der_null() -> Bytes {
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_null, Null))
}

///|
fn der_empty_octet_string() -> Bytes {
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_octet_string, OctetString(b"")))
}

///|
fn cn_name(cn : String) -> @pkix.Name {
  let cn_oid = @asn1.ObjectIdentifier::from_arcs([2U, 5, 4, 3])
  let av : @pkix.AttributeTypeAndValue = {
    oid: cn_oid,
    value: @asn1.Element::new(@asn1.tag_utf8_string, Utf8String(cn)),
  }
  { rdns: [[av]] }
}

///|
fn ed25519_spki(pk : @ed25519.PublicKey) -> @pkix.SubjectPublicKeyInfo {
  {
    algorithm: ed25519_alg_id(),
    subject_public_key: { bytes: pk.to_bytes(), unused_bits: 0 },
  }
}

///|
// basicConstraints { cA = TRUE }
fn basic_constraints_ca_ext() -> @pkix.Extension {
  // SEQUENCE { BOOLEAN TRUE }
  let elem = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([@asn1.Element::new(@asn1.tag_boolean, Boolean(true))]),
  )
  let value = @asn1.encode_der(elem)
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 19]),
    critical: true,
    value,
  }
}

///|
// basicConstraints { cA = TRUE, pathLenConstraint = n }
fn basic_constraints_ca_pathlen_ext(path_len : Int) -> @pkix.Extension {
  // INTEGER content as a single byte (we only test small non-negative values).
  let int_bytes = Bytes::makei(1, fn(_) { path_len.to_byte() })
  let elem = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_boolean, Boolean(true)),
      @asn1.Element::new(@asn1.tag_integer, Integer(int_bytes)),
    ]),
  )
  let value = @asn1.encode_der(elem)
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 19]),
    critical: true,
    value,
  }
}

///|
fn basic_constraints_ca_pathlen_raw_ext(path_len : Bytes) -> @pkix.Extension {
  let elem = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_boolean, Boolean(true)),
      @asn1.Element::new(@asn1.tag_integer, Integer(path_len)),
    ]),
  )
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 19]),
    critical: true,
    value: @asn1.encode_der(elem),
  }
}

///|
fn basic_constraints_with_extra_field_ext() -> @pkix.Extension {
  let elem = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_boolean, Boolean(true)),
      @asn1.Element::new(@asn1.tag_integer, Integer(b"\x00")),
      @asn1.Element::new(@asn1.tag_boolean, Boolean(false)),
    ]),
  )
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 19]),
    critical: true,
    value: @asn1.encode_der(elem),
  }
}

///|
// basicConstraints { cA = FALSE } (i.e. end-entity)
fn basic_constraints_non_ca_ext() -> @pkix.Extension {
  // Empty SEQUENCE — cA defaults to FALSE.
  let elem = @asn1.Element::new(@asn1.tag_sequence, Sequence([]))
  let value = @asn1.encode_der(elem)
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 19]),
    critical: true,
    value,
  }
}

///|
// Build a v3 self-signed Ed25519 cert from a seed, validity, subject CN, and
// extensions. Returns the (parsed) `Certificate` plus the public key.
fn build_self_signed_ed25519(
  seed_hex : String,
  cn : String,
  not_before : String,
  not_after : String,
  extensions : Array[@pkix.Extension],
) -> (@pkix.Certificate, @ed25519.PublicKey) raise {
  build_ed25519_cert(
    seed_hex, cn, cn, // self-signed: issuer = subject
     not_before, not_after, extensions, seed_hex,
  )
}

///|
// Build a v3 Ed25519 cert signed by `issuer_seed_hex`, with subject pubkey
// derived from `subject_seed_hex`.
fn build_ed25519_cert(
  subject_seed_hex : String,
  subject_cn : String,
  issuer_cn : String,
  not_before : String,
  not_after : String,
  extensions : Array[@pkix.Extension],
  issuer_seed_hex : String,
) -> (@pkix.Certificate, @ed25519.PublicKey) raise {
  let subject_seed = hex_to_bytes(subject_seed_hex)
  let issuer_seed = hex_to_bytes(issuer_seed_hex)
  let subject_sk = @ed25519.PrivateKey::from_seed(subject_seed)
  let issuer_sk = @ed25519.PrivateKey::from_seed(issuer_seed)
  let subject_pk = subject_sk.public_key()
  let tbs : @pkix.TbsCertificate = {
    version: 2, // v3
    serial_number: b"\x01",
    signature: ed25519_alg_id(),
    issuer: cn_name(issuer_cn),
    validity: {
      not_before,
      not_after,
      not_before_tag: @asn1.tag_utc_time,
      not_after_tag: @asn1.tag_utc_time,
    },
    subject: cn_name(subject_cn),
    subject_public_key_info: ed25519_spki(subject_pk),
    issuer_unique_id: None,
    subject_unique_id: None,
    extensions,
  }
  let tbs_elem = @pkix.tbs_certificate_to_element(tbs)
  let tbs_bytes = @asn1.encode_der(tbs_elem)
  let sig = issuer_sk.sign(tbs_bytes)
  let cert : @pkix.Certificate = {
    tbs,
    signature_algorithm: ed25519_alg_id(),
    signature: { bytes: sig, unused_bits: 0 },
  }
  (cert, subject_pk)
}

// ─── extract_public_key ──────────────────────────────────────────────────

///|
test "extract_public_key: Ed25519 SPKI" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let spki = ed25519_spki(pk)
  let key = @pkix_verify.extract_public_key(spki)
  match key {
    Ed25519(got) => @debug.assert_eq(got.to_bytes(), pk.to_bytes())
    _ => assert_true(false)
  }
}

///|
test "extract_public_key: unsupported OID raises" {
  let bogus_oid = @asn1.ObjectIdentifier::from_arcs([1U, 2, 3, 4])
  let spki : @pkix.SubjectPublicKeyInfo = {
    algorithm: { algorithm: bogus_oid, parameters: None },
    subject_public_key: { bytes: b"\x00", unused_bits: 0 },
  }
  try @pkix_verify.extract_public_key(spki) catch {
    UnsupportedPublicKeyAlgorithm(_) => ()
    _ => assert_true(false)
  } noraise {
    _ => assert_true(false)
  }
}

///|
test "ATTACK pkix_verify: Ed25519 SPKI parameters must be absent" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let pk = @ed25519.PrivateKey::from_seed(seed).public_key()
  let spki : @pkix.SubjectPublicKeyInfo = {
    algorithm: {
      algorithm: @asn1.ObjectIdentifier::from_arcs([1U, 3, 101, 112]),
      parameters: Some(der_null()),
    },
    subject_public_key: { bytes: pk.to_bytes(), unused_bits: 0 },
  }
  try @pkix_verify.extract_public_key(spki) catch {
    UnsupportedPublicKeyAlgorithm(_) => ()
    _ => assert_true(false)
  } noraise {
    _ => assert_true(false)
  }
}

///|
test "ATTACK pkix_verify: RSA SPKI rsaEncryption parameters must be NULL when present" {
  let rsa_pkcs1 = hex_to_bytes("300702020101020103") // n=257, e=3
  let spki : @pkix.SubjectPublicKeyInfo = {
    algorithm: rsa_encryption_alg_id(Some(der_empty_octet_string())),
    subject_public_key: { bytes: rsa_pkcs1, unused_bits: 0 },
  }
  try @pkix_verify.extract_public_key(spki) catch {
    UnsupportedPublicKeyAlgorithm(_) => ()
    _ => assert_true(false)
  } noraise {
    _ => assert_true(false)
  }
}

///|
test "ATTACK pkix_verify: Ed25519 signature AlgorithmIdentifier parameters must be absent" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let sk = @ed25519.PrivateKey::from_seed(seed)
  let pk = sk.public_key()
  let msg = b"pkix parameter check"
  let sig = sk.sign(msg)
  let bad_alg : @pkix.AlgorithmIdentifier = {
    algorithm: @asn1.ObjectIdentifier::from_arcs([1U, 3, 101, 112]),
    parameters: Some(der_null()),
  }
  try
    @pkix_verify.verify_signature(
      msg,
      bad_alg,
      { bytes: sig, unused_bits: 0 },
      Ed25519(pk),
    )
  catch {
    MalformedExtension(_) => ()
    _ => assert_true(false)
  } noraise {
    _ => assert_true(false)
  }
}

// ─── verify_certificate (positive) ───────────────────────────────────────

///|
test "verify_certificate: self-signed Ed25519 succeeds" {
  let (cert, pk) = build_self_signed_ed25519(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "Test Root",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_ca_ext()],
  )
  @pkix_verify.verify_certificate(cert, Ed25519(pk), "250101000000Z")
}

///|
test "verify_certificate: self-signed Ed25519 round-trips through DER" {
  // The whole point of re-encoding TBS in verify_certificate is that the
  // parser/serializer roundtrip is byte-stable; confirm that by parsing the
  // serialized cert and verifying the parsed copy.
  let (cert, pk) = build_self_signed_ed25519(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "Test Root",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_ca_ext()],
  )
  let der = @pkix.serialize_certificate(cert)
  let parsed = @pkix.parse_certificate(der)
  @pkix_verify.verify_certificate(parsed, Ed25519(pk), "250101000000Z")
}

// ─── verify_certificate (negative) ───────────────────────────────────────

///|
test "verify_certificate: tampered signature fails" {
  let (cert, pk) = build_self_signed_ed25519(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "Test Root",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_ca_ext()],
  )
  // Flip the lowest bit of the signature.
  let sig_len = cert.signature.bytes.length()
  let tampered = Bytes::makei(sig_len, fn(i) {
    if i == 0 {
      (cert.signature.bytes[0].to_int() ^ 0x01).to_byte()
    } else {
      cert.signature.bytes[i]
    }
  })
  let bad : @pkix.Certificate = {
    tbs: cert.tbs,
    signature_algorithm: cert.signature_algorithm,
    signature: { bytes: tampered, unused_bits: 0 },
  }
  try @pkix_verify.verify_certificate(bad, Ed25519(pk), "250101000000Z") catch {
    SignatureMismatch => ()
    _ => assert_true(false)
  } noraise {
    _ => assert_true(false)
  }
}

///|
test "verify_certificate: NotYetValid before notBefore" {
  let (cert, pk) = build_self_signed_ed25519(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "Test Root",
    "300101000000Z",
    "400101000000Z",
    [basic_constraints_ca_ext()],
  )
  try
    @pkix_verify.verify_certificate(cert, Ed25519(pk), "250101000000Z")
  catch {
    NotYetValid => ()
    _ => assert_true(false)
  } noraise {
    _ => assert_true(false)
  }
}

///|
test "verify_certificate: Expired after notAfter" {
  let (cert, pk) = build_self_signed_ed25519(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "Test Root",
    "100101000000Z",
    "200101000000Z",
    [basic_constraints_ca_ext()],
  )
  try
    @pkix_verify.verify_certificate(cert, Ed25519(pk), "250101000000Z")
  catch {
    Expired => ()
    _ => assert_true(false)
  } noraise {
    _ => assert_true(false)
  }
}

///|
test "ATTACK verify_certificate: impossible now date is rejected" {
  let (cert, pk) = build_self_signed_ed25519(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "Test Root",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_ca_ext()],
  )
  try
    @pkix_verify.verify_certificate(cert, Ed25519(pk), "250231235959Z")
  catch {
    MalformedExtension(_) => ()
    other => abort("expected MalformedExtension, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted certificate verification with impossible now date")
  }
}

// ─── verify_chain ────────────────────────────────────────────────────────

///|
test "verify_chain: 2-cert chain (leaf + intermediate + anchor pubkey) passes" {
  // Trust anchor: seed A. Intermediate signed by anchor. Leaf signed by
  // intermediate.
  let anchor_seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let inter_seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
  let leaf_seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
  let anchor_sk = @ed25519.PrivateKey::from_seed(hex_to_bytes(anchor_seed))
  let anchor_pk = anchor_sk.public_key()
  let (inter, _) = build_ed25519_cert(
    inter_seed,
    "Test Intermediate",
    "Test Root",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_ca_ext()],
    anchor_seed,
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Test Leaf",
    "Test Intermediate",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_non_ca_ext()],
    inter_seed,
  )
  @pkix_verify.verify_chain(leaf, [inter], Ed25519(anchor_pk), "250101000000Z")
}

///|
test "verify_chain: IssuerSubjectMismatch when intermediate's subject != leaf's issuer" {
  let anchor_seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let inter_seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
  let leaf_seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
  let anchor_sk = @ed25519.PrivateKey::from_seed(hex_to_bytes(anchor_seed))
  let anchor_pk = anchor_sk.public_key()
  let (inter, _) = build_ed25519_cert(
    inter_seed,
    "Test Intermediate",
    "Test Root",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_ca_ext()],
    anchor_seed,
  )
  // Leaf claims a DIFFERENT issuer name than the intermediate's subject.
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Test Leaf",
    "Other Intermediate",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_non_ca_ext()],
    inter_seed,
  )
  try
    @pkix_verify.verify_chain(
      leaf,
      [inter],
      Ed25519(anchor_pk),
      "250101000000Z",
    )
  catch {
    IssuerSubjectMismatch => ()
    _ => assert_true(false)
  } noraise {
    _ => assert_true(false)
  }
}

///|
test "verify_chain: NotACA when intermediate lacks basicConstraints cA" {
  let anchor_seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let inter_seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
  let leaf_seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
  let anchor_sk = @ed25519.PrivateKey::from_seed(hex_to_bytes(anchor_seed))
  let anchor_pk = anchor_sk.public_key()
  // Intermediate has basicConstraints with cA = FALSE — invalid as a CA.
  let (inter, _) = build_ed25519_cert(
    inter_seed,
    "Test Intermediate",
    "Test Root",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_non_ca_ext()],
    anchor_seed,
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Test Leaf",
    "Test Intermediate",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_non_ca_ext()],
    inter_seed,
  )
  try
    @pkix_verify.verify_chain(
      leaf,
      [inter],
      Ed25519(anchor_pk),
      "250101000000Z",
    )
  catch {
    NotACA => ()
    _ => assert_true(false)
  } noraise {
    _ => assert_true(false)
  }
}

///|
test "verify_chain: PathLengthExceeded when intermediate's pathLen too small" {
  // Build a 3-cert chain: anchor → inter_top → inter_mid → leaf where
  // inter_top sets pathLenConstraint=0 (meaning zero further sub-CAs may
  // follow). Since inter_mid is itself a CA below inter_top, that violates
  // the constraint.
  let anchor_seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let top_seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
  let mid_seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
  let leaf_seed = "0000000000000000000000000000000000000000000000000000000000000001"
  let anchor_sk = @ed25519.PrivateKey::from_seed(hex_to_bytes(anchor_seed))
  let anchor_pk = anchor_sk.public_key()
  let (top, _) = build_ed25519_cert(
    top_seed,
    "Top CA",
    "Test Root",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_ca_pathlen_ext(0)],
    anchor_seed,
  )
  let (mid, _) = build_ed25519_cert(
    mid_seed,
    "Mid CA",
    "Top CA",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_ca_ext()],
    top_seed,
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Mid CA",
    "200101000000Z",
    "300101000000Z",
    [basic_constraints_non_ca_ext()],
    mid_seed,
  )
  // intermediates ordered leaf → root direction.
  try
    @pkix_verify.verify_chain(
      leaf,
      [mid, top],
      Ed25519(anchor_pk),
      "250101000000Z",
    )
  catch {
    PathLengthExceeded => ()
    _ => assert_true(false)
  } noraise {
    _ => assert_true(false)
  }
}

// ─── real-world: Let's Encrypt R10 signed by ISRG Root X1 ────────────────

///|
let isrg_root_x1_pem : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
  #|TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
  #|cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
  #|WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
  #|ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
  #|MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
  #|h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
  #|0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
  #|A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
  #|T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
  #|B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
  #|B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
  #|KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
  #|OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
  #|jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
  #|qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
  #|rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
  #|HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
  #|hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
  #|ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
  #|3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
  #|NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
  #|ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
  #|TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
  #|jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
  #|oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
  #|4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
  #|mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
  #|emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
  #|-----END CERTIFICATE-----

///|
// Lifted out of `mizchi/pkix/fixtures_test.mbt` because that file is
// test-scope and we cannot import it from here.
let lets_encrypt_r10_pem : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIFBTCCAu2gAwIBAgIQS6hSk/eaL6JzBkuoBI110DANBgkqhkiG9w0BAQsFADBP
  #|MQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFy
  #|Y2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTAeFw0yNDAzMTMwMDAwMDBa
  #|Fw0yNzAzMTIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBF
  #|bmNyeXB0MQwwCgYDVQQDEwNSMTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
  #|AoIBAQDPV+XmxFQS7bRH/sknWHZGUCiMHT6I3wWd1bUYKb3dtVq/+vbOo76vACFL
  #|YlpaPAEvxVgD9on/jhFD68G14BQHlo9vH9fnuoE5CXVlt8KvGFs3Jijno/QHK20a
  #|/6tYvJWuQP/py1fEtVt/eA0YYbwX51TGu0mRzW4Y0YCF7qZlNrx06rxQTOr8IfM4
  #|FpOUurDTazgGzRYSespSdcitdrLCnF2YRVxvYXvGLe48E1KGAdlX5jgc3421H5KR
  #|mudKHMxFqHJV8LDmowfs/acbZp4/SItxhHFYyTr6717yW0QrPHTnj7JHwQdqzZq3
  #|DZb3EoEmUVQK7GH29/Xi8orIlQ2NAgMBAAGjgfgwgfUwDgYDVR0PAQH/BAQDAgGG
  #|MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATASBgNVHRMBAf8ECDAGAQH/
  #|AgEAMB0GA1UdDgQWBBS7vMNHpeS8qcbDpHIMEI2iNeHI6DAfBgNVHSMEGDAWgBR5
  #|tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAKG
  #|Fmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0gBAwwCjAIBgZngQwBAgEwJwYD
  #|VR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVuY3Iub3JnLzANBgkqhkiG9w0B
  #|AQsFAAOCAgEAkrHnQTfreZ2B5s3iJeE6IOmQRJWjgVzPw139vaBw1bGWKCIL0vIo
  #|zwzn1OZDjCQiHcFCktEJr59L9MhwTyAWsVrdAfYf+B9haxQnsHKNY67u4s5Lzzfd
  #|u6PUzeetUK29v+PsPmI2cJkxp+iN3epi4hKu9ZzUPSwMqtCceb7qPVxEbpYxY1p9
  #|1n5PJKBLBX9eb9LU6l8zSxPWV7bK3lG4XaMJgnT9x3ies7msFtpKK5bDtotij/l0
  #|GaKeA97pb5uwD9KgWvaFXMIEt8jVTjLEvwRdvCn294GPDF08U8lAkIv7tghluaQh
  #|1QnlE4SEN4LOECj8dsIGJXpGUk3aU3KkJz9icKy+aUgA+2cP21uh6NcDIS3XyfaZ
  #|QjmDQ993ChII8SXWupQZVBiIpcWO4RqZk3lr7Bz5MUCwzDIA359e57SSq5CCkY0N
  #|4B6Vulk7LktfwrdGNVI5BsC9qqxSwSKgRJeZ9wygIaehbHFHFhcBaMDKpiZlBHyz
  #|rsnnlFXCb5s8HKn5LsUgGvB24L7sGNZP2CX7dhHov+YhD+jozLW2p9W4959Bz2Ei
  #|RmqDtmiXLnzqTpXbI+suyCsohKRg6Un0RC47+cpiVwHiXZAW+cn8eiNIjqbVgXLx
  #|KPpdzvvtTnOPlC7SQZSYmdunr3Bf9b77AiC/ZidstK36dRILKz7OA54=
  #|-----END CERTIFICATE-----

///|
test "verify_certificate: LE R10 intermediate signed by ISRG Root X1" {
  let root_der = @pem.decode(isrg_root_x1_pem).data
  let r10_der = @pem.decode(lets_encrypt_r10_pem).data
  let root = @pkix.parse_certificate(root_der)
  let r10 = @pkix.parse_certificate(r10_der)
  let root_pubkey = @pkix_verify.extract_public_key(
    root.tbs.subject_public_key_info,
  )
  // R10's validity: 2024-03-13 to 2027-03-12. Use 2025-01-01.
  @pkix_verify.verify_certificate(r10, root_pubkey, "250101000000Z")
}

///|
test "verify_certificate: LE R10 expired check fires before 2024-03-13" {
  let r10_der = @pem.decode(lets_encrypt_r10_pem).data
  let root_der = @pem.decode(isrg_root_x1_pem).data
  let r10 = @pkix.parse_certificate(r10_der)
  let root = @pkix.parse_certificate(root_der)
  let root_pubkey = @pkix_verify.extract_public_key(
    root.tbs.subject_public_key_info,
  )
  try @pkix_verify.verify_certificate(r10, root_pubkey, "200101000000Z") catch {
    NotYetValid => ()
    _ => assert_true(false)
  } noraise {
    _ => assert_true(false)
  }
}

// -----------------------------------------------------------------------------
// Security attack tests
// -----------------------------------------------------------------------------

///|
// Construct a v3 Ed25519 cert carrying a single critical extension with an
// OID we do NOT recognise (1.2.3.4.5 — IANA-unassigned playground arc) and a
// trivial DER value. RFC 5280 §4.2: the verifier MUST reject.
test "ATTACK RFC 5280 §4.2: unknown critical extension rejected" {
  let unknown_oid = @asn1.ObjectIdentifier::from_arcs([1U, 2, 3, 4, 5])
  // extnValue: a tiny OCTET STRING-shaped payload — for an unknown extension
  // the content doesn't matter because we reject before parsing it.
  let value : Bytes = b"\x04\x00"
  let bad_ext : @pkix.Extension = { oid: unknown_oid, critical: true, value }
  let (cert, pk) = build_self_signed_ed25519(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "Attacker CA",
    "250101000000Z",
    "260101000000Z",
    [bad_ext],
  )
  let issuer_pk = @pkix_verify.PublicKey::Ed25519(pk)
  try @pkix_verify.verify_certificate(cert, issuer_pk, "250601000000Z") catch {
    UnknownCriticalExtension(oid) => @debug.assert_eq(oid, unknown_oid)
    other =>
      abort("unknown critical extension NOT rejected: " + repr(other) + "")
  } noraise {
    other =>
      abort("unknown critical extension NOT rejected: " + repr(other) + "")
  }
}

///|
test "ATTACK RFC 5280 §4.2: recognised-but-unenforced critical extensions reject" {
  let san = san_ext("example.com")
  let critical_san : @pkix.Extension = {
    oid: san.oid,
    critical: true,
    value: san.value,
  }
  let policy_ext : @pkix.Extension = {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 32]),
    critical: true,
    value: @asn1.encode_der(
      @asn1.Element::new(@asn1.tag_sequence, Sequence([])),
    ),
  }
  let cases : Array[@pkix.Extension] = [critical_san, policy_ext]
  for ext in cases {
    let (cert, pk) = build_self_signed_ed25519(
      "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
      "Critical Extension",
      "250101000000Z",
      "260101000000Z",
      [ext],
    )
    let issuer_pk = @pkix_verify.PublicKey::Ed25519(pk)
    try
      @pkix_verify.verify_certificate(cert, issuer_pk, "250601000000Z")
    catch {
      UnknownCriticalExtension(oid) => @debug.assert_eq(oid, ext.oid)
      other =>
        abort("unenforced critical extension accepted: " + repr(other) + "")
    } noraise {
      other =>
        abort("unenforced critical extension accepted: " + repr(other) + "")
    }
  }
}

///|
// Same OID but `critical = false` — the verifier ignores it per RFC 5280.
test "non-critical unknown extension is silently accepted" {
  let unknown_oid = @asn1.ObjectIdentifier::from_arcs([1U, 2, 3, 4, 5])
  let value : Bytes = b"\x04\x00"
  let benign_ext : @pkix.Extension = {
    oid: unknown_oid,
    critical: false,
    value,
  }
  let (cert, pk) = build_self_signed_ed25519(
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
    "Benign CA",
    "250101000000Z",
    "260101000000Z",
    [benign_ext],
  )
  let issuer_pk = @pkix_verify.PublicKey::Ed25519(pk)
  // Should not raise.
  @pkix_verify.verify_certificate(cert, issuer_pk, "250601000000Z")
}

// -----------------------------------------------------------------------------
// Compliance test fixtures: extension builders for the new enforcement paths
// -----------------------------------------------------------------------------

///|
// keyUsage BIT STRING. cRLSign(6) always set so the string is non-empty;
// keyCertSign(5) is optional. critical defaults to true.
fn key_usage_ext(key_cert_sign : Bool, critical : Bool) -> @pkix.Extension {
  let mut byte0 = 0x02 // cRLSign (bit 6)
  if key_cert_sign {
    byte0 = byte0 | 0x04 // keyCertSign (bit 5)
  }
  let bytes = Bytes::makei(1, fn(_) { byte0.to_byte() })
  let bs : @asn1.BitString = { unused_bits: 1, bytes }
  let value = @asn1.encode_der(
    @asn1.Element::new(@asn1.tag_bit_string, BitString(bs)),
  )
  { oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 15]), critical, value }
}

///|
// subjectAltName extension carrying a single dNSName ([2] IMPLICIT IA5String).
fn san_ext(dns : String) -> @pkix.Extension {
  let dns_bytes = Bytes::makei(dns.length(), fn(i) {
    dns.get_char(i).unwrap().to_int().to_byte()
  })
  let dns_element = @asn1.Element::new(
    @asn1.Tag::context(2U),
    @asn1.Value::Unknown(dns_bytes),
  )
  let san_seq = @asn1.Element::new(@asn1.tag_sequence, Sequence([dns_element]))
  let value = @asn1.encode_der(san_seq)
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 17]),
    critical: false,
    value,
  }
}

///|
// nameConstraints with a single excludedSubtrees DNS entry.
fn name_constraints_excluded_ext(dns : String) -> @pkix.Extension {
  let dns_bytes = Bytes::makei(dns.length(), fn(i) {
    dns.get_char(i).unwrap().to_int().to_byte()
  })
  // GeneralSubtree = SEQUENCE { base [2] IA5String }
  // Then [1] IMPLICIT SEQUENCE OF GeneralSubtree = excludedSubtrees.
  let base = @asn1.Element::new(
    @asn1.Tag::context(2U),
    @asn1.Value::Unknown(dns_bytes),
  )
  let gst = @asn1.Element::new(@asn1.tag_sequence, Sequence([base]))
  let gst_bytes = @asn1.encode_der(gst)
  // [1] IMPLICIT SEQUENCE OF GeneralSubtree — context-specific constructed.
  let excluded_subtrees = @asn1.Element::new(
    @asn1.Tag::context(1U, constructed=true),
    @asn1.Value::Unknown(gst_bytes),
  )
  let nc = @asn1.Element::new(@asn1.tag_sequence, Sequence([excluded_subtrees]))
  let value = @asn1.encode_der(nc)
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 30]),
    critical: true,
    value,
  }
}

///|
// nameConstraints with a single permittedSubtrees DNS entry ([0] IMPLICIT).
fn name_constraints_permitted_ext(dns : String) -> @pkix.Extension {
  let dns_bytes = Bytes::makei(dns.length(), fn(i) {
    dns.get_char(i).unwrap().to_int().to_byte()
  })
  let base = @asn1.Element::new(
    @asn1.Tag::context(2U),
    @asn1.Value::Unknown(dns_bytes),
  )
  let gst = @asn1.Element::new(@asn1.tag_sequence, Sequence([base]))
  let gst_bytes = @asn1.encode_der(gst)
  // [0] IMPLICIT SEQUENCE OF GeneralSubtree — context-specific constructed.
  let permitted_subtrees = @asn1.Element::new(
    @asn1.Tag::context(0U, constructed=true),
    @asn1.Value::Unknown(gst_bytes),
  )
  let nc = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([permitted_subtrees]),
  )
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 30]),
    critical: true,
    value: @asn1.encode_der(nc),
  }
}

///|
// nameConstraints with two permittedSubtrees DNS entries ([0] IMPLICIT).
fn name_constraints_permitted2_ext(
  dns1 : String,
  dns2 : String,
) -> @pkix.Extension {
  let mk_gst = fn(dns : String) {
    let dns_bytes = Bytes::makei(dns.length(), fn(i) {
      dns.get_char(i).unwrap().to_int().to_byte()
    })
    let base = @asn1.Element::new(
      @asn1.Tag::context(2U),
      @asn1.Value::Unknown(dns_bytes),
    )
    @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence([base])))
  }
  // SEQUENCE OF GeneralSubtree content = gst1 || gst2 (raw concatenation).
  let gst1_bytes = mk_gst(dns1)
  let gst2_bytes = mk_gst(dns2)
  let content = Bytes::makei(gst1_bytes.length() + gst2_bytes.length(), fn(i) {
    if i < gst1_bytes.length() {
      gst1_bytes[i]
    } else {
      gst2_bytes[i - gst1_bytes.length()]
    }
  })
  let permitted_subtrees = @asn1.Element::new(
    @asn1.Tag::context(0U, constructed=true),
    @asn1.Value::Unknown(content),
  )
  let nc = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([permitted_subtrees]),
  )
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 30]),
    critical: true,
    value: @asn1.encode_der(nc),
  }
}

///|
fn name_constraints_excluded_with_maximum_ext(dns : String) -> @pkix.Extension {
  let dns_bytes = Bytes::makei(dns.length(), fn(i) {
    dns.get_char(i).unwrap().to_int().to_byte()
  })
  let base = @asn1.Element::new(
    @asn1.Tag::context(2U),
    @asn1.Value::Unknown(dns_bytes),
  )
  let maximum = @asn1.Element::new(
    @asn1.Tag::context(1U),
    @asn1.Value::Unknown(b"\x01"),
  )
  let gst = @asn1.Element::new(@asn1.tag_sequence, Sequence([base, maximum]))
  let gst_bytes = @asn1.encode_der(gst)
  let excluded_subtrees = @asn1.Element::new(
    @asn1.Tag::context(1U, constructed=true),
    @asn1.Value::Unknown(gst_bytes),
  )
  let nc = @asn1.Element::new(@asn1.tag_sequence, Sequence([excluded_subtrees]))
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 30]),
    critical: true,
    value: @asn1.encode_der(nc),
  }
}

///|
fn name_constraints_unknown_top_level_ext() -> @pkix.Extension {
  let unexpected = @asn1.Element::new(
    @asn1.Tag::context(2U, constructed=true),
    @asn1.Value::Unknown(b""),
  )
  let nc = @asn1.Element::new(@asn1.tag_sequence, Sequence([unexpected]))
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 30]),
    critical: true,
    value: @asn1.encode_der(nc),
  }
}

///|
// extendedKeyUsage with one explicit OID (e.g. id-kp-serverAuth).
fn eku_ext_server_auth() -> @pkix.Extension {
  let server_auth = @asn1.ObjectIdentifier::from_arcs([
    1U, 3, 6, 1, 5, 5, 7, 3, 1,
  ])
  let value = @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([@asn1.Element::new(@asn1.tag_oid, Oid(server_auth))]),
    ),
  )
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 37]),
    critical: false,
    value,
  }
}

// -----------------------------------------------------------------------------
// Compliance: keyUsage enforcement
// -----------------------------------------------------------------------------

///|
test "ATTACK RFC 5280 §6.1.4(n): issuer keyUsage WITHOUT keyCertSign rejected" {
  // Build a 2-cert chain: leaf signed by intermediate, intermediate has
  // keyUsage but lacks keyCertSign. Should fail with KeyUsageMissingCertSign.
  let inter_seed = "0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10"
  let leaf_seed = "ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544332211ee"
  let bad_ku = key_usage_ext(false, true)
  let bc = basic_constraints_ca_ext()
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "Bad Intermediate",
    "250101000000Z",
    "260101000000Z",
    [bc, bad_ku],
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Bad Intermediate",
    "250101000000Z",
    "260101000000Z",
    [],
    inter_seed,
  )
  let inter_pk_extracted = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  ignore(inter_pk_extracted)
  // The trust anchor is the issuer of `inter`, which is `inter` itself
  // (self-signed). So anchor = inter's pubkey, intermediates = [inter].
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  try @pkix_verify.verify_chain(leaf, [inter], anchor, "250601000000Z") catch {
    KeyUsageMissingCertSign => ()
    other =>
      abort(
        "intermediate without keyCertSign NOT rejected: " + repr(other) + "",
      )
  } noraise {
    other =>
      abort(
        "intermediate without keyCertSign NOT rejected: " + repr(other) + "",
      )
  }
}

///|
test "keyUsage WITH keyCertSign passes" {
  let inter_seed = "1112131415161718191a1b1c1d1e1f201112131415161718191a1b1c1d1e1f20"
  let leaf_seed = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
  let good_ku = key_usage_ext(true, true)
  let bc = basic_constraints_ca_ext()
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "Good Intermediate",
    "250101000000Z",
    "260101000000Z",
    [bc, good_ku],
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Good Intermediate",
    "250101000000Z",
    "260101000000Z",
    [],
    inter_seed,
  )
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  // Should pass.
  @pkix_verify.verify_chain(leaf, [inter], anchor, "250601000000Z")
}

///|
test "ATTACK RFC 5280 §4.2: duplicate extension OIDs are rejected before use" {
  let inter_seed = "9192939495969798999a9b9c9d9e9fa09192939495969798999a9b9c9d9e9fa0"
  let leaf_seed = "a1a2a3a4a5a6a7a8a9aaabacadaeafa0a1a2a3a4a5a6a7a8a9aaabacadaeafa0"
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "Duplicate Extension CA",
    "250101000000Z",
    "260101000000Z",
    [basic_constraints_ca_ext(), basic_constraints_non_ca_ext()],
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Duplicate Extension CA",
    "250101000000Z",
    "260101000000Z",
    [],
    inter_seed,
  )
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  try @pkix_verify.verify_chain(leaf, [inter], anchor, "250601000000Z") catch {
    MalformedExtension(_) => ()
    other => abort("duplicate extension OID not rejected: " + repr(other))
  } noraise {
    other => abort("duplicate extension OID not rejected: " + repr(other))
  }
}

// -----------------------------------------------------------------------------
// Compliance: nameConstraints (DNS) enforcement
// -----------------------------------------------------------------------------

///|
test "ATTACK RFC 5280 §4.2.1.10: nameConstraints excludedSubtrees blocks child SAN" {
  // Intermediate excludes ".evil.com". Leaf has SAN dNSName "x.evil.com".
  // verify_chain must reject with NameConstraintViolation.
  let inter_seed = "2122232425262728292a2b2c2d2e2f302122232425262728292a2b2c2d2e2f30"
  let leaf_seed = "8877665544332211ffeeddccbbaa99887766554433221100ffeeddccbbaa9988"
  let bc = basic_constraints_ca_ext()
  let ku = key_usage_ext(true, true)
  let nc = name_constraints_excluded_ext("evil.com")
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "Constrained CA",
    "250101000000Z",
    "260101000000Z",
    [bc, ku, nc],
  )
  let leaf_san = san_ext("x.evil.com")
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Constrained CA",
    "250101000000Z",
    "260101000000Z",
    [leaf_san],
    inter_seed,
  )
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  try @pkix_verify.verify_chain(leaf, [inter], anchor, "250601000000Z") catch {
    NameConstraintViolation(name) => @debug.assert_eq(name, "x.evil.com")
    other => abort("excludedSubtree DNS NOT enforced: " + repr(other) + "")
  } noraise {
    other => abort("excludedSubtree DNS NOT enforced: " + repr(other) + "")
  }
}

///|
test "nameConstraints excludedSubtrees lets through a different DNS suffix" {
  // Same constraints as above but leaf SAN is "x.good.com" — allowed.
  let inter_seed = "3132333435363738393a3b3c3d3e3f403132333435363738393a3b3c3d3e3f40"
  let leaf_seed = "1111222233334444555566667777888811112222333344445555666677778888"
  let bc = basic_constraints_ca_ext()
  let ku = key_usage_ext(true, true)
  let nc = name_constraints_excluded_ext("evil.com")
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "Constrained CA",
    "250101000000Z",
    "260101000000Z",
    [bc, ku, nc],
  )
  let leaf_san = san_ext("api.good.com")
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Constrained CA",
    "250101000000Z",
    "260101000000Z",
    [leaf_san],
    inter_seed,
  )
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  @pkix_verify.verify_chain(leaf, [inter], anchor, "250601000000Z")
}

///|
// RFC 5280 §6.1.4(g): when intersecting permittedSubtrees down the chain
// produces the EMPTY set (two CAs whose permitted DNS subtrees are disjoint),
// the resulting permitted name space is empty and every subsequent name MUST
// be rejected. A buggy verifier that treats "empty permitted set" the same as
// "no permitted constraint" lets a CA escape the subtree it was restricted to.
//
// Chain: anchor (unconstrained) -> Inter A (permitted example.com)
//        -> Inter B (permitted evil.org) -> leaf (SAN www.evil.org).
// Inter A may only certify under example.com, so a leaf for evil.org issued
// through B MUST NOT validate.
test "ATTACK RFC 5280 §6.1.4(g): disjoint permittedSubtrees intersection denies all" {
  let anchor_seed = "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd"
  let inter_a_seed = "1122334455667788990011aabbccddeeff1122334455667788990011aabbccdd"
  let inter_b_seed = "2233445566778899001122aabbccddeeff2233445566778899001122aabbccdd"
  let leaf_seed = "3344556677889900112233aabbccddeeff3344556677889900112233aabbccdd"
  let ca_exts = fn(nc : @pkix.Extension) {
    [basic_constraints_ca_ext(), key_usage_ext(true, true), nc]
  }
  let (anchor, _) = build_self_signed_ed25519(
    anchor_seed,
    "Disjoint NC Anchor",
    "250101000000Z",
    "260101000000Z",
    [basic_constraints_ca_ext(), key_usage_ext(true, true)],
  )
  let anchor_pk = @pkix_verify.extract_public_key(
    anchor.tbs.subject_public_key_info,
  )
  let (inter_a, _) = build_ed25519_cert(
    inter_a_seed,
    "Inter A example.com",
    "Disjoint NC Anchor",
    "250101000000Z",
    "260101000000Z",
    ca_exts(name_constraints_permitted_ext("example.com")),
    anchor_seed,
  )
  let (inter_b, _) = build_ed25519_cert(
    inter_b_seed,
    "Inter B evil.org",
    "Inter A example.com",
    "250101000000Z",
    "260101000000Z",
    ca_exts(name_constraints_permitted_ext("evil.org")),
    inter_a_seed,
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Inter B evil.org",
    "250101000000Z",
    "260101000000Z",
    [san_ext("www.evil.org")],
    inter_b_seed,
  )
  // intermediates[0] is the leaf's direct parent (Inter B), [1] is Inter A.
  try
    @pkix_verify.verify_chain(
      leaf,
      [inter_b, inter_a],
      anchor_pk,
      "250601000000Z",
    )
  catch {
    NameConstraintViolation(name) => @debug.assert_eq(name, "www.evil.org")
    other => abort("expected NameConstraintViolation, got: " + repr(other) + "")
  } noraise {
    _ =>
      abort(
        "name-constraints bypass: leaf for evil.org accepted despite Inter A being restricted to example.com",
      )
  }
}

///|
// Positive counterpart: a child CA that NARROWS the parent's permitted subtree
// (sub.example.com ⊆ example.com) must still allow a leaf inside the narrowed
// space. Guards against the empty-set fix over-rejecting legitimate chains.
test "nameConstraints: child narrows parent permittedSubtrees, leaf still allowed" {
  let anchor_seed = "0a0b0c0d0e0f00112233445566778899aabbccddeeff0a0b0c0d0e0f00112233"
  let inter_a_seed = "1a1b1c1d1e1f00112233445566778899aabbccddeeff1a1b1c1d1e1f00112233"
  let inter_b_seed = "2a2b2c2d2e2f00112233445566778899aabbccddeeff2a2b2c2d2e2f00112233"
  let leaf_seed = "3a3b3c3d3e3f00112233445566778899aabbccddeeff3a3b3c3d3e3f00112233"
  let ca_exts = fn(nc : @pkix.Extension) {
    [basic_constraints_ca_ext(), key_usage_ext(true, true), nc]
  }
  let (anchor, _) = build_self_signed_ed25519(
    anchor_seed,
    "Narrow NC Anchor",
    "250101000000Z",
    "260101000000Z",
    [basic_constraints_ca_ext(), key_usage_ext(true, true)],
  )
  let anchor_pk = @pkix_verify.extract_public_key(
    anchor.tbs.subject_public_key_info,
  )
  // Parent permits example.com; child narrows to sub.example.com.
  let (inter_a, _) = build_ed25519_cert(
    inter_a_seed,
    "Inter A example.com",
    "Narrow NC Anchor",
    "250101000000Z",
    "260101000000Z",
    ca_exts(name_constraints_permitted_ext("example.com")),
    anchor_seed,
  )
  let (inter_b, _) = build_ed25519_cert(
    inter_b_seed,
    "Inter B sub.example.com",
    "Inter A example.com",
    "250101000000Z",
    "260101000000Z",
    ca_exts(name_constraints_permitted_ext("sub.example.com")),
    inter_a_seed,
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Inter B sub.example.com",
    "250101000000Z",
    "260101000000Z",
    [san_ext("host.sub.example.com")],
    inter_b_seed,
  )
  @pkix_verify.verify_chain(
    leaf,
    [inter_b, inter_a],
    anchor_pk,
    "250601000000Z",
  )
}

///|
// Regression for PR #2 review (codex): when a single child subtree is broader
// than SEVERAL parent permitted subtrees, the intersection must keep ALL of
// them, not just the first. Parent permits {a.example.com, b.example.com}; the
// child re-asserts the broader {example.com}. A leaf under b.example.com (the
// subtree that an early `break` would have dropped) must still validate.
test "nameConstraints: intersection keeps every narrower parent subtree" {
  let anchor_seed = "0e0f00112233445566778899aabbccddeeff0e0f00112233445566778899aabb"
  let inter_a_seed = "1e1f00112233445566778899aabbccddeeff1e1f00112233445566778899aabb"
  let inter_b_seed = "2e2f00112233445566778899aabbccddeeff2e2f00112233445566778899aabb"
  let leaf_b_seed = "3e3f00112233445566778899aabbccddeeff3e3f00112233445566778899aabb"
  let leaf_bad_seed = "4e4f00112233445566778899aabbccddeeff4e4f00112233445566778899aabb"
  let ca_exts = fn(nc : @pkix.Extension) {
    [basic_constraints_ca_ext(), key_usage_ext(true, true), nc]
  }
  let (anchor, _) = build_self_signed_ed25519(
    anchor_seed,
    "Multi NC Anchor",
    "250101000000Z",
    "260101000000Z",
    [basic_constraints_ca_ext(), key_usage_ext(true, true)],
  )
  let anchor_pk = @pkix_verify.extract_public_key(
    anchor.tbs.subject_public_key_info,
  )
  let (inter_a, _) = build_ed25519_cert(
    inter_a_seed,
    "Inter A a+b.example.com",
    "Multi NC Anchor",
    "250101000000Z",
    "260101000000Z",
    ca_exts(name_constraints_permitted2_ext("a.example.com", "b.example.com")),
    anchor_seed,
  )
  let (inter_b, _) = build_ed25519_cert(
    inter_b_seed,
    "Inter B example.com",
    "Inter A a+b.example.com",
    "250101000000Z",
    "260101000000Z",
    ca_exts(name_constraints_permitted_ext("example.com")),
    inter_a_seed,
  )
  // Leaf under b.example.com — the subtree a buggy early-break drops.
  let (leaf_b, _) = build_ed25519_cert(
    leaf_b_seed,
    "Leaf B",
    "Inter B example.com",
    "250101000000Z",
    "260101000000Z",
    [san_ext("host.b.example.com")],
    inter_b_seed,
  )
  @pkix_verify.verify_chain(
    leaf_b,
    [inter_b, inter_a],
    anchor_pk,
    "250601000000Z",
  )
  // A name inside example.com but outside both a/b subtrees must still fail.
  let (leaf_bad, _) = build_ed25519_cert(
    leaf_bad_seed,
    "Leaf BAD",
    "Inter B example.com",
    "250101000000Z",
    "260101000000Z",
    [san_ext("host.c.example.com")],
    inter_b_seed,
  )
  try
    @pkix_verify.verify_chain(
      leaf_bad,
      [inter_b, inter_a],
      anchor_pk,
      "250601000000Z",
    )
  catch {
    NameConstraintViolation(name) =>
      @debug.assert_eq(name, "host.c.example.com")
    other => abort("expected NameConstraintViolation, got: " + repr(other))
  } noraise {
    _ => abort("name outside the permitted a/b subtrees wrongly accepted")
  }
}

///|
// Same intersection but with parent/child order of specificity swapped: the
// PARENT is the narrower subtree (sub.example.com) and the child re-asserts the
// broader example.com. The intersection must keep the narrower sub.example.com,
// so a leaf within it is allowed while example.com-but-not-sub names are not.
// Guards the parent⊆child branch of intersect_dns_constraints.
test "nameConstraints: intersection keeps narrower parent subtree" {
  let anchor_seed = "0c0d0e0f00112233445566778899aabbccddeeff0c0d0e0f0011223344556677"
  let inter_a_seed = "1c1d1e1f00112233445566778899aabbccddeeff1c1d1e1f0011223344556677"
  let inter_b_seed = "2c2d2e2f00112233445566778899aabbccddeeff2c2d2e2f0011223344556677"
  let leaf_ok_seed = "3c3d3e3f00112233445566778899aabbccddeeff3c3d3e3f0011223344556677"
  let leaf_bad_seed = "4c4d4e4f00112233445566778899aabbccddeeff4c4d4e4f0011223344556677"
  let ca_exts = fn(nc : @pkix.Extension) {
    [basic_constraints_ca_ext(), key_usage_ext(true, true), nc]
  }
  let (anchor, _) = build_self_signed_ed25519(
    anchor_seed,
    "Swap NC Anchor",
    "250101000000Z",
    "260101000000Z",
    [basic_constraints_ca_ext(), key_usage_ext(true, true)],
  )
  let anchor_pk = @pkix_verify.extract_public_key(
    anchor.tbs.subject_public_key_info,
  )
  let (inter_a, _) = build_ed25519_cert(
    inter_a_seed,
    "Inter A sub.example.com",
    "Swap NC Anchor",
    "250101000000Z",
    "260101000000Z",
    ca_exts(name_constraints_permitted_ext("sub.example.com")),
    anchor_seed,
  )
  let (inter_b, _) = build_ed25519_cert(
    inter_b_seed,
    "Inter B example.com",
    "Inter A sub.example.com",
    "250101000000Z",
    "260101000000Z",
    ca_exts(name_constraints_permitted_ext("example.com")),
    inter_a_seed,
  )
  // Leaf inside sub.example.com is allowed.
  let (leaf_ok, _) = build_ed25519_cert(
    leaf_ok_seed,
    "Leaf OK",
    "Inter B example.com",
    "250101000000Z",
    "260101000000Z",
    [san_ext("api.sub.example.com")],
    inter_b_seed,
  )
  @pkix_verify.verify_chain(
    leaf_ok,
    [inter_b, inter_a],
    anchor_pk,
    "250601000000Z",
  )
  // Leaf at example.com but outside sub.example.com must be rejected.
  let (leaf_bad, _) = build_ed25519_cert(
    leaf_bad_seed,
    "Leaf BAD",
    "Inter B example.com",
    "250101000000Z",
    "260101000000Z",
    [san_ext("www.example.com")],
    inter_b_seed,
  )
  try
    @pkix_verify.verify_chain(
      leaf_bad,
      [inter_b, inter_a],
      anchor_pk,
      "250601000000Z",
    )
  catch {
    NameConstraintViolation(name) => @debug.assert_eq(name, "www.example.com")
    other => abort("expected NameConstraintViolation, got: " + repr(other))
  } noraise {
    _ => abort("name outside narrower sub.example.com subtree wrongly accepted")
  }
}

///|
test "ATTACK nameConstraints: unsupported GeneralSubtree maximum is rejected" {
  let inter_seed = "7172737475767778797a7b7c7d7e7f807172737475767778797a7b7c7d7e7f80"
  let leaf_seed = "8182838485868788898a8b8c8d8e8f908182838485868788898a8b8c8d8e8f90"
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "Bounded NC CA",
    "250101000000Z",
    "260101000000Z",
    [
      basic_constraints_ca_ext(),
      key_usage_ext(true, true),
      name_constraints_excluded_with_maximum_ext("evil.com"),
    ],
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Bounded NC CA",
    "250101000000Z",
    "260101000000Z",
    [san_ext("api.good.com")],
    inter_seed,
  )
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  try @pkix_verify.verify_chain(leaf, [inter], anchor, "250601000000Z") catch {
    MalformedExtension(_) => ()
    other => abort("GeneralSubtree maximum not rejected: " + repr(other))
  } noraise {
    other => abort("GeneralSubtree maximum not rejected: " + repr(other))
  }
}

///|
test "ATTACK nameConstraints: leading-dot excludedSubtrees blocks subdomain" {
  let inter_seed = "9192939495969798999a9b9c9d9e9fa09192939495969798999a9b9c9d9e9fa0"
  let leaf_seed = "a1a2a3a4a5a6a7a8a9aaabacadaeafa0a1a2a3a4a5a6a7a8a9aaabacadaeafa0"
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "Leading Dot NC CA",
    "250101000000Z",
    "260101000000Z",
    [
      basic_constraints_ca_ext(),
      key_usage_ext(true, true),
      name_constraints_excluded_ext(".evil.com"),
    ],
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Leading Dot NC CA",
    "250101000000Z",
    "260101000000Z",
    [san_ext("api.evil.com")],
    inter_seed,
  )
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  try @pkix_verify.verify_chain(leaf, [inter], anchor, "250601000000Z") catch {
    NameConstraintViolation(name) => @debug.assert_eq(name, "api.evil.com")
    other => abort("leading-dot excludedSubtrees not enforced: " + repr(other))
  } noraise {
    _ => abort("accepted subdomain under leading-dot excludedSubtrees")
  }
}

///|
test "ATTACK nameConstraints: unknown top-level field is rejected" {
  let inter_seed = "b1b2b3b4b5b6b7b8b9babbbcbdbebfb0b1b2b3b4b5b6b7b8b9babbbcbdbebfb0"
  let leaf_seed = "c1c2c3c4c5c6c7c8c9cacbcccdcecfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfc0"
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "Unknown NC CA",
    "250101000000Z",
    "260101000000Z",
    [
      basic_constraints_ca_ext(),
      key_usage_ext(true, true),
      name_constraints_unknown_top_level_ext(),
    ],
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Unknown NC CA",
    "250101000000Z",
    "260101000000Z",
    [san_ext("api.good.com")],
    inter_seed,
  )
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  try @pkix_verify.verify_chain(leaf, [inter], anchor, "250601000000Z") catch {
    MalformedExtension(_) => ()
    other => abort("unknown nameConstraints field not rejected: " + repr(other))
  } noraise {
    _ => abort("accepted unknown top-level nameConstraints field")
  }
}

// -----------------------------------------------------------------------------
// Compliance: required EKU on leaf
// -----------------------------------------------------------------------------

///|
test "required_eku: leaf without EKU passes (unrestricted per RFC 5280)" {
  let inter_seed = "4142434445464748494a4b4c4d4e4f504142434445464748494a4b4c4d4e4f50"
  let leaf_seed = "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788ee"
  let bc = basic_constraints_ca_ext()
  let ku = key_usage_ext(true, true)
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "CA",
    "250101000000Z",
    "260101000000Z",
    [bc, ku],
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "CA",
    "250101000000Z",
    "260101000000Z",
    [],
    inter_seed,
  )
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  let opts : @pkix_verify.VerifyChainOptions = {
    required_eku: Some(
      @asn1.ObjectIdentifier::from_arcs([1U, 3, 6, 1, 5, 5, 7, 3, 1]),
    ),
  }
  @pkix_verify.verify_chain_with_options(
    leaf,
    [inter],
    anchor,
    "250601000000Z",
    opts,
  )
}

///|
test "required_eku: leaf with mismatching EKU is rejected" {
  let inter_seed = "5152535455565758595a5b5c5d5e5f605152535455565758595a5b5c5d5e5f60"
  let leaf_seed = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  let bc = basic_constraints_ca_ext()
  let ku = key_usage_ext(true, true)
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "CA",
    "250101000000Z",
    "260101000000Z",
    [bc, ku],
  )
  // Leaf has EKU = serverAuth, caller requires clientAuth — should fail.
  let server_auth_only = eku_ext_server_auth()
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "CA",
    "250101000000Z",
    "260101000000Z",
    [server_auth_only],
    inter_seed,
  )
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  let client_auth = @asn1.ObjectIdentifier::from_arcs([
    1U, 3, 6, 1, 5, 5, 7, 3, 2,
  ])
  let opts : @pkix_verify.VerifyChainOptions = {
    required_eku: Some(client_auth),
  }
  try
    @pkix_verify.verify_chain_with_options(
      leaf,
      [inter],
      anchor,
      "250601000000Z",
      opts,
    )
  catch {
    ExtendedKeyUsageMissing(oid) => @debug.assert_eq(oid, client_auth)
    other => abort("required_eku not enforced: " + repr(other) + "")
  } noraise {
    other => abort("required_eku not enforced: " + repr(other) + "")
  }
}

///|
test "required_eku: leaf with matching EKU passes" {
  let inter_seed = "6162636465666768696a6b6c6d6e6f706162636465666768696a6b6c6d6e6f70"
  let leaf_seed = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
  let bc = basic_constraints_ca_ext()
  let ku = key_usage_ext(true, true)
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "CA",
    "250101000000Z",
    "260101000000Z",
    [bc, ku],
  )
  let server_auth_ext = eku_ext_server_auth()
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "CA",
    "250101000000Z",
    "260101000000Z",
    [server_auth_ext],
    inter_seed,
  )
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  let server_auth = @asn1.ObjectIdentifier::from_arcs([
    1U, 3, 6, 1, 5, 5, 7, 3, 1,
  ])
  let opts : @pkix_verify.VerifyChainOptions = {
    required_eku: Some(server_auth),
  }
  @pkix_verify.verify_chain_with_options(
    leaf,
    [inter],
    anchor,
    "250601000000Z",
    opts,
  )
}

///|
test "ATTACK required leaf digitalSignature: keyUsage without bit 0 is rejected" {
  let inter_seed = "7172737475767778797a7b7c7d7e7f807172737475767778797a7b7c7d7e7f80"
  let leaf_seed = "0101010101010101010101010101010101010101010101010101010101010101"
  let bc = basic_constraints_ca_ext()
  let ku = key_usage_ext(true, true)
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "CA",
    "250101000000Z",
    "260101000000Z",
    [bc, ku],
  )
  let leaf_ku_without_signature = key_usage_ext(false, true)
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "CA",
    "250101000000Z",
    "260101000000Z",
    [leaf_ku_without_signature],
    inter_seed,
  )
  let anchor = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  let opts : @pkix_verify.VerifyChainOptions = { required_eku: None }
  try
    @pkix_verify.verify_chain_for_signature(
      leaf,
      [inter],
      anchor,
      "250601000000Z",
      opts,
    )
  catch {
    KeyUsageMissingDigitalSignature => ()
    other => abort("leaf keyUsage not enforced: " + repr(other) + "")
  } noraise {
    _ => abort("accepted leaf keyUsage without digitalSignature")
  }
}

// -----------------------------------------------------------------------------
// pathLenConstraint sanity (RFC 5280 §4.2.1.9)
// -----------------------------------------------------------------------------

///|
// Build a 3-cert chain: anchor → I1 → I0 → leaf, where I1 carries
// pathLenConstraint = 0. RFC: I1 says "at most 0 non-self CAs may follow
// me", but the chain has one (I0) before the leaf → reject.
test "ATTACK: pathLenConstraint=0 with intermediate before leaf must reject" {
  let i1_seed = "abababababababababababababababababababababababababababababababab"
  let i0_seed = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
  let leaf_seed = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
  let ku = key_usage_ext(true, true)
  let (i1_cert, _) = build_self_signed_ed25519(
    i1_seed,
    "I1",
    "250101000000Z",
    "260101000000Z",
    [basic_constraints_ca_pathlen_ext(0), ku],
  )
  let (i0_cert, _) = build_ed25519_cert(
    i0_seed,
    "I0",
    "I1",
    "250101000000Z",
    "260101000000Z",
    [basic_constraints_ca_ext(), key_usage_ext(true, true)],
    i1_seed,
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "I0",
    "250101000000Z",
    "260101000000Z",
    [],
    i0_seed,
  )
  let anchor_pk = @pkix_verify.extract_public_key(
    i1_cert.tbs.subject_public_key_info,
  )
  try
    @pkix_verify.verify_chain(
      leaf,
      [i0_cert, i1_cert],
      anchor_pk,
      "250601000000Z",
    )
  catch {
    PathLengthExceeded => ()
    other =>
      abort("pathLen=0 + 1 intermediate NOT rejected: " + repr(other) + "")
  } noraise {
    other =>
      abort("pathLen=0 + 1 intermediate NOT rejected: " + repr(other) + "")
  }
}

///|
test "ATTACK: negative pathLenConstraint is malformed, not a large limit" {
  let inter_seed = "abababababababababababababababababababababababababababababababab"
  let leaf_seed = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "Bad pathLen CA",
    "250101000000Z",
    "260101000000Z",
    [basic_constraints_ca_pathlen_raw_ext(b"\xff"), key_usage_ext(true, true)],
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Bad pathLen CA",
    "250101000000Z",
    "260101000000Z",
    [],
    inter_seed,
  )
  let anchor_pk = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  try
    @pkix_verify.verify_chain(leaf, [inter], anchor_pk, "250601000000Z")
  catch {
    MalformedExtension(_) => ()
    other => abort("negative pathLen not rejected: " + repr(other) + "")
  } noraise {
    other => abort("negative pathLen not rejected: " + repr(other) + "")
  }
}

///|
test "ATTACK: basicConstraints with trailing fields is malformed" {
  let inter_seed = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
  let leaf_seed = "5656565656565656565656565656565656565656565656565656565656565656"
  let (inter, _) = build_self_signed_ed25519(
    inter_seed,
    "Trailing basicConstraints CA",
    "250101000000Z",
    "260101000000Z",
    [basic_constraints_with_extra_field_ext(), key_usage_ext(true, true)],
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "Trailing basicConstraints CA",
    "250101000000Z",
    "260101000000Z",
    [],
    inter_seed,
  )
  let anchor_pk = @pkix_verify.extract_public_key(
    inter.tbs.subject_public_key_info,
  )
  try
    @pkix_verify.verify_chain(leaf, [inter], anchor_pk, "250601000000Z")
  catch {
    MalformedExtension(_) => ()
    other =>
      abort("trailing basicConstraints not rejected: " + repr(other) + "")
  } noraise {
    other =>
      abort("trailing basicConstraints not rejected: " + repr(other) + "")
  }
}

///|
test "pathLenConstraint=1 with one intermediate before leaf passes" {
  let i1_seed = "1212121212121212121212121212121212121212121212121212121212121212"
  let i0_seed = "3434343434343434343434343434343434343434343434343434343434343434"
  let leaf_seed = "5656565656565656565656565656565656565656565656565656565656565656"
  let (i1_cert, _) = build_self_signed_ed25519(
    i1_seed,
    "I1",
    "250101000000Z",
    "260101000000Z",
    [basic_constraints_ca_pathlen_ext(1), key_usage_ext(true, true)],
  )
  let (i0_cert, _) = build_ed25519_cert(
    i0_seed,
    "I0",
    "I1",
    "250101000000Z",
    "260101000000Z",
    [basic_constraints_ca_ext(), key_usage_ext(true, true)],
    i1_seed,
  )
  let (leaf, _) = build_ed25519_cert(
    leaf_seed,
    "Leaf",
    "I0",
    "250101000000Z",
    "260101000000Z",
    [],
    i0_seed,
  )
  let anchor_pk = @pkix_verify.extract_public_key(
    i1_cert.tbs.subject_public_key_info,
  )
  // Should pass — I1 allows 1 sub-CA, I0 is exactly that.
  @pkix_verify.verify_chain(
    leaf,
    [i0_cert, i1_cert],
    anchor_pk,
    "250601000000Z",
  )
}
