// OCSP parse + verify tests.
//
// We hand-build a BasicOCSPResponse from a TBSCertificate-style structure,
// sign it with a deterministic Ed25519 key, wrap in OCSPResponse, and run
// the round-trip through `verify(...)`. This exercises the same path that a
// real responder's bytes would take.

// ─── hex helpers ────────────────────────────────────────────────────────

///|
fn hex_to_bytes(s : String) -> Bytes {
  fn nibble(c : Int) -> Int {
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

  let n = s.length() / 2
  let arr = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = nibble(s.code_unit_at(i * 2).to_int())
    let lo = nibble(s.code_unit_at(i * 2 + 1).to_int())
    arr[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::makei(n, fn(i) { arr[i] })
}

// ─── Ed25519 cert builders (copied minimal subset from pkix_verify tests) ─

///|
fn ed25519_alg_id() -> @pkix.AlgorithmIdentifier {
  {
    algorithm: @asn1.ObjectIdentifier::from_arcs([1U, 3, 101, 112]),
    parameters: None,
  }
}

///|
fn ed25519_spki(pk : @ed25519.PublicKey) -> @pkix.SubjectPublicKeyInfo {
  {
    algorithm: ed25519_alg_id(),
    subject_public_key: { bytes: pk.to_bytes(), unused_bits: 0 },
  }
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
// Build a v3 Ed25519 cert from a subject seed, an issuer seed, validity, and
// optional extensions. Returns the parsed cert.
fn build_ed25519_cert(
  subject_seed_hex : String,
  subject_cn : String,
  issuer_cn : String,
  not_before : String,
  not_after : String,
  extensions : Array[@pkix.Extension],
  issuer_seed_hex : String,
) -> @pkix.Certificate raise {
  let subject_sk = @ed25519.PrivateKey::from_seed(
    hex_to_bytes(subject_seed_hex),
  )
  let issuer_sk = @ed25519.PrivateKey::from_seed(hex_to_bytes(issuer_seed_hex))
  let subject_pk = subject_sk.public_key()
  let tbs : @pkix.TbsCertificate = {
    version: 2,
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
  cert
}

///|
fn ext_key_usage_ocsp_signing() -> @pkix.Extension {
  // EKU = SEQUENCE OF OID, containing id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)
  let kp = @asn1.ObjectIdentifier::from_arcs([1U, 3, 6, 1, 5, 5, 7, 3, 9])
  let elem = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([@asn1.Element::new(@asn1.tag_oid, Oid(kp))]),
  )
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 37]),
    critical: false,
    value: @asn1.encode_der(elem),
  }
}

// ─── OCSP response builder ──────────────────────────────────────────────
//
// Builds a BasicOCSPResponse with a single SingleResponse, then wraps it in
// OCSPResponse. Signs tbsResponseData with `signer_seed_hex` (caller must
// arrange that the signer key matches whatever the verifier expects).

///|
fn id_sha256_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 16, 840, 1, 101, 3, 4, 2, 1])
}

///|
fn id_sha1_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 3, 14, 3, 2, 26])
}

///|
fn id_pkix_ocsp_basic_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 3, 6, 1, 5, 5, 7, 48, 1, 1])
}

///|
// Build the OCTET STRING content of a CertID for (issuer_cert, target_serial).
fn build_cert_id_elem(
  issuer_cert : @pkix.Certificate,
  target_serial : Bytes,
  use_sha256 : Bool,
) -> @asn1.Element {
  let alg_oid = if use_sha256 { id_sha256_oid() } else { id_sha1_oid() }
  let name_der = @pkix.serialize_name(issuer_cert.tbs.subject)
  let key_bytes = issuer_cert.tbs.subject_public_key_info.subject_public_key.bytes
  let name_hash = if use_sha256 {
    @hash.sha256(name_der)
  } else {
    @hash.sha1(name_der)
  }
  let key_hash = if use_sha256 {
    @hash.sha256(key_bytes)
  } else {
    @hash.sha1(key_bytes)
  }
  // CertID's hashAlgorithm is an AlgorithmIdentifier; many real responders
  // omit parameters for these hash OIDs, some emit NULL. Use absent (the
  // RFC 4055 recommended form for SHA-256, and acceptable for SHA-1 here).
  let hash_alg_elem = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([@asn1.Element::new(@asn1.tag_oid, Oid(alg_oid))]),
  )
  @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      hash_alg_elem,
      @asn1.Element::new(@asn1.tag_octet_string, OctetString(name_hash)),
      @asn1.Element::new(@asn1.tag_octet_string, OctetString(key_hash)),
      @asn1.Element::new(@asn1.tag_integer, Integer(target_serial)),
    ]),
  )
}

///|
enum BuildStatus {
  BGood
  BRevoked(String) // revocation_time
  BUnknown
}

///|
fn build_single_response_elem(
  issuer_cert : @pkix.Certificate,
  target_serial : Bytes,
  status : BuildStatus,
  this_update : String,
  next_update : String?,
  use_sha256 : Bool,
) -> @asn1.Element {
  let cert_id = build_cert_id_elem(issuer_cert, target_serial, use_sha256)
  let status_elem = match status {
    BGood =>
      // good [0] IMPLICIT NULL — content empty.
      @asn1.Element::new(@asn1.Tag::context(0U), Unknown(b""))
    BRevoked(t) => {
      // revoked [1] IMPLICIT RevokedInfo = SEQUENCE { revocationTime GenTime }
      // IMPLICIT replaces the SEQUENCE tag; content is the body of the
      // SEQUENCE. We need to emit `GeneralizedTime` element bytes here.
      let inner_elem = @asn1.Element::new(
        @asn1.tag_generalized_time,
        GeneralizedTime(t),
      )
      let inner_bytes = @asn1.encode_der(inner_elem)
      @asn1.Element::new(
        @asn1.Tag::context(1U, constructed=true),
        Unknown(inner_bytes),
      )
    }
    BUnknown =>
      // unknown [2] IMPLICIT NULL — content empty.
      @asn1.Element::new(@asn1.Tag::context(2U), Unknown(b""))
  }
  let items : Array[@asn1.Element] = [
    cert_id,
    status_elem,
    @asn1.Element::new(@asn1.tag_generalized_time, GeneralizedTime(this_update)),
  ]
  match next_update {
    Some(nu) => {
      // nextUpdate [0] EXPLICIT GeneralizedTime
      let nu_elem = @asn1.Element::new(
        @asn1.tag_generalized_time,
        GeneralizedTime(nu),
      )
      let nu_bytes = @asn1.encode_der(nu_elem)
      items.push(
        @asn1.Element::new(
          @asn1.Tag::context(0U, constructed=true),
          Unknown(nu_bytes),
        ),
      )
    }
    None => ()
  }
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn build_response_data_elem(
  responder_id_by_name : @pkix.Name,
  produced_at : String,
  single : @asn1.Element,
) -> @asn1.Element {
  // ResponderID byName [1] EXPLICIT Name — serialize the Name and decode_der
  // back to get an Element we can wrap in the context tag.
  let name_bytes = @pkix.serialize_name(responder_id_by_name)
  let name_as_elem = @asn1.decode_der(name_bytes) catch {
    _ => abort("name encode")
  }
  let rid_elem = @asn1.Element::new(
    @asn1.Tag::context(1U, constructed=true),
    Unknown(@asn1.encode_der(name_as_elem)),
  )
  @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      rid_elem,
      @asn1.Element::new(
        @asn1.tag_generalized_time,
        GeneralizedTime(produced_at),
      ),
      @asn1.Element::new(@asn1.tag_sequence, Sequence([single])),
    ]),
  )
}

///|
fn build_basic_ocsp_der(
  response_data_elem : @asn1.Element,
  signer_seed_hex : String,
  embedded_cert : @pkix.Certificate?,
) -> Bytes raise {
  let signer_sk = @ed25519.PrivateKey::from_seed(hex_to_bytes(signer_seed_hex))
  let tbs_bytes = @asn1.encode_der(response_data_elem)
  let sig = signer_sk.sign(tbs_bytes)
  let sig_alg_elem = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(
        @asn1.tag_oid,
        Oid(@asn1.ObjectIdentifier::from_arcs([1U, 3, 101, 112])),
      ),
    ]),
  )
  let sig_bs_elem = @asn1.Element::new(
    @asn1.tag_bit_string,
    BitString({ bytes: sig, unused_bits: 0 }),
  )
  let items : Array[@asn1.Element] = [
    response_data_elem, sig_alg_elem, sig_bs_elem,
  ]
  match embedded_cert {
    Some(cert) => {
      // certs [0] EXPLICIT SEQUENCE OF Certificate
      let cert_bytes = @pkix.serialize_certificate(cert)
      let cert_elem = @asn1.decode_der(cert_bytes) catch {
        _ => abort("cert encode")
      }
      let inner_seq = @asn1.Element::new(
        @asn1.tag_sequence,
        Sequence([cert_elem]),
      )
      items.push(
        @asn1.Element::new(
          @asn1.Tag::context(0U, constructed=true),
          Unknown(@asn1.encode_der(inner_seq)),
        ),
      )
    }
    None => ()
  }
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence(items)))
}

///|
fn build_ocsp_response_der(basic_der : Bytes) -> Bytes {
  // OCSPResponse ::= SEQUENCE {
  //   responseStatus  ENUMERATED (0=successful),
  //   responseBytes   [0] EXPLICIT ResponseBytes }
  //
  // ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
  let status_elem = @asn1.Element::new(
    @asn1.Tag::universal(10U),
    Unknown(b"\x00"),
  )
  let rb_elem = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_oid, Oid(id_pkix_ocsp_basic_oid())),
      @asn1.Element::new(@asn1.tag_octet_string, OctetString(basic_der)),
    ]),
  )
  let rb_inner_bytes = @asn1.encode_der(rb_elem)
  @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([
        status_elem,
        @asn1.Element::new(
          @asn1.Tag::context(0U, constructed=true),
          Unknown(rb_inner_bytes),
        ),
      ]),
    ),
  )
}

// ─── tests ──────────────────────────────────────────────────────────────

///|
let issuer_seed_hex : String = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

///|
let cert_seed_hex : String = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"

///|
test "ocsp: good status, direct-signed, SHA-256 CertID" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex,
    "Test Issuer",
    "Test Issuer",
    "200101000000Z",
    "300101000000Z",
    [],
    issuer_seed_hex,
  )
  let cert = build_ed25519_cert(
    cert_seed_hex,
    "Test Leaf",
    "Test Issuer",
    "230101000000Z",
    "330101000000Z",
    [],
    issuer_seed_hex,
  )
  let single = build_single_response_elem(
    issuer,
    cert.tbs.serial_number,
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
    true,
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  let status = @ocsp.verify(ocsp, cert, issuer, "20250601000000Z")
  @debug.assert_eq(status, Good)
}

///|
test "ocsp: revoked status round-trips with reason code" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex,
    "Test Issuer",
    "Test Issuer",
    "200101000000Z",
    "300101000000Z",
    [],
    issuer_seed_hex,
  )
  let cert = build_ed25519_cert(
    cert_seed_hex,
    "Test Leaf",
    "Test Issuer",
    "230101000000Z",
    "330101000000Z",
    [],
    issuer_seed_hex,
  )
  let single = build_single_response_elem(
    issuer,
    cert.tbs.serial_number,
    BRevoked("20240505000000Z"),
    "20240601000000Z",
    Some("20300101000000Z"),
    true,
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240601000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  let status = @ocsp.verify(ocsp, cert, issuer, "20250601000000Z")
  // Reason is absent in our builder (no [0] EXPLICIT CRLReason emitted).
  match status {
    Revoked(revocation_time~, reason~) => {
      @debug.assert_eq(revocation_time, "20240505000000Z")
      @debug.assert_eq(reason, None)
    }
    _ => abort("expected Revoked")
  }
}

///|
test "ocsp: unknown status" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex,
    "Test Issuer",
    "Test Issuer",
    "200101000000Z",
    "300101000000Z",
    [],
    issuer_seed_hex,
  )
  let cert = build_ed25519_cert(
    cert_seed_hex,
    "Test Leaf",
    "Test Issuer",
    "230101000000Z",
    "330101000000Z",
    [],
    issuer_seed_hex,
  )
  let single = build_single_response_elem(
    issuer,
    cert.tbs.serial_number,
    BUnknown,
    "20240101000000Z",
    Some("20300101000000Z"),
    true,
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  let status = @ocsp.verify(ocsp, cert, issuer, "20250601000000Z")
  @debug.assert_eq(status, Unknown)
}

///|
test "ocsp: SHA-1 CertID also accepted" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex,
    "Test Issuer",
    "Test Issuer",
    "200101000000Z",
    "300101000000Z",
    [],
    issuer_seed_hex,
  )
  let cert = build_ed25519_cert(
    cert_seed_hex,
    "Test Leaf",
    "Test Issuer",
    "230101000000Z",
    "330101000000Z",
    [],
    issuer_seed_hex,
  )
  let single = build_single_response_elem(
    issuer,
    cert.tbs.serial_number,
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
    false, // SHA-1
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  let status = @ocsp.verify(ocsp, cert, issuer, "20250601000000Z")
  @debug.assert_eq(status, Good)
}

///|
test "ocsp: stale response (now >= nextUpdate) rejected" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex,
    "Test Issuer",
    "Test Issuer",
    "200101000000Z",
    "300101000000Z",
    [],
    issuer_seed_hex,
  )
  let cert = build_ed25519_cert(
    cert_seed_hex,
    "Test Leaf",
    "Test Issuer",
    "230101000000Z",
    "330101000000Z",
    [],
    issuer_seed_hex,
  )
  let single = build_single_response_elem(
    issuer,
    cert.tbs.serial_number,
    BGood,
    "20240101000000Z",
    Some("20240201000000Z"),
    true,
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, cert, issuer, "20250601000000Z") catch {
    StaleResponse(_) => ()
    other => abort("expected StaleResponse, got " + repr(other) + "")
  } noraise {
    other => abort("expected StaleResponse, got " + repr(other) + "")
  }
}

///|
test "ocsp: wrong issuer (BadSignature)" {
  // Build OCSP signed by a key NOT matching the issuer cert we'll pass to
  // verify(). We do this by signing the BasicOCSPResponse with a different
  // seed but still embedding the original issuer's name as responderID.
  let issuer = build_ed25519_cert(
    issuer_seed_hex,
    "Test Issuer",
    "Test Issuer",
    "200101000000Z",
    "300101000000Z",
    [],
    issuer_seed_hex,
  )
  let cert = build_ed25519_cert(
    cert_seed_hex,
    "Test Leaf",
    "Test Issuer",
    "230101000000Z",
    "330101000000Z",
    [],
    issuer_seed_hex,
  )
  let single = build_single_response_elem(
    issuer,
    cert.tbs.serial_number,
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
    true,
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  // Sign with cert_seed, not issuer_seed.
  let basic = build_basic_ocsp_der(rd, cert_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, cert, issuer, "20250601000000Z") catch {
    BadSignature => ()
    other => abort("expected BadSignature, got " + repr(other) + "")
  } noraise {
    other => abort("expected BadSignature, got " + repr(other) + "")
  }
}

///|
test "ocsp: cert not in responses list (CertNotFound)" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex,
    "Test Issuer",
    "Test Issuer",
    "200101000000Z",
    "300101000000Z",
    [],
    issuer_seed_hex,
  )
  let cert = build_ed25519_cert(
    cert_seed_hex,
    "Test Leaf",
    "Test Issuer",
    "230101000000Z",
    "330101000000Z",
    [],
    issuer_seed_hex,
  )
  // Build a SingleResponse for a different serial.
  let single = build_single_response_elem(
    issuer,
    b"\x99",
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
    true,
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, cert, issuer, "20250601000000Z") catch {
    CertNotFound => ()
    other => abort("expected CertNotFound, got " + repr(other) + "")
  } noraise {
    other => abort("expected CertNotFound, got " + repr(other) + "")
  }
}

///|
test "ocsp: parse_response without verify works on a successful response" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex,
    "Test Issuer",
    "Test Issuer",
    "200101000000Z",
    "300101000000Z",
    [],
    issuer_seed_hex,
  )
  let cert = build_ed25519_cert(
    cert_seed_hex,
    "Test Leaf",
    "Test Issuer",
    "230101000000Z",
    "330101000000Z",
    [],
    issuer_seed_hex,
  )
  let single = build_single_response_elem(
    issuer,
    cert.tbs.serial_number,
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
    true,
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  let parsed = @ocsp.parse_response(ocsp)
  @debug.assert_eq(parsed.produced_at, "20240101000000Z")
  @debug.assert_eq(parsed.responses.length(), 1)
  @debug.assert_eq(parsed.responses[0].this_update, "20240101000000Z")
  @debug.assert_eq(parsed.responses[0].next_update, Some("20300101000000Z"))
  match parsed.responses[0].status {
    Good => ()
    _ => abort("expected Good")
  }
}

///|
test "ocsp: parse_response rejects non-successful OCSPResponseStatus" {
  // Hand-build an OCSPResponse with status = 3 (tryLater) and no responseBytes.
  let status_elem = @asn1.Element::new(
    @asn1.Tag::universal(10U),
    Unknown(b"\x03"),
  )
  let der = @asn1.encode_der(
    @asn1.Element::new(@asn1.tag_sequence, Sequence([status_elem])),
  )
  try @ocsp.parse_response(der) catch {
    ResponseNotSuccessful(3) => ()
    other => abort("expected ResponseNotSuccessful(3), got " + repr(other) + "")
  } noraise {
    other => abort("expected ResponseNotSuccessful(3), got " + repr(other) + "")
  }
}

///|
test "ocsp: delegated responder cert path" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex,
    "Test Issuer",
    "Test Issuer",
    "200101000000Z",
    "300101000000Z",
    [],
    issuer_seed_hex,
  )
  let leaf = build_ed25519_cert(
    cert_seed_hex,
    "Test Leaf",
    "Test Issuer",
    "230101000000Z",
    "330101000000Z",
    [],
    issuer_seed_hex,
  )
  // Build a delegated responder cert: subject = "OCSP Responder", signed by
  // issuer, with id-kp-OCSPSigning EKU.
  let resp_seed_hex = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
  let responder = build_ed25519_cert(
    resp_seed_hex,
    "OCSP Responder",
    "Test Issuer",
    "230101000000Z",
    "330101000000Z",
    [ext_key_usage_ocsp_signing()],
    issuer_seed_hex,
  )
  // The OCSP response is signed by the responder, not the issuer.
  let single = build_single_response_elem(
    issuer,
    leaf.tbs.serial_number,
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
    true,
  )
  // responderID byName uses the responder's subject (not the issuer's).
  let rd = build_response_data_elem(
    responder.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, resp_seed_hex, Some(responder))
  let ocsp = build_ocsp_response_der(basic)
  let status = @ocsp.verify(ocsp, leaf, issuer, "20250601000000Z")
  @debug.assert_eq(status, Good)
}
