// CRL parse + verify tests.
//
// Hand-builds a CertificateList (CRL) with one or two revoked entries, signs
// the tbsCertList with a deterministic Ed25519 key, then runs `verify(...)`
// and `is_revoked(...)`.

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

// ─── Ed25519 cert builder ───────────────────────────────────────────────

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
fn build_ed25519_cert(
  subject_seed_hex : String,
  subject_cn : String,
  issuer_cn : String,
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
      not_before: "200101000000Z",
      not_after: "300101000000Z",
      not_before_tag: @asn1.tag_utc_time,
      not_after_tag: @asn1.tag_utc_time,
    },
    subject: cn_name(subject_cn),
    subject_public_key_info: ed25519_spki(subject_pk),
    issuer_unique_id: None,
    subject_unique_id: None,
    extensions: [],
  }
  let tbs_elem = @pkix.tbs_certificate_to_element(tbs)
  let tbs_bytes = @asn1.encode_der(tbs_elem)
  let sig = issuer_sk.sign(tbs_bytes)
  {
    tbs,
    signature_algorithm: ed25519_alg_id(),
    signature: { bytes: sig, unused_bits: 0 },
  }
}

// ─── CRL builder ────────────────────────────────────────────────────────

///|
priv struct RevokedSpec {
  serial : Bytes
  date : String // UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime
}

///|
fn build_crl_der(
  issuer_cert : @pkix.Certificate,
  this_update : String,
  next_update : String?,
  revoked : Array[RevokedSpec],
  signer_seed_hex : String,
) -> Bytes raise {
  let signer_sk = @ed25519.PrivateKey::from_seed(hex_to_bytes(signer_seed_hex))
  // tbsCertList ::= SEQUENCE {
  //   version INTEGER OPTIONAL,
  //   signature AlgorithmIdentifier,
  //   issuer Name,
  //   thisUpdate Time,
  //   nextUpdate Time OPTIONAL,
  //   revokedCertificates SEQUENCE OF { serial, date } OPTIONAL,
  //   crlExtensions [0] EXPLICIT Extensions OPTIONAL }
  let items : Array[@asn1.Element] = []
  // version = 1 (v2)
  items.push(@asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")))
  // signature algorithm: ed25519
  items.push(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([
        @asn1.Element::new(
          @asn1.tag_oid,
          Oid(@asn1.ObjectIdentifier::from_arcs([1U, 3, 101, 112])),
        ),
      ]),
    ),
  )
  // issuer: re-decode the serialized subject of issuer_cert to get an Element.
  let issuer_name_bytes = @pkix.serialize_name(issuer_cert.tbs.subject)
  let issuer_elem = @asn1.decode_der(issuer_name_bytes) catch {
    _ => abort("name")
  }
  items.push(issuer_elem)
  // thisUpdate
  let tu_elem = if this_update.length() == 13 {
    @asn1.Element::new(@asn1.tag_utc_time, UtcTime(this_update))
  } else {
    @asn1.Element::new(@asn1.tag_generalized_time, GeneralizedTime(this_update))
  }
  items.push(tu_elem)
  // nextUpdate (optional)
  match next_update {
    Some(nu) => {
      let nu_elem = if nu.length() == 13 {
        @asn1.Element::new(@asn1.tag_utc_time, UtcTime(nu))
      } else {
        @asn1.Element::new(@asn1.tag_generalized_time, GeneralizedTime(nu))
      }
      items.push(nu_elem)
    }
    None => ()
  }
  // revokedCertificates
  if revoked.length() > 0 {
    let entries : Array[@asn1.Element] = []
    for r in revoked {
      let date_elem = if r.date.length() == 13 {
        @asn1.Element::new(@asn1.tag_utc_time, UtcTime(r.date))
      } else {
        @asn1.Element::new(@asn1.tag_generalized_time, GeneralizedTime(r.date))
      }
      entries.push(
        @asn1.Element::new(
          @asn1.tag_sequence,
          Sequence([
            @asn1.Element::new(@asn1.tag_integer, Integer(r.serial)),
            date_elem,
          ]),
        ),
      )
    }
    items.push(@asn1.Element::new(@asn1.tag_sequence, Sequence(entries)))
  }
  let tbs_elem = @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
  let tbs_bytes = @asn1.encode_der(tbs_elem)
  let sig = signer_sk.sign(tbs_bytes)
  let outer_sig_alg = @asn1.Element::new(
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
  @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([tbs_elem, outer_sig_alg, sig_bs_elem]),
    ),
  )
}

// ─── tests ──────────────────────────────────────────────────────────────

///|
let issuer_seed_hex : String = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

///|
test "crl: parse a CRL with two revoked entries" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [
      { serial: b"\x10", date: "240501000000Z" },
      { serial: b"\x42", date: "240601000000Z" },
    ],
    issuer_seed_hex,
  )
  let crl = @crl.parse(der)
  assert_eq(crl.this_update, "240101000000Z")
  assert_eq(crl.next_update, Some("300101000000Z"))
  assert_eq(crl.revoked.length(), 2)
  assert_eq(crl.revoked[0].serial, b"\x10")
  assert_eq(crl.revoked[0].revocation_date, "240501000000Z")
  assert_eq(crl.revoked[1].serial, b"\x42")
}

///|
test "crl: verify signature with correct issuer" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [{ serial: b"\x10", date: "240501000000Z" }],
    issuer_seed_hex,
  )
  let crl = @crl.verify(der, issuer, "250601000000Z")
  assert_eq(crl.revoked.length(), 1)
}

///|
test "crl: is_revoked finds revoked serial, misses others" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [
      { serial: b"\x10", date: "240501000000Z" },
      { serial: b"\x42", date: "240601000000Z" },
    ],
    issuer_seed_hex,
  )
  let crl = @crl.parse(der)
  assert_true(@crl.is_revoked(crl, b"\x10"))
  assert_true(@crl.is_revoked(crl, b"\x42"))
  assert_false(@crl.is_revoked(crl, b"\x99"))
}

///|
test "crl: is_revoked tolerates DER sign-prefix byte" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  // Serial 0x80 needs a leading 0x00 to stay positive as an INTEGER.
  let der = build_crl_der(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [{ serial: b"\x00\x80", date: "240501000000Z" }],
    issuer_seed_hex,
  )
  let crl = @crl.parse(der)
  // Caller might pass either form.
  assert_true(@crl.is_revoked(crl, b"\x00\x80"))
  assert_true(@crl.is_revoked(crl, b"\x80"))
  assert_false(@crl.is_revoked(crl, b"\x81"))
}

///|
test "crl: wrong issuer rejected with BadSignature" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  // Sign with a different key.
  let wrong_seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
  let der = build_crl_der(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [{ serial: b"\x10", date: "240501000000Z" }],
    wrong_seed,
  )
  match (try? @crl.verify(der, issuer, "250601000000Z")) {
    Err(BadSignature) => ()
    other => abort("expected BadSignature, got \{other}")
  }
}

///|
test "crl: stale CRL (now >= nextUpdate) rejected" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der(
    issuer,
    "240101000000Z",
    Some("240201000000Z"),
    [{ serial: b"\x10", date: "240115000000Z" }],
    issuer_seed_hex,
  )
  match (try? @crl.verify(der, issuer, "250601000000Z")) {
    Err(StaleCrl(_)) => ()
    other => abort("expected StaleCrl, got \{other}")
  }
}

///|
test "crl: CRL without nextUpdate parses and verifies" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der(
    issuer,
    "240101000000Z",
    None,
    [{ serial: b"\x10", date: "240501000000Z" }],
    issuer_seed_hex,
  )
  let crl = @crl.verify(der, issuer, "250601000000Z")
  assert_eq(crl.next_update, None)
}

///|
test "crl: empty revoked list" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [],
    issuer_seed_hex,
  )
  let crl = @crl.verify(der, issuer, "250601000000Z")
  assert_eq(crl.revoked.length(), 0)
  assert_false(@crl.is_revoked(crl, b"\x10"))
}

///|
test "crl: IssuerMismatch when issuer_cert.subject != CRL.issuer" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  // Build a CRL signed by `issuer`'s key but listing a different issuer name.
  let alt_issuer = build_ed25519_cert(
    issuer_seed_hex, "Other Issuer", "Other Issuer", issuer_seed_hex,
  )
  let der = build_crl_der(
    alt_issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [{ serial: b"\x10", date: "240501000000Z" }],
    issuer_seed_hex,
  )
  // verify() will reject before signature check because subjects don't match.
  match (try? @crl.verify(der, issuer, "250601000000Z")) {
    Err(IssuerMismatch) => ()
    other => abort("expected IssuerMismatch, got \{other}")
  }
}
