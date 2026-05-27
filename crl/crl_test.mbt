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
fn ed25519_alg_elem(with_null_params : Bool) -> @asn1.Element {
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(
      @asn1.tag_oid,
      Oid(@asn1.ObjectIdentifier::from_arcs([1U, 3, 101, 112])),
    ),
  ]
  if with_null_params {
    items.push(@asn1.Element::new(@asn1.tag_null, Null))
  }
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
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
  build_ed25519_cert_with_extensions(
    subject_seed_hex,
    subject_cn,
    issuer_cn,
    issuer_seed_hex,
    [],
  )
}

///|
fn build_ed25519_cert_with_extensions(
  subject_seed_hex : String,
  subject_cn : String,
  issuer_cn : String,
  issuer_seed_hex : String,
  extensions : Array[@pkix.Extension],
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
    extensions,
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

///|
fn key_usage_ext(bits : Bytes) -> @pkix.Extension {
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 15]),
    critical: true,
    value: @asn1.encode_der(
      @asn1.Element::new(
        @asn1.tag_bit_string,
        BitString({ bytes: bits, unused_bits: 0 }),
      ),
    ),
  }
}

// ─── CRL builder ────────────────────────────────────────────────────────

///|
priv struct RevokedSpec {
  serial : Bytes
  date : String // UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime
}

///|
fn build_crl_der_with_options(
  issuer_cert : @pkix.Certificate,
  this_update : String,
  next_update : String?,
  revoked : Array[RevokedSpec],
  signer_seed_hex : String,
  inner_sig_alg_elem : @asn1.Element,
  outer_sig_alg_elem : @asn1.Element,
  extra_tbs_fields : Array[@asn1.Element],
  version_bytes? : Bytes = b"\x01",
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
  items.push(@asn1.Element::new(@asn1.tag_integer, Integer(version_bytes)))
  // signature algorithm: ed25519
  items.push(inner_sig_alg_elem)
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
  for extra in extra_tbs_fields {
    items.push(extra)
  }
  let tbs_elem = @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
  let tbs_bytes = @asn1.encode_der(tbs_elem)
  let sig = signer_sk.sign(tbs_bytes)
  let sig_bs_elem = @asn1.Element::new(
    @asn1.tag_bit_string,
    BitString({ bytes: sig, unused_bits: 0 }),
  )
  @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([tbs_elem, outer_sig_alg_elem, sig_bs_elem]),
    ),
  )
}

///|
fn build_crl_der(
  issuer_cert : @pkix.Certificate,
  this_update : String,
  next_update : String?,
  revoked : Array[RevokedSpec],
  signer_seed_hex : String,
) -> Bytes raise {
  build_crl_der_with_options(
    issuer_cert,
    this_update,
    next_update,
    revoked,
    signer_seed_hex,
    ed25519_alg_elem(false),
    ed25519_alg_elem(false),
    [],
  )
}

///|
fn build_crl_der_with_revoked_entry_elems(
  issuer_cert : @pkix.Certificate,
  this_update : String,
  next_update : String?,
  revoked_entries : Array[@asn1.Element],
  signer_seed_hex : String,
) -> Bytes raise {
  let signer_sk = @ed25519.PrivateKey::from_seed(hex_to_bytes(signer_seed_hex))
  let items : Array[@asn1.Element] = []
  items.push(@asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")))
  items.push(ed25519_alg_elem(false))
  let issuer_name_bytes = @pkix.serialize_name(issuer_cert.tbs.subject)
  let issuer_elem = @asn1.decode_der(issuer_name_bytes) catch {
    _ => abort("name")
  }
  items.push(issuer_elem)
  let tu_elem = if this_update.length() == 13 {
    @asn1.Element::new(@asn1.tag_utc_time, UtcTime(this_update))
  } else {
    @asn1.Element::new(@asn1.tag_generalized_time, GeneralizedTime(this_update))
  }
  items.push(tu_elem)
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
  items.push(@asn1.Element::new(@asn1.tag_sequence, Sequence(revoked_entries)))
  let tbs_elem = @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
  let tbs_bytes = @asn1.encode_der(tbs_elem)
  let sig = signer_sk.sign(tbs_bytes)
  let sig_bs_elem = @asn1.Element::new(
    @asn1.tag_bit_string,
    BitString({ bytes: sig, unused_bits: 0 }),
  )
  @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([tbs_elem, ed25519_alg_elem(false), sig_bs_elem]),
    ),
  )
}

///|
fn crl_extension_elem(
  oid : @asn1.ObjectIdentifier,
  critical : Bool,
) -> @asn1.Element {
  crl_extension_elem_with_value(oid, critical, b"\x05\x00")
}

///|
fn crl_extension_elem_with_value(
  oid : @asn1.ObjectIdentifier,
  critical : Bool,
  extn_value : Bytes,
) -> @asn1.Element {
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_oid, Oid(oid)),
  ]
  if critical {
    items.push(@asn1.Element::new(@asn1.tag_boolean, Boolean(true)))
  }
  items.push(
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(extn_value)),
  )
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn crl_number_extension_elem(critical : Bool, value : Bytes) -> @asn1.Element {
  crl_extension_elem_with_value(
    @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 20]),
    critical,
    value,
  )
}

///|
fn crl_extensions_explicit(exts : Array[@asn1.Element]) -> @asn1.Element {
  let seq = @asn1.Element::new(@asn1.tag_sequence, Sequence(exts))
  @asn1.Element::new(
    @asn1.Tag::context(0U, constructed=true),
    Unknown(@asn1.encode_der(seq)),
  )
}

// ─── tests ──────────────────────────────────────────────────────────────

///|
let issuer_seed_hex : String = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

///|
let openssl_ref_ca_pem : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIC/TCCAeWgAwIBAgIJAMfe2hGkAfZGMA0GCSqGSIb3DQEBCwUAMBwxGjAYBgNV
  #|BAMMEVJlZmVyZW5jZSBSb290IENBMB4XDTI2MDUyNzA1MDQ0NloXDTM2MDUyNDA1
  #|MDQ0NlowHDEaMBgGA1UEAwwRUmVmZXJlbmNlIFJvb3QgQ0EwggEiMA0GCSqGSIb3
  #|DQEBAQUAA4IBDwAwggEKAoIBAQDiow1UzEZVc3XKxM/WTdbKGvFytsvGQ0hI7W/3
  #|V/cL4pehxalQhTfRFROP9teG6GWWhbKm4fPMFxHA9qxZPd/I2nRWODtLslizgHls
  #|1synAsPqmF3xxOgU6NPqad/xizTEUZfAt0JMSJdWU5SS0Nh+a6o8niKf7lfSmC6H
  #|t4RMoAyr4uymrIjyyw1Lw+dlvoAU0G3gLpTzBRaiThwnTC2AlmB7upjya/Rt9D1f
  #|zb+rfxfJ4CbbIyDTnUve5JYLFSvBVo+gn20pCidxAX2Ekm1I9fSqpUQNH5o8EzHq
  #|gGcUSJjZurFrnDIsYh3TIVVKrnSKTLhmxcXymWoLKvnmAEkBAgMBAAGjQjBAMA8G
  #|A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRu/Z/GVcL3
  #|Rk6ZmYnMKNAAaP97LjANBgkqhkiG9w0BAQsFAAOCAQEAd2OMeqJgeXIQvoAMgl8d
  #|0ih9FUS+KaaTnOfbaiiPMcMn/6hl1M2rRwbdR4aZnnnJHpfi0I7x4OInAEaS5kO2
  #|nP9Fl+mOMp5SUzp5FDv7ogLC/LO9r09q6T/qGADB5xpJ2NHb0nEkZQQLIlW3skmY
  #|IZ1SQsIV1AAOxoOKMKb09McvRoihyZ4z63H22OlbLqLKrWGPNfBSk6o7HFACtm30
  #|MpGMpGiperbzRhcmsMPcFrKEen7zvlDa0WmnkBR8AljWLJGydVMOiCDDrEpyhR9E
  #|N5SPPLSC4+BDx0k/AB6GM2X3+mY6InHt7v5FxDfCK2ok7IEgND1GbWdbmWa7rnSQ
  #|cg==
  #|-----END CERTIFICATE-----

///|
let openssl_ref_leaf_pem : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIDJjCCAg6gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UEAwwRUmVm
  #|ZXJlbmNlIFJvb3QgQ0EwHhcNMjYwNTI3MDUwNDQ2WhcNMzYwNTI0MDUwNDQ2WjAZ
  #|MRcwFQYDVQQDDA5SZWZlcmVuY2UgTGVhZjCCASIwDQYJKoZIhvcNAQEBBQADggEP
  #|ADCCAQoCggEBAKcRsqK0Sy8FWp9VWLMIUNUG6dvut1acOturMefBL+KwOy0792Es
  #|E7S3s4Lzw1b6ZSB0ZVmnnQ/fL98iN8R4hN+uwfLhkFPyyMvVFuJv9pnHqgzcbV44
  #|4Tpux6PT7NbcMgXqYMjguTt/2ZKQITEUtNXctAIMSh9CsMyRWnb2cUs2c9oA30xs
  #|1zTkZUqLko8QpE4HHiCumTXi+rkjsm1dG4/Zck8Ugb/G1jerx3tbYwgDvwgHT8kj
  #|cZ1IKNk1i0AiO2rBaSzDEMFko8rzW+mCfwNbaBpWGNShucG/rgleBEkkRO+/sFn+
  #|iO4JEjsm6FCwbr4HbSM7Zy/fmejH9HQIUb0CAwEAAaN1MHMwDAYDVR0TAQH/BAIw
  #|ADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYE
  #|FEnO1ZkR07jNiI/5ikudqEm0Ll+CMB8GA1UdIwQYMBaAFG79n8ZVwvdGTpmZicwo
  #|0ABo/3suMA0GCSqGSIb3DQEBCwUAA4IBAQC9wg9Hp/0lLvwGfy+ZfZVMR5Zqb95H
  #|wtQXiZoSgh8ihiJDrRpF+YbfoZhfQTvqEFs2m8icKBBWS+bZ597DwrZLAQ2s46Rs
  #|rDLSQJR5jXJ3IB+Uuv91QTsCir2Pp4nRVhU+edjKoNIGlRaP4Sm2H2aInFUzW/NS
  #|ZMcgqOOsDHK2aOn07pFB6PMjDatkLOQdoIjjRrb8WdnTOq8yJVPyWlZt+mD6oUOl
  #|V0Sg/2pW3pfHPN4QiTnypfTwhaNt260s2M4hPVDIM6WHOMpe+u0zgbZQXvj+4tsU
  #|GjctzIbppDx0T4RcnrbzTRcpuyLsFnDeIoEqRqDjhW+n6L6uirsFg+iE
  #|-----END CERTIFICATE-----

///|
let openssl_ref_crl_der_hex : String = "3082018c3076020101300d06092a864886f70d01010b0500301c311a301806035504030c115265666572656e636520526f6f74204341170d3236303532373035303534305a170d3336303532343035303534305a3015301302021000170d3236" +
  "303532373035303534305aa00f300d300b0603551d14040402021001300d06092a864886f70d01010b0500038201010024c80f26c9f983dfc826e06b5db8d19b942fe907496c65a5468104e2918abf060afef11e2cc0011c8900ed8efb21b6e1" +
  "1e8931f0a8b5c4324aa463a234c61992a2c2ee40ec34a6b0cc3348429eac846d7a24c0caecd5bcf81d0f640c0cfa91f093aae32c62b83a18e5fb2f1961b25ee4b31d17fc734efe4f57d28a42c67f9679b6f96da74b730d4f6e3fc2be91a26848" +
  "09b286c918cc27cf4028c7e2db8bfaaaed504648cea9bbf12652572a80195bbdd9a3aaac18bd02c438c3ed8065ad19bb2d63cf1c7d8ddf26ee39c214198dedf6ba473a24b0b0725dc67fa5fecc3e89466ae1f39542f1fa98bc7c150ec8fb0b0c" +
  "ff98d1b110f5b76810cc8d6336753653"

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
  @debug.assert_eq(crl.this_update, "240101000000Z")
  @debug.assert_eq(crl.next_update, Some("300101000000Z"))
  @debug.assert_eq(crl.revoked.length(), 2)
  @debug.assert_eq(crl.revoked[0].serial, b"\x10")
  @debug.assert_eq(crl.revoked[0].revocation_date, "240501000000Z")
  @debug.assert_eq(crl.revoked[1].serial, b"\x42")
}

///|
test "crl reference: OpenSSL RSA CRL verifies and revoked serial matches" {
  let issuer = @pkix.parse_certificate(@pem.decode(openssl_ref_ca_pem).data)
  let leaf = @pkix.parse_certificate(@pem.decode(openssl_ref_leaf_pem).data)
  let der = hex_to_bytes(openssl_ref_crl_der_hex)
  let crl = @crl.verify(der, issuer, "270101000000Z")
  assert_true(@crl.is_revoked(crl, leaf.tbs.serial_number))
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
  @debug.assert_eq(crl.revoked.length(), 1)
}

///|
test "ATTACK crl: issuer keyUsage without cRLSign is rejected" {
  let issuer = build_ed25519_cert_with_extensions(
    issuer_seed_hex,
    "Test Issuer",
    "Test Issuer",
    issuer_seed_hex,
    [key_usage_ext(b"\x80")], // digitalSignature only, no cRLSign bit.
  )
  let der = build_crl_der(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [{ serial: b"\x10", date: "240501000000Z" }],
    issuer_seed_hex,
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    KeyUsageMissingCrlSign => ()
    other => abort("expected KeyUsageMissingCrlSign, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted CRL signed by issuer without cRLSign keyUsage")
  }
}

///|
test "ATTACK crl: non-digit Time is rejected before freshness trust" {
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
  try @crl.verify(der, issuer, "2506AA000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted CRL with non-digit Time")
  }
}

///|
test "ATTACK crl: impossible now date is rejected" {
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
  try @crl.verify(der, issuer, "250231235959Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted CRL verification with impossible now date")
  }
}

///|
test "ATTACK crl: inner and outer signature AlgorithmIdentifier must match exactly" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der_with_options(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [{ serial: b"\x10", date: "240501000000Z" }],
    issuer_seed_hex,
    ed25519_alg_elem(true),
    ed25519_alg_elem(false),
    [],
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    AlgorithmMismatch => ()
    Malformed(_) => ()
    other => abort("expected AlgorithmMismatch, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted CRL with mismatched AlgorithmIdentifier parameters")
  }
}

///|
test "ATTACK crl: unsupported TBSCertList version is rejected" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der_with_options(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [{ serial: b"\x10", date: "240501000000Z" }],
    issuer_seed_hex,
    ed25519_alg_elem(false),
    ed25519_alg_elem(false),
    [],
    version_bytes=b"\x02",
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted CRL with unsupported TBSCertList version")
  }
}

///|
test "ATTACK crl: unexpected trailing TBSCertList field is malformed" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der_with_options(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [],
    issuer_seed_hex,
    ed25519_alg_elem(false),
    ed25519_alg_elem(false),
    [@asn1.Element::new(@asn1.tag_null, Null)],
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted CRL with unexpected trailing TBSCertList field")
  }
}

///|
test "ATTACK crl: unsupported critical CRL extension is rejected" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let unknown_oid = @asn1.ObjectIdentifier::from_arcs([1U, 2, 3, 4])
  let der = build_crl_der_with_options(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [],
    issuer_seed_hex,
    ed25519_alg_elem(false),
    ed25519_alg_elem(false),
    [crl_extensions_explicit([crl_extension_elem(unknown_oid, true)])],
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted CRL with unsupported critical extension")
  }
}

///|
test "ATTACK crl: unsupported non-critical CRL extension is rejected" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let unknown_oid = @asn1.ObjectIdentifier::from_arcs([1U, 2, 3, 4])
  let der = build_crl_der_with_options(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [],
    issuer_seed_hex,
    ed25519_alg_elem(false),
    ed25519_alg_elem(false),
    [crl_extensions_explicit([crl_extension_elem(unknown_oid, false)])],
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted CRL with unsupported non-critical extension")
  }
}

///|
test "ATTACK crl: delta CRL indicator is rejected" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let delta_crl_indicator_oid = @asn1.ObjectIdentifier::from_arcs([
    2U, 5, 29, 27,
  ])
  let base_crl_number = @asn1.encode_der(
    @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
  )
  let der = build_crl_der_with_options(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [],
    issuer_seed_hex,
    ed25519_alg_elem(false),
    ed25519_alg_elem(false),
    [
      crl_extensions_explicit([
        crl_extension_elem_with_value(
          delta_crl_indicator_oid, false, base_crl_number,
        ),
      ]),
    ],
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted delta CRL without base-CRL semantics")
  }
}

///|
test "ATTACK crl: issuingDistributionPoint scoped CRL is rejected" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let issuing_distribution_point_oid = @asn1.ObjectIdentifier::from_arcs([
    2U, 5, 29, 28,
  ])
  let empty_scope = @asn1.encode_der(
    @asn1.Element::new(@asn1.tag_sequence, Sequence([])),
  )
  let der = build_crl_der_with_options(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [{ serial: b"\x10", date: "240501000000Z" }],
    issuer_seed_hex,
    ed25519_alg_elem(false),
    ed25519_alg_elem(false),
    [
      crl_extensions_explicit([
        crl_extension_elem_with_value(
          issuing_distribution_point_oid, true, empty_scope,
        ),
      ]),
    ],
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted scoped CRL without distribution-point matching")
  }
}

///|
test "ATTACK crl: certificateIssuer entry extension is rejected" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let certificate_issuer_oid = @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 29])
  let entry = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_integer, Integer(b"\x10")),
      @asn1.Element::new(@asn1.tag_utc_time, UtcTime("240501000000Z")),
      @asn1.Element::new(
        @asn1.tag_sequence,
        Sequence([
          crl_extension_elem_with_value(
            certificate_issuer_oid,
            true,
            @asn1.encode_der(
              @asn1.Element::new(@asn1.tag_sequence, Sequence([])),
            ),
          ),
        ]),
      ),
    ]),
  )
  let der = build_crl_der_with_revoked_entry_elems(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [entry],
    issuer_seed_hex,
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted indirect CRL entry without certificateIssuer support")
  }
}

///|
test "crl: non-critical cRLNumber is accepted after value validation" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der_with_options(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [],
    issuer_seed_hex,
    ed25519_alg_elem(false),
    ed25519_alg_elem(false),
    [
      crl_extensions_explicit([
        crl_number_extension_elem(
          false,
          @asn1.encode_der(
            @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
          ),
        ),
      ]),
    ],
  )
  let crl = @crl.verify(der, issuer, "250601000000Z")
  @debug.assert_eq(crl.revoked.length(), 0)
}

///|
test "ATTACK crl: cRLNumber value must be DER INTEGER" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der_with_options(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [],
    issuer_seed_hex,
    ed25519_alg_elem(false),
    ed25519_alg_elem(false),
    [crl_extensions_explicit([crl_number_extension_elem(false, b"\x05\x00")])],
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted cRLNumber extension without INTEGER value")
  }
}

///|
test "ATTACK crl: critical cRLNumber is rejected" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let der = build_crl_der_with_options(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [],
    issuer_seed_hex,
    ed25519_alg_elem(false),
    ed25519_alg_elem(false),
    [
      crl_extensions_explicit([
        crl_number_extension_elem(
          true,
          @asn1.encode_der(
            @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
          ),
        ),
      ]),
    ],
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted critical cRLNumber extension")
  }
}

///|
test "ATTACK crl: unsupported non-critical entry extension is rejected" {
  let issuer = build_ed25519_cert(
    issuer_seed_hex, "Test Issuer", "Test Issuer", issuer_seed_hex,
  )
  let unknown_oid = @asn1.ObjectIdentifier::from_arcs([1U, 2, 3, 4])
  let entry = @asn1.Element::new(
    @asn1.tag_sequence,
    Sequence([
      @asn1.Element::new(@asn1.tag_integer, Integer(b"\x10")),
      @asn1.Element::new(@asn1.tag_utc_time, UtcTime("240501000000Z")),
      @asn1.Element::new(
        @asn1.tag_sequence,
        Sequence([crl_extension_elem(unknown_oid, false)]),
      ),
    ]),
  )
  let der = build_crl_der_with_revoked_entry_elems(
    issuer,
    "240101000000Z",
    Some("300101000000Z"),
    [entry],
    issuer_seed_hex,
  )
  try @crl.verify(der, issuer, "250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted CRL with unsupported non-critical entry extension")
  }
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
  try @crl.verify(der, issuer, "250601000000Z") catch {
    BadSignature => ()
    other => abort("expected BadSignature, got " + repr(other) + "")
  } noraise {
    other => abort("expected BadSignature, got " + repr(other) + "")
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
  try @crl.verify(der, issuer, "250601000000Z") catch {
    StaleCrl(_) => ()
    other => abort("expected StaleCrl, got " + repr(other) + "")
  } noraise {
    other => abort("expected StaleCrl, got " + repr(other) + "")
  }
}

///|
test "crl: CRL without nextUpdate parses" {
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
  let crl = @crl.parse(der)
  @debug.assert_eq(crl.next_update, None)
}

///|
test "ATTACK crl: verify rejects CRL without nextUpdate freshness bound" {
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
  try @crl.verify(der, issuer, "250601000000Z") catch {
    StaleCrl(_) => ()
    other => abort("expected StaleCrl, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted CRL without nextUpdate freshness bound")
  }
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
  @debug.assert_eq(crl.revoked.length(), 0)
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
  try @crl.verify(der, issuer, "250601000000Z") catch {
    IssuerMismatch => ()
    other => abort("expected IssuerMismatch, got " + repr(other) + "")
  } noraise {
    other => abort("expected IssuerMismatch, got " + repr(other) + "")
  }
}
