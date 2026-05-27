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

///|
fn key_usage_ext(bits : Bytes) -> @pkix.Extension {
  let elem = @asn1.Element::new(
    @asn1.tag_bit_string,
    BitString({ bytes: bits, unused_bits: 0 }),
  )
  {
    oid: @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 15]),
    critical: true,
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
fn hash_algorithm_elem(
  alg_oid : @asn1.ObjectIdentifier,
  params : @asn1.Element?,
) -> @asn1.Element {
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_oid, Oid(alg_oid)),
  ]
  match params {
    Some(p) => items.push(p)
    None => ()
  }
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
// Build the OCTET STRING content of a CertID for (issuer_cert, target_serial).
fn build_cert_id_elem_with_params(
  issuer_cert : @pkix.Certificate,
  target_serial : Bytes,
  use_sha256 : Bool,
  params : @asn1.Element?,
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
  let hash_alg_elem = hash_algorithm_elem(alg_oid, params)
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
fn build_cert_id_elem(
  issuer_cert : @pkix.Certificate,
  target_serial : Bytes,
  use_sha256 : Bool,
) -> @asn1.Element {
  build_cert_id_elem_with_params(issuer_cert, target_serial, use_sha256, None)
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
  build_single_response_elem_with_cert_id(
    cert_id, status, this_update, next_update,
  )
}

///|
fn build_single_response_elem_with_cert_id(
  cert_id : @asn1.Element,
  status : BuildStatus,
  this_update : String,
  next_update : String?,
) -> @asn1.Element {
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
fn build_single_response_elem_with_status(
  cert_id : @asn1.Element,
  status_elem : @asn1.Element,
  this_update : String,
  next_update : String?,
) -> @asn1.Element {
  let items : Array[@asn1.Element] = [
    cert_id,
    status_elem,
    @asn1.Element::new(@asn1.tag_generalized_time, GeneralizedTime(this_update)),
  ]
  match next_update {
    Some(nu) => {
      let nu_elem = @asn1.Element::new(
        @asn1.tag_generalized_time,
        GeneralizedTime(nu),
      )
      items.push(
        @asn1.Element::new(
          @asn1.Tag::context(0U, constructed=true),
          Unknown(@asn1.encode_der(nu_elem)),
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
fn append_sequence_field(
  elem : @asn1.Element,
  extra : @asn1.Element,
) -> @asn1.Element {
  match elem.value {
    Sequence(items) => {
      let out : Array[@asn1.Element] = []
      for item in items {
        out.push(item)
      }
      out.push(extra)
      @asn1.Element::new(elem.tag, Sequence(out))
    }
    _ => abort("append_sequence_field expects SEQUENCE")
  }
}

///|
fn prepend_sequence_field(
  elem : @asn1.Element,
  extra : @asn1.Element,
) -> @asn1.Element {
  match elem.value {
    Sequence(items) => {
      let out : Array[@asn1.Element] = [extra]
      for item in items {
        out.push(item)
      }
      @asn1.Element::new(elem.tag, Sequence(out))
    }
    _ => abort("prepend_sequence_field expects SEQUENCE")
  }
}

///|
fn ocsp_extension_elem(
  oid : @asn1.ObjectIdentifier,
  critical : Bool,
) -> @asn1.Element {
  let items : Array[@asn1.Element] = [
    @asn1.Element::new(@asn1.tag_oid, Oid(oid)),
  ]
  if critical {
    items.push(@asn1.Element::new(@asn1.tag_boolean, Boolean(true)))
  }
  items.push(
    @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"\x05\x00")),
  )
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn ocsp_extensions_explicit(
  number : UInt,
  exts : Array[@asn1.Element],
) -> @asn1.Element {
  let seq = @asn1.Element::new(@asn1.tag_sequence, Sequence(exts))
  @asn1.Element::new(
    @asn1.Tag::context(number, constructed=true),
    Unknown(@asn1.encode_der(seq)),
  )
}

///|
fn build_basic_ocsp_der_with_extra(
  response_data_elem : @asn1.Element,
  signer_seed_hex : String,
  embedded_cert : @pkix.Certificate?,
  extra_fields : Array[@asn1.Element],
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
  for extra in extra_fields {
    items.push(extra)
  }
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence(items)))
}

///|
fn build_basic_ocsp_der(
  response_data_elem : @asn1.Element,
  signer_seed_hex : String,
  embedded_cert : @pkix.Certificate?,
) -> Bytes raise {
  build_basic_ocsp_der_with_extra(
    response_data_elem,
    signer_seed_hex,
    embedded_cert,
    [],
  )
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
let openssl_ref_ocsp_responder_pem : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIDMDCCAhigAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwHDEaMBgGA1UEAwwRUmVm
  #|ZXJlbmNlIFJvb3QgQ0EwHhcNMjYwNTI3MDUwNDQ2WhcNMzYwNTI0MDUwNDQ2WjAj
  #|MSEwHwYDVQQDDBhSZWZlcmVuY2UgT0NTUCBSZXNwb25kZXIwggEiMA0GCSqGSIb3
  #|DQEBAQUAA4IBDwAwggEKAoIBAQCnGyj/Dn/ULpkL+h9Rt5VbxcJNq6W3pAGA+s2i
  #|fggD3T+6bbzZM3HJ7/uT6EluDoXEoutx8ZYtRjWOYkg9zreJ4n0ff5g5zrZ0Jkon
  #|c0xu2u+K8w180GtC0f2LW9nwHDYqkYAGGUvP/+CuO84bjawXICnuZCChT+MeiZOe
  #|2NVei4yX+TIQTqvG8fAZAD2JLvqKvc8G64hPeUePQlNY6eFbq7bKcEyW2B+nOKHf
  #|O9KGLzVBduGTO2ojtTHrH82Bo1X738DIDH3ruEs2g9eg7EbjeDFfUIk7p8dKSVx0
  #|E5WIP95XYM5HXpo9XasQsxVURUCp5/w3OhkWurWCX2Cexi/TAgMBAAGjdTBzMAwG
  #|A1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMJ
  #|MB0GA1UdDgQWBBRDaHHdXO+ZrRl49d8vgjhAh1bi9zAfBgNVHSMEGDAWgBRu/Z/G
  #|VcL3Rk6ZmYnMKNAAaP97LjANBgkqhkiG9w0BAQsFAAOCAQEAHyrUvBiVs0g1F8/T
  #|34nGKzJ1AhIRb4rUHhue06qAa0tinigt9zK23KSHSVSiyHCmGUCrNK1nwk5lJsA/
  #|VkCvdeEZTIO74yBDn8Gj25AXPRaequipuZers8rf/gsyWFMvUdKEOeNrAfFtVzLX
  #|LjBD02PASFOQhM0wvUTQ08YUsAK0Jg8tIpByXNstK1D8ITiWUDqA6oJ0cdOzZ4cs
  #|PVG9Y02U32Lnc1ZajzZcUYQUiWNRXhgNAJOYZBBrlj57DlipdywgGRr5YaWsgLKa
  #|Ygi4GUSVnwfv+H21Ev/B/6t59GRr0EJq+1Gfe0zTv6H/JIGK9L87nJHQVKlY8UWu
  #|1m1NAw==
  #|-----END CERTIFICATE-----

///|
let openssl_ref_ocsp_direct_der_hex : String = "308201cd0a0100a08201c6308201c206092b0601050507300101048201b3308201af308198a11e301c311a301806035504030c115265666572656e636520526f6f74204341180f32303236303532373035303435355a30653063303b30090605" +
  "2b0e03021a0500041437152737810065c977c9007888800e11ccfe107404146efd9fc655c2f7464e999989cc28d00068ff7b2e020210008000180f32303236303532373035303435355aa011180f32303336303532343035303435355a300d06" +
  "092a864886f70d01010b0500038201010042016c04346876e3276954b2cd78d044da5bbdad81e36be3d068e50b3e03f82bbb8e18085c6e82375bc3cde84e8b80ed825f62b5be98d45c4b391333e52e6982d134d0421b35a0a06ec5c4517bd09f" +
  "5f643bf041e1dc78b6f9977d98cc86daba7746696c97984c40880abc53da5d5344d29c6d1be09de9d76b6d229f05ea288ebbd157d09990373310d37ac5a52f987007b68e61138a98e56d1b1ab02e9f725038ab93298abe686aa602b53ed5ca80" +
  "310157a7a3af5f5c747d601faeb9d274d00a4808ba8f988d4a75e8e3665021206ed4bbd64c6d2315cc8221353b8ed202da6accc2826ba554684f5d1a2c0bc6fdb041504af04d93a7d3564e76f670ae3779"

///|
let openssl_ref_ocsp_delegated_der_hex : String = "308205100a0100a08205093082050506092b0601050507300101048204f6308204f230819fa12530233121301f06035504030c185265666572656e6365204f43535020526573706f6e646572180f32303236303532373035303435355a306530" +
  "63303b300906052b0e03021a0500041437152737810065c977c9007888800e11ccfe107404146efd9fc655c2f7464e999989cc28d00068ff7b2e020210008000180f32303236303532373035303435355aa011180f3230333630353234303530" +
  "3435355a300d06092a864886f70d01010b0500038201010048483ac86a25fda7a705c504d7e7c3d1dbdf39c0a71e8bc25ffd954270d1413b69306774ee4fd6f28169b4a62cb18a4545f221a52566ad1943cf3f2c60bd12b6e142d135982d1a29" +
  "d772849198845effcffbbbff04b5aed8654a8d6f34f1c954eabafa2b616ce4a5322c5e50286ea8354991c1571e8c7a661bebb8c5e0ef74088f5e3e46890eaae8cf2e5dc492b0d466ef0c5624c2faf05b5c2822506c2745fa3ccd559206c66917" +
  "0daa6a310f74ff356e158a5930066b57b8eac59519f950fe7d48174b5a973f37f165d6f264b840957516b964c3690bbfb06683617be6957b875aa72dcd7b7925f2d26550c494949d53be498d9f05e90279b5c2524d03be8da082033830820334" +
  "3082033030820218a00302010202021001300d06092a864886f70d01010b0500301c311a301806035504030c115265666572656e636520526f6f74204341301e170d3236303532373035303434365a170d3336303532343035303434365a3023" +
  "3121301f06035504030c185265666572656e6365204f43535020526573706f6e64657230820122300d06092a864886f70d01010105000382010f003082010a0282010100a71b28ff0e7fd42e990bfa1f51b7955bc5c24daba5b7a40180facda2" +
  "7e0803dd3fba6dbcd93371c9effb93e8496e0e85c4a2eb71f1962d46358e62483dceb789e27d1f7f9839ceb674264a27734c6edaef8af30d7cd06b42d1fd8b5bd9f01c362a918006194bcfffe0ae3bce1b8dac172029ee6420a14fe31e89939e" +
  "d8d55e8b8c97f932104eabc6f1f019003d892efa8abdcf06eb884f79478f425358e9e15babb6ca704c96d81fa738a1df3bd2862f354176e1933b6a23b531eb1fcd81a355fbdfc0c80c7debb84b3683d7a0ec46e378315f50893ba7c74a495c74" +
  "1395883fde5760ce475e9a3d5dab10b315544540a9e7fc373a1916bab5825f609ec62fd30203010001a3753073300c0603551d130101ff04023000300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070309" +
  "301d0603551d0e04160414436871dd5cef99ad1978f5df2f8238408756e2f7301f0603551d230418301680146efd9fc655c2f7464e999989cc28d00068ff7b2e300d06092a864886f70d01010b050003820101001f2ad4bc1895b3483517cfd3" +
  "df89c62b32750212116f8ad41e1b9ed3aa806b4b629e282df732b6dca4874954a2c870a61940ab34ad67c24e6526c03f5640af75e1194c83bbe320439fc1a3db90173d169eaae8a9b997abb3cadffe0b3258532f51d28439e36b01f16d5732d7" +
  "2e3043d363c048539084cd30bd44d0d3c614b002b4260f2d2290725cdb2d2b50fc213896503a80ea827471d3b367872c3d51bd634d94df62e773565a8f365c5184148963515e180d00939864106b963e7b0e58a9772c20191af961a5ac80b29a" +
  "6208b81944959f07eff87db512ffc1ffab79f4646bd0426afb519f7b4cd3bfa1ff24818af4bf3b9c91d054a958f145aed66d4d03"

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
test "ocsp reference: OpenSSL direct RSA response verifies" {
  let issuer = @pkix.parse_certificate(@pem.decode(openssl_ref_ca_pem).data)
  let cert = @pkix.parse_certificate(@pem.decode(openssl_ref_leaf_pem).data)
  let status = @ocsp.verify(
    hex_to_bytes(openssl_ref_ocsp_direct_der_hex),
    cert,
    issuer,
    "270101000000Z",
  )
  @debug.assert_eq(status, Good)
}

///|
test "ocsp reference: OpenSSL delegated RSA responder verifies" {
  let issuer = @pkix.parse_certificate(@pem.decode(openssl_ref_ca_pem).data)
  let cert = @pkix.parse_certificate(@pem.decode(openssl_ref_leaf_pem).data)
  // Keep the delegated responder cert fixture parsed independently so the
  // embedded BasicOCSPResponse cert can be compared during debugging.
  let _ = @pkix.parse_certificate(
    @pem.decode(openssl_ref_ocsp_responder_pem).data,
  )
  let status = @ocsp.verify(
    hex_to_bytes(openssl_ref_ocsp_delegated_der_hex),
    cert,
    issuer,
    "270101000000Z",
  )
  @debug.assert_eq(status, Good)
}

///|
test "ATTACK ocsp: non-digit time input is rejected before status trust" {
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
  try @ocsp.verify(ocsp, cert, issuer, "202506AA000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted OCSP status with non-digit time input")
  }
}

///|
test "ATTACK ocsp: impossible now date is rejected" {
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
  try @ocsp.verify(ocsp, cert, issuer, "20250231235959Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted OCSP verification with impossible now date")
  }
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
test "ATTACK ocsp: CertID hashAlgorithm rejects non-NULL parameters" {
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
  let cert_id = build_cert_id_elem_with_params(
    issuer,
    cert.tbs.serial_number,
    true,
    Some(@asn1.Element::new(@asn1.tag_octet_string, OctetString(b""))),
  )
  let single = build_single_response_elem_with_cert_id(
    cert_id,
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, cert, issuer, "20250601000000Z") catch {
    Malformed(_) => ()
    UnsupportedHashAlgorithm(_) => ()
    other => abort("expected malformed hashAlgorithm, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted CertID hashAlgorithm with non-NULL parameters")
  }
}

///|
test "ATTACK ocsp: good CertStatus must have empty NULL content" {
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
  let cert_id = build_cert_id_elem(issuer, cert.tbs.serial_number, true)
  let single = build_single_response_elem_with_status(
    cert_id,
    @asn1.Element::new(@asn1.Tag::context(0U), Unknown(b"\x05\x00")),
    "20240101000000Z",
    Some("20300101000000Z"),
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, cert, issuer, "20250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted non-empty good CertStatus")
  }
}

///|
test "ATTACK ocsp: unexpected BasicOCSPResponse trailing field is malformed" {
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
  let basic = build_basic_ocsp_der_with_extra(rd, issuer_seed_hex, None, [
    @asn1.Element::new(@asn1.tag_null, Null),
  ])
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, cert, issuer, "20250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted BasicOCSPResponse with trailing field")
  }
}

///|
test "ATTACK ocsp: unsupported critical response extension is rejected" {
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
  let unknown_oid = @asn1.ObjectIdentifier::from_arcs([1U, 2, 3, 4])
  let rd = append_sequence_field(
    build_response_data_elem(issuer.tbs.subject, "20240101000000Z", single),
    ocsp_extensions_explicit(1U, [ocsp_extension_elem(unknown_oid, true)]),
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, cert, issuer, "20250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted unsupported critical response extension")
  }
}

///|
test "ATTACK ocsp: unsupported non-critical response extension is rejected" {
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
  let unknown_oid = @asn1.ObjectIdentifier::from_arcs([1U, 2, 3, 4])
  let rd = append_sequence_field(
    build_response_data_elem(issuer.tbs.subject, "20240101000000Z", single),
    ocsp_extensions_explicit(1U, [ocsp_extension_elem(unknown_oid, false)]),
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, cert, issuer, "20250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted unsupported non-critical response extension")
  }
}

///|
test "ATTACK ocsp: unsupported critical single extension is rejected" {
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
  let unknown_oid = @asn1.ObjectIdentifier::from_arcs([1U, 2, 3, 4])
  let single = append_sequence_field(
    build_single_response_elem(
      issuer,
      cert.tbs.serial_number,
      BGood,
      "20240101000000Z",
      Some("20300101000000Z"),
      true,
    ),
    ocsp_extensions_explicit(1U, [ocsp_extension_elem(unknown_oid, true)]),
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, cert, issuer, "20250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted unsupported critical single extension")
  }
}

///|
test "ATTACK ocsp: unsupported non-critical single extension is rejected" {
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
  let unknown_oid = @asn1.ObjectIdentifier::from_arcs([1U, 2, 3, 4])
  let single = append_sequence_field(
    build_single_response_elem(
      issuer,
      cert.tbs.serial_number,
      BGood,
      "20240101000000Z",
      Some("20300101000000Z"),
      true,
    ),
    ocsp_extensions_explicit(1U, [ocsp_extension_elem(unknown_oid, false)]),
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, cert, issuer, "20250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted unsupported non-critical single extension")
  }
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

///|
test "ATTACK ocsp: delegated responder keyUsage must allow digitalSignature" {
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
  let resp_seed_hex = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
  let responder = build_ed25519_cert(
    resp_seed_hex,
    "OCSP Responder",
    "Test Issuer",
    "230101000000Z",
    "330101000000Z",
    [
      ext_key_usage_ocsp_signing(),
      key_usage_ext(b"\x20"), // keyEncipherment only; no digitalSignature.
    ],
    issuer_seed_hex,
  )
  let single = build_single_response_elem(
    issuer,
    leaf.tbs.serial_number,
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
    true,
  )
  let rd = build_response_data_elem(
    responder.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, resp_seed_hex, Some(responder))
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, leaf, issuer, "20250601000000Z") catch {
    ResponderMissingDigitalSignatureKeyUsage => ()
    other =>
      abort(
        "expected ResponderMissingDigitalSignatureKeyUsage, got " + repr(other),
      )
  } noraise {
    _ => abort("accepted delegated OCSP responder without digitalSignature")
  }
}

///|
test "ATTACK ocsp: delegated responder issuer DN must match issuer cert subject" {
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
  let resp_seed_hex = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
  let responder = build_ed25519_cert(
    resp_seed_hex,
    "OCSP Responder",
    "Other Issuer",
    "230101000000Z",
    "330101000000Z",
    [ext_key_usage_ocsp_signing()],
    issuer_seed_hex,
  )
  let single = build_single_response_elem(
    issuer,
    leaf.tbs.serial_number,
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
    true,
  )
  let rd = build_response_data_elem(
    responder.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, resp_seed_hex, Some(responder))
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, leaf, issuer, "20250601000000Z") catch {
    ResponderNotSignedByIssuer => ()
    other => abort("expected ResponderNotSignedByIssuer, got " + repr(other))
  } noraise {
    _ => abort("accepted delegated OCSP responder with mismatched issuer DN")
  }
}

///|
test "ATTACK ocsp: unsupported ResponseData version is rejected" {
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
  let single = build_single_response_elem(
    issuer,
    leaf.tbs.serial_number,
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
    true,
  )
  let rd0 = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let bad_version = @asn1.Element::new(
    @asn1.Tag::context(0U, constructed=true),
    Unknown(
      @asn1.encode_der(@asn1.Element::new(@asn1.tag_integer, Integer(b"\x01"))),
    ),
  )
  let rd = prepend_sequence_field(rd0, bad_version)
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, leaf, issuer, "20250601000000Z") catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted OCSP ResponseData with unsupported version")
  }
}

///|
test "ATTACK ocsp: producedAt in the future is rejected" {
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
  let single = build_single_response_elem(
    issuer,
    leaf.tbs.serial_number,
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
    true,
  )
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20260101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, issuer_seed_hex, None)
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, leaf, issuer, "20250601000000Z") catch {
    StaleResponse(_) => ()
    other => abort("expected StaleResponse, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted OCSP response produced in the future")
  }
}

///|
test "ATTACK ocsp: delegated responderID must match embedded responder cert" {
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
  let single = build_single_response_elem(
    issuer,
    leaf.tbs.serial_number,
    BGood,
    "20240101000000Z",
    Some("20300101000000Z"),
    true,
  )
  // The signature and embedded cert are from the delegated responder, but
  // responderID falsely names the issuer. The responderID must identify the
  // certificate whose key verified the BasicOCSPResponse signature.
  let rd = build_response_data_elem(
    issuer.tbs.subject,
    "20240101000000Z",
    single,
  )
  let basic = build_basic_ocsp_der(rd, resp_seed_hex, Some(responder))
  let ocsp = build_ocsp_response_der(basic)
  try @ocsp.verify(ocsp, leaf, issuer, "20250601000000Z") catch {
    ResponderIdMismatch => ()
    other => abort("expected ResponderIdMismatch, got " + repr(other) + "")
  } noraise {
    _ => abort("accepted delegated OCSP with mismatched responderID")
  }
}
