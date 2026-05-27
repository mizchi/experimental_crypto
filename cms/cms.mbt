// mizchi/cms — Minimal RFC 5652 CMS SignedData verification.
//
// Scope:
//   - Detached CMS SignedData (eContent omitted; message provided by caller)
//   - One signer per SignedData (the only case openssl/gpgsm produce in
//     practice for `gpg --detach-sign` and `openssl cms -sign`)
//   - RSA-PKCS#1 v1.5 with SHA-256/384/512
//   - ECDSA P-256/P-384 with SHA-256/384
//   - signed_attrs MUST be present (modern signers always emit them) and
//     MUST contain messageDigest matching H(message). The signature is
//     then verified over the SET-OF re-encoding of signed_attrs.
//
// Out of scope:
//   - Encrypted CMS (EnvelopedData)
//   - Multiple signers / signer hierarchy
//   - certificateOnly / degenerate CMS
//   - Attribute certificate handling

///|
pub suberror CmsError {
  ContentTypeMismatch(@asn1.ObjectIdentifier)
  Asn1(@asn1.Asn1Error)
  Pkix(@pkix.PkixError)
  Malformed(String)
  NoSignerInfo
  NoSignerCertificate
  // Signer cert (matching SignerInfo.sid) is not in the certificates SET.
  SignerCertificateNotFound
  // [0] subjectKeyIdentifier sid form is not yet implemented.
  UnsupportedSid(String)
  UnsupportedDigestAlgorithm(@asn1.ObjectIdentifier)
  UnsupportedSignatureAlgorithm(@asn1.ObjectIdentifier)
  MessageDigestMismatch
  MissingMessageDigest
  Rsa(@rsa.RsaError)
  P256(@p256.P256Error)
  P384(@p384.P384Error)
} derive(Debug)

///|
pub(all) struct CmsSignedData {
  // Parsed signer certificate (the first one in `certificates`).
  signer_cert : @pkix.Certificate
  // Additional intermediate certificates carried in the CMS bundle.
  extra_certs : Array[@pkix.Certificate]
  // The single SignerInfo we decode. Multi-signer SignedData is rejected.
  signer : SignerInfoFields
}

///|
pub(all) struct SignerInfoFields {
  // Signer identifier — only issuerAndSerialNumber is supported (the
  // dominant choice for openssl/gpgsm-produced CMS). `[0] subjectKeyIdentifier`
  // is recognised at parse time and rejected via UnsupportedSid below.
  sid_issuer : Bytes // raw DER of the Name SEQUENCE
  sid_serial : Bytes // raw INTEGER content
  digest_alg : @asn1.ObjectIdentifier
  // Raw content bytes of the [0] IMPLICIT signed_attrs field (without
  // the [0] tag/length header). Needed to (a) extract the messageDigest
  // attribute and (b) reconstruct the SET OF for signature verification.
  signed_attrs_content : Bytes
  signature_alg : @asn1.ObjectIdentifier
  signature : Bytes
}

// ─── OIDs ────────────────────────────────────────────────────────────────

///|
fn id_signed_data() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 113549, 1, 7, 2])
}

///|
fn id_message_digest() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 113549, 1, 9, 4])
}

///|
fn id_sha256() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 16, 840, 1, 101, 3, 4, 2, 1])
}

///|
fn id_sha384() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 16, 840, 1, 101, 3, 4, 2, 2])
}

///|
fn id_sha512() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 16, 840, 1, 101, 3, 4, 2, 3])
}

///|
fn id_rsa_encryption() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 113549, 1, 1, 1])
}

///|
fn id_sha256_with_rsa() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 113549, 1, 1, 11])
}

///|
fn id_sha384_with_rsa() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 113549, 1, 1, 12])
}

///|
fn id_sha512_with_rsa() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 113549, 1, 1, 13])
}

///|
fn id_ecdsa_with_sha256() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 10045, 4, 3, 2])
}

///|
fn id_ecdsa_with_sha384() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 10045, 4, 3, 3])
}

///|
fn is_der_null(elem : @asn1.Element) -> Bool {
  let der = @asn1.encode_der(elem)
  der.length() == 2 && der[0] == b'\x05' && der[1] == b'\x00'
}

///|
fn parse_algorithm_identifier(
  elem : @asn1.Element,
  ctx : String,
) -> (@asn1.ObjectIdentifier, @asn1.Element?) raise CmsError {
  let items = expect_sequence(elem, ctx)
  if items.length() < 1 || items.length() > 2 {
    raise Malformed(ctx + " arity")
  }
  let oid = expect_oid(items[0], ctx + ".algorithm")
  let params = if items.length() == 2 { Some(items[1]) } else { None }
  (oid, params)
}

///|
fn require_params_absent(
  params : @asn1.Element?,
  name : String,
) -> Unit raise CmsError {
  match params {
    Some(_) => raise Malformed(name + " parameters must be absent")
    None => ()
  }
}

///|
fn require_params_null_if_present(
  params : @asn1.Element?,
  name : String,
) -> Unit raise CmsError {
  match params {
    Some(p) =>
      if !is_der_null(p) {
        raise Malformed(name + " parameters must be DER NULL")
      }
    None => ()
  }
}

///|
fn validate_digest_algorithm_identifier(
  oid : @asn1.ObjectIdentifier,
  params : @asn1.Element?,
) -> Unit raise CmsError {
  if oid == id_sha256() || oid == id_sha384() || oid == id_sha512() {
    require_params_absent(params, "SHA-2 digestAlgorithm")
  } else {
    raise UnsupportedDigestAlgorithm(oid)
  }
}

///|
fn validate_signature_algorithm_identifier(
  oid : @asn1.ObjectIdentifier,
  params : @asn1.Element?,
) -> Unit raise CmsError {
  if oid == id_sha256_with_rsa() ||
    oid == id_sha384_with_rsa() ||
    oid == id_sha512_with_rsa() ||
    oid == id_rsa_encryption() {
    require_params_null_if_present(params, "RSA signatureAlgorithm")
  } else if oid == id_ecdsa_with_sha256() || oid == id_ecdsa_with_sha384() {
    require_params_absent(params, "ECDSA signatureAlgorithm")
  } else {
    raise UnsupportedSignatureAlgorithm(oid)
  }
}

// ─── parse CMS ContentInfo + SignedData ──────────────────────────────────

///|
/// Decode a binary (DER) CMS SignedData blob (the `gpg --detach-sign`
/// / `openssl cms -sign -outform DER` output). Pulls out the single
/// SignerInfo and the signer's certificate; rejects multi-signer
/// bundles (rare for git signing).
pub fn parse_signed_data(der : Bytes) -> CmsSignedData raise CmsError {
  let elem = @asn1.decode_der(der) catch { e => raise Asn1(e) }
  // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
  let items = expect_sequence(elem, "ContentInfo")
  if items.length() != 2 {
    raise Malformed("ContentInfo arity != 2")
  }
  let ct = expect_oid(items[0], "ContentInfo.contentType")
  if ct != id_signed_data() {
    raise ContentTypeMismatch(ct)
  }
  // items[1] is [0] EXPLICIT SignedData. Its content is the inner DER.
  let inner_bytes = extract_context_explicit(items[1], 0U)
  let sd_elem = @asn1.decode_der(inner_bytes) catch { e => raise Asn1(e) }
  // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encap, certs[0]?, crls[1]?, signerInfos SET }
  let sd_items = expect_sequence(sd_elem, "SignedData")
  if sd_items.length() < 4 {
    raise Malformed("SignedData arity")
  }
  let _version = sd_items[0]
  let _digest_algs = sd_items[1]
  let _encap = sd_items[2]
  // certificates and crls are optional; signerInfos is mandatory and is
  // the LAST element. Walk to find them.
  let certs : Array[@pkix.Certificate] = []
  let mut signer_infos : Array[@asn1.Element]? = None
  for i = 3; i < sd_items.length(); i = i + 1 {
    let item = sd_items[i]
    if item.tag.class_ == @asn1.TagClass::ContextSpecific &&
      item.tag.number == 0U {
      // certificates [0] IMPLICIT SET — content is a sequence of cert DERs
      let bytes = extract_context_implicit(item)
      let inner_dec = @asn1.Decoder::new(bytes)
      while !inner_dec.is_empty() {
        let cert_elem = inner_dec.read_element() catch { e => raise Asn1(e) }
        let cert_bytes = @asn1.encode_der(cert_elem)
        let cert = @pkix.parse_certificate(cert_bytes) catch {
          e => raise Pkix(e)
        }
        certs.push(cert)
      }
    } else if item.tag.class_ == @asn1.TagClass::ContextSpecific &&
      item.tag.number == 1U {
      // crls [1] IMPLICIT — ignore
      ()
    } else {
      // The mandatory signerInfos SET (universal tag 17).
      match item.value {
        Set(xs) => signer_infos = Some(xs)
        _ => raise Malformed("expected signerInfos SET")
      }
    }
  }
  if certs.length() == 0 {
    raise NoSignerCertificate
  }
  let si_list = match signer_infos {
    Some(xs) => xs
    None => raise Malformed("missing signerInfos")
  }
  if si_list.length() == 0 {
    raise NoSignerInfo
  }
  if si_list.length() > 1 {
    raise Malformed("multi-signer SignedData not supported")
  }
  let signer = parse_signer_info(si_list[0])
  // Locate the signer's cert by IssuerAndSerialNumber match. The bundle
  // may carry intermediate certs in any order; the previous "always
  // certs[0]" assumption broke multi-cert bundles.
  let mut signer_idx = -1
  for i = 0; i < certs.length(); i = i + 1 {
    if cert_matches_sid(certs[i], signer.sid_issuer, signer.sid_serial) {
      signer_idx = i
      break
    }
  }
  if signer_idx < 0 {
    raise SignerCertificateNotFound
  }
  let signer_cert = certs[signer_idx]
  let extra_certs : Array[@pkix.Certificate] = []
  for i = 0; i < certs.length(); i = i + 1 {
    if i != signer_idx {
      extra_certs.push(certs[i])
    }
  }
  { signer_cert, extra_certs, signer }
}

///|
fn parse_signer_info(elem : @asn1.Element) -> SignerInfoFields raise CmsError {
  let items = expect_sequence(elem, "SignerInfo")
  if items.length() < 5 {
    raise Malformed("SignerInfo arity")
  }
  // 0: version
  // 1: sid (issuerAndSerialNumber SEQUENCE or [0] subjectKeyIdentifier)
  // 2: digestAlgorithm
  // 3 (optional): [0] IMPLICIT signedAttrs
  // -3 .. -1: signatureAlgorithm, signature, [optional [1] unsignedAttrs]
  let (sid_issuer, sid_serial) = parse_signer_identifier(items[1])
  let (digest_alg, digest_params) = parse_algorithm_identifier(
    items[2],
    "SignerInfo.digestAlgorithm",
  )
  validate_digest_algorithm_identifier(digest_alg, digest_params)
  let mut idx = 3
  let mut signed_attrs : Bytes? = None
  if items[idx].tag.class_ == @asn1.TagClass::ContextSpecific &&
    items[idx].tag.number == 0U {
    signed_attrs = Some(extract_context_implicit(items[idx]))
    idx = idx + 1
  }
  let (signature_alg, signature_params) = parse_algorithm_identifier(
    items[idx],
    "SignerInfo.signatureAlgorithm",
  )
  validate_signature_algorithm_identifier(signature_alg, signature_params)
  idx = idx + 1
  let signature = match items[idx].value {
    OctetString(b) => b
    _ => raise Malformed("SignerInfo.signature")
  }
  let attrs = match signed_attrs {
    Some(b) => b
    None =>
      raise Malformed("signedAttrs required (detached CMS must hash content)")
  }
  {
    sid_issuer,
    sid_serial,
    digest_alg,
    signed_attrs_content: attrs,
    signature_alg,
    signature,
  }
}

///|
// SignerIdentifier ::= CHOICE {
//   issuerAndSerialNumber IssuerAndSerialNumber,    -- SEQUENCE
//   subjectKeyIdentifier [0] SubjectKeyIdentifier   -- OCTET STRING
// }
// IssuerAndSerialNumber ::= SEQUENCE {
//   issuer Name,
//   serialNumber CertificateSerialNumber          -- INTEGER
// }
// Compare a cert's issuer/serial to a parsed SignerIdentifier. Issuer
// match is byte-exact on the DER-encoded Name; serial match strips any
// leading 0x00 sign byte from both sides.
fn cert_matches_sid(
  cert : @pkix.Certificate,
  sid_issuer : Bytes,
  sid_serial : Bytes,
) -> Bool {
  let cert_issuer_der = @pkix.serialize_name(cert.tbs.issuer)
  if cert_issuer_der != sid_issuer {
    return false
  }
  // serialNumber INTEGER content. cert.tbs.serial_number is stored
  // exactly as the DER content bytes; same for sid_serial. Strip a
  // single leading 0x00 sign byte to normalise.
  let a = strip_int_sign(cert.tbs.serial_number)
  let b = strip_int_sign(sid_serial)
  a == b
}

///|
fn strip_int_sign(b : Bytes) -> Bytes {
  if b.length() > 1 && b[0] == b'\x00' {
    Bytes::makei(b.length() - 1, fn(i) { b[i + 1] })
  } else {
    b
  }
}

///|
fn parse_signer_identifier(
  elem : @asn1.Element,
) -> (Bytes, Bytes) raise CmsError {
  if elem.tag.class_ == @asn1.TagClass::ContextSpecific && elem.tag.number == 0U {
    raise UnsupportedSid("subjectKeyIdentifier")
  }
  let items = expect_sequence(elem, "SignerInfo.sid (issuerAndSerialNumber)")
  if items.length() != 2 {
    raise Malformed("IssuerAndSerialNumber arity != 2")
  }
  // Re-encode the issuer Name as DER so we can byte-compare against
  // certificate subject DNs later.
  let issuer_der = @asn1.encode_der(items[0])
  let serial = match items[1].value {
    Integer(b) => b
    _ => raise Malformed("IssuerAndSerialNumber.serialNumber not INTEGER")
  }
  (issuer_der, serial)
}

// ─── helpers ─────────────────────────────────────────────────────────────

///|
fn expect_sequence(
  elem : @asn1.Element,
  ctx : String,
) -> Array[@asn1.Element] raise CmsError {
  match elem.value {
    Sequence(xs) => xs
    _ => raise Malformed(ctx + ": expected SEQUENCE")
  }
}

///|
fn expect_oid(
  elem : @asn1.Element,
  ctx : String,
) -> @asn1.ObjectIdentifier raise CmsError {
  match elem.value {
    Oid(o) => o
    _ => raise Malformed(ctx + ": expected OID")
  }
}

///|
// For [N] EXPLICIT wrappers, the inner element is encoded INSIDE the
// context-tagged wrapper. @asn1 stores it as Unknown(bytes) where bytes
// are the wrapped element's DER (tag included).
fn extract_context_explicit(
  elem : @asn1.Element,
  expected_tag : UInt,
) -> Bytes raise CmsError {
  if elem.tag.class_ != @asn1.TagClass::ContextSpecific ||
    elem.tag.number != expected_tag {
    raise Malformed(
      "expected [" + expected_tag.to_string() + "] EXPLICIT wrapper",
    )
  }
  match elem.value {
    Unknown(b) => b
    _ => raise Malformed("context-tag content not raw bytes")
  }
}

///|
// For [N] IMPLICIT context-tagged values, the original tag is replaced
// with the context tag. @asn1 stores the raw content bytes (without the
// context tag/length header) in Unknown.
fn extract_context_implicit(elem : @asn1.Element) -> Bytes raise CmsError {
  match elem.value {
    Unknown(b) => b
    _ => raise Malformed("context-tag content not raw bytes")
  }
}

// ─── signature verification ──────────────────────────────────────────────

///|
/// Verify a CMS detached signature.
///
/// Steps (RFC 5652 §5.4):
///   1. Compute H_digestAlg(message)
///   2. Find messageDigest attribute in signed_attrs; assert equality
///   3. Re-encode signed_attrs from [0] IMPLICIT to universal SET OF
///   4. Verify signer.signature over the re-encoded SET using
///      signer.signature_alg + signer_cert's public key
pub fn verify_detached(
  sd : CmsSignedData,
  message : Bytes,
) -> Bool raise CmsError {
  let digest = digest_for_alg(sd.signer.digest_alg, message)
  // Walk signed_attrs SET to find messageDigest.
  let attrs = parse_attributes(sd.signer.signed_attrs_content)
  let md = find_message_digest_attr(attrs)
  if md != digest {
    raise MessageDigestMismatch
  }
  // Reconstruct SET OF attributes for signature verification.
  let to_verify = reencode_signed_attrs_as_set(sd.signer.signed_attrs_content)
  // Extract issuer public key from the embedded signer cert.
  let issuer_pubkey = @pkix_verify.extract_public_key(
    sd.signer_cert.tbs.subject_public_key_info,
  ) catch {
    _ => raise NoSignerCertificate
  }
  verify_signature(
    sd.signer.signature_alg,
    sd.signer.digest_alg,
    issuer_pubkey,
    to_verify,
    sd.signer.signature,
  )
}

///|
fn verify_signature(
  sig_alg : @asn1.ObjectIdentifier,
  digest_alg : @asn1.ObjectIdentifier,
  pubkey : @pkix_verify.PublicKey,
  message : Bytes,
  signature : Bytes,
) -> Bool raise CmsError {
  if sig_alg == id_sha256_with_rsa() ||
    sig_alg == id_sha384_with_rsa() ||
    sig_alg == id_sha512_with_rsa() ||
    sig_alg == id_rsa_encryption() {
    // Pick the hash from `signature_alg` when it encodes one (the
    // sha*WithRSAEncryption OIDs); fall back to `digest_alg` for the
    // bare id-rsaEncryption case. Cross-check the two when both are
    // explicit so a signer can't put SHA-1-with-RSA in the signature OID
    // while telling the verifier it's SHA-256.
    let hash_alg = if sig_alg == id_sha256_with_rsa() {
      if digest_alg != id_sha256() {
        raise UnsupportedSignatureAlgorithm(sig_alg)
      }
      @rsa.HashAlg::Sha256
    } else if sig_alg == id_sha384_with_rsa() {
      if digest_alg != id_sha384() {
        raise UnsupportedSignatureAlgorithm(sig_alg)
      }
      @rsa.HashAlg::Sha384
    } else if sig_alg == id_sha512_with_rsa() {
      if digest_alg != id_sha512() {
        raise UnsupportedSignatureAlgorithm(sig_alg)
      }
      @rsa.HashAlg::Sha512
      // Bare id-rsaEncryption: take the hash from digestAlgorithm.
    } else if digest_alg == id_sha256() {
      @rsa.HashAlg::Sha256
    } else if digest_alg == id_sha384() {
      @rsa.HashAlg::Sha384
    } else if digest_alg == id_sha512() {
      @rsa.HashAlg::Sha512
    } else {
      raise UnsupportedDigestAlgorithm(digest_alg)
    }
    match pubkey {
      Rsa(pk) =>
        pk.verify(message, signature, hash_alg) catch {
          e => raise Rsa(e)
        }
      _ => raise UnsupportedSignatureAlgorithm(sig_alg)
    }
  } else if sig_alg == id_ecdsa_with_sha256() {
    match pubkey {
      P256(pk) =>
        @p256.verify(pk, message, signature, @p256.SignatureFormat::Der) catch {
          e => raise P256(e)
        }
      _ => raise UnsupportedSignatureAlgorithm(sig_alg)
    }
  } else if sig_alg == id_ecdsa_with_sha384() {
    match pubkey {
      P384(pk) =>
        @p384.verify(pk, message, signature, @p384.SignatureFormat::Der) catch {
          e => raise P384(e)
        }
      _ => raise UnsupportedSignatureAlgorithm(sig_alg)
    }
  } else {
    raise UnsupportedSignatureAlgorithm(sig_alg)
  }
}

///|
fn digest_for_alg(
  alg : @asn1.ObjectIdentifier,
  data : Bytes,
) -> Bytes raise CmsError {
  if alg == id_sha256() {
    @hash.sha256(data)
  } else if alg == id_sha384() {
    @hash.sha384(data)
  } else if alg == id_sha512() {
    @hash.sha512(data)
  } else {
    raise UnsupportedDigestAlgorithm(alg)
  }
}

///|
// Re-encode a [0] IMPLICIT signedAttrs body as a universal SET OF.
// The body bytes are unchanged — only the outer tag and (potentially)
// length need to be emitted.
fn reencode_signed_attrs_as_set(body : Bytes) -> Bytes {
  let n = body.length()
  let len_prefix = encode_der_length(n)
  let total = 1 + len_prefix.length() + n
  Bytes::makei(total, fn(i) {
    if i == 0 {
      b'\x31' // universal SET (constructed)
    } else if i < 1 + len_prefix.length() {
      len_prefix[i - 1]
    } else {
      body[i - 1 - len_prefix.length()]
    }
  })
}

///|
fn encode_der_length(n : Int) -> Bytes {
  if n < 0x80 {
    Bytes::makei(1, fn(_) { n.to_byte() })
  } else if n < 0x100 {
    Bytes::makei(2, fn(i) { if i == 0 { b'\x81' } else { n.to_byte() } })
  } else if n < 0x10000 {
    Bytes::makei(3, fn(i) {
      if i == 0 {
        b'\x82'
      } else if i == 1 {
        ((n >> 8) & 0xff).to_byte()
      } else {
        (n & 0xff).to_byte()
      }
    })
  } else if n < 0x1000000 {
    Bytes::makei(4, fn(i) {
      if i == 0 {
        b'\x83'
      } else if i == 1 {
        ((n >> 16) & 0xff).to_byte()
      } else if i == 2 {
        ((n >> 8) & 0xff).to_byte()
      } else {
        (n & 0xff).to_byte()
      }
    })
  } else {
    abort("length too big")
  }
}

// ─── Attribute parser ────────────────────────────────────────────────────

///|
priv struct CmsAttribute {
  oid : @asn1.ObjectIdentifier
  // The raw DER bytes of the values SET content (after stripping the
  // outer SET tag/length).
  values_set_content : Bytes
}

///|
fn parse_attributes(
  attrs_content : Bytes,
) -> Array[CmsAttribute] raise CmsError {
  let dec = @asn1.Decoder::new(attrs_content)
  let out : Array[CmsAttribute] = []
  while !dec.is_empty() {
    let attr_elem = dec.read_element() catch { e => raise Asn1(e) }
    let items = expect_sequence(attr_elem, "Attribute")
    if items.length() != 2 {
      raise Malformed("Attribute arity != 2")
    }
    let oid = expect_oid(items[0], "Attribute.oid")
    let values_content = match items[1].value {
      Set(_) => {
        // We need the RAW bytes of the SET content, not the parsed
        // elements. Re-encode items[1] back to DER and strip the SET
        // tag/length so the caller can re-parse the inner element.
        let der = @asn1.encode_der(items[1])
        // Strip outer SET tag (1 byte) + length encoding
        let n_total = der.length()
        let len_byte = der[1].to_int()
        let len_skip = if len_byte < 0x80 { 2 } else { 2 + (len_byte & 0x7f) }
        Bytes::makei(n_total - len_skip, fn(i) { der[len_skip + i] })
      }
      _ => raise Malformed("Attribute.values not SET")
    }
    out.push({ oid, values_set_content: values_content })
  }
  out
}

///|
fn find_message_digest_attr(
  attrs : Array[CmsAttribute],
) -> Bytes raise CmsError {
  let mut md_value : Bytes? = None
  for a in attrs {
    if a.oid == id_message_digest() {
      if md_value is Some(_) {
        raise Malformed("duplicate messageDigest attribute")
      }
      // Attribute values is a SET OF; for messageDigest there must be
      // exactly one OCTET STRING value.
      let dec = @asn1.Decoder::new(a.values_set_content)
      if dec.is_empty() {
        raise Malformed("messageDigest values empty")
      }
      let val_elem = dec.read_element() catch { e => raise Asn1(e) }
      if !dec.is_empty() {
        raise Malformed("messageDigest values arity != 1")
      }
      match val_elem.value {
        OctetString(b) => md_value = Some(b)
        _ => raise Malformed("messageDigest value not OCTET STRING")
      }
    }
  }
  match md_value {
    Some(b) => b
    None => raise MissingMessageDigest
  }
}

// ─── chain integration helper ────────────────────────────────────────────

///|
/// Verify a CMS detached signature AND the signer cert's chain to a
/// trust anchor pubkey. This composes `verify_detached` with
/// `@pkix_verify.verify_chain_with_options`. Intermediates are taken
/// from `sd.extra_certs`. The signer cert is the leaf.
///
/// Returns `true` iff:
///   1. The signature verifies cleanly via `verify_detached`, AND
///   2. The signer cert's chain (signer cert + extra_certs + anchor) is
///      valid at `now` per RFC 5280 §6.1 (basic constraints, key usage,
///      validity windows, signature on every cert in the chain).
pub fn verify_with_chain(
  sd : CmsSignedData,
  message : Bytes,
  trust_anchor_pubkey : @pkix_verify.PublicKey,
  now : String,
) -> Bool raise CmsError {
  if !verify_detached(sd, message) {
    return false
  }
  @pkix_verify.verify_chain(
    sd.signer_cert,
    sd.extra_certs,
    trust_anchor_pubkey,
    now,
  ) catch {
    _ => return false
  }
  true
}
