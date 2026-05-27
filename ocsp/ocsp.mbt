// RFC 6960 OCSP response parser + verifier.
//
// Scope: PARSE-AND-VERIFY of an OCSPResponse (DER bytes). The caller fetches
// the response over HTTP (or via cached AIA URL) and hands us the bytes.
// We do not initiate any network I/O.
//
// What we verify (`verify(...)`):
//   1. OCSPResponseStatus == 0 (successful).
//   2. responseType == id-pkix-ocsp-basic.
//   3. CertID (issuerNameHash, issuerKeyHash, serialNumber) matches the cert
//      under inspection, given the issuer cert. SHA-1 and SHA-256 hashAlgorithm
//      are supported; anything else is rejected.
//   4. thisUpdate <= now < nextUpdate (when nextUpdate is present).
//   5. BasicOCSPResponse.signature verifies against either:
//        - responderID byName/byKey matching the issuer cert directly, OR
//        - an embedded delegated responder cert in `certs[0]`, itself signed
//          by the issuer cert and carrying the id-kp-OCSPSigning EKU.
//
// Out of scope:
//   - OCSP nonces / responseExtensions
//   - OCSP request construction
//   - HTTP transport
//   - id-pkix-ocsp-nocheck on delegated responders (we accept the responder
//     cert validity window; we do not check its CRL)

// ─── data types ──────────────────────────────────────────────────────────

///|
/// Status of a single cert as reported by an OCSP responder
/// (RFC 6960 §4.2.1).
pub(all) enum CertStatus {
  /// `good [0] IMPLICIT NULL` — the cert is not revoked.
  Good
  /// `revoked [1] IMPLICIT RevokedInfo` — the cert has been revoked.
  /// `reason` is the optional CRLReason (RFC 5280 §5.3.1), 0..10.
  Revoked(revocation_time~ : String, reason~ : Int?)
  /// `unknown [2] IMPLICIT UnknownInfo` — responder does not know this cert.
  Unknown
} derive(Debug, Eq)

///|
/// One entry inside `ResponseData.responses`.
pub(all) struct OcspSingleResponse {
  /// SHA-1 or SHA-256 of the encoded issuer Name (depends on hash_alg).
  cert_id_issuer_name_hash : Bytes
  /// SHA-1 or SHA-256 of the issuer's subjectPublicKey BIT STRING value
  /// (the key bytes, NOT the SPKI wrapper — RFC 6960 §4.1.1).
  cert_id_issuer_key_hash : Bytes
  /// The cert's serial number (big-endian two's complement, leading 0x00 sign
  /// byte preserved as-is for byte-exact comparison).
  cert_id_serial_number : Bytes
  /// Hash algorithm OID for issuerNameHash / issuerKeyHash.
  cert_id_hash_alg : @asn1.ObjectIdentifier
  status : CertStatus
  /// thisUpdate / nextUpdate are GeneralizedTime (YYYYMMDDHHMMSSZ).
  this_update : String
  next_update : String?
} derive(Debug)

///|
/// Parsed top-level OCSP response (after unwrapping BasicOCSPResponse).
pub(all) struct OcspResponse {
  produced_at : String
  responses : Array[OcspSingleResponse]
  /// The signer cert: present iff the BasicOCSPResponse carried a delegated
  /// responder certificate in its `certs [0] EXPLICIT` field. Direct-signed
  /// responses (signed by the issuer key itself) have None here.
  signer_cert : @pkix.Certificate?
} derive(Debug)

///|
pub suberror OcspError {
  /// OCSPResponseStatus was not successful (0). Value carried verbatim
  /// (1=malformedRequest, 2=internalError, 3=tryLater, 5=sigRequired,
  /// 6=unauthorized — RFC 6960 §4.2.1).
  ResponseNotSuccessful(Int)
  /// responseType OID was not id-pkix-ocsp-basic.
  UnsupportedResponseType(@asn1.ObjectIdentifier)
  /// Cert under inspection is not in the SingleResponse list.
  CertNotFound
  /// CertID hashAlgorithm is neither SHA-1 nor SHA-256.
  UnsupportedHashAlgorithm(@asn1.ObjectIdentifier)
  /// thisUpdate > now (response is from the future), or nextUpdate <= now.
  /// String carries which boundary failed for diagnostics.
  StaleResponse(String)
  /// Signature on the BasicOCSPResponse did not verify against the determined
  /// signer key.
  BadSignature
  /// Delegated responder cert is missing the id-kp-OCSPSigning EKU.
  ResponderMissingOcspSigningEku
  /// Delegated responder cert is itself signed by something that is not the
  /// issuer cert under consideration.
  ResponderNotSignedByIssuer
  /// ResponderID did not match issuer cert (when no delegated responder
  /// cert was supplied).
  ResponderIdMismatch
  /// Structural problems in the DER.
  Malformed(String)
  Asn1(@asn1.Asn1Error)
  Pkix(@pkix.PkixError)
  PkixVerify(@pkix_verify.PkixVerifyError)
} derive(Debug)

// ─── OIDs ────────────────────────────────────────────────────────────────

///|
fn id_pkix_ocsp_basic() -> @asn1.ObjectIdentifier {
  // 1.3.6.1.5.5.7.48.1.1
  @asn1.ObjectIdentifier::from_arcs([1U, 3, 6, 1, 5, 5, 7, 48, 1, 1])
}

///|
fn id_sha1() -> @asn1.ObjectIdentifier {
  // 1.3.14.3.2.26
  @asn1.ObjectIdentifier::from_arcs([1U, 3, 14, 3, 2, 26])
}

///|
fn id_sha256() -> @asn1.ObjectIdentifier {
  // 2.16.840.1.101.3.4.2.1
  @asn1.ObjectIdentifier::from_arcs([2U, 16, 840, 1, 101, 3, 4, 2, 1])
}

///|
fn id_kp_ocsp_signing() -> @asn1.ObjectIdentifier {
  // 1.3.6.1.5.5.7.3.9
  @asn1.ObjectIdentifier::from_arcs([1U, 3, 6, 1, 5, 5, 7, 3, 9])
}

///|
fn id_ce_ext_key_usage() -> @asn1.ObjectIdentifier {
  // 2.5.29.37
  @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 37])
}

///|
fn is_der_null(bytes : Bytes) -> Bool {
  bytes.length() == 2 && bytes[0] == b'\x05' && bytes[1] == b'\x00'
}

///|
fn validate_cert_id_hash_algorithm(
  alg : @pkix.AlgorithmIdentifier,
) -> Unit raise OcspError {
  if alg.algorithm != id_sha1() && alg.algorithm != id_sha256() {
    raise UnsupportedHashAlgorithm(alg.algorithm)
  }
  match alg.parameters {
    Some(p) =>
      if !is_der_null(p) {
        raise Malformed("CertID.hashAlgorithm parameters must be DER NULL")
      }
    None => ()
  }
}

// ─── small element helpers ──────────────────────────────────────────────

///|
fn expect_sequence(
  elem : @asn1.Element,
) -> Array[@asn1.Element] raise OcspError {
  match elem.value {
    Sequence(items) =>
      if elem.tag == @asn1.tag_sequence {
        items
      } else {
        raise Malformed("expected universal SEQUENCE tag")
      }
    _ => raise Malformed("expected SEQUENCE")
  }
}

///|
fn expect_oid(elem : @asn1.Element) -> @asn1.ObjectIdentifier raise OcspError {
  match elem.value {
    Oid(o) => o
    _ => raise Malformed("expected OID")
  }
}

///|
fn expect_octet_string(elem : @asn1.Element) -> Bytes raise OcspError {
  match elem.value {
    OctetString(b) => b
    _ => raise Malformed("expected OCTET STRING")
  }
}

///|
fn expect_bool(elem : @asn1.Element) -> Bool raise OcspError {
  match elem.value {
    Boolean(b) => b
    _ => raise Malformed("expected BOOLEAN")
  }
}

///|
fn expect_integer(elem : @asn1.Element) -> Bytes raise OcspError {
  match elem.value {
    Integer(b) => b
    _ => raise Malformed("expected INTEGER")
  }
}

///|
fn expect_integer_small(elem : @asn1.Element) -> Int raise OcspError {
  let bytes = expect_integer(elem)
  if bytes.length() == 0 || bytes.length() > 4 {
    raise Malformed("INTEGER out of small range")
  }
  if (bytes[0].to_int() & 0x80) != 0 {
    raise Malformed("INTEGER must be non-negative")
  }
  let mut v = 0
  for i in 0..<bytes.length() {
    v = (v << 8) | bytes[i].to_int()
  }
  v
}

///|
fn expect_response_data_version(elem : @asn1.Element) -> Unit raise OcspError {
  let version = expect_integer_small(elem)
  if version != 0 {
    raise Malformed("ResponseData: unsupported version")
  }
}

///|
fn expect_generalized_time(elem : @asn1.Element) -> String raise OcspError {
  match elem.value {
    GeneralizedTime(s) => s
    _ => raise Malformed("expected GeneralizedTime")
  }
}

///|
fn expect_bit_string(elem : @asn1.Element) -> @asn1.BitString raise OcspError {
  match elem.value {
    BitString(b) => b
    _ => raise Malformed("expected BIT STRING")
  }
}

///|
fn expect_enumerated_small(elem : @asn1.Element) -> Int raise OcspError {
  // ENUMERATED has universal tag 10 and is encoded like INTEGER.
  if elem.tag.class_ != Universal ||
    elem.tag.number != 10U ||
    elem.tag.constructed {
    raise Malformed("expected ENUMERATED")
  }
  let bytes = match elem.value {
    Unknown(b) => b
    _ => raise Malformed("ENUMERATED missing raw content")
  }
  if bytes.length() == 0 || bytes.length() > 4 {
    raise Malformed("ENUMERATED out of range")
  }
  let mut v = 0
  for i in 0..<bytes.length() {
    v = (v << 8) | bytes[i].to_int()
  }
  // Sign extension: ENUMERATED uses two's complement like INTEGER. We don't
  // expect negative response statuses or revocation reasons, but be defensive.
  if (bytes[0].to_int() & 0x80) != 0 {
    // negative — leave as-is; caller will see negative value
    v = v - (1 << (bytes.length() * 8))
  }
  v
}

///|
fn parse_extension_meta(
  elem : @asn1.Element,
) -> (@asn1.ObjectIdentifier, Bool) raise OcspError {
  let items = expect_sequence(elem)
  if items.length() < 2 || items.length() > 3 {
    raise Malformed("Extension arity")
  }
  let oid = expect_oid(items[0])
  let mut critical = false
  let value_index = if items.length() == 3 {
    critical = expect_bool(items[1])
    2
  } else {
    1
  }
  let _ = expect_octet_string(items[value_index])
  (oid, critical)
}

///|
fn reject_unsupported_extensions(
  elem : @asn1.Element,
  context : String,
) -> Unit raise OcspError {
  let items = expect_sequence(elem)
  let seen : Array[@asn1.ObjectIdentifier] = []
  for item in items {
    let (oid, _) = parse_extension_meta(item)
    for prev in seen {
      if prev == oid {
        raise Malformed(context + ": duplicate extension")
      }
    }
    seen.push(oid)
  }
  if items.length() > 0 {
    raise Malformed(context + ": unsupported extension")
  }
}

///|
// Context [n] EXPLICIT: outer = ContextSpecific n constructed, content = a
// single nested TLV. Matches `match_context_explicit` in pkix.
fn match_context_explicit(
  elem : @asn1.Element,
  number : UInt,
) -> @asn1.Element? raise OcspError {
  if elem.tag.class_ != ContextSpecific || elem.tag.number != number {
    return None
  }
  if !elem.tag.constructed {
    raise Malformed("context [" + number.to_string() + "] not constructed")
  }
  match elem.value {
    Unknown(raw) => Some(@asn1.decode_der(raw) catch { e => raise Asn1(e) })
    _ => raise Malformed("context [" + number.to_string() + "] no raw payload")
  }
}

// ─── CertID (RFC 6960 §4.1.1) ────────────────────────────────────────────
//
// CertID ::= SEQUENCE {
//   hashAlgorithm   AlgorithmIdentifier,
//   issuerNameHash  OCTET STRING,
//   issuerKeyHash   OCTET STRING,
//   serialNumber    CertificateSerialNumber }

///|
priv struct ParsedCertId {
  hash_alg : @asn1.ObjectIdentifier
  issuer_name_hash : Bytes
  issuer_key_hash : Bytes
  serial_number : Bytes
}

///|
fn parse_cert_id(elem : @asn1.Element) -> ParsedCertId raise OcspError {
  let items = expect_sequence(elem)
  if items.length() != 4 {
    raise Malformed("CertID arity")
  }
  let alg = @pkix.parse_algorithm_identifier_elem(items[0]) catch {
    e => raise Pkix(e)
  }
  validate_cert_id_hash_algorithm(alg)
  let issuer_name_hash = expect_octet_string(items[1])
  let issuer_key_hash = expect_octet_string(items[2])
  let serial = expect_integer(items[3])
  {
    hash_alg: alg.algorithm,
    issuer_name_hash,
    issuer_key_hash,
    serial_number: serial,
  }
}

///|
// Apply the hash algorithm to `data`. Returns the digest, or raises if the
// OID is one we do not implement.
fn run_hash_alg(
  alg : @asn1.ObjectIdentifier,
  data : Bytes,
) -> Bytes raise OcspError {
  if alg == id_sha1() {
    @hash.sha1(data)
  } else if alg == id_sha256() {
    @hash.sha256(data)
  } else {
    raise UnsupportedHashAlgorithm(alg)
  }
}

// ─── SingleResponse (RFC 6960 §4.2.1) ────────────────────────────────────
//
// SingleResponse ::= SEQUENCE {
//   certID                       CertID,
//   certStatus                   CertStatus,
//   thisUpdate                   GeneralizedTime,
//   nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
//   singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
//
// CertStatus ::= CHOICE {
//   good        [0] IMPLICIT NULL,
//   revoked     [1] IMPLICIT RevokedInfo,
//   unknown     [2] IMPLICIT UnknownInfo }
//
// RevokedInfo ::= SEQUENCE {
//   revocationTime              GeneralizedTime,
//   revocationReason  [0]       EXPLICIT CRLReason OPTIONAL }

///|
fn parse_cert_status(elem : @asn1.Element) -> CertStatus raise OcspError {
  if elem.tag.class_ != ContextSpecific {
    raise Malformed("certStatus: expected context-specific tag")
  }
  match elem.tag.number {
    0U => {
      // good — IMPLICIT NULL, content empty
      expect_empty_implicit_null(elem, "good")
      Good
    }
    1U => {
      // revoked — IMPLICIT RevokedInfo (SEQUENCE)
      if !elem.tag.constructed {
        raise Malformed("revoked: expected constructed tag")
      }
      let raw = match elem.value {
        Unknown(b) => b
        _ => raise Malformed("revoked: missing raw content")
      }
      // Parse the SEQUENCE content out of the raw bytes. Because the SEQUENCE
      // tag was replaced by [1] IMPLICIT, the content here is the body of the
      // SEQUENCE OF RevokedInfo fields, not a full SEQUENCE element. We
      // re-wrap with a SEQUENCE tag and decode.
      let dec = @asn1.Decoder::new(raw)
      let items : Array[@asn1.Element] = []
      while !dec.is_empty() {
        items.push(dec.read_element() catch { e => raise Asn1(e) })
      }
      if items.length() < 1 {
        raise Malformed("RevokedInfo: missing revocationTime")
      }
      if items.length() > 2 {
        raise Malformed("RevokedInfo: trailing fields")
      }
      let rev_time = expect_generalized_time(items[0])
      let mut reason : Int? = None
      if items.length() >= 2 {
        match match_context_explicit(items[1], 0U) {
          Some(inner) =>
            // CRLReason ::= ENUMERATED (RFC 5280 §5.3.1)
            reason = Some(expect_enumerated_small(inner))
          None => raise Malformed("RevokedInfo: unexpected field")
        }
      }
      Revoked(revocation_time=rev_time, reason~)
    }
    2U => {
      // unknown — IMPLICIT UnknownInfo ::= NULL
      expect_empty_implicit_null(elem, "unknown")
      Unknown
    }
    _ => raise Malformed("certStatus: unrecognised tag")
  }
}

///|
fn expect_empty_implicit_null(
  elem : @asn1.Element,
  name : String,
) -> Unit raise OcspError {
  if elem.tag.constructed {
    raise Malformed(name + " CertStatus must be primitive")
  }
  let raw = match elem.value {
    Unknown(b) => b
    _ => raise Malformed(name + " CertStatus missing raw content")
  }
  if raw.length() != 0 {
    raise Malformed(name + " CertStatus content must be empty")
  }
}

///|
fn parse_single_response(
  elem : @asn1.Element,
) -> OcspSingleResponse raise OcspError {
  let items = expect_sequence(elem)
  if items.length() < 3 {
    raise Malformed("SingleResponse: too few fields")
  }
  let cid = parse_cert_id(items[0])
  let status = parse_cert_status(items[1])
  let this_update = expect_generalized_time(items[2])
  let mut next_update : String? = None
  let mut idx = 3
  if idx < items.length() {
    match match_context_explicit(items[idx], 0U) {
      Some(inner) => {
        next_update = Some(expect_generalized_time(inner))
        idx = idx + 1
      }
      None => ()
    }
  }
  // singleExtensions [1] EXPLICIT. Their semantics are not implemented, so a
  // verified OCSP response must fail closed instead of ignoring them.
  if idx < items.length() {
    match match_context_explicit(items[idx], 1U) {
      Some(exts) => {
        reject_unsupported_extensions(exts, "singleExtensions")
        idx = idx + 1
      }
      None => raise Malformed("SingleResponse: unexpected trailing field")
    }
  }
  if idx != items.length() {
    raise Malformed("SingleResponse: trailing fields")
  }
  {
    cert_id_issuer_name_hash: cid.issuer_name_hash,
    cert_id_issuer_key_hash: cid.issuer_key_hash,
    cert_id_serial_number: cid.serial_number,
    cert_id_hash_alg: cid.hash_alg,
    status,
    this_update,
    next_update,
  }
}

// ─── ResponseData (RFC 6960 §4.2.1) ──────────────────────────────────────
//
// ResponseData ::= SEQUENCE {
//   version              [0] EXPLICIT Version DEFAULT v1,
//   responderID              ResponderID,
//   producedAt               GeneralizedTime,
//   responses                SEQUENCE OF SingleResponse,
//   responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
//
// ResponderID ::= CHOICE {
//   byName   [1] EXPLICIT Name,
//   byKey    [2] EXPLICIT KeyHash }

///|
priv enum ResponderId {
  ByName(@pkix.Name)
  ByKey(Bytes) // SHA-1 of the responder's public key
}

///|
priv struct ParsedResponseData {
  responder_id : ResponderId
  produced_at : String
  responses : Array[OcspSingleResponse]
}

///|
fn parse_responder_id(elem : @asn1.Element) -> ResponderId raise OcspError {
  if elem.tag.class_ != ContextSpecific {
    raise Malformed("responderID: expected context tag")
  }
  if !elem.tag.constructed {
    raise Malformed("responderID: must be EXPLICIT (constructed)")
  }
  let raw = match elem.value {
    Unknown(b) => b
    _ => raise Malformed("responderID: missing raw payload")
  }
  let inner = @asn1.decode_der(raw) catch { e => raise Asn1(e) }
  match elem.tag.number {
    1U => {
      // byName [1] EXPLICIT Name
      let name = @pkix.parse_name(@asn1.encode_der(inner)) catch {
        e => raise Pkix(e)
      }
      ByName(name)
    }
    2U =>
      // byKey [2] EXPLICIT KeyHash (OCTET STRING)
      ByKey(expect_octet_string(inner))
    _ => raise Malformed("responderID: unrecognised choice")
  }
}

///|
fn parse_response_data(
  elem : @asn1.Element,
) -> ParsedResponseData raise OcspError {
  let items = expect_sequence(elem)
  let mut idx = 0
  // Optional [0] EXPLICIT Version
  if idx < items.length() {
    match match_context_explicit(items[idx], 0U) {
      Some(inner) => {
        // Version DEFAULT v1 is encoded as INTEGER 0 when present. Future
        // versions may alter semantics, so fail closed.
        expect_response_data_version(inner)
        idx = idx + 1
      }
      None => ()
    }
  }
  if items.length() - idx < 3 {
    raise Malformed("ResponseData: too few fields")
  }
  let responder_id = parse_responder_id(items[idx])
  let produced_at = expect_generalized_time(items[idx + 1])
  let responses_seq = expect_sequence(items[idx + 2])
  idx = idx + 3
  let responses : Array[OcspSingleResponse] = []
  for sr in responses_seq {
    responses.push(parse_single_response(sr))
  }
  // [1] EXPLICIT responseExtensions OPTIONAL. Nonces and other extensions can
  // bind request semantics, so reject them until each supported OID is enforced.
  if idx < items.length() {
    match match_context_explicit(items[idx], 1U) {
      Some(exts) => {
        reject_unsupported_extensions(exts, "responseExtensions")
        idx = idx + 1
      }
      None => raise Malformed("ResponseData: unexpected trailing field")
    }
  }
  if idx != items.length() {
    raise Malformed("ResponseData: trailing fields")
  }
  { responder_id, produced_at, responses }
}

// ─── BasicOCSPResponse (RFC 6960 §4.2.1) ─────────────────────────────────
//
// BasicOCSPResponse ::= SEQUENCE {
//   tbsResponseData      ResponseData,
//   signatureAlgorithm   AlgorithmIdentifier,
//   signature            BIT STRING,
//   certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

///|
priv struct ParsedBasicOcsp {
  tbs_bytes : Bytes
  response_data : ParsedResponseData
  signature_algorithm : @pkix.AlgorithmIdentifier
  signature : @asn1.BitString
  certs : Array[@pkix.Certificate]
}

///|
fn parse_basic_ocsp(der : Bytes) -> ParsedBasicOcsp raise OcspError {
  let outer = @asn1.decode_der(der) catch { e => raise Asn1(e) }
  let items = expect_sequence(outer)
  if items.length() < 3 {
    raise Malformed("BasicOCSPResponse: too few fields")
  }
  if items.length() > 4 {
    raise Malformed("BasicOCSPResponse: too many fields")
  }
  let tbs_elem = items[0]
  // Re-encode the parsed tbsResponseData to obtain the exact signed bytes.
  // RFC 6960 mandates DER, so this is byte-stable for compliant responders.
  let tbs_bytes = @asn1.encode_der(tbs_elem)
  let rd = parse_response_data(tbs_elem)
  let sig_alg = @pkix.parse_algorithm_identifier_elem(items[1]) catch {
    e => raise Pkix(e)
  }
  let sig = expect_bit_string(items[2])
  let certs : Array[@pkix.Certificate] = []
  if items.length() == 4 {
    match match_context_explicit(items[3], 0U) {
      Some(inner) => {
        let cert_items = expect_sequence(inner)
        for ce in cert_items {
          let der_bytes = @asn1.encode_der(ce)
          let cert = @pkix.parse_certificate(der_bytes) catch {
            e => raise Pkix(e)
          }
          certs.push(cert)
        }
      }
      None => raise Malformed("BasicOCSPResponse: unexpected trailing field")
    }
  }
  {
    tbs_bytes,
    response_data: rd,
    signature_algorithm: sig_alg,
    signature: sig,
    certs,
  }
}

// ─── top-level OCSPResponse ──────────────────────────────────────────────
//
// OCSPResponse ::= SEQUENCE {
//   responseStatus   OCSPResponseStatus,
//   responseBytes    [0] EXPLICIT ResponseBytes OPTIONAL }
//
// ResponseBytes ::= SEQUENCE {
//   responseType     OBJECT IDENTIFIER,
//   response         OCTET STRING }

///|
/// Parse an OCSP response (DER). Validates structure and unwraps the inner
/// BasicOCSPResponse. Does NOT verify the signature; use `verify(...)` for
/// the full check.
///
/// On a non-successful OCSPResponseStatus, raises `ResponseNotSuccessful(n)`.
pub fn parse_response(der : Bytes) -> OcspResponse raise OcspError {
  let outer = @asn1.decode_der(der) catch { e => raise Asn1(e) }
  let items = expect_sequence(outer)
  if items.length() < 1 {
    raise Malformed("OCSPResponse: empty")
  }
  if items.length() > 2 {
    raise Malformed("OCSPResponse: trailing fields")
  }
  let status = expect_enumerated_small(items[0])
  if status != 0 {
    raise ResponseNotSuccessful(status)
  }
  if items.length() < 2 {
    raise Malformed("OCSPResponse: successful but no responseBytes")
  }
  let rb_inner = match match_context_explicit(items[1], 0U) {
    Some(e) => e
    None => raise Malformed("OCSPResponse: missing [0] EXPLICIT responseBytes")
  }
  let rb_items = expect_sequence(rb_inner)
  if rb_items.length() != 2 {
    raise Malformed("ResponseBytes arity")
  }
  let response_type = expect_oid(rb_items[0])
  if response_type != id_pkix_ocsp_basic() {
    raise UnsupportedResponseType(response_type)
  }
  let basic_der = expect_octet_string(rb_items[1])
  let basic = parse_basic_ocsp(basic_der)
  let signer_cert : @pkix.Certificate? = if basic.certs.length() > 0 {
    Some(basic.certs[0])
  } else {
    None
  }
  {
    produced_at: basic.response_data.produced_at,
    responses: basic.response_data.responses,
    signer_cert,
  }
}

// ─── time comparison ─────────────────────────────────────────────────────
//
// All OCSP times are GeneralizedTime (YYYYMMDDHHMMSSZ, length 15). We compare
// lexicographically, which is correct for that canonical format. The `now`
// argument may also be a UTCTime (YYMMDDHHMMSSZ, length 13); we normalize.

///|
fn decimal2(s : String, offset : Int) -> Int {
  let hi = s.get_char(offset).unwrap().to_int() - '0'.to_int()
  let lo = s.get_char(offset + 1).unwrap().to_int() - '0'.to_int()
  hi * 10 + lo
}

///|
fn decimal4(s : String, offset : Int) -> Int {
  decimal2(s, offset) * 100 + decimal2(s, offset + 2)
}

///|
fn days_in_month(year : Int, month : Int) -> Int {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31
    4 | 6 | 9 | 11 => 30
    2 => if is_leap_year(year) { 29 } else { 28 }
    _ => 0
  }
}

///|
fn is_leap_year(year : Int) -> Bool {
  year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

///|
fn validate_time_fields(
  s : String,
  year : Int,
  month_at : Int,
  day_at : Int,
  hour_at : Int,
  minute_at : Int,
  second_at : Int,
) -> Unit raise OcspError {
  if year <= 0 {
    raise Malformed("time: invalid year")
  }
  let month = decimal2(s, month_at)
  let day = decimal2(s, day_at)
  let hour = decimal2(s, hour_at)
  let minute = decimal2(s, minute_at)
  let second = decimal2(s, second_at)
  if month < 1 || month > 12 {
    raise Malformed("time: invalid month")
  }
  if day < 1 || day > days_in_month(year, month) {
    raise Malformed("time: invalid day")
  }
  if hour > 23 || minute > 59 || second > 59 {
    raise Malformed("time: invalid clock")
  }
}

///|
fn normalize_time(s : String) -> String raise OcspError {
  if s.length() == 15 {
    if s.get_char(14).unwrap() != 'Z' {
      raise Malformed("time: GeneralizedTime must end with Z")
    }
    for i = 0; i < 14; i = i + 1 {
      let c = s.get_char(i).unwrap()
      if c < '0' || c > '9' {
        raise Malformed("time: GeneralizedTime non-digit")
      }
    }
    validate_time_fields(s, decimal4(s, 0), 4, 6, 8, 10, 12)
    return s
  }
  if s.length() == 13 {
    if s.get_char(12).unwrap() != 'Z' {
      raise Malformed("time: UTCTime must end with Z")
    }
    for i = 0; i < 12; i = i + 1 {
      let c = s.get_char(i).unwrap()
      if c < '0' || c > '9' {
        raise Malformed("time: UTCTime non-digit")
      }
    }
    let zero = '0'.to_int()
    let yy_hi = s.code_unit_at(0).to_int() - zero
    let yy_lo = s.code_unit_at(1).to_int() - zero
    let yy = yy_hi * 10 + yy_lo
    let century = if yy < 50 { "20" } else { "19" }
    let year = if yy < 50 { 2000 + yy } else { 1900 + yy }
    validate_time_fields(s, year, 2, 4, 6, 8, 10)
    return century + s
  }
  raise Malformed("time: unsupported format length " + s.length().to_string())
}

// ─── signer determination ───────────────────────────────────────────────

///|
// Hash of the issuer's subjectPublicKey BIT STRING value, per RFC 6960
// §4.1.1. This is the BIT STRING content bytes WITHOUT the unused-bits
// prefix — the public key material proper.
fn hash_issuer_key(
  alg : @asn1.ObjectIdentifier,
  issuer_cert : @pkix.Certificate,
) -> Bytes raise OcspError {
  let spk = issuer_cert.tbs.subject_public_key_info.subject_public_key
  // RFC 6960 §4.1.1: "issuerKeyHash is the hash of the issuer's public key.
  // The hash shall be calculated over the value (excluding tag and length)
  // of the subject public key field in the issuer's certificate."
  // "value of the BIT STRING subjectPublicKey [excluding the tag, length,
  // and number of unused bits]"  — RFC 6960 §4.1.1.
  run_hash_alg(alg, spk.bytes)
}

///|
fn hash_issuer_name(
  alg : @asn1.ObjectIdentifier,
  issuer_cert : @pkix.Certificate,
) -> Bytes raise OcspError {
  let name_der = @pkix.serialize_name(issuer_cert.tbs.subject)
  run_hash_alg(alg, name_der)
}

///|
// Match SingleResponse against (cert, issuer_cert). Returns the matching
// entry or raises CertNotFound.
fn find_matching_single(
  responses : Array[OcspSingleResponse],
  cert : @pkix.Certificate,
  issuer_cert : @pkix.Certificate,
) -> OcspSingleResponse raise OcspError {
  let cert_serial = cert.tbs.serial_number
  for sr in responses {
    if !bytes_equal(sr.cert_id_serial_number, cert_serial) {
      continue
    }
    let computed_name = hash_issuer_name(sr.cert_id_hash_alg, issuer_cert)
    if !bytes_equal(computed_name, sr.cert_id_issuer_name_hash) {
      continue
    }
    let computed_key = hash_issuer_key(sr.cert_id_hash_alg, issuer_cert)
    if !bytes_equal(computed_key, sr.cert_id_issuer_key_hash) {
      continue
    }
    return sr
  }
  raise CertNotFound
}

///|
fn bytes_equal(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

// ─── signer (responder pubkey) determination ────────────────────────────
//
// Two cases per RFC 6960 §4.2.2.2 / §2.6:
//   A. Direct sign: responderID matches the issuer cert's identity. Verify
//      the BasicOCSPResponse signature with issuer's pubkey.
//   B. Delegated sign: BasicOCSPResponse.certs[0] holds the responder's cert.
//      That responder cert must (a) be signed by issuer_cert.pubkey, and (b)
//      carry id-kp-OCSPSigning in its EKU.

///|
fn responder_id_matches_issuer(
  rid : ResponderId,
  issuer_cert : @pkix.Certificate,
) -> Bool {
  responder_id_matches_cert(rid, issuer_cert)
}

///|
fn responder_id_matches_cert(
  rid : ResponderId,
  cert : @pkix.Certificate,
) -> Bool {
  match rid {
    ByName(name) => {
      let subject_der = @pkix.serialize_name(cert.tbs.subject)
      let rid_name_der = @pkix.serialize_name(name)
      bytes_equal(subject_der, rid_name_der)
    }
    ByKey(kh) => {
      // KeyHash is SHA-1 of the responder's subjectPublicKey BIT STRING content.
      let h = @hash.sha1(
        cert.tbs.subject_public_key_info.subject_public_key.bytes,
      )
      bytes_equal(h, kh)
    }
  }
}

///|
fn cert_has_ocsp_signing_eku(cert : @pkix.Certificate) -> Bool raise OcspError {
  for ext in cert.tbs.extensions {
    if ext.oid == id_ce_ext_key_usage() {
      let elem = @asn1.decode_der(ext.value) catch { e => raise Asn1(e) }
      let items = expect_sequence(elem)
      let target = id_kp_ocsp_signing()
      for it in items {
        match it.value {
          Oid(o) => if o == target { return true }
          _ => raise Malformed("EKU: expected OIDs")
        }
      }
      return false
    }
  }
  false
}

///|
// Determine which key signed the BasicOCSPResponse and verify the signature.
fn verify_basic_signature(
  basic : ParsedBasicOcsp,
  issuer_cert : @pkix.Certificate,
  now : String,
) -> Unit raise OcspError {
  let signer_pubkey = if basic.certs.length() > 0 {
    // Delegated responder.
    let resp_cert = basic.certs[0]
    if !cert_has_ocsp_signing_eku(resp_cert) {
      raise ResponderMissingOcspSigningEku
    }
    if !responder_id_matches_cert(basic.response_data.responder_id, resp_cert) {
      raise ResponderIdMismatch
    }
    // The responder cert itself must be signed by the issuer cert.
    let issuer_pk = @pkix_verify.extract_public_key(
      issuer_cert.tbs.subject_public_key_info,
    ) catch {
      e => raise PkixVerify(e)
    }
    @pkix_verify.verify_certificate(resp_cert, issuer_pk, now) catch {
      _ => raise ResponderNotSignedByIssuer
    }
    @pkix_verify.extract_public_key(resp_cert.tbs.subject_public_key_info) catch {
      e => raise PkixVerify(e)
    }
  } else {
    // Direct: responderID must match the issuer cert.
    if !responder_id_matches_issuer(
        basic.response_data.responder_id,
        issuer_cert,
      ) {
      raise ResponderIdMismatch
    }
    @pkix_verify.extract_public_key(issuer_cert.tbs.subject_public_key_info) catch {
      e => raise PkixVerify(e)
    }
  }
  @pkix_verify.verify_signature(
    basic.tbs_bytes,
    basic.signature_algorithm,
    basic.signature,
    signer_pubkey,
  ) catch {
    _ => raise BadSignature
  }
}

// ─── top-level verify ───────────────────────────────────────────────────

///|
/// Parse `response_der`, verify the BasicOCSPResponse signature, and return
/// the status reported for `cert`.
///
/// `cert` is the certificate the caller wants a revocation status for;
/// `issuer_cert` is the certificate that issued `cert` (its direct parent in
/// the X.509 chain). `now` is in either UTCTime (YYMMDDHHMMSSZ, 13 chars) or
/// GeneralizedTime (YYYYMMDDHHMMSSZ, 15 chars).
pub fn verify(
  response_der : Bytes,
  cert : @pkix.Certificate,
  issuer_cert : @pkix.Certificate,
  now : String,
) -> CertStatus raise OcspError {
  // 1. Parse and structural checks.
  let outer = @asn1.decode_der(response_der) catch { e => raise Asn1(e) }
  let items = expect_sequence(outer)
  if items.length() < 1 {
    raise Malformed("OCSPResponse: empty")
  }
  if items.length() > 2 {
    raise Malformed("OCSPResponse: trailing fields")
  }
  let status = expect_enumerated_small(items[0])
  if status != 0 {
    raise ResponseNotSuccessful(status)
  }
  if items.length() < 2 {
    raise Malformed("OCSPResponse: successful but no responseBytes")
  }
  let rb_inner = match match_context_explicit(items[1], 0U) {
    Some(e) => e
    None => raise Malformed("OCSPResponse: missing responseBytes")
  }
  let rb_items = expect_sequence(rb_inner)
  if rb_items.length() != 2 {
    raise Malformed("ResponseBytes arity")
  }
  let response_type = expect_oid(rb_items[0])
  if response_type != id_pkix_ocsp_basic() {
    raise UnsupportedResponseType(response_type)
  }
  let basic_der = expect_octet_string(rb_items[1])
  let basic = parse_basic_ocsp(basic_der)

  // 2. Verify signature first — a malformed responder cert / bad sig should
  // be rejected before we trust any thisUpdate / nextUpdate field.
  verify_basic_signature(basic, issuer_cert, now)

  // 3. Freshness for ResponseData itself.
  let now_n = normalize_time(now)
  let produced_n = normalize_time(basic.response_data.produced_at)
  if now_n < produced_n {
    raise StaleResponse("producedAt > now")
  }

  // 4. Locate the SingleResponse that matches (cert, issuer_cert).
  let single = find_matching_single(
    basic.response_data.responses,
    cert,
    issuer_cert,
  )

  // 5. Freshness window.
  let this_n = normalize_time(single.this_update)
  if now_n < this_n {
    raise StaleResponse("thisUpdate > now")
  }
  match single.next_update {
    Some(nu) => {
      let next_n = normalize_time(nu)
      if !(now_n < next_n) {
        raise StaleResponse("nextUpdate <= now")
      }
    }
    None => () // No nextUpdate → no upper bound (RFC 6960 §4.2.2.1)
  }

  // 6. Return the status.
  single.status
}
