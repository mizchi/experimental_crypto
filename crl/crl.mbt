// RFC 5280 §5 Certificate Revocation List (CRL) parser and verifier.
//
// Scope: PARSE-AND-VERIFY of a CertificateList (DER bytes). The caller fetches
// the CRL over HTTP (or via CDP URL) and hands us the bytes. We do not
// initiate any network I/O.
//
// What we verify (`verify(...)`):
//   1. CertificateList signature against the issuer cert's public key.
//   2. thisUpdate <= now (and now < nextUpdate, if present).
//
// What we do NOT do:
//   - Authority Key Identifier matching beyond the issuer parameter.
//
// Unsupported CRL / CRL-entry extensions are rejected. This keeps the verifier
// from accepting revocation decisions whose scope or delta semantics it cannot
// enforce yet.

// ─── data types ──────────────────────────────────────────────────────────

///|
/// One revoked-certificate entry inside `TBSCertList.revokedCertificates`.
pub(all) struct CrlEntry {
  /// `userCertificate` — the revoked cert's serial number, as the raw
  /// big-endian two's-complement encoding (with any DER sign-prefix byte
  /// preserved). Use `is_revoked` for sign-prefix-tolerant comparison.
  serial : Bytes
  /// `revocationDate` — UTCTime or GeneralizedTime, normalized to the
  /// original wire encoding (YYMMDDHHMMSSZ or YYYYMMDDHHMMSSZ).
  revocation_date : String
} derive(Debug)

///|
/// Parsed CertificateList (RFC 5280 §5.1).
pub(all) struct Crl {
  issuer : @pkix.Name
  this_update : String
  next_update : String?
  revoked : Array[CrlEntry]
} derive(Debug)

///|
pub suberror CrlError {
  /// CRL signature did not verify against the supplied issuer cert.
  BadSignature
  /// thisUpdate > now (CRL is from the future), or now >= nextUpdate.
  StaleCrl(String)
  /// CRL's `issuer` DN does not match the supplied `issuer_cert.subject`.
  IssuerMismatch
  /// Inner TBSCertList.signature does not match outer signatureAlgorithm.
  AlgorithmMismatch
  /// Structural problems in the DER.
  Malformed(String)
  Asn1(@asn1.Asn1Error)
  Pkix(@pkix.PkixError)
  PkixVerify(@pkix_verify.PkixVerifyError)
} derive(Debug)

// ─── small helpers ──────────────────────────────────────────────────────

///|
fn expect_sequence(elem : @asn1.Element) -> Array[@asn1.Element] raise CrlError {
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
fn expect_integer(elem : @asn1.Element) -> Bytes raise CrlError {
  match elem.value {
    Integer(b) => b
    _ => raise Malformed("expected INTEGER")
  }
}

///|
fn expect_oid(elem : @asn1.Element) -> @asn1.ObjectIdentifier raise CrlError {
  match elem.value {
    Oid(o) => o
    _ => raise Malformed("expected OID")
  }
}

///|
fn expect_bool(elem : @asn1.Element) -> Bool raise CrlError {
  match elem.value {
    Boolean(b) => b
    _ => raise Malformed("expected BOOLEAN")
  }
}

///|
fn expect_octet_string(elem : @asn1.Element) -> Bytes raise CrlError {
  match elem.value {
    OctetString(b) => b
    _ => raise Malformed("expected OCTET STRING")
  }
}

///|
fn expect_integer_small(elem : @asn1.Element) -> Int raise CrlError {
  let bytes = expect_integer(elem)
  if bytes.length() == 0 || bytes.length() > 4 {
    raise Malformed("INTEGER out of small range")
  }
  let mut v = 0
  for i in 0..<bytes.length() {
    v = (v << 8) | bytes[i].to_int()
  }
  v
}

///|
fn expect_bit_string(elem : @asn1.Element) -> @asn1.BitString raise CrlError {
  match elem.value {
    BitString(b) => b
    _ => raise Malformed("expected BIT STRING")
  }
}

///|
fn expect_time(elem : @asn1.Element) -> String raise CrlError {
  // RFC 5280: Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
  match elem.value {
    UtcTime(s) => s
    GeneralizedTime(s) => s
    _ => raise Malformed("expected UTCTime or GeneralizedTime")
  }
}

///|
fn match_context_explicit(
  elem : @asn1.Element,
  number : UInt,
) -> @asn1.Element? raise CrlError {
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

///|
fn parse_extension_meta(
  elem : @asn1.Element,
) -> (@asn1.ObjectIdentifier, Bool) raise CrlError {
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
) -> Unit raise CrlError {
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

// ─── revokedCertificates entry ──────────────────────────────────────────
//
// SEQUENCE {
//   userCertificate         CertificateSerialNumber,
//   revocationDate          Time,
//   crlEntryExtensions      Extensions OPTIONAL }

///|
fn parse_revoked_entry(elem : @asn1.Element) -> CrlEntry raise CrlError {
  let items = expect_sequence(elem)
  if items.length() < 2 || items.length() > 3 {
    raise Malformed("revokedCertificate: arity")
  }
  let serial = expect_integer(items[0])
  let rev_date = expect_time(items[1])
  if items.length() == 3 {
    reject_unsupported_extensions(items[2], "crlEntryExtensions")
  }
  { serial, revocation_date: rev_date }
}

// ─── TBSCertList ────────────────────────────────────────────────────────
//
// TBSCertList ::= SEQUENCE {
//   version                 INTEGER OPTIONAL,    -- v2 = 1
//   signature               AlgorithmIdentifier,
//   issuer                  Name,
//   thisUpdate              Time,
//   nextUpdate              Time OPTIONAL,
//   revokedCertificates     SEQUENCE OF { ... } OPTIONAL,
//   crlExtensions       [0] EXPLICIT Extensions OPTIONAL }

///|
priv struct ParsedTbsCertList {
  inner_signature_alg : @pkix.AlgorithmIdentifier
  issuer : @pkix.Name
  this_update : String
  next_update : String?
  revoked : Array[CrlEntry]
}

///|
fn parse_tbs_cert_list(
  elem : @asn1.Element,
) -> ParsedTbsCertList raise CrlError {
  let items = expect_sequence(elem)
  if items.length() < 3 {
    raise Malformed("TBSCertList: too few fields")
  }
  let mut idx = 0
  // Optional version
  match items[idx].value {
    Integer(_) => {
      let _ = expect_integer_small(items[idx])
      idx = idx + 1
    }
    _ => () // no version → v1 (DEFAULT)
  }
  if items.length() - idx < 3 {
    raise Malformed("TBSCertList: missing required fields")
  }
  let inner_sig_alg = @pkix.parse_algorithm_identifier_elem(items[idx]) catch {
    e => raise Pkix(e)
  }
  let issuer = parse_name_from_elem(items[idx + 1])
  let this_update = expect_time(items[idx + 2])
  idx = idx + 3
  let mut next_update : String? = None
  let revoked : Array[CrlEntry] = []
  // nextUpdate: present iff next item is a Time (UTCTime/GeneralizedTime).
  if idx < items.length() {
    match items[idx].value {
      UtcTime(s) => {
        next_update = Some(s)
        idx = idx + 1
      }
      GeneralizedTime(s) => {
        next_update = Some(s)
        idx = idx + 1
      }
      _ => ()
    }
  }
  // revokedCertificates: SEQUENCE OF {...} OPTIONAL — universal SEQUENCE
  // tag, distinguishable from [0] EXPLICIT crlExtensions which is context.
  if idx < items.length() {
    let candidate = items[idx]
    if candidate.tag == @asn1.tag_sequence {
      let entries = expect_sequence(candidate)
      for e in entries {
        revoked.push(parse_revoked_entry(e))
      }
      idx = idx + 1
    }
  }
  // crlExtensions [0] EXPLICIT. Scope / delta / indirect-CRL semantics are not
  // implemented, so reject rather than returning a trusted partial result.
  if idx < items.length() {
    match match_context_explicit(items[idx], 0U) {
      Some(exts) => {
        reject_unsupported_extensions(exts, "crlExtensions")
        idx = idx + 1
      }
      None => raise Malformed("TBSCertList: unexpected trailing field")
    }
  }
  if idx != items.length() {
    raise Malformed("TBSCertList: trailing fields")
  }
  {
    inner_signature_alg: inner_sig_alg,
    issuer,
    this_update,
    next_update,
    revoked,
  }
}

///|
fn parse_name_from_elem(elem : @asn1.Element) -> @pkix.Name raise CrlError {
  // pkix has no public elem-based Name parser; round-trip via DER encode.
  @pkix.parse_name(@asn1.encode_der(elem)) catch {
    e => raise Pkix(e)
  }
}

// ─── parse top-level CertificateList ───────────────────────────────────
//
// CertificateList ::= SEQUENCE {
//   tbsCertList         TBSCertList,
//   signatureAlgorithm  AlgorithmIdentifier,
//   signature           BIT STRING }

///|
priv struct ParsedCertificateList {
  tbs_bytes : Bytes
  tbs : ParsedTbsCertList
  outer_signature_alg : @pkix.AlgorithmIdentifier
  signature : @asn1.BitString
}

///|
fn parse_certificate_list(der : Bytes) -> ParsedCertificateList raise CrlError {
  let outer = @asn1.decode_der(der) catch { e => raise Asn1(e) }
  let items = expect_sequence(outer)
  if items.length() != 3 {
    raise Malformed("CertificateList: must have 3 fields")
  }
  let tbs_elem = items[0]
  // Re-encode the parsed tbsCertList to obtain the exact signed bytes.
  // RFC 5280 mandates DER, so re-encode is byte-stable for compliant CRLs.
  let tbs_bytes = @asn1.encode_der(tbs_elem)
  let tbs = parse_tbs_cert_list(tbs_elem)
  let outer_alg = @pkix.parse_algorithm_identifier_elem(items[1]) catch {
    e => raise Pkix(e)
  }
  let sig = expect_bit_string(items[2])
  // RFC 5280 §5.1.1.2 / §5.1.2.2: the outer signatureAlgorithm MUST match
  // the inner TBSCertList.signature.
  if outer_alg != tbs.inner_signature_alg {
    raise AlgorithmMismatch
  }
  { tbs_bytes, tbs, outer_signature_alg: outer_alg, signature: sig }
}

///|
/// Parse a CertificateList (CRL) from DER. Does NOT verify the signature;
/// use `verify(...)` for the full check.
pub fn parse(der : Bytes) -> Crl raise CrlError {
  let p = parse_certificate_list(der)
  {
    issuer: p.tbs.issuer,
    this_update: p.tbs.this_update,
    next_update: p.tbs.next_update,
    revoked: p.tbs.revoked,
  }
}

// ─── time helpers ───────────────────────────────────────────────────────

///|
fn normalize_time(s : String) -> String raise CrlError {
  if s.length() == 15 {
    if s.get_char(14).unwrap() != 'Z' {
      raise Malformed("time: GeneralizedTime must end with Z")
    }
    return s
  }
  if s.length() == 13 {
    if s.get_char(12).unwrap() != 'Z' {
      raise Malformed("time: UTCTime must end with Z")
    }
    let zero = '0'.to_int()
    let yy_hi = s.code_unit_at(0).to_int() - zero
    let yy_lo = s.code_unit_at(1).to_int() - zero
    let yy = yy_hi * 10 + yy_lo
    let century = if yy < 50 { "20" } else { "19" }
    return century + s
  }
  raise Malformed("time: unsupported format length " + s.length().to_string())
}

// ─── verify ─────────────────────────────────────────────────────────────

///|
fn names_match(a : @pkix.Name, b : @pkix.Name) -> Bool {
  @pkix.serialize_name(a) == @pkix.serialize_name(b)
}

///|
/// Parse and fully verify a CRL: signature against `issuer_cert.pubkey`,
/// DN linkage (CRL.issuer == issuer_cert.subject), and freshness against
/// `now` (UTCTime YYMMDDHHMMSSZ or GeneralizedTime YYYYMMDDHHMMSSZ).
pub fn verify(
  crl_der : Bytes,
  issuer_cert : @pkix.Certificate,
  now : String,
) -> Crl raise CrlError {
  let p = parse_certificate_list(crl_der)
  // DN linkage.
  if !names_match(p.tbs.issuer, issuer_cert.tbs.subject) {
    raise IssuerMismatch
  }
  // Signature.
  let issuer_pk = @pkix_verify.extract_public_key(
    issuer_cert.tbs.subject_public_key_info,
  ) catch {
    e => raise PkixVerify(e)
  }
  @pkix_verify.verify_signature(
    p.tbs_bytes,
    p.outer_signature_alg,
    p.signature,
    issuer_pk,
  ) catch {
    _ => raise BadSignature
  }
  // Freshness.
  let now_n = normalize_time(now)
  let this_n = normalize_time(p.tbs.this_update)
  if now_n < this_n {
    raise StaleCrl("thisUpdate > now")
  }
  match p.tbs.next_update {
    Some(nu) => {
      let next_n = normalize_time(nu)
      if !(now_n < next_n) {
        raise StaleCrl("now >= nextUpdate")
      }
    }
    None => ()
  }
  {
    issuer: p.tbs.issuer,
    this_update: p.tbs.this_update,
    next_update: p.tbs.next_update,
    revoked: p.tbs.revoked,
  }
}

// ─── revocation lookup ──────────────────────────────────────────────────

///|
// Strip a leading DER sign-prefix byte (a 0x00 added to keep the INTEGER
// non-negative when the next byte has the high bit set). After stripping
// the two sides of an `is_revoked` comparison agree even if one came from
// a parsed cert (which preserves the prefix) and the other from a caller
// that hand-built the serial without one.
fn strip_serial_sign_prefix(b : Bytes) -> Bytes {
  if b.length() >= 2 && b[0] == b'\x00' && (b[1].to_int() & 0x80) != 0 {
    return Bytes::makei(b.length() - 1, fn(i) { b[i + 1] })
  }
  b
}

///|
/// Byte-compare `serial` against each entry's serial number. Sign-prefix
/// bytes (a leading 0x00 added to keep a high-bit-set INTEGER non-negative)
/// are stripped on both sides before comparison.
pub fn is_revoked(crl : Crl, serial : Bytes) -> Bool {
  let target = strip_serial_sign_prefix(serial)
  for entry in crl.revoked {
    let s = strip_serial_sign_prefix(entry.serial)
    if s.length() != target.length() {
      continue
    }
    let mut eq = true
    for i = 0; i < s.length(); i = i + 1 {
      if s[i] != target[i] {
        eq = false
        break
      }
    }
    if eq {
      return true
    }
  }
  false
}
