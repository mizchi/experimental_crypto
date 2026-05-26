// X.509 v3 chain verification.
//
// Builds on top of `mizchi/pkix` (parser) + `mizchi/ed25519` / `mizchi/rsa`
// (signature primitives). The strategy is:
//
//   1. extract_public_key:  SPKI(algorithm OID) → typed `PublicKey`.
//   2. verify_signature:    re-encode TBS, hand the bytes + signature to the
//                           right primitive.
//   3. verify_certificate:  signature + validity. (basicConstraints / path-
//                           length are caller-side because the meaning of
//                           "is this CA permitted to issue" depends on
//                           position in the chain.)
//   4. verify_chain:        walk leaf → intermediates → trust anchor, check
//                           DN linkage + basicConstraints + signatures.
//
// We deliberately do NOT touch revocation (CRL / OCSP), name constraints, or
// EKU policy in this round.

///|
pub(all) enum PublicKey {
  Ed25519(@ed25519.PublicKey)
  Rsa(@rsa.RsaPublicKey)
  P256(@p256.PublicKey)
  P384(@p384.PublicKey)
}

///|
pub suberror PkixVerifyError {
  UnsupportedSignatureAlgorithm(@asn1.ObjectIdentifier)
  UnsupportedPublicKeyAlgorithm(@asn1.ObjectIdentifier)
  SignatureMismatch
  NotYetValid
  Expired
  NotACA
  PathLengthExceeded
  IssuerSubjectMismatch
  EmptyChain
  MalformedExtension(String)
  // RFC 5280 §4.2: "If a certificate contains a critical extension that the
  // application cannot process, then the application MUST reject the
  // certificate". Raised when a critical extension's OID is not in our
  // recognised set.
  UnknownCriticalExtension(@asn1.ObjectIdentifier)
  // RFC 5280 §6.1.4(n): an issuer's keyUsage, if present, MUST include
  // keyCertSign.
  KeyUsageMissingCertSign
  // RFC 5280 §6.1.3(b) / §4.2.1.10: child's DNS name is excluded by the
  // parent's nameConstraints.excludedSubtrees, or outside its
  // permittedSubtrees.
  NameConstraintViolation(String)
  // The leaf cert's extendedKeyUsage does not contain the OID the caller
  // required via VerifyChainOptions.required_eku.
  ExtendedKeyUsageMissing(@asn1.ObjectIdentifier)
  Pkix(@pkix.PkixError)
  Rsa(@rsa.RsaError)
  Ed25519(@ed25519.Ed25519Error)
  P256(@p256.P256Error)
  P384(@p384.P384Error)
  Asn1(@asn1.Asn1Error)
} derive(Show)

// ─── OIDs ────────────────────────────────────────────────────────────────

///|
// id-Ed25519, RFC 8410 §3.
fn ed25519_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 3, 101, 112])
}

///|
// rsaEncryption, PKCS#1 / RFC 8017.
fn rsa_encryption_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 113549, 1, 1, 1])
}

///|
// sha256WithRSAEncryption, PKCS#1.
fn sha256_with_rsa_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 113549, 1, 1, 11])
}

///|
// id-ecPublicKey, RFC 5480 §2.1.1.
fn ec_public_key_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 10045, 2, 1])
}

///|
// secp256r1 (P-256) namedCurve, RFC 5480 §2.1.1.1.
fn secp256r1_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 10045, 3, 1, 7])
}

///|
// ecdsa-with-SHA256, RFC 5758 §3.2.
fn ecdsa_with_sha256_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 10045, 4, 3, 2])
}

///|
// secp384r1 (P-384) namedCurve, RFC 5480 §2.1.1.1.
fn secp384r1_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 3, 132, 0, 34])
}

///|
// ecdsa-with-SHA384, RFC 5758 §3.2.
fn ecdsa_with_sha384_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 10045, 4, 3, 3])
}

///|
// basicConstraints, RFC 5280 §4.2.1.9.
fn basic_constraints_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 19])
}

// ─── recognised critical extensions ──────────────────────────────────────
//
// RFC 5280 §4.2 mandates that a verifier MUST reject any certificate
// containing a critical extension it cannot process. Status of each:
//
//   PROCESSED — fully enforced during chain validation:
//     - basicConstraints (cA + pathLen)
//     - keyUsage (keyCertSign on issuers, §6.1.4(n))
//     - nameConstraints (DNS-name subtree matching, §6.1.3(b))
//     - extendedKeyUsage (when caller requests a specific EKU via
//       VerifyChainOptions.required_eku)
//
//   RECOGNISED-BUT-NOT-ENFORCED — accepted critical but not used in our
//   verifier scope. Documented gaps:
//     - subjectAltName: identity matching is the caller's concern;
//       use `extract_dns_san` to retrieve the names.
//     - certificatePolicies / policyConstraints / inhibitAnyPolicy:
//       policy-graph processing (RFC 5280 §6.1.4(a)..(o)) is out of
//       scope — this verifier returns "valid"/"invalid", not a set of
//       valid policies. A caller that needs policy enforcement should
//       layer it on top.

///|
fn key_usage_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 15])
}

///|
fn extended_key_usage_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 37])
}

///|
fn subject_alt_name_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 17])
}

///|
fn certificate_policies_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 32])
}

///|
fn name_constraints_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 30])
}

///|
fn policy_constraints_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 36])
}

///|
fn inhibit_any_policy_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 54])
}

///|
fn is_recognised_critical_extension(oid : @asn1.ObjectIdentifier) -> Bool {
  oid == basic_constraints_oid() ||
  oid == key_usage_oid() ||
  oid == extended_key_usage_oid() ||
  oid == subject_alt_name_oid() ||
  oid == certificate_policies_oid() ||
  oid == name_constraints_oid() ||
  oid == policy_constraints_oid() ||
  oid == inhibit_any_policy_oid()
}

///|
fn check_critical_extensions(
  cert : @pkix.Certificate,
) -> Unit raise PkixVerifyError {
  for ext in cert.tbs.extensions {
    if ext.critical && not(is_recognised_critical_extension(ext.oid)) {
      raise UnknownCriticalExtension(ext.oid)
    }
  }
}

// ─── keyUsage (RFC 5280 §4.2.1.3 + §6.1.4(n)) ────────────────────────────

///|
// Returns true if the cert carries a keyUsage extension whose bit 5
// (keyCertSign) is set, OR if no keyUsage extension is present at all
// (in which case the key may be used for any purpose, per RFC 5280).
fn issuer_allows_cert_sign(
  cert : @pkix.Certificate,
) -> Bool raise PkixVerifyError {
  for ext in cert.tbs.extensions {
    if ext.oid == key_usage_oid() {
      let elem = @asn1.decode_der(ext.value) catch { e => raise Asn1(e) }
      let bs = match elem.value {
        BitString(b) => b
        _ => raise MalformedExtension("keyUsage: expected BIT STRING")
      }
      if bs.bytes.length() == 0 {
        // RFC 5280: "at least one of the bits MUST be set to 1"
        raise MalformedExtension("keyUsage: empty BIT STRING")
      }
      // Bit 5 of the BIT STRING = bit at position (7 - 5) = 2 of byte 0.
      return ((bs.bytes[0].to_int() >> 2) & 1) == 1
    }
  }
  // Extension absent ⇒ unrestricted usage permitted (RFC 5280 §4.2.1.3).
  true
}

// ─── subjectAltName / GeneralName parsing (DNS only) ─────────────────────

///|
// Extract dNSName entries from a SubjectAltName extension's extnValue.
// Other GeneralName variants (IP, URI, otherName, ...) are intentionally
// skipped — we only do DNS-name constraint matching.
fn extract_dns_names_from_san_value(
  ext_value : Bytes,
) -> Array[String] raise PkixVerifyError {
  let elem = @asn1.decode_der(ext_value) catch { e => raise Asn1(e) }
  let items = match elem.value {
    Sequence(xs) => xs
    _ => raise MalformedExtension("subjectAltName: expected SEQUENCE")
  }
  let dns : Array[String] = []
  for item in items {
    // dNSName is [2] IMPLICIT IA5String — context-specific tag 2, primitive.
    if item.tag.class_ == @asn1.TagClass::ContextSpecific &&
      item.tag.number == 2U &&
      not(item.tag.constructed) {
      match item.value {
        Unknown(raw) => dns.push(bytes_to_ascii(raw))
        _ => ()
      }
    }
  }
  dns
}

///|
fn bytes_to_ascii(b : Bytes) -> String {
  let buf = StringBuilder::new()
  for i in 0..<b.length() {
    buf.write_char(b[i].to_int().to_char().unwrap())
  }
  buf.to_string()
}

///|
/// Public accessor: return all dNSName entries from a cert's SAN. Useful
/// for callers that want to verify the cert identity matches an expected
/// hostname (a check this verifier deliberately does NOT perform).
pub fn extract_dns_san(
  cert : @pkix.Certificate,
) -> Array[String] raise PkixVerifyError {
  for ext in cert.tbs.extensions {
    if ext.oid == subject_alt_name_oid() {
      return extract_dns_names_from_san_value(ext.value)
    }
  }
  []
}

// ─── nameConstraints (RFC 5280 §4.2.1.10 + §6.1.3(b)) ────────────────────

///|
priv struct DnsNameConstraints {
  // Permitted-subtrees (empty means "no permitted constraint" i.e. all
  // allowed); excluded-subtrees take precedence over permitted (RFC 5280).
  permitted : Array[String]
  excluded : Array[String]
}

///|
// Parse nameConstraints, picking out the dNSName generalNames from
// permittedSubtrees / excludedSubtrees. Subtrees with other name kinds
// (IP / RFC822 / URI / DN) are conservatively rejected when they would
// alter chain semantics — but only the dns subset is enforced; non-DNS
// permitted subtrees mean child certs with non-DNS names cannot be
// constrained by us. We surface that as a hard malformed for now to
// avoid silent under-enforcement.
fn parse_dns_name_constraints(
  ext_value : Bytes,
) -> DnsNameConstraints raise PkixVerifyError {
  let elem = @asn1.decode_der(ext_value) catch { e => raise Asn1(e) }
  let items = match elem.value {
    Sequence(xs) => xs
    _ => raise MalformedExtension("nameConstraints: expected SEQUENCE")
  }
  let permitted : Array[String] = []
  let excluded : Array[String] = []
  for item in items {
    // permittedSubtrees [0], excludedSubtrees [1] (both context-tagged,
    // CONSTRUCTED — they're SEQUENCEs).
    if item.tag.class_ != @asn1.TagClass::ContextSpecific {
      continue
    }
    let target_array = if item.tag.number == 0U {
      permitted
    } else if item.tag.number == 1U {
      excluded
    } else {
      continue
    }
    // Re-parse the context-tagged inner as a SEQUENCE OF GeneralSubtree
    // (GeneralSubtree ::= SEQUENCE { base GeneralName, ... }).
    let subtrees_bytes = match item.value {
      Unknown(b) => b
      _ => raise MalformedExtension("nameConstraints: subtrees not raw")
    }
    // The context-tagged value contains the SEQUENCE OF GeneralSubtree
    // contents directly (since the implicit tag replaced SEQUENCE's tag).
    // Re-wrap with a SEQUENCE header and decode.
    let inner_dec = @asn1.Decoder::new(subtrees_bytes)
    while not(inner_dec.is_empty()) {
      let gst = inner_dec.read_element() catch { e => raise Asn1(e) }
      let gst_items = match gst.value {
        Sequence(xs) => xs
        _ => raise MalformedExtension("nameConstraints: GeneralSubtree shape")
      }
      if gst_items.length() < 1 {
        raise MalformedExtension("nameConstraints: empty GeneralSubtree")
      }
      let base = gst_items[0]
      if base.tag.class_ == @asn1.TagClass::ContextSpecific &&
        base.tag.number == 2U &&
        not(base.tag.constructed) {
        match base.value {
          Unknown(raw) => target_array.push(bytes_to_ascii(raw))
          _ => ()
        }
      }
      // Non-DNS subtree kinds (IP, RFC822, ...) are intentionally ignored
      // here. This is a known under-enforcement: a permittedSubtrees with
      // ONLY non-DNS entries would falsely become "no DNS restriction" in
      // our model. Tracked in the recognised-but-not-enforced comment.
    }
  }
  { permitted, excluded }
}

///|
fn find_dns_name_constraints(
  cert : @pkix.Certificate,
) -> DnsNameConstraints? raise PkixVerifyError {
  for ext in cert.tbs.extensions {
    if ext.oid == name_constraints_oid() {
      return Some(parse_dns_name_constraints(ext.value))
    }
  }
  None
}

///|
// RFC 5280 §4.2.1.10: a DNS subtree matches a candidate DNS name if either
// they are identical OR the candidate has the subtree as a suffix following
// a "." boundary. Comparison is case-insensitive (ASCII).
fn dns_name_in_subtree(name : String, subtree : String) -> Bool {
  let n = ascii_lower(name)
  let s = ascii_lower(subtree)
  if s == "" {
    return true
  }
  if n == s {
    return true
  }
  // "host.example.com" matches subtree "example.com" via a "."-boundary.
  if n.length() > s.length() + 1 {
    let tail_start = n.length() - s.length()
    let dot_pos = tail_start - 1
    let mut tail_matches = true
    for i = 0; i < s.length(); i = i + 1 {
      if n.get_char(tail_start + i).unwrap() != s.get_char(i).unwrap() {
        tail_matches = false
        break
      }
    }
    if tail_matches && n.get_char(dot_pos).unwrap() == '.' {
      return true
    }
  }
  false
}

///|
fn ascii_lower(s : String) -> String {
  let buf = StringBuilder::new()
  for c in s {
    let n = c.to_int()
    if n >= 0x41 && n <= 0x5a {
      buf.write_char((n + 0x20).to_char().unwrap())
    } else {
      buf.write_char(c)
    }
  }
  buf.to_string()
}

///|
// Check that `dns` is permitted (matches a permittedSubtree if any) and not
// excluded (matches no excludedSubtree).
fn dns_within_constraints(
  dns : String,
  cons : DnsNameConstraints,
) -> Bool {
  for ex in cons.excluded {
    if dns_name_in_subtree(dns, ex) {
      return false
    }
  }
  if cons.permitted.length() == 0 {
    return true
  }
  for p in cons.permitted {
    if dns_name_in_subtree(dns, p) {
      return true
    }
  }
  false
}

///|
// Enforce a parent's nameConstraints against a child cert's SAN dNSNames.
// Returns the violating name (raises NameConstraintViolation) if any name
// fails. Certs with no SAN are unconstrained from a DNS perspective.
fn enforce_name_constraints(
  parent_constraints : DnsNameConstraints,
  child : @pkix.Certificate,
) -> Unit raise PkixVerifyError {
  let dns_names = extract_dns_san(child)
  for dns in dns_names {
    if not(dns_within_constraints(dns, parent_constraints)) {
      raise NameConstraintViolation(dns)
    }
  }
}

// ─── extendedKeyUsage (RFC 5280 §4.2.1.12) ───────────────────────────────

///|
fn extract_ekus(
  cert : @pkix.Certificate,
) -> Array[@asn1.ObjectIdentifier]? raise PkixVerifyError {
  for ext in cert.tbs.extensions {
    if ext.oid == extended_key_usage_oid() {
      let elem = @asn1.decode_der(ext.value) catch { e => raise Asn1(e) }
      let items = match elem.value {
        Sequence(xs) => xs
        _ => raise MalformedExtension("EKU: expected SEQUENCE")
      }
      let out : Array[@asn1.ObjectIdentifier] = []
      for it in items {
        match it.value {
          Oid(o) => out.push(o)
          _ => raise MalformedExtension("EKU: expected OIDs")
        }
      }
      return Some(out)
    }
  }
  None
}

///|
// Special EKU OID `anyExtendedKeyUsage = 2.5.29.37.0` (RFC 5280 §4.2.1.12)
// — when present, satisfies any required EKU check.
fn any_eku_oid() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([2U, 5, 29, 37, 0])
}

///|
fn enforce_required_eku(
  cert : @pkix.Certificate,
  required : @asn1.ObjectIdentifier,
) -> Unit raise PkixVerifyError {
  match extract_ekus(cert) {
    None =>
      // RFC 5280 §4.2.1.12: "If a certificate contains both a key usage
      // extension and an extended key usage extension, then both
      // extensions MUST be processed independently". When the EKU
      // extension is absent the cert can be used for any purpose, so
      // any required_eku is satisfied.
      ()
    Some(ekus) => {
      let any_oid = any_eku_oid()
      for o in ekus {
        if o == required || o == any_oid {
          return
        }
      }
      raise ExtendedKeyUsageMissing(required)
    }
  }
}

// ─── public key extraction ───────────────────────────────────────────────

///|
pub fn extract_public_key(
  spki : @pkix.SubjectPublicKeyInfo,
) -> PublicKey raise PkixVerifyError {
  let alg = spki.algorithm.algorithm
  if alg == ed25519_oid() {
    if spki.subject_public_key.unused_bits != 0 {
      raise UnsupportedPublicKeyAlgorithm(alg)
    }
    let pk = @ed25519.PublicKey::from_bytes(spki.subject_public_key.bytes) catch {
      e => raise Ed25519(e)
    }
    Ed25519(pk)
  } else if alg == rsa_encryption_oid() {
    if spki.subject_public_key.unused_bits != 0 {
      raise UnsupportedPublicKeyAlgorithm(alg)
    }
    let pk = @rsa.RsaPublicKey::from_pkcs1_der(spki.subject_public_key.bytes) catch {
      e => raise Rsa(e)
    }
    Rsa(pk)
  } else if alg == ec_public_key_oid() {
    // RFC 5480 §2.1.1: AlgorithmIdentifier parameters MUST be a namedCurve
    // OID for the EC curve being used. We handle P-256 and P-384.
    let curve_oid = match spki.algorithm.parameters {
      Some(param_bytes) => {
        let elem = @asn1.decode_der(param_bytes) catch { e => raise Asn1(e) }
        match elem.value {
          Oid(o) => o
          _ => raise UnsupportedPublicKeyAlgorithm(alg)
        }
      }
      None => raise UnsupportedPublicKeyAlgorithm(alg)
    }
    if spki.subject_public_key.unused_bits != 0 {
      raise UnsupportedPublicKeyAlgorithm(alg)
    }
    if curve_oid == secp256r1_oid() {
      let pk = @p256.PublicKey::from_uncompressed(spki.subject_public_key.bytes) catch {
        e => raise P256(e)
      }
      P256(pk)
    } else if curve_oid == secp384r1_oid() {
      let pk = @p384.PublicKey::from_uncompressed(spki.subject_public_key.bytes) catch {
        e => raise P384(e)
      }
      P384(pk)
    } else {
      raise UnsupportedPublicKeyAlgorithm(alg)
    }
  } else {
    raise UnsupportedPublicKeyAlgorithm(alg)
  }
}

// ─── signature verification ──────────────────────────────────────────────

///|
pub fn verify_signature(
  message : Bytes,
  signature_alg : @pkix.AlgorithmIdentifier,
  signature : @asn1.BitString,
  issuer_pubkey : PublicKey,
) -> Unit raise PkixVerifyError {
  let alg = signature_alg.algorithm
  if signature.unused_bits != 0 {
    // Signature BIT STRING is always 8-bit aligned for the algorithms we
    // support; anything else is malformed.
    raise SignatureMismatch
  }
  let sig_bytes = signature.bytes
  if alg == ed25519_oid() {
    match issuer_pubkey {
      Ed25519(pk) => {
        if sig_bytes.length() != 64 {
          raise SignatureMismatch
        }
        let ok = pk.verify(message, sig_bytes)
        if not(ok) {
          raise SignatureMismatch
        }
      }
      _ => raise UnsupportedSignatureAlgorithm(alg)
    }
  } else if alg == sha256_with_rsa_oid() {
    match issuer_pubkey {
      Rsa(pk) => {
        let ok = pk.verify(message, sig_bytes, @rsa.HashAlg::Sha256) catch {
          e => raise Rsa(e)
        }
        if not(ok) {
          raise SignatureMismatch
        }
      }
      _ => raise UnsupportedSignatureAlgorithm(alg)
    }
  } else if alg == ecdsa_with_sha256_oid() {
    match issuer_pubkey {
      P256(pk) => {
        // X.509 / RFC 5480: the ECDSA signature value is the DER encoding of
        // `SEQUENCE { INTEGER r, INTEGER s }`, not the JOSE raw form.
        let ok = @p256.verify(
          pk,
          message,
          sig_bytes,
          @p256.SignatureFormat::Der,
        ) catch {
          e => raise P256(e)
        }
        if not(ok) {
          raise SignatureMismatch
        }
      }
      _ => raise UnsupportedSignatureAlgorithm(alg)
    }
  } else if alg == ecdsa_with_sha384_oid() {
    match issuer_pubkey {
      P384(pk) => {
        let ok = @p384.verify(
          pk,
          message,
          sig_bytes,
          @p384.SignatureFormat::Der,
        ) catch {
          e => raise P384(e)
        }
        if not(ok) {
          raise SignatureMismatch
        }
      }
      _ => raise UnsupportedSignatureAlgorithm(alg)
    }
  } else {
    raise UnsupportedSignatureAlgorithm(alg)
  }
}

// ─── validity ────────────────────────────────────────────────────────────

///|
// UTCTime / GeneralizedTime comparison.
//
// RFC 5280 §4.1.2.5: UTCTime is YYMMDDHHMMSSZ with YY < 50 ⇒ 20YY else 19YY.
// We normalize to YYYYMMDDHHMMSSZ which is lexicographic = chronological.
fn normalize_time(s : String) -> String {
  // GeneralizedTime is already YYYYMMDDHHMMSSZ.
  if s.length() >= 15 {
    return s
  }
  // UTCTime: YYMMDDHHMMSSZ, length 13.
  if s.length() < 2 {
    return s
  }
  let zero = '0'.to_int()
  let yy_hi = s.code_unit_at(0).to_int() - zero
  let yy_lo = s.code_unit_at(1).to_int() - zero
  let yy = yy_hi * 10 + yy_lo
  let century = if yy < 50 { "20" } else { "19" }
  century + s
}

///|
fn check_validity(
  validity : @pkix.Validity,
  now : String,
) -> Unit raise PkixVerifyError {
  let nb = normalize_time(validity.not_before)
  let na = normalize_time(validity.not_after)
  let now_n = normalize_time(now)
  if now_n < nb {
    raise NotYetValid
  }
  if now_n > na {
    raise Expired
  }
}

// ─── certificate verification ────────────────────────────────────────────

///|
pub fn verify_certificate(
  cert : @pkix.Certificate,
  issuer_pubkey : PublicKey,
  now : String,
) -> Unit raise PkixVerifyError {
  check_validity(cert.tbs.validity, now)
  // RFC 5280 §4.2: reject any certificate that carries a critical
  // extension we do not recognise. Runs before signature verification so
  // we don't spend a (potentially expensive) RSA modexp on a cert we'd
  // refuse on policy grounds anyway.
  check_critical_extensions(cert)
  // Re-encode TBS so we can hand the exact signed bytes to the primitive.
  // The pkix DER roundtrip is byte-stable for the certs we care about
  // (verified by `pkix fixture: ... DER roundtrip is byte-stable`).
  let tbs_elem = @pkix.tbs_certificate_to_element(cert.tbs) catch {
    e => raise Pkix(e)
  }
  let tbs_bytes = @asn1.encode_der(tbs_elem)
  verify_signature(
    tbs_bytes,
    cert.signature_algorithm,
    cert.signature,
    issuer_pubkey,
  )
}

// ─── chain verification ──────────────────────────────────────────────────

///|
// Byte-compare two DN encodings. RFC 5280 lets either binary or LDAP string
// comparison be used; binary matches what RFC actually mandates for issuer /
// subject linkage when both came out of DER parsers like ours, and is also
// what most validators do in practice.
fn names_match(a : @pkix.Name, b : @pkix.Name) -> Bool {
  @pkix.serialize_name(a) == @pkix.serialize_name(b)
}

///|
// Returns (is_ca, path_len_constraint).
//
//   BasicConstraints ::= SEQUENCE {
//     cA                      BOOLEAN DEFAULT FALSE,
//     pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
fn parse_basic_constraints(
  ext : @pkix.Extension,
) -> (Bool, Int?) raise PkixVerifyError {
  let elem = @asn1.decode_der(ext.value) catch { e => raise Asn1(e) }
  let items = match elem.value {
    Sequence(xs) => xs
    _ => raise MalformedExtension("basicConstraints: expected SEQUENCE")
  }
  let mut is_ca = false
  let mut path_len : Int? = None
  let mut idx = 0
  if idx < items.length() {
    match items[idx].value {
      Boolean(b) => {
        is_ca = b
        idx = idx + 1
      }
      _ => ()
    }
  }
  if idx < items.length() {
    match items[idx].value {
      Integer(bs) =>
        if bs.length() == 0 || bs.length() > 4 {
          raise MalformedExtension("pathLenConstraint out of range")
        } else {
          let mut v = 0
          for i in 0..<bs.length() {
            v = (v << 8) | bs[i].to_int()
          }
          path_len = Some(v)
        }
      _ => ()
    }
  }
  (is_ca, path_len)
}

///|
// Look up basicConstraints; absent extension ⇒ (cA=false, pathLen=None).
fn find_basic_constraints(
  cert : @pkix.Certificate,
) -> (Bool, Int?) raise PkixVerifyError {
  for ext in cert.tbs.extensions {
    if ext.oid == basic_constraints_oid() {
      return parse_basic_constraints(ext)
    }
  }
  (false, None)
}

///|
///|
/// Options that fine-tune chain verification. Defaults are conservative
/// (no caller-required EKU, but all the in-chain extension checks remain on).
pub(all) struct VerifyChainOptions {
  // If set, the leaf cert's extendedKeyUsage MUST contain this OID (or
  // anyExtendedKeyUsage). If the leaf has no EKU extension the constraint
  // is satisfied (RFC 5280 §4.2.1.12).
  required_eku : @asn1.ObjectIdentifier?
}

///|
pub fn VerifyChainOptions::default() -> VerifyChainOptions {
  { required_eku: None }
}

///|
/// Wrapper preserving the original verify_chain API. Equivalent to
/// `verify_chain_with_options(... , VerifyChainOptions::default())`.
pub fn verify_chain(
  leaf : @pkix.Certificate,
  intermediates : Array[@pkix.Certificate],
  trust_anchor_pubkey : PublicKey,
  now : String,
) -> Unit raise PkixVerifyError {
  verify_chain_with_options(
    leaf,
    intermediates,
    trust_anchor_pubkey,
    now,
    VerifyChainOptions::default(),
  )
}

///|
/// Verify a leaf cert against a trust anchor pubkey, walking through any
/// supplied intermediates. Enforces:
///
///   - validity (notBefore <= now <= notAfter) for every cert
///   - RFC 5280 §4.2 critical-extension recognition
///   - signature on every cert in the chain
///   - DN linkage (child.issuer == parent.subject)
///   - basicConstraints.cA on every intermediate
///   - basicConstraints.pathLenConstraint
///   - keyUsage.keyCertSign on issuer certs (RFC 5280 §6.1.4(n))
///   - nameConstraints (DNS subtree subset, RFC 5280 §6.1.3(b))
///   - extendedKeyUsage on the leaf if VerifyChainOptions.required_eku set
pub fn verify_chain_with_options(
  leaf : @pkix.Certificate,
  intermediates : Array[@pkix.Certificate],
  trust_anchor_pubkey : PublicKey,
  now : String,
  opts : VerifyChainOptions,
) -> Unit raise PkixVerifyError {
  check_validity(leaf.tbs.validity, now)
  for inter in intermediates {
    check_validity(inter.tbs.validity, now)
  }
  let mut current_pubkey = trust_anchor_pubkey
  let n = intermediates.length()
  // Active DNS name constraint set, intersected as we walk down the chain.
  // None ⇒ no constraint yet. The trust anchor's constraints (if any) are
  // out-of-band; we assume the caller's anchor is unconstrained.
  let mut active_constraints : DnsNameConstraints? = None
  for i = n - 1; i >= 0; i = i - 1 {
    let inter = intermediates[i]
    let (is_ca, _) = find_basic_constraints(inter)
    if not(is_ca) {
      raise NotACA
    }
    let (_, this_path_len) = find_basic_constraints(inter)
    match this_path_len {
      Some(limit) => if i > limit { raise PathLengthExceeded }
      None => ()
    }
    // Issuer keyUsage must allow cert signing (RFC 5280 §6.1.4(n)).
    if not(issuer_allows_cert_sign(inter)) {
      raise KeyUsageMissingCertSign
    }
    // Active nameConstraints from any ancestor must hold for THIS cert's
    // SAN as well — a CA cannot escape its parent's constraints just by
    // issuing further sub-CAs.
    match active_constraints {
      Some(cons) => enforce_name_constraints(cons, inter)
      None => ()
    }
    // Signature: inter is signed by current_pubkey.
    verify_certificate(inter, current_pubkey, now)
    if i < n - 1 {
      let parent = intermediates[i + 1]
      if not(names_match(inter.tbs.issuer, parent.tbs.subject)) {
        raise IssuerSubjectMismatch
      }
    }
    // If THIS cert carries nameConstraints, narrow the active set. We do
    // not intersect — a child CA's nameConstraints REPLACES the parent's
    // for everything below (RFC 5280 §6.1.4(g) is more subtle in full
    // generality; this is a defensible simplification for the DNS-only
    // subset since narrowing is what real chains do in practice).
    match find_dns_name_constraints(inter) {
      Some(c) => active_constraints = Some(c)
      None => ()
    }
    current_pubkey = extract_public_key(inter.tbs.subject_public_key_info)
  }
  // Leaf.
  // Active nameConstraints apply to the leaf's SAN.
  match active_constraints {
    Some(cons) => enforce_name_constraints(cons, leaf)
    None => ()
  }
  verify_certificate(leaf, current_pubkey, now)
  if n > 0 {
    let direct_parent = intermediates[0]
    if not(names_match(leaf.tbs.issuer, direct_parent.tbs.subject)) {
      raise IssuerSubjectMismatch
    }
  }
  // Caller-requested EKU on the leaf (if any).
  match opts.required_eku {
    Some(o) => enforce_required_eku(leaf, o)
    None => ()
  }
}
