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
pub fn verify_chain(
  leaf : @pkix.Certificate,
  intermediates : Array[@pkix.Certificate],
  trust_anchor_pubkey : PublicKey,
  now : String,
) -> Unit raise PkixVerifyError {
  // We model the chain as: leaf, intermediates[0], ..., intermediates[N-1]
  // all signed against `trust_anchor_pubkey` at the top.
  //
  // For each child→parent pair we check:
  //   - signature (child.tbs signed by parent's pubkey)
  //   - DN linkage (child.issuer == parent.subject)  [intermediate only]
  //   - parent is a CA via basicConstraints           [intermediate only]
  //   - path length is respected                      [intermediate only]
  //   - validity of every cert in the chain
  //
  // The trust anchor has no cert here, only a pubkey; we assume the caller
  // already vetted the anchor's basicConstraints out of band.
  check_validity(leaf.tbs.validity, now)
  for inter in intermediates {
    check_validity(inter.tbs.validity, now)
  }
  // Walk parent → child from the top of the chain down to the leaf.
  // `current_pubkey` always holds the verifier for the next certificate.
  let mut current_pubkey = trust_anchor_pubkey
  // intermediates in reverse order: index N-1 is signed by trust anchor,
  // index N-2 by N-1's pubkey, ... leaf by intermediates[0].
  let n = intermediates.length()
  for i = n - 1; i >= 0; i = i - 1 {
    let inter = intermediates[i]
    // Sub-CA must be a CA; pathLen, if set on the parent, must allow this
    // many further non-self CA certs between it and any leaf. Here `i` is
    // the number of intermediates BELOW this one in the chain (= # CAs
    // between this cert and the leaf, exclusive of this cert and the leaf).
    let (is_ca, _) = find_basic_constraints(inter)
    if not(is_ca) {
      raise NotACA
    }
    // If THIS cert has a pathLenConstraint, the number of non-self-signed
    // intermediate CAs that may follow (between it and the leaf) is bounded.
    // Following intermediates in our chain: i (indices 0..i-1).
    let (_, this_path_len) = find_basic_constraints(inter)
    match this_path_len {
      Some(limit) => if i > limit { raise PathLengthExceeded }
      None => ()
    }
    // Signature: inter is signed by current_pubkey (= parent above).
    verify_certificate(inter, current_pubkey, now)
    // DN linkage to the parent if we have one (when i == n-1 the parent is
    // the trust anchor and we have no cert for it; the caller asserted the
    // pubkey corresponds to the right DN).
    if i < n - 1 {
      let parent = intermediates[i + 1]
      if not(names_match(inter.tbs.issuer, parent.tbs.subject)) {
        raise IssuerSubjectMismatch
      }
    }
    current_pubkey = extract_public_key(inter.tbs.subject_public_key_info)
  }
  // Finally the leaf.
  verify_certificate(leaf, current_pubkey, now)
  if n > 0 {
    let direct_parent = intermediates[0]
    if not(names_match(leaf.tbs.issuer, direct_parent.tbs.subject)) {
      raise IssuerSubjectMismatch
    }
  }
}
