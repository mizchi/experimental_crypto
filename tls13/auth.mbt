// TLS 1.3 server authentication: verify a CertificateVerify signature against
// the leaf certificate's public key (RFC 8446 §4.4.3). This is the step that
// actually authenticates the server's identity to the negotiated handshake.
//
// Chain-of-trust validation of the certificate itself (the leaf up to a trust
// anchor, validity, name constraints, …) is a separate concern handled by
// `pkix_verify`; this module only checks that the server proved possession of
// the leaf key by signing the transcript.

///|
pub suberror AuthError {
  // The leaf certificate DER did not parse.
  Pkix(@pkix.PkixError)
  // The leaf SubjectPublicKeyInfo used an algorithm we cannot model.
  PkixVerify(@pkix_verify.PkixVerifyError)
  // RFC 8446 §4.4.3 forbids RSASSA-PKCS1-v1_5 in CertificateVerify.
  DisallowedScheme(SignatureScheme)
  // The signature scheme does not match the certificate's key type.
  KeyMismatch(SignatureScheme)
  // A recognised-but-not-wired or unknown signature scheme.
  UnsupportedScheme(SignatureScheme)
} derive(Debug)

///|
/// Verify a server `CertificateVerify` over the handshake transcript.
///
/// `leaf_cert_der` is the leaf certificate (the first entry of the parsed
/// Certificate chain). `transcript` is `Transcript-Hash(ClientHello ..
/// Certificate)` — everything up to but not including the CertificateVerify.
/// Returns `true` iff the signature is valid for the server CertificateVerify
/// content under the leaf key. Raises on a scheme that is forbidden in TLS 1.3,
/// mismatched with the key type, or unsupported; an otherwise-well-formed but
/// invalid signature returns `false` (fail closed).
pub fn verify_server_certificate_verify(
  leaf_cert_der : Bytes,
  cv : CertificateVerify,
  transcript : Bytes,
) -> Bool raise AuthError {
  let cert = @pkix.parse_certificate(leaf_cert_der) catch { e => raise Pkix(e) }
  let pubkey = @pkix_verify.extract_public_key(cert.tbs.subject_public_key_info) catch {
    e => raise PkixVerify(e)
  }
  let content = certificate_verify_content(
    server_certificate_verify_context, transcript,
  )
  verify_cert_verify_signature(cv.scheme, cv.signature, pubkey, content)
}

///|
// Dispatch the signature scheme to the matching primitive, binding the scheme
// to the certificate's key type. Primitive-level failures (bad encoding, wrong
// length, tag/MAC mismatch) collapse to `false`; policy problems raise.
fn verify_cert_verify_signature(
  scheme : SignatureScheme,
  signature : Bytes,
  pubkey : @pkix_verify.PublicKey,
  content : Bytes,
) -> Bool raise AuthError {
  match (scheme, pubkey) {
    (RsaPssRsaeSha256, Rsa(pk)) =>
      (try? pk.verify_pss(content, signature, @rsa.HashAlg::Sha256)).unwrap_or(
        false,
      )
    (RsaPssRsaeSha384, Rsa(pk)) =>
      (try? pk.verify_pss(content, signature, @rsa.HashAlg::Sha384)).unwrap_or(
        false,
      )
    (RsaPssRsaeSha512, Rsa(pk)) =>
      (try? pk.verify_pss(content, signature, @rsa.HashAlg::Sha512)).unwrap_or(
        false,
      )
    (EcdsaSecp256r1Sha256, P256(pk)) =>
      (try? @p256.verify(pk, content, signature, @p256.SignatureFormat::Der)).unwrap_or(
        false,
      )
    (EcdsaSecp384r1Sha384, P384(pk)) =>
      (try? @p384.verify(pk, content, signature, @p384.SignatureFormat::Der)).unwrap_or(
        false,
      )
    (Ed25519, Ed25519(pk)) => pk.verify(content, signature)
    // RFC 8446 §4.4.3: PKCS#1 v1.5 schemes MUST NOT appear in CertificateVerify.
    (RsaPkcs1Sha256, _) | (RsaPkcs1Sha384, _) | (RsaPkcs1Sha512, _) =>
      raise DisallowedScheme(scheme)
    // Recognised but not wired here (no P-521 / Ed448 public-key support in
    // pkix_verify), or an unknown code point.
    (EcdsaSecp521r1Sha512, _) | (Ed448, _) | (Unknown(_), _) =>
      raise UnsupportedScheme(scheme)
    // A supported scheme paired with the wrong certificate key type.
    _ => raise KeyMismatch(scheme)
  }
}
