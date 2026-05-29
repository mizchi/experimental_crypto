// Server-authentication conformance against RFC 8448 §3: verify the server's
// CertificateVerify (rsa_pss_rsae_sha256 over a 1024-bit RSA leaf) against the
// reconstructed transcript. Reuses the hex helpers / flight constants defined
// in handshake_test.mbt (same blackbox test package).

///|
test "RFC 8448 section 3 server CertificateVerify authenticates" {
  let h = @tls13.CipherSuite::Aes128GcmSha256.hash()
  let ch = hs_hex(hs_client_hello)
  let sh = hs_hex(hs_server_hello)
  let flight = hs_hex(hs_server_flight)
  let msgs = @tls13.parse_handshake_flight(flight)
  @debug.assert_eq(msgs.length(), 4)
  let (_, ee_body) = msgs[0]
  let (t_cert, cert_body) = msgs[1]
  let (t_cv, cv_body) = msgs[2]
  @debug.assert_eq(t_cert, @tls13.HandshakeType::Certificate)
  @debug.assert_eq(t_cv, @tls13.HandshakeType::CertificateVerify)
  let leaf = @tls13.parse_certificate(cert_body)[0]
  let cv = @tls13.parse_certificate_verify(cv_body)

  // CertificateVerify covers Transcript-Hash(ClientHello .. Certificate).
  let cv_start = 4 + ee_body.length() + (4 + cert_body.length())
  let pre_cv = Bytes::makei(cv_start, fn(i) { flight[i] })
  let transcript = h.transcript_hash(hs_concat([ch, sh, pre_cv]))

  // The server's signature authenticates against the leaf key.
  @debug.assert_eq(
    @tls13.verify_server_certificate_verify(leaf, cv, transcript),
    true,
  )

  // A different transcript (e.g. a tampered handshake) must not authenticate.
  @debug.assert_eq(
    @tls13.verify_server_certificate_verify(leaf, cv, h.transcript_hash(b"x")),
    false,
  )
}

///|
test "CertificateVerify dispatch rejects PKCS#1 v1.5 and key mismatches" {
  let h = @tls13.CipherSuite::Aes128GcmSha256.hash()
  let ch = hs_hex(hs_client_hello)
  let sh = hs_hex(hs_server_hello)
  let flight = hs_hex(hs_server_flight)
  let msgs = @tls13.parse_handshake_flight(flight)
  let (_, ee_body) = msgs[0]
  let (_, cert_body) = msgs[1]
  let leaf = @tls13.parse_certificate(cert_body)[0]
  let cv_start = 4 + ee_body.length() + (4 + cert_body.length())
  let pre_cv = Bytes::makei(cv_start, fn(i) { flight[i] })
  let transcript = h.transcript_hash(hs_concat([ch, sh, pre_cv]))

  // RFC 8446 §4.4.3 forbids PKCS#1 v1.5 in CertificateVerify; reusing the real
  // signature bytes under a PKCS1 scheme must be refused, not just return false.
  let (_, cv_body) = msgs[2]
  let real_cv = @tls13.parse_certificate_verify(cv_body)
  let pkcs1_cv : @tls13.CertificateVerify = {
    scheme: @tls13.SignatureScheme::RsaPkcs1Sha256,
    signature: real_cv.signature,
  }
  try
    @tls13.verify_server_certificate_verify(leaf, pkcs1_cv, transcript)
    |> ignore
  catch {
    DisallowedScheme(_) => ()
    other => abort("expected DisallowedScheme, got " + repr(other))
  } noraise {
    _ => abort("accepted a PKCS#1 v1.5 CertificateVerify")
  }

  // An ECDSA scheme against the RSA leaf key is a key/scheme mismatch.
  let ecdsa_cv : @tls13.CertificateVerify = {
    scheme: @tls13.SignatureScheme::EcdsaSecp256r1Sha256,
    signature: real_cv.signature,
  }
  try
    @tls13.verify_server_certificate_verify(leaf, ecdsa_cv, transcript)
    |> ignore
  catch {
    KeyMismatch(_) => ()
    other => abort("expected KeyMismatch, got " + repr(other))
  } noraise {
    _ => abort("accepted an ECDSA scheme against an RSA certificate")
  }
}
