// End-to-end client-driver conformance against RFC 8448 §3: run the full 1-RTT
// client handshake over the RFC's ClientHello/ServerHello, ECDHE secret, and
// decrypted server flight, and confirm the negotiated keys, the server
// certificate chain, and the client Finished all match the trace.

///|
test "RFC 8448 section 3 client_handshake_1rtt end-to-end" {
  let suite = @tls13.CipherSuite::Aes128GcmSha256
  let ch = hs_hex(hs_client_hello)
  let sh = hs_hex(hs_server_hello)
  let flight = hs_hex(hs_server_flight)
  let ecdhe = hs_hex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d",
  )
  let result = @tls13.client_handshake_1rtt(suite, ch, sh, ecdhe, flight)

  // Server authentication succeeded, and the cert chain is the RFC leaf.
  @debug.assert_eq(result.server_certificates.length(), 1)
  @debug.assert_eq(result.server_certificates[0].length(), 432)

  // Negotiated keys match RFC 8448 §3.
  let k = result.keys
  @debug.assert_eq(
    k.server_handshake_key,
    hs_hex("3fce516009c21727d0f2e4e86ee403bc"),
  )
  @debug.assert_eq(k.server_handshake_iv, hs_hex("5d313eb2671276ee13000b30"))
  @debug.assert_eq(
    k.server_application_key,
    hs_hex("9f02283b6c9c07efc26bb9f2ac92e356"),
  )
  @debug.assert_eq(k.server_application_iv, hs_hex("cf782b88dd83549aadf1e984"))
  @debug.assert_eq(
    k.client_application_key,
    hs_hex("17422dda596ed5d9acd890e3c63f5051"),
  )
  @debug.assert_eq(k.client_application_iv, hs_hex("5b78923dee08579033e523d9"))

  // The client Finished message to send matches the RFC trace.
  @debug.assert_eq(
    result.client_finished,
    hs_hex(
      "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61",
    ),
  )
}

///|
test "client_handshake_1rtt fails closed on a tampered server flight" {
  let suite = @tls13.CipherSuite::Aes128GcmSha256
  let ch = hs_hex(hs_client_hello)
  let sh = hs_hex(hs_server_hello)
  let flight = hs_hex(hs_server_flight)
  let ecdhe = hs_hex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d",
  )

  // Flip a byte inside the CertificateVerify signature region (near the end of
  // the flight, before the 36-byte Finished). This breaks the server's
  // signature over the transcript -> CertificateVerifyFailed.
  let cv_byte = flight.length() - 36 - 10
  let tampered = Bytes::makei(flight.length(), fn(i) {
    if i == cv_byte {
      (flight[i].to_int() ^ 0x01).to_byte()
    } else {
      flight[i]
    }
  })
  try
    @tls13.client_handshake_1rtt(suite, ch, sh, ecdhe, tampered) |> ignore
  catch {
    CertificateVerifyFailed => ()
    other => abort("expected CertificateVerifyFailed, got " + repr(other))
  } noraise {
    _ => abort("accepted a tampered CertificateVerify")
  }

  // A wrong ECDHE secret leaves CertificateVerify intact (it does not depend on
  // it) but desynchronises the server Finished MAC -> ServerFinishedFailed.
  let wrong_ecdhe = Bytes::makei(32, fn(_) { b'\x00' })
  try
    @tls13.client_handshake_1rtt(suite, ch, sh, wrong_ecdhe, flight) |> ignore
  catch {
    ServerFinishedFailed => ()
    other => abort("expected ServerFinishedFailed, got " + repr(other))
  } noraise {
    _ => abort("accepted a handshake with the wrong ECDHE secret")
  }
}
