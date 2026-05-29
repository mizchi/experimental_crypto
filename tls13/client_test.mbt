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
// Replace `src.length()` bytes of `b` starting at `start` with `src`.
fn cl_splice(b : Bytes, start : Int, src : Bytes) -> Bytes {
  Bytes::makei(b.length(), fn(i) {
    if i >= start && i < start + src.length() {
      src[i - start]
    } else {
      b[i]
    }
  })
}

///|
test "client_handshake_1rtt rejects ServerHello downgrade / version / suite attacks" {
  let suite = @tls13.CipherSuite::Aes128GcmSha256
  let ch = hs_hex(hs_client_hello)
  let sh = hs_hex(hs_server_hello)
  let flight = hs_hex(hs_server_flight)
  let ecdhe = hs_hex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d",
  )
  // In the SH message, random occupies bytes 6..38; supported_versions' value
  // is the final 2 bytes; cipher_suite is at bytes 39..41.

  // (1) RFC 8446 §4.1.3 downgrade sentinel "DOWNGRD\x01" in random -> rejected.
  let sh_downgrade = cl_splice(sh, 6 + 24, b"DOWNGRD\x01")
  try
    @tls13.client_handshake_1rtt(suite, ch, sh_downgrade, ecdhe, flight)
    |> ignore
  catch {
    DowngradeDetected => ()
    other => abort("expected DowngradeDetected, got " + repr(other))
  } noraise {
    _ => abort("accepted a downgrade-sentinel ServerHello")
  }

  // (2) supported_versions negotiates 0x0303 (TLS 1.2) instead of 0x0304.
  let sh_v12 = cl_splice(sh, sh.length() - 1, b"\x03")
  try
    @tls13.client_handshake_1rtt(suite, ch, sh_v12, ecdhe, flight) |> ignore
  catch {
    NotTls13(_) => ()
    other => abort("expected NotTls13, got " + repr(other))
  } noraise {
    _ => abort("accepted a non-TLS-1.3 ServerHello")
  }

  // (3) The driver is invoked with a suite different from the negotiated one.
  try
    @tls13.client_handshake_1rtt(
      @tls13.CipherSuite::Aes256GcmSha384,
      ch,
      sh,
      ecdhe,
      flight,
    )
    |> ignore
  catch {
    CipherSuiteMismatch(got) => @debug.assert_eq(got, 0x1301)
    other => abort("expected CipherSuiteMismatch, got " + repr(other))
  } noraise {
    _ => abort("accepted a cipher-suite mismatch")
  }

  // (4) HelloRetryRequest random must not be treated as a normal ServerHello.
  let sh_hrr = cl_splice(
    sh,
    6,
    hs_hex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"),
  )
  try
    @tls13.client_handshake_1rtt(suite, ch, sh_hrr, ecdhe, flight) |> ignore
  catch {
    HelloRetryRequestUnsupported => ()
    other => abort("expected HelloRetryRequestUnsupported, got " + repr(other))
  } noraise {
    _ => abort("accepted a HelloRetryRequest as a ServerHello")
  }
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

  // An all-zero ECDHE secret (small-order point / contributory failure,
  // RFC 7748 §6.1) is rejected up front, before any key derivation.
  let zero_ecdhe = Bytes::makei(32, fn(_) { b'\x00' })
  try
    @tls13.client_handshake_1rtt(suite, ch, sh, zero_ecdhe, flight) |> ignore
  catch {
    WeakSharedSecret => ()
    other => abort("expected WeakSharedSecret, got " + repr(other))
  } noraise {
    _ => abort("accepted an all-zero ECDHE secret")
  }

  // A merely wrong (non-zero) ECDHE secret desynchronises the server Finished
  // MAC -> ServerFinishedFailed.
  let wrong_ecdhe = Bytes::makei(32, fn(i) {
    if i == 0 {
      b'\x01'
    } else {
      b'\x00'
    }
  })
  try
    @tls13.client_handshake_1rtt(suite, ch, sh, wrong_ecdhe, flight) |> ignore
  catch {
    ServerFinishedFailed => ()
    other => abort("expected ServerFinishedFailed, got " + repr(other))
  } noraise {
    _ => abort("accepted a handshake with the wrong ECDHE secret")
  }
}
