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

///|
test "hostname_matches_san: exact, wildcard, and rejections (RFC 6125)" {
  // Exact, case-insensitive.
  @debug.assert_eq(
    @tls13.hostname_matches_san("example.com", "example.com"),
    true,
  )
  @debug.assert_eq(
    @tls13.hostname_matches_san("EXAMPLE.com", "example.COM"),
    true,
  )
  @debug.assert_eq(
    @tls13.hostname_matches_san("example.com", "example.org"),
    false,
  )
  // Left-most wildcard matches exactly one label.
  @debug.assert_eq(
    @tls13.hostname_matches_san("a.example.com", "*.example.com"),
    true,
  )
  @debug.assert_eq(
    @tls13.hostname_matches_san("WWW.Example.com", "*.example.com"),
    true,
  )
  // ...but NOT zero labels, NOT multiple labels.
  @debug.assert_eq(
    @tls13.hostname_matches_san("example.com", "*.example.com"),
    false,
  )
  @debug.assert_eq(
    @tls13.hostname_matches_san("a.b.example.com", "*.example.com"),
    false,
  )
  // Partial-label wildcards and bare/over-broad wildcards are rejected.
  @debug.assert_eq(
    @tls13.hostname_matches_san("foo.example.com", "f*.example.com"),
    false,
  )
  @debug.assert_eq(@tls13.hostname_matches_san("example.com", "*.com"), false)
  @debug.assert_eq(@tls13.hostname_matches_san("anything", "*"), false)
  @debug.assert_eq(@tls13.hostname_matches_san("", "example.com"), false)
  @debug.assert_eq(@tls13.hostname_matches_san("example.com", ""), false)
}

///|
test "client_handshake_1rtt_verified rejects an untrusted chain" {
  let suite = @tls13.CipherSuite::Aes128GcmSha256
  let ch = hs_hex(hs_client_hello)
  let sh = hs_hex(hs_server_hello)
  let flight = hs_hex(hs_server_flight)
  let ecdhe = hs_hex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d",
  )
  // The RFC 8448 leaf is a self-signed end-entity (cA=false) and chains to no
  // CA. Use it (parsed) as the trust anchor: the handshake auth succeeds, but
  // chain validation rejects it (the anchor is not a CA / no valid path).
  let leaf_der = hs_hex(
    "308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de1",
  )
  let anchor = @pkix.parse_certificate(leaf_der)
  try
    @tls13.client_handshake_1rtt_verified(
      suite, ch, sh, ecdhe, flight, anchor, "20240101000000Z", "rsa",
    )
    |> ignore
  catch {
    ChainUntrusted(_) => ()
    other => abort("expected ChainUntrusted, got " + repr(other))
  } noraise {
    _ => abort("turnkey accepted an untrusted certificate chain")
  }
}
