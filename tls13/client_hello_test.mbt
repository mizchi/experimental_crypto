// ClientHello builder round-trip and structural checks.

///|
test "build_client_hello round-trips through parse_client_hello" {
  let random = Bytes::makei(32, fn(i) { i.to_byte() })
  let session_id = Bytes::makei(32, fn(i) { (0xa0 + i).to_byte() })
  let x25519_pub = Bytes::makei(32, fn(i) { (0x10 + i).to_byte() })
  let p256_pub = Bytes::makei(65, fn(i) {
    if i == 0 {
      b'\x04'
    } else {
      i.to_byte()
    }
  })
  let msg = @tls13.build_client_hello(
    random,
    session_id,
    [
      @tls13.CipherSuite::Aes128GcmSha256,
      @tls13.CipherSuite::ChaCha20Poly1305Sha256,
    ],
    [@tls13.NamedGroup::X25519, @tls13.NamedGroup::Secp256r1],
    [
      { group: @tls13.NamedGroup::X25519, key_exchange: x25519_pub },
      { group: @tls13.NamedGroup::Secp256r1, key_exchange: p256_pub },
    ],
    [
      @tls13.SignatureScheme::EcdsaSecp256r1Sha256,
      @tls13.SignatureScheme::RsaPssRsaeSha256,
      @tls13.SignatureScheme::Ed25519,
    ],
    server_name=Some("example.com"),
  )

  // Frames as a ClientHello handshake message.
  let (t, body, consumed) = @tls13.parse_handshake(msg)
  @debug.assert_eq(t, @tls13.HandshakeType::ClientHello)
  @debug.assert_eq(consumed, msg.length())

  let ch = @tls13.parse_client_hello(body)
  @debug.assert_eq(ch.legacy_version, 0x0303)
  @debug.assert_eq(ch.random, random)
  @debug.assert_eq(ch.legacy_session_id, session_id)
  @debug.assert_eq(ch.cipher_suites, [0x1301, 0x1303])
  @debug.assert_eq(ch.supported_versions, [0x0304])
  @debug.assert_eq(ch.key_shares.length(), 2)
  @debug.assert_eq(ch.key_shares[0].group, @tls13.NamedGroup::X25519)
  @debug.assert_eq(ch.key_shares[0].key_exchange, x25519_pub)
  @debug.assert_eq(ch.key_shares[1].group, @tls13.NamedGroup::Secp256r1)
  @debug.assert_eq(ch.key_shares[1].key_exchange, p256_pub)
}

///|
test "build_client_hello without SNI and with empty session id" {
  let random = Bytes::makei(32, fn(_) { b'\x07' })
  let x25519_pub = Bytes::makei(32, fn(i) { i.to_byte() })
  let msg = @tls13.build_client_hello(
    random,
    b"",
    [@tls13.CipherSuite::Aes128GcmSha256],
    [@tls13.NamedGroup::X25519],
    [{ group: @tls13.NamedGroup::X25519, key_exchange: x25519_pub }],
    [@tls13.SignatureScheme::EcdsaSecp256r1Sha256],
  )
  let (_, body, _) = @tls13.parse_handshake(msg)
  let ch = @tls13.parse_client_hello(body)
  @debug.assert_eq(ch.legacy_session_id, b"")
  @debug.assert_eq(ch.cipher_suites, [0x1301])
  @debug.assert_eq(ch.supported_versions, [0x0304])
  @debug.assert_eq(ch.key_shares.length(), 1)
}

///|
test "build_client_hello rejects a bad random length" {
  try
    @tls13.build_client_hello(
      b"\x00\x01\x02",
      b"",
      [@tls13.CipherSuite::Aes128GcmSha256],
      [@tls13.NamedGroup::X25519],
      [{ group: @tls13.NamedGroup::X25519, key_exchange: b"\x00" }],
      [@tls13.SignatureScheme::EcdsaSecp256r1Sha256],
    )
    |> ignore
  catch {
    Malformed(_) => ()
    other => abort("expected Malformed, got " + repr(other))
  } noraise {
    _ => abort("accepted a non-32-byte random")
  }
}
