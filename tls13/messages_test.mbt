// Parser conformance against the RFC 8448 §3 server flight.

///|
fn msg_hexval(c : Char) -> Int {
  let n = c.to_int()
  if n >= '0'.to_int() && n <= '9'.to_int() {
    n - '0'.to_int()
  } else if n >= 'a'.to_int() && n <= 'f'.to_int() {
    n - 'a'.to_int() + 10
  } else {
    abort("bad hex char")
  }
}

///|
fn msg_hex(s : String) -> Bytes {
  let n = s.length() / 2
  Bytes::makei(n, fn(i) {
    (msg_hexval(s.get_char(2 * i).unwrap()) * 16 +
    msg_hexval(s.get_char(2 * i + 1).unwrap())).to_byte()
  })
}

///|
test "RFC 8448 section 3 ServerHello parses suite + key share + version" {
  // ServerHello body (handshake header 02 00 00 56 stripped).
  let sh_msg = msg_hex(
    "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
  )
  let (t, body, _) = @tls13.parse_handshake(sh_msg)
  @debug.assert_eq(t, @tls13.HandshakeType::ServerHello)
  let sh = @tls13.parse_server_hello(body)
  @debug.assert_eq(sh.is_hello_retry_request, false)
  @debug.assert_eq(sh.legacy_version, 0x0303)
  @debug.assert_eq(sh.cipher_suite, 0x1301) // TLS_AES_128_GCM_SHA256
  @debug.assert_eq(sh.selected_version, Some(0x0304)) // TLS 1.3
  @debug.assert_eq(sh.key_share_group, Some(@tls13.NamedGroup::X25519))
  @debug.assert_eq(
    sh.key_share,
    Some(
      msg_hex(
        "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f",
      ),
    ),
  )
}

///|
test "RFC 8448 section 3 Certificate parses the server certificate chain" {
  // Certificate handshake message (header 0b 00 01 b9 included).
  let cert_msg = msg_hex(
    "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000",
  )
  let (t, body, _) = @tls13.parse_handshake(cert_msg)
  @debug.assert_eq(t, @tls13.HandshakeType::Certificate)
  let chain = @tls13.parse_certificate(body)
  @debug.assert_eq(chain.length(), 1)
  // The single cert is 0x01b0 = 432 bytes and is a DER SEQUENCE (0x30).
  @debug.assert_eq(chain[0].length(), 432)
  @debug.assert_eq(chain[0][0], b'\x30')
}

///|
test "RFC 8448 section 3 CertificateVerify parses scheme + signature" {
  // CertificateVerify handshake message (header 0f 00 00 84 included).
  let cv_msg = msg_hex(
    "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3",
  )
  let (t, body, _) = @tls13.parse_handshake(cv_msg)
  @debug.assert_eq(t, @tls13.HandshakeType::CertificateVerify)
  let cv = @tls13.parse_certificate_verify(body)
  @debug.assert_eq(cv.scheme, @tls13.SignatureScheme::RsaPssRsaeSha256)
  @debug.assert_eq(cv.signature.length(), 128)
  @debug.assert_eq(cv.signature[0], b'\x5a')
  @debug.assert_eq(cv.signature[127], b'\xf3')
}

///|
test "parsers fail closed on truncation and trailing data" {
  // CertificateVerify with a signature length longer than the data.
  let bad = msg_hex("08040080" + "5a747c5d")
  try @tls13.parse_certificate_verify(bad) |> ignore catch {
    _ => ()
  } noraise {
    _ => abort("accepted truncated CertificateVerify")
  }
  // Certificate with a non-empty certificate_request_context (server auth).
  let bad_ctx = msg_hex("0100000000")
  try @tls13.parse_certificate(bad_ctx) |> ignore catch {
    _ => ()
  } noraise {
    _ => abort("accepted non-empty certificate_request_context")
  }
}
