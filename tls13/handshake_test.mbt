// TLS 1.3 handshake-layer tests. The Finished test is an end-to-end RFC 8448
// §3 conformance check: it reconstructs the handshake transcript from the RFC's
// ClientHello/ServerHello/EncryptedExtensions/Certificate/CertificateVerify
// bytes, runs the full key schedule, and confirms the server Finished MAC.

///|
fn hs_hexval(c : Char) -> Int {
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
fn hs_hex(s : String) -> Bytes {
  let n = s.length() / 2
  Bytes::makei(n, fn(i) {
    (hs_hexval(s.get_char(2 * i).unwrap()) * 16 +
    hs_hexval(s.get_char(2 * i + 1).unwrap())).to_byte()
  })
}

///|
fn hs_concat(parts : Array[Bytes]) -> Bytes {
  let total = parts.fold(init=0, fn(acc, b) { acc + b.length() })
  let out = FixedArray::make(total, b'\x00')
  let mut o = 0
  for b in parts {
    for i in 0..<b.length() {
      out[o + i] = b[i]
    }
    o = o + b.length()
  }
  Bytes::makei(total, fn(i) { out[i] })
}

// RFC 8448 §3 ClientHello and ServerHello handshake messages (record header
// stripped).

///|
let hs_client_hello : String = "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"

///|
let hs_server_hello : String = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"

// EncryptedExtensions || Certificate || CertificateVerify || Finished (the
// server's encrypted flight payload; same constant as the record-layer test).

///|
let hs_server_flight : String = "080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"

///|
test "RFC 8448 section 3 server Finished verifies end-to-end" {
  let suite = @tls13.CipherSuite::Aes128GcmSha256
  let h = suite.hash()
  let ch = hs_hex(hs_client_hello)
  let sh = hs_hex(hs_server_hello)
  let flight = hs_hex(hs_server_flight)

  // Split the server flight into {EE,Cert,CertVerify}=623?... actually walk it.
  let msgs = @tls13.parse_handshake_flight(flight)
  @debug.assert_eq(msgs.length(), 4)
  let (t_ee, _) = msgs[0]
  @debug.assert_eq(t_ee, @tls13.HandshakeType::EncryptedExtensions)
  let (t_fin, fin_body) = msgs[3]
  @debug.assert_eq(t_fin, @tls13.HandshakeType::Finished)

  // Re-run the key schedule to the server handshake traffic secret.
  let early = h.early_secret(b"")
  let ecdhe = hs_hex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d",
  )
  let handshake = h.handshake_secret(early, ecdhe)
  let th_ch_sh = h.transcript_hash(hs_concat([ch, sh]))
  let s_hs = h.server_handshake_traffic_secret(handshake, th_ch_sh)

  // Transcript for the server Finished = CH..CertificateVerify (everything in
  // the flight except the trailing Finished message itself).
  let cert_verify_end = flight.length() - (fin_body.length() + 4)
  let pre_finished = Bytes::makei(cert_verify_end, fn(i) { flight[i] })
  let transcript = h.transcript_hash(hs_concat([ch, sh, pre_finished]))

  // The recomputed verify_data matches the RFC server Finished MAC.
  @debug.assert_eq(
    @tls13.finished_mac(suite, s_hs, transcript),
    hs_hex("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"),
  )

  // build_finished reproduces the exact RFC Finished message...
  let built = @tls13.build_finished(suite, s_hs, transcript)
  @debug.assert_eq(
    built,
    hs_hex(
      "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718",
    ),
  )
  // ...and verify_finished accepts the RFC message.
  @debug.assert_eq(@tls13.verify_finished(suite, s_hs, transcript, built), true)

  // A one-bit change in the transcript must make verification fail.
  let bad_transcript = h.transcript_hash(hs_concat([ch, sh]))
  @debug.assert_eq(
    @tls13.verify_finished(suite, s_hs, bad_transcript, built),
    false,
  )
}

///|
test "handshake message framing round-trips" {
  let body = b"\x00\x01\x02\x03\x04\x05"
  let msg = @tls13.handshake_message(
    @tls13.HandshakeType::EncryptedExtensions,
    body,
  )
  // type(8) || uint24(6) || body
  @debug.assert_eq(msg[0], b'\x08')
  @debug.assert_eq(msg[1], b'\x00')
  @debug.assert_eq(msg[2], b'\x00')
  @debug.assert_eq(msg[3], b'\x06')
  let (t, parsed, consumed) = @tls13.parse_handshake(msg)
  @debug.assert_eq(t, @tls13.HandshakeType::EncryptedExtensions)
  @debug.assert_eq(parsed, body)
  @debug.assert_eq(consumed, msg.length())
}

///|
test "CertificateVerify signed content has the RFC 8446 framing" {
  let th = Bytes::makei(32, fn(i) { i.to_byte() })
  let content = @tls13.certificate_verify_content(
    @tls13.server_certificate_verify_context, th,
  )
  // 64 spaces || context(33 bytes) || 0x00 || 32-byte hash = 130 bytes.
  @debug.assert_eq(content.length(), 64 + 33 + 1 + 32)
  for i in 0..<64 {
    @debug.assert_eq(content[i], b'\x20')
  }
  @debug.assert_eq(content[64], b'\x54') // 'T'
  @debug.assert_eq(content[64 + 33], b'\x00') // separator
  @debug.assert_eq(content[64 + 33 + 1], b'\x00') // first transcript byte
  @debug.assert_eq(content[content.length() - 1], b'\x1f') // last transcript byte (31)
}
