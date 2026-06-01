// TLS 1.2 handshake-message tests. The server-sent messages are real wire
// bytes captured from `openssl s_server -tls1_2 -cipher
// ECDHE-ECDSA-AES128-GCM-SHA256` (a P-256/ECDSA leaf, X25519 ECDHE group), so
// the parsers are pinned against a genuine OpenSSL handshake.

// Captured ServerHello (includes the 4-byte handshake header).

///|
let sh_msg : String = "0200003d03038641c6835ee3573dd4ff1b3ecad7ef6f7c108f5e2d5cc6600f7f9a717fd7f1d900c02b000015ff01000100000b0004030001020023000000170000"

// Captured Certificate message.

///|
let cert_msg : String = "0b0001880001850001823082017e30820123a00302010202141f240643e48ae966c0a201ba2b1ced62ca275035300a06082a8648ce3d04030230143112301006035504030c096c6f63616c686f7374301e170d3236303630313135333132385a170d3236303630333135333132385a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d0301070342000483c72919c953c8f7ec2f7417ba158827fd4758f7ccbf6dbac220a57a48b8a29d5c4ad2478f4b47381632bc726ea53436aacaa7fef1cfd0b8d8b6fc10e807817ea3533051301d0603551d0e04160414275d436b54b40c00d64d943ec3b5761aad0f080a301f0603551d23041830168014275d436b54b40c00d64d943ec3b5761aad0f080a300f0603551d130101ff040530030101ff300a06082a8648ce3d04030203490030460221008fa024dea191bfc4acb7e452195e04285560e1b81d84c93108b25fc2f4ccfaa3022100abf6ca2bea1b78b0bb10aa357b6f6d12d28d1e6fd6564ea4c5bd4d463faa614a"

// Captured ServerKeyExchange message.

///|
let ske_msg : String = "0c00006e03001d2049b001528753ecb2309104d50956bdc2b9092d642d7b478563e8350d9b5dd05e040300463044022061242c1429c9547f64f92c519594005b83599a3eda3a9ab2e846161cb4c95023022063e1fa1ad2a36e492fa86e62d91901477db0f9b7f5cc1f2cbf41482b3a5a4276"

///|
test "TLS 1.2 parse real ServerHello (openssl)" {
  let (ty, body) = @tls12.parse_handshake(hx(sh_msg))
  inspect(ty.to_int(), content="2") // ServerHello
  let sh = @tls12.parse_server_hello(body)
  inspect(sh.cipher_suite().to_u16(), content="49195") // 0xc02b
  inspect(sh.random().length(), content="32")
  inspect(
    tohx(sh.random()),
    content="8641c6835ee3573dd4ff1b3ecad7ef6f7c108f5e2d5cc6600f7f9a717fd7f1d9",
  )
}

///|
test "TLS 1.2 parse real Certificate (openssl): single leaf, valid DER prefix" {
  let (ty, body) = @tls12.parse_handshake(hx(cert_msg))
  inspect(ty.to_int(), content="11") // Certificate
  let certs = @tls12.parse_certificate(body)
  inspect(certs.length(), content="1")
  // Leaf is a DER SEQUENCE (0x30 0x82) of declared length 0x017e.
  let leaf = certs[0]
  inspect(leaf.length(), content="386") // 0x182
  inspect(leaf[0].to_int(), content="48") // 0x30 SEQUENCE
  inspect(leaf[1].to_int(), content="130") // 0x82 long-form length
}

///|
test "TLS 1.2 parse real ServerKeyExchange (openssl): X25519 ECDHE + ECDSA sig" {
  let (ty, body) = @tls12.parse_handshake(hx(ske_msg))
  inspect(ty.to_int(), content="12") // ServerKeyExchange
  let ske = @tls12.parse_server_key_exchange(body)
  inspect(ske.named_group(), content="29") // 0x001d X25519
  inspect(ske.public_key().length(), content="32")
  inspect(
    tohx(ske.public_key()),
    content="49b001528753ecb2309104d50956bdc2b9092d642d7b478563e8350d9b5dd05e",
  )
  inspect(ske.sig_scheme(), content="1027") // 0x0403 ecdsa_secp256r1_sha256
  inspect(ske.signature().length(), content="70") // 0x46 DER ECDSA sig
  inspect(ske.signature()[0].to_int(), content="48") // 0x30 SEQUENCE
}

///|
test "TLS 1.2 ServerKeyExchange signed_material layout" {
  let (_ty, body) = @tls12.parse_handshake(hx(ske_msg))
  let ske = @tls12.parse_server_key_exchange(body)
  let cr = rep(0x11, 32)
  let sr = rep(0x22, 32)
  let signed = ske.signed_material(cr, sr)
  // client_random(32) || server_random(32) || ServerECDHParams(1+2+1+32 = 36)
  inspect(signed.length(), content="100")
  // ServerECDHParams begins with curve_type=3, group=0x001d, pklen=0x20.
  inspect(signed[64].to_int(), content="3")
  inspect(signed[65].to_int(), content="0")
  inspect(signed[66].to_int(), content="29")
  inspect(signed[67].to_int(), content="32")
}

///|
test "TLS 1.2 ServerHelloDone must be empty" {
  let (ty, body) = @tls12.parse_handshake(hx("0e000000"))
  inspect(ty.to_int(), content="14")
  @tls12.parse_server_hello_done(body)
  inspect(body.length(), content="0")
}

///|
test "TLS 1.2 ClientHello build round-trips through the framing" {
  let cr = rep(0xaa, 32)
  let body = @tls12.build_client_hello(
    cr,
    [
      @tls12.CipherSuite::EcdheEcdsaAes128GcmSha256,
      @tls12.CipherSuite::EcdheRsaAes128GcmSha256,
    ],
    [@tls12.group_x25519, @tls12.group_secp256r1],
    "localhost",
  )
  let framed = @tls12.handshake_message(@tls12.HandshakeType::ClientHello, body)
  let (ty, body2) = @tls12.parse_handshake(framed)
  inspect(ty.to_int(), content="1")
  // version 0x0303 then the 32-byte client_random.
  inspect(body2[0].to_int(), content="3")
  inspect(body2[1].to_int(), content="3")
  inspect(
    tohx(Bytes::makei(32, fn(i) { body2[2 + i] })),
    content="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  )
}

///|
test "TLS 1.2 ClientKeyExchange build frames the ECPoint with a 1-byte length" {
  let pk = rep(0x07, 32)
  let cke = @tls12.build_client_key_exchange(pk)
  inspect(cke.length(), content="33")
  inspect(cke[0].to_int(), content="32") // ECPoint length
  inspect(cke[1].to_int(), content="7")
}
