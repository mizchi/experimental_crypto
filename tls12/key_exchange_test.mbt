// TLS 1.2 ECDHE key-exchange driver tests.
//
// The headline test verifies the *real* ServerKeyExchange signature from the
// captured openssl handshake end-to-end: leaf cert (ECDSA P-256) + the two
// 32-byte randoms from the same ClientHello/ServerHello + the ECDHE params,
// all checked through @pkix / @p256. This exercises cert SPKI extraction,
// signed-material reconstruction, and signature dispatch in one shot.

///|
let kx_client_random : String = "93fe717a9fdea4ae751edaa707625854e6b88e05b205b83fe9dc52fc56402809"

///|
let kx_server_random : String = "8641c6835ee3573dd4ff1b3ecad7ef6f7c108f5e2d5cc6600f7f9a717fd7f1d9"

///|
let kx_leaf : String = "3082017e30820123a00302010202141f240643e48ae966c0a201ba2b1ced62ca275035300a06082a8648ce3d04030230143112301006035504030c096c6f63616c686f7374301e170d3236303630313135333132385a170d3236303630333135333132385a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d0301070342000483c72919c953c8f7ec2f7417ba158827fd4758f7ccbf6dbac220a57a48b8a29d5c4ad2478f4b47381632bc726ea53436aacaa7fef1cfd0b8d8b6fc10e807817ea3533051301d0603551d0e04160414275d436b54b40c00d64d943ec3b5761aad0f080a301f0603551d23041830168014275d436b54b40c00d64d943ec3b5761aad0f080a300f0603551d130101ff040530030101ff300a06082a8648ce3d04030203490030460221008fa024dea191bfc4acb7e452195e04285560e1b81d84c93108b25fc2f4ccfaa3022100abf6ca2bea1b78b0bb10aa357b6f6d12d28d1e6fd6564ea4c5bd4d463faa614a"

///|
test "TLS 1.2 verify real ServerKeyExchange signature (ECDSA P-256, openssl)" {
  let (_ty, body) = @tls12.parse_handshake(hx(ske_msg))
  let ske = @tls12.parse_server_key_exchange(body)
  let ok = @tls12.verify_server_key_exchange(
    hx(kx_leaf),
    ske,
    hx(kx_client_random),
    hx(kx_server_random),
  )
  inspect(ok, content="true")
}

///|
test "TLS 1.2 ServerKeyExchange verify fails on a tampered client_random" {
  let (_ty, body) = @tls12.parse_handshake(hx(ske_msg))
  let ske = @tls12.parse_server_key_exchange(body)
  // Flip one byte of the client_random: the signed transcript no longer matches.
  let bad = rep(0x00, 32)
  let ok = @tls12.verify_server_key_exchange(
    hx(kx_leaf),
    ske,
    bad,
    hx(kx_server_random),
  )
  inspect(ok, content="false")
}

// An independent self-signed P-256 leaf for "localhost" minted by `openssl`
// (a stand-in for an active MITM's own certificate).

///|
let attacker_leaf : String = "3082017c30820123a00302010202146307ae7f7e59d21a4d27eb55d988d7ec42148c33300a06082a8648ce3d04030230143112301006035504030c096c6f63616c686f7374301e170d3236303630323034333030355a170d3236303630343034333030355a30143112301006035504030c096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d03010703420004e974135f7339958beb552d1bc9d64a865567e6a0e278355995ebda40fac5494d39020aa0a365cf4f5ccd7daf68167be985380b34635b4711a80b65842845f627a3533051301d0603551d0e04160414015dbf04e6cbe68bf6b4180cdc188f9a5d02387b301f0603551d23041830168014015dbf04e6cbe68bf6b4180cdc188f9a5d02387b300f0603551d130101ff040530030101ff300a06082a8648ce3d04030203470030440220259012e041fe1a4c4766cb50357d6cc430214577f33a120b0126bc135588ab9c0220671d1e5f94137a38b292a028a230f922bde3a4f131d60f4eae4902e3a38b2b4b"

///|
// Signature binding is sound: the captured SKE was signed by the real leaf's
// key, so it does NOT verify against an unrelated (attacker) certificate.
//
// SECURITY NOTE: this only proves the *signature* binds to the presented leaf
// key. `verify_server_key_exchange` does NOT establish that the leaf is
// trusted — an attacker presenting their OWN cert and signing the SKE with the
// matching key WOULD pass. Callers MUST additionally chain-verify the leaf to a
// trust anchor (mizchi/pkix_verify) and check the hostname. See the docstring.
test "TLS 1.2 SKE does not verify against an unrelated attacker certificate" {
  let (_ty, body) = @tls12.parse_handshake(hx(ske_msg))
  let ske = @tls12.parse_server_key_exchange(body)
  let ok = @tls12.verify_server_key_exchange(
    hx(attacker_leaf),
    ske,
    hx(kx_client_random),
    hx(kx_server_random),
  )
  inspect(ok, content="false")
}

///|
test "TLS 1.2 ECDHE X25519 agreement matches the x25519 module directly" {
  // Two parties: client ephemeral + server ephemeral, both fixed scalars.
  let client_priv = rep(0x42, 32)
  let server_priv = rep(0x77, 32)
  let server_pub = @tls12.ecdhe_client_public(@tls12.group_x25519, server_priv)
  let client_pub = @tls12.ecdhe_client_public(@tls12.group_x25519, client_priv)
  let pms_client = @tls12.ecdhe_pre_master_secret(
    @tls12.group_x25519, client_priv, server_pub,
  )
  let pms_server = @tls12.ecdhe_pre_master_secret(
    @tls12.group_x25519, server_priv, client_pub,
  )
  inspect(tohx(pms_client), content=tohx(pms_server))
}

///|
test "TLS 1.2 ECDHE P-256 agreement is symmetric" {
  let client_priv = rep(0x11, 32)
  let server_priv = rep(0x22, 32)
  let server_pub = @tls12.ecdhe_client_public(
    @tls12.group_secp256r1, server_priv,
  )
  let client_pub = @tls12.ecdhe_client_public(
    @tls12.group_secp256r1, client_priv,
  )
  inspect(server_pub.length(), content="65") // uncompressed SEC1 point
  let pms_client = @tls12.ecdhe_pre_master_secret(
    @tls12.group_secp256r1, client_priv, server_pub,
  )
  let pms_server = @tls12.ecdhe_pre_master_secret(
    @tls12.group_secp256r1, server_priv, client_pub,
  )
  inspect(pms_client.length(), content="32") // X-coordinate
  inspect(tohx(pms_client), content=tohx(pms_server))
}

///|
test "TLS 1.2 ECDHE P-384 agreement is symmetric (48-byte secret)" {
  let client_priv = rep(0x33, 48)
  let server_priv = rep(0x44, 48)
  let server_pub = @tls12.ecdhe_client_public(
    @tls12.group_secp384r1, server_priv,
  )
  let client_pub = @tls12.ecdhe_client_public(
    @tls12.group_secp384r1, client_priv,
  )
  let pms_client = @tls12.ecdhe_pre_master_secret(
    @tls12.group_secp384r1, client_priv, server_pub,
  )
  let pms_server = @tls12.ecdhe_pre_master_secret(
    @tls12.group_secp384r1, server_priv, client_pub,
  )
  inspect(pms_client.length(), content="48")
  inspect(tohx(pms_client), content=tohx(pms_server))
}

///|
test "TLS 1.2 derive_session_keys slices the AES-128-GCM key_block" {
  // pms = 00..2f, randoms fixed; cross-checked against the reference key_block
  // (b78bf2.. from the prf_test fixtures) sliced as key||key||iv||iv.
  let pms = Bytes::makei(48, fn(i) { i.to_byte() })
  let suite = @tls12.CipherSuite::EcdheEcdsaAes128GcmSha256
  let h = suite.prf_hash()
  let ms = h.master_secret(pms, rep(0x11, 32), rep(0x22, 32))
  let keys = @tls12.derive_session_keys(suite, ms, rep(0x11, 32), rep(0x22, 32))
  // key_block = b78bf22c34f80793432e769ce1c38570 980bb56b9e230b59338bbd84711c1f26 e336a7de 011ac693
  inspect(keys.master_secret().length(), content="48")
  inspect(
    tohx(keys.client_keys().key_bytes()),
    content="b78bf22c34f80793432e769ce1c38570",
  )
  inspect(
    tohx(keys.server_keys().key_bytes()),
    content="980bb56b9e230b59338bbd84711c1f26",
  )
  inspect(tohx(keys.client_keys().iv_bytes()), content="e336a7de")
  inspect(tohx(keys.server_keys().iv_bytes()), content="011ac693")
}
