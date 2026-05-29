// TLS 1.3 key-schedule conformance against RFC 8448 §3 "Simple 1-RTT
// Handshake" (cipher suite TLS_AES_128_GCM_SHA256). Every secret, traffic key,
// IV, and Finished key below is copied verbatim from the RFC trace.

///|
fn ks_hexval(c : Char) -> Int {
  let n = c.to_int()
  if n >= '0'.to_int() && n <= '9'.to_int() {
    n - '0'.to_int()
  } else if n >= 'a'.to_int() && n <= 'f'.to_int() {
    n - 'a'.to_int() + 10
  } else if n >= 'A'.to_int() && n <= 'F'.to_int() {
    n - 'A'.to_int() + 10
  } else {
    abort("bad hex char")
  }
}

///|
fn ks_hex(s : String) -> Bytes {
  let n = s.length() / 2
  Bytes::makei(n, fn(i) {
    (ks_hexval(s.get_char(2 * i).unwrap()) * 16 +
    ks_hexval(s.get_char(2 * i + 1).unwrap())).to_byte()
  })
}

///|
test "RFC 8448 section 3 SHA-256 key schedule" {
  let h = @tls13.Hash::Sha256

  // {server} extract secret "early": salt 0, IKM all-zero (no PSK).
  let early = h.early_secret(b"")
  @debug.assert_eq(
    early,
    ks_hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"),
  )

  // {server} extract secret "handshake": IKM is the X25519 ECDHE output.
  let ecdhe = ks_hex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d",
  )
  let handshake = h.handshake_secret(early, ecdhe)
  @debug.assert_eq(
    handshake,
    ks_hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"),
  )

  // Transcript-Hash(ClientHello .. ServerHello).
  let th_ch_sh = ks_hex(
    "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8",
  )
  let c_hs = h.client_handshake_traffic_secret(handshake, th_ch_sh)
  @debug.assert_eq(
    c_hs,
    ks_hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"),
  )
  let s_hs = h.server_handshake_traffic_secret(handshake, th_ch_sh)
  @debug.assert_eq(
    s_hs,
    ks_hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"),
  )

  // {server} extract secret "master".
  let master = h.master_secret(handshake)
  @debug.assert_eq(
    master,
    ks_hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"),
  )

  // Server handshake write key / IV (from s hs traffic) and Finished key.
  @debug.assert_eq(
    h.write_key(s_hs, 16),
    ks_hex("3fce516009c21727d0f2e4e86ee403bc"),
  )
  @debug.assert_eq(h.write_iv(s_hs), ks_hex("5d313eb2671276ee13000b30"))
  @debug.assert_eq(
    h.finished_key(s_hs),
    ks_hex("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"),
  )

  // Transcript-Hash(ClientHello .. server Finished) for the application secrets.
  let th_ch_sf = ks_hex(
    "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13",
  )
  let c_ap = h.client_application_traffic_secret(master, th_ch_sf)
  @debug.assert_eq(
    c_ap,
    ks_hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"),
  )
  let s_ap = h.server_application_traffic_secret(master, th_ch_sf)
  @debug.assert_eq(
    s_ap,
    ks_hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"),
  )
  @debug.assert_eq(
    h.exporter_master_secret(master, th_ch_sf),
    ks_hex("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50"),
  )

  // Server application write key / IV (from s ap traffic).
  @debug.assert_eq(
    h.write_key(s_ap, 16),
    ks_hex("9f02283b6c9c07efc26bb9f2ac92e356"),
  )
  @debug.assert_eq(h.write_iv(s_ap), ks_hex("cf782b88dd83549aadf1e984"))
}

///|
test "HKDF-Expand-Label / Derive-Secret primitives (RFC 8448 derived stage)" {
  let h = @tls13.Hash::Sha256
  // Derive-Secret(Early, "derived", "") feeds the handshake extract's salt.
  let early = ks_hex(
    "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
  )
  let derived = h.derive_secret(early, "derived", h.transcript_hash(b""))
  @debug.assert_eq(
    derived,
    ks_hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"),
  )
  // The empty-string transcript hash used above is SHA-256("").
  @debug.assert_eq(
    h.transcript_hash(b""),
    ks_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
  )
}
