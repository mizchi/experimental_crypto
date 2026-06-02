// QUIC v1 crypto tests against RFC 9001 Appendix A.
// (Derivation values reproduced independently; the HP mask cross-checked with
// Node AES-128-ECB on the A.2 sample.)

///|
fn qhex(s : String) -> Bytes {
  fn nib(c : Char) -> Int {
    let n = c.to_int()
    if n >= 0x30 && n <= 0x39 {
      n - 0x30
    } else if n >= 0x61 && n <= 0x66 {
      n - 0x61 + 10
    } else {
      abort("bad hex")
    }
  }

  let len = s.length() / 2
  let out = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = ((nib(s.get_char(i * 2).unwrap()) << 4) |
    nib(s.get_char(i * 2 + 1).unwrap())).to_byte()
  }
  Bytes::makei(len, fn(j) { out[j] })
}

///|
fn qtohex(b : Bytes) -> String {
  let d = "0123456789abcdef"
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_char(d.get_char(v >> 4).unwrap())
    sb.write_char(d.get_char(v & 0xf).unwrap())
  }
  sb.to_string()
}

///|
test "QUIC v1 Initial key derivation (RFC 9001 A.1)" {
  // Client Destination Connection ID from Appendix A.1.
  let (client, server) = @quic.initial_keys(qhex("8394c8f03e515708"))
  // Client
  inspect(
    qtohex(client.secret_bytes()),
    content="c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
  )
  inspect(
    qtohex(client.key_bytes()),
    content="1f369613dd76d5467730efcbe3b1a22d",
  )
  inspect(qtohex(client.iv_bytes()), content="fa044b2f42a3fd3b46fb255c")
  inspect(qtohex(client.hp_bytes()), content="9f50449e04a0e810283a1e9933adedd2")
  // Server
  inspect(
    qtohex(server.secret_bytes()),
    content="3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
  )
  inspect(
    qtohex(server.key_bytes()),
    content="cf3a5331653c364c88f0f379b6067e37",
  )
  inspect(qtohex(server.iv_bytes()), content="0ac1493ca1905853b0bba03e")
  inspect(qtohex(server.hp_bytes()), content="c206b8d9b9f0f37644430b490eeaa314")
}

///|
test "QUIC header-protection mask (RFC 9001 A.2 sample)" {
  let (client, _server) = @quic.initial_keys(qhex("8394c8f03e515708"))
  let sample = qhex("d1b1c98dd7689fb8ec11d242b123dc9b")
  let mask = @quic.header_protection_mask(client.hp_bytes(), sample)
  inspect(qtohex(mask), content="437b9aec36")
}

///|
test "QUIC packet nonce = iv XOR right-aligned packet number" {
  let (client, _s) = @quic.initial_keys(qhex("8394c8f03e515708"))
  // iv = fa044b2f42a3fd3b46fb255c ; packet number 2 → XOR into the last byte.
  inspect(
    qtohex(@quic.packet_nonce(client.iv_bytes(), 2UL)),
    content="fa044b2f42a3fd3b46fb255e",
  )
  // packet number 0 leaves the iv unchanged.
  inspect(
    qtohex(@quic.packet_nonce(client.iv_bytes(), 0UL)),
    content="fa044b2f42a3fd3b46fb255c",
  )
}

///|
test "QUIC AEAD seal/open round trip" {
  let (client, _s) = @quic.initial_keys(qhex("8394c8f03e515708"))
  let header = qhex("c300000001088394c8f03e5157080000449e00000002")
  let payload = b"quic initial crypto frame payload"
  let sealed_pkt = @quic.seal_payload(client, 2UL, header, payload)
  let opened = @quic.open_payload(client, 2UL, header, sealed_pkt)
  inspect(qtohex(opened), content=qtohex(payload))
  // Wrong packet number → nonce mismatch → AEAD tag fails.
  let mut rejected = false
  let _ = @quic.open_payload(client, 3UL, header, sealed_pkt) catch {
    _ => {
      rejected = true
      b""
    }
  }
  inspect(rejected, content="true")
}
