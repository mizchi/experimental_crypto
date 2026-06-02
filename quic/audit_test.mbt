// Adversarial / gray-box regressions for the quic module. The headline KATs
// live in quic_test.mbt; these pin the security-critical reject paths an
// attacker would probe: AAD (header) integrity, ciphertext integrity,
// truncation, and input-length validation. No exploitable bug was found; these
// lock the behaviour in.

///|
fn ahex(s : String) -> Bytes {
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
fn flip_last(b : Bytes) -> Bytes {
  Bytes::makei(b.length(), fn(i) {
    if i == b.length() - 1 {
      (b[i].to_int() ^ 0x01).to_byte()
    } else {
      b[i]
    }
  })
}

///|
test "QUIC open rejects a tampered header (AAD)" {
  let (client, _s) = @quic.initial_keys(ahex("8394c8f03e515708"))
  let header = ahex("c300000001088394c8f03e5157080000449e00000002")
  let ct = @quic.seal_payload(client, 1UL, header, b"crypto frame")
  // Flip one bit of the header used as AAD → tag must fail.
  let bad_header = flip_last(header)
  inspect(
    (try? @quic.open_payload(client, 1UL, bad_header, ct)) is Err(_),
    content="true",
  )
  // The unmodified header still opens.
  inspect(
    (try? @quic.open_payload(client, 1UL, header, ct)) is Err(_),
    content="false",
  )
}

///|
test "QUIC open rejects a tampered ciphertext / tag" {
  let (client, _s) = @quic.initial_keys(ahex("8394c8f03e515708"))
  let header = ahex("c30000000100")
  let ct = @quic.seal_payload(client, 7UL, header, b"payload bytes here")
  inspect(
    (try? @quic.open_payload(client, 7UL, header, flip_last(ct))) is Err(_),
    content="true",
  )
}

///|
test "QUIC open rejects a truncated record without crashing" {
  let (client, _s) = @quic.initial_keys(ahex("8394c8f03e515708"))
  // Shorter than the 16-byte GCM tag.
  let tiny = ahex("0011223344")
  inspect(
    (try? @quic.open_payload(client, 0UL, b"hdr", tiny)) is Err(_),
    content="true",
  )
}

///|
test "QUIC packet_nonce validates the IV length" {
  inspect(
    (try? @quic.packet_nonce(ahex("0011223344"), 1UL)) is Err(_),
    content="true",
  )
  inspect(
    (try? @quic.packet_nonce(ahex("000000000000000000000000"), 1UL)) is Err(_),
    content="false",
  )
}

///|
test "QUIC header_protection_mask validates the sample length" {
  let (client, _s) = @quic.initial_keys(ahex("8394c8f03e515708"))
  // 15-byte sample → reject (not a silent short read).
  inspect(
    (try? @quic.header_protection_mask(
      client.hp_bytes(),
      ahex("000102030405060708090a0b0c0d0e"),
    ))
    is Err(_),
    content="true",
  )
}

///|
test "QUIC distinct packet numbers give distinct nonces (reuse is caller's job)" {
  let (client, _s) = @quic.initial_keys(ahex("8394c8f03e515708"))
  let n1 = @quic.packet_nonce(client.iv_bytes(), 1UL)
  let n2 = @quic.packet_nonce(client.iv_bytes(), 2UL)
  // Different PNs must not collide (a collision under one key would be a
  // catastrophic GCM nonce reuse).
  let mut differ = false
  for i in 0..<12 {
    if n1[i] != n2[i] {
      differ = true
      break
    }
  }
  inspect(differ, content="true")
}
