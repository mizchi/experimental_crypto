// ECH tests: build an ECHConfigList around a known X25519 recipient key, parse
// it, and HPKE seal→open a payload (the round trip proves the parsed fields +
// the "tls ech" info are consistent between sender and receiver).

///|
fn cat(parts : Array[Bytes]) -> Bytes {
  let mut n = 0
  for p in parts {
    n += p.length()
  }
  let out = FixedArray::make(n, b'\x00')
  let mut o = 0
  for p in parts {
    for i in 0..<p.length() {
      out[o + i] = p[i]
    }
    o += p.length()
  }
  Bytes::makei(n, fn(i) { out[i] })
}

///|
fn u16(v : Int) -> Bytes {
  Bytes::makei(2, fn(i) {
    if i == 0 {
      (v >> 8).to_byte()
    } else {
      (v & 0xff).to_byte()
    }
  })
}

///|
fn u8b(v : Int) -> Bytes {
  Bytes::makei(1, fn(_i) { (v & 0xff).to_byte() })
}

///|
fn ascii(s : String) -> Bytes {
  Bytes::makei(s.length(), fn(i) {
    (s.get_char(i).unwrap().to_int() & 0xff).to_byte()
  })
}

///|
// Build a single-config ECHConfigList (version 0xfe0d) around `pk` with one
// ChaCha20Poly1305 suite and the given public_name.
fn build_config_list(
  pk : Bytes,
  config_id : Int,
  public_name : String,
) -> Bytes {
  let pn = ascii(public_name)
  let contents = cat([
    u8b(config_id),
    u16(0x0020), // kem_id X25519
    u16(pk.length()),
    pk,
    u16(4), // one cipher suite
    u16(0x0001), // kdf HKDF-SHA256
    u16(0x0003), // aead ChaCha20Poly1305
    u8b(0), // maximum_name_length
    u8b(pn.length()),
    pn,
    u16(0), // extensions
  ])
  let config = cat([u16(0xfe0d), u16(contents.length()), contents])
  cat([u16(config.length()), config])
}

///|
test "ECH parse ECHConfigList fields" {
  let sk = Bytes::makei(32, fn(i) { (i + 1).to_byte() })
  let pk = @x25519.PrivateKey::from_bytes(sk).public_key().to_bytes()
  let list = build_config_list(pk, 0x2a, "example.com")
  let configs = @ech.parse_ech_config_list(list)
  inspect(configs.length(), content="1")
  let c = configs[0]
  inspect(c.config_id(), content="42") // 0x2a
  inspect(c.kem_id(), content="32") // 0x0020
  inspect(c.public_name(), content="example.com")
  inspect(c.public_key().length(), content="32")
  inspect(c.cipher_suites().length(), content="1")
}

///|
test "ECH HPKE seal -> open round trip" {
  let sk_r = Bytes::makei(32, fn(i) { (i + 7).to_byte() })
  let pk_r = @x25519.PrivateKey::from_bytes(sk_r).public_key().to_bytes()
  let list = build_config_list(pk_r, 0x01, "cover.example")
  let cfg = @ech.parse_ech_config_list(list)[0]
  // Fixed ephemeral for a deterministic test (production: fresh CSPRNG).
  let sk_e = Bytes::makei(32, fn(i) { (i * 3 + 5).to_byte() })
  let inner = b"this is the encoded ClientHelloInner"
  let aad = b"ClientHelloOuterAAD"
  let (enc, payload) = cfg.seal(inner, aad, sk_e)
  inspect(enc.length(), content="32") // X25519 enc
  let recovered = cfg.open(enc, sk_r, aad, payload)
  let mut same = recovered.length() == inner.length()
  if same {
    for i in 0..<inner.length() {
      if recovered[i] != inner[i] {
        same = false
        break
      }
    }
  }
  inspect(same, content="true")
}

///|
test "ECH open rejects wrong AAD and wrong recipient key" {
  let sk_r = Bytes::makei(32, fn(i) { (i + 7).to_byte() })
  let pk_r = @x25519.PrivateKey::from_bytes(sk_r).public_key().to_bytes()
  let cfg = @ech.parse_ech_config_list(build_config_list(pk_r, 1, "x.example"))[0]
  let sk_e = Bytes::makei(32, fn(i) { (i + 9).to_byte() })
  let (enc, payload) = cfg.seal(b"inner", b"aad", sk_e)
  // Wrong AAD.
  inspect(
    (try? cfg.open(enc, sk_r, b"different aad", payload)) is Err(_),
    content="true",
  )
  // Wrong recipient key.
  let wrong = Bytes::makei(32, fn(i) { (i + 99).to_byte() })
  inspect(
    (try? cfg.open(enc, wrong, b"aad", payload)) is Err(_),
    content="true",
  )
}

///|
test "ECH rejects a config with no supported suite" {
  let sk = Bytes::makei(32, fn(i) { (i + 1).to_byte() })
  let pk = @x25519.PrivateKey::from_bytes(sk).public_key().to_bytes()
  let pn = ascii("ex.com")
  // Offer only AES-128-GCM (0x0001), which the library's HPKE does not do.
  let contents = cat([
    u8b(1),
    u16(0x0020),
    u16(pk.length()),
    pk,
    u16(4),
    u16(0x0001),
    u16(0x0001), // aead AES-128-GCM (unsupported here)
    u8b(0),
    u8b(pn.length()),
    pn,
    u16(0),
  ])
  let config = cat([u16(0xfe0d), u16(contents.length()), contents])
  let list = cat([u16(config.length()), config])
  let cfg = @ech.parse_ech_config_list(list)[0]
  inspect(
    (try? cfg.seal(b"x", b"y", Bytes::makei(32, fn(i) { i.to_byte() })))
    is Err(_),
    content="true",
  )
}
