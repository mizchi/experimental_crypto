// TLS 1.2 PRF + key-schedule known-answer tests.
//
// PRF vectors are the canonical IETF TLS WG values
// (https://www.ietf.org/mail-archive/web/tls/current/msg03416.html); the
// key-schedule vectors are computed from a reference TLS 1.2 PRF for fixed
// inputs to lock in label strings and random-ordering.

///|
fn hx(s : String) -> Bytes {
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
fn tohx(b : Bytes) -> String {
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
fn rep(byte : Int, n : Int) -> Bytes {
  Bytes::makei(n, fn(_i) { (byte & 0xff).to_byte() })
}

///|
test "TLS 1.2 PRF-SHA256 IETF TLS WG vector" {
  let secret = hx("9bbe436ba940f017b17652849a71db35")
  let seed = hx("a0ba9f936cda311827a6f796ffd5198c")
  let out = @tls12.PrfHash::Sha256.prf(secret, "test label", seed, 100)
  inspect(
    tohx(out),
    content="e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66",
  )
}

///|
test "TLS 1.2 PRF-SHA384 IETF TLS WG vector" {
  let secret = hx("b80b733d6ceefcdc71566ea48e5567df")
  let seed = hx("cd665cf6a8447dd6ff8b27555edb7465")
  let out = @tls12.PrfHash::Sha384.prf(secret, "test label", seed, 148)
  inspect(
    tohx(out),
    content="7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d9184259b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee691c8f3a26854308d5eaa3be85e0990703d73e56f",
  )
}

// Fixed inputs: pms = 00..2f, client_random = 0x11*32, server_random = 0x22*32.

///|
test "TLS 1.2 master_secret wiring" {
  let pms = Bytes::makei(48, fn(i) { i.to_byte() })
  let ms = @tls12.PrfHash::Sha256.master_secret(
    pms,
    rep(0x11, 32),
    rep(0x22, 32),
  )
  inspect(
    tohx(ms),
    content="bf2551a89a700d5408b099b3d733fd2a9f44a59f47bec76b219de5796d273c6f8e1cf456a7689d195e9894b193822fc3",
  )
}

///|
test "TLS 1.2 key_block uses reversed (server||client) random order" {
  let pms = Bytes::makei(48, fn(i) { i.to_byte() })
  let h = @tls12.PrfHash::Sha256
  let ms = h.master_secret(pms, rep(0x11, 32), rep(0x22, 32))
  let kb = h.key_block(ms, rep(0x11, 32), rep(0x22, 32), 40)
  inspect(
    tohx(kb),
    content="b78bf22c34f80793432e769ce1c38570980bb56b9e230b59338bbd84711c1f26e336a7de011ac693",
  )
}

///|
test "TLS 1.2 finished_verify_data (client finished)" {
  let pms = Bytes::makei(48, fn(i) { i.to_byte() })
  let h = @tls12.PrfHash::Sha256
  let ms = h.master_secret(pms, rep(0x11, 32), rep(0x22, 32))
  let fin = h.finished_verify_data(ms, "client finished", rep(0xab, 64))
  inspect(tohx(fin), content="e11a792c3e8cfb9e8f168ee6")
}

///|
test "TLS 1.2 extended_master_secret (RFC 7627)" {
  let pms = Bytes::makei(48, fn(i) { i.to_byte() })
  let h = @tls12.PrfHash::Sha256
  // session_hash = SHA-256(transcript); here transcript = 0xab*64.
  let session_hash = h.transcript_hash(rep(0xab, 64))
  let ems = h.extended_master_secret(pms, session_hash)
  inspect(
    tohx(ems),
    content="bd22b4ecf908e38793f81ae953b9b1293c20811fb23f1eea3c4860ec3968f5d612eac95524d818e27206229b0af00014",
  )
}
