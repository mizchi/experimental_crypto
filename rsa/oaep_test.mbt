// RSA-OAEP tests. The private key + ciphertexts are produced by Node's
// `crypto.publicEncrypt` (RSA_PKCS1_OAEP_PADDING) for SHA-1/256/384/512 and a
// labeled SHA-256 case, so MoonBit's decrypt is cross-validated against a real
// OAEP implementation. The encrypt path is round-tripped through decrypt.

///|
fn oaep_hex(s : String) -> Bytes {
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
let oaep_sk_pem : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCqGy0cng53NOu5
  #|nwLFp/8obR4P+3sv538xjuEFg+oT6I+zv8K8p4Z6TD8uRvaaZegEpXnhUKbT0184
  #|fa3NDjUh3tTEM4DnBt7DlGcHF3/6LnkSecOZoNdaFo8R+6MDJcpsOgzEukw2MqbT
  #|UCL9bny2amwrnhtu0uMiniTM1GcNB09+2j9VRo6rMT9AEQwU+zXQS+4Ikz8CHo1R
  #|ZdnNalAEQ/r9iCx6PQ15fyJOfg60A+SOT62oYm5YkazOxRCKwwe/j10CIKACTkLb
  #|IVUGZCvY7jzGJqj1py9fw8kH/px1QmR/tLl3ERLAOS8FkakcPO9kGUGDoDPfS3SA
  #|LAx+X4TPAgMBAAECggEAR7c5Z61DUAKhtxpQ4uAW9QY7/GT75JBm0Y/5Uofw8f/E
  #|RfX8teizC3CF2o7UfPelv/+7yMBl9TxSEtD5q0/oGqWFckp8d+ovlKlGXnkL3YAm
  #|TyHC00w6PqLwIpbCfRs7ojE/HNmmM9ta9g/9EHe6YHWxsRnxWuHSHNArl6ec4qKY
  #|ajQt4T/wk6uxG6SrMapD9UFDLtmcxcGuo3zmnJLmwJum9iK+Kz6DV34GDtOumMlq
  #|hT87X3QSqmfh8CpB+uD0a2ITd1vvajxEVX6bAjTyeX82hoqdCcyyDvXczhjHvyvH
  #|TO6LxsfE53VmZ8A52rz8I9plsZ/J25zkX5E5Y5R4wQKBgQDTXRpHUlxdTTWd5kKm
  #|IUr/vnFJZV73gJpHitubXdtJjayDszjfiY2HRlEltT4aKg+9L2EdfkAncc1sjVCO
  #|+rIIZpaiV+21VsV07KaKfpgRtbLFCslLa0MOBlef+Xn69YxYBJW4/ts5AQZmlHt/
  #|Zrzi4YL7P7qX9R74yPPvpvN8sQKBgQDOB5RF3Rh3Hq4SlC39YXfv9FeSfrqJcY7B
  #|2HHgEHuXyN0bnxcFNVqJnAgTyoGrhiejXxBbcFB4/DOPnymV6tbMpQ23aJ/sx+0a
  #|7afVle+/pg+khchA8a7djJFQ/ZECv3E0CYLzAQtc5Rvvn44wbTkfyuzovb2DfzoQ
  #|+axwVTV5fwKBgQCadBem9M2gNLKwnzonEn8u4ekBHH3IWYbkLtmJ8I01c70URJyT
  #|5X2x07Wq24X1MrVrpzrNhZu191iJMb8jrJj6wJTlL2H6uNz0M5cD77yKfH+Vs+sj
  #|HM/UaNgRhAoaVONo0njixgJG5rPZtDmHAPmYxfikR47ASpSGcrqnbxXREQKBgQCW
  #|IZe+QRpu0wBtsWTB2qCXTinyKj6roQAx6RMx/1DQjiHw2sDfnr1WwUhxg4NyBdQk
  #|jEVTHEjHoJ/B7G1VPUdA4JVaLPc8h4MTuFIwpY2KzetgK8x85qBR+Ph7WAqvQemv
  #|za6KfRxWmOz+c/oc97pEnI5+GqVaiP87F3S8dpr86QKBgQCYHbrzH/4l3tGYW8VD
  #|3i8hQl0t1PXzJI8DgeuNS5+se8mL4qM4v/z0ke/cT3kZW8NZPPoTUcTsMeYV0U2W
  #|Hl2xP7v0I34uk0dfI4Sl77ANyxICp3XwVZe/qBnZrhfNxQmJdWVFj696GaVogpsP
  #|36LCFevAMpMDeNaVrTYqOEysfA==
  #|-----END PRIVATE KEY-----

///|
let oaep_pt : String = "5253412d4f41455020696e7465726f7020706c61696e74657874"

///|
fn oaep_decrypt_ok(
  ct_hex : String,
  hash : @rsa.OaepHash,
  label : Bytes,
) -> Unit raise {
  let sk = @rsa.RsaPrivateKey::from_pkcs8_pem(oaep_sk_pem)
  let pt = sk.decrypt_oaep(oaep_hex(ct_hex), hash~, label~)
  let exp = oaep_hex(oaep_pt)
  assert_eq(pt.length(), exp.length())
  for i in 0..<exp.length() {
    assert_eq(pt[i], exp[i])
  }
}

///|
test "RSA-OAEP decrypt Node ciphertext: SHA-256 (default), no label" {
  oaep_decrypt_ok(
    "82c0b0c2a9b1ffb2f278c204a755dc8259667cd9c3ed8d9596aff6aa4ceef1d6cf33981431b954a57168652355480cf9112fac08022355aa3ad38b0b6505e6d9e249151a99f4273119535d424694aec93b5c985a2aca8e41d4cf391727d49d73c3a7fc45b29f63120eb0c8704e2c60fbfbda4d5503a982dcf82bfa1dc4e8693386134bbb0c009c521937c7d12ce38fe4f634c1e84557459cbaf9928cebf5a4ce799e2292c3633093177ffa28af090bfe3321c6f64f033c6d428cb8b063db674c5ee1f4fd9f86be1f267c07b370567198bd56e51d97b8b1bafcef0c1d95b49e7470c8345cb77e3be8e177a97e6f272d94675cff6ea911821fd9372d82bc7d18b6",
    @rsa.OaepHash::Sha256,
    b"",
  )
}

///|
test "RSA-OAEP decrypt Node ciphertext: SHA-1" {
  oaep_decrypt_ok(
    "52432805e8eda8b9dc500f38342bd6f67051030bb5a01e10a5df206e19b7b4ba8223b507873b60791cded45373d082fc5de7cfca413c181cf215749eff21249828951a7e8b9cb1665a3ed84d27b4bd95e081de04d2e0fc582e8995a5ca38977d833ba939d5374970a90192106d29efac722991d1d6db002f6d779f4dbf4bf9e969c2f2b88e651cce6b6b1bb25bb692ec508905eb2e44d9cb0903412f89a03544fc6ce2e15eb3d5f835a798d2ff25a20651a24c3c6bfab0a3ad013e347ef2c370bcd7a013df5da48ae17f6c47339743a8b1101859263a7d027a4b1f2c42391de609797212d989097713beedb918a2073fc7e2b7922c3d89570a51a0db67ad43de",
    @rsa.OaepHash::Sha1,
    b"",
  )
}

///|
test "RSA-OAEP decrypt Node ciphertext: SHA-384" {
  oaep_decrypt_ok(
    "425d79c6497259e48c20bb3839c9811439089b4996245ed6c496a6c55e1e27b36c73374d822edc920f74725addd8ef5ce5857b7f5cf4fbafac8b1d83f2ce0e7c80fb0c47a411c62986915f4df6b7447ec4ac3af81c596be612d2e230a0d32a674df6c174ed73843a4d7128b45f5883c6b510b9eb945704124331a4f5ef0cf78a7cf26885045f08f740e7869c4e573ea9de34944b3060ce8c027bee9d0e94d93f7c928ee2e3ad9d74ded47050fb3ef8419e389e3a30f1434c71961876e6925e785b448ccd703810ff845316bd843b091d24bac2020367d6fba4d96614239df39472ed0f0ce03fb790d592638d276ca223babeecae51ef4f91c114727f2280dae9",
    @rsa.OaepHash::Sha384,
    b"",
  )
}

///|
test "RSA-OAEP decrypt Node ciphertext: SHA-512" {
  oaep_decrypt_ok(
    "656d514f7229e8b814ccd5a712484ff4a9c7a0af3cb6fab9dc1a29927291eabc5dda8cbcca103bf4cff548370efa1c2e01e08860aecc52b9cf1968af655a701828257ad586739f1c2527855efacba01ed2aa0b98faa49c8f0465b957f7c71e7cc62f8089159f65da8182a281480bf580b3b6708797a43df6cb64b43b611f68a24d99b901f4cfdb5bb021cd0a5fd8e49090de651ec55bdb39c45e3e507d1599ccca5e40b7b7aa5e0a86590a3b1127f9c6941a5258e3b1e72c2f7b41f89b5f0c0502d33af2525b59c86f73430876b223815ac728877e5a69e30a7798a5146824e37721fd3cd5a477412c7eafdec44bbb4ea5e42fcb51f75b2070a4179bfc90b360",
    @rsa.OaepHash::Sha512,
    b"",
  )
}

///|
test "RSA-OAEP decrypt Node ciphertext: SHA-256 with label" {
  oaep_decrypt_ok(
    "174ec6d60805e5237855e4f39c46aee9639bd166b1eed3e9088ab077ee0171b3e1e9fdff0c2e7a545d1f821feeaf2cfb9fe0040afb929f528858fb3da5090d5bb23e740105adb0d761cce2c82eaf01ee9ebb36aceeaf3afb68b042d63b112fab0aa685e19a1c724243f7b8ad8d061a7e72b035e07b2c82d06820bf91f5e247af905e5c3deba3f48539d9a6eb48551f9446011cacb0e648496da95cf5ed050e90d658701308004c9da7919d34e501ad565894f89a1b7bd510ca06ab6aedc90eb809dbba5abb46b2531c423e95433e277fde73dd2f64cdf15df096de9dfb568426490b4670a2632c832b4f568350aaeeef9b5ac16f363a00a22754318175e95e8b",
    @rsa.OaepHash::Sha256,
    oaep_hex("00112233"),
  )
}

///|
test "RSA-OAEP encrypt -> decrypt round trip (SHA-256)" {
  let sk = @rsa.RsaPrivateKey::from_pkcs8_pem(oaep_sk_pem)
  let pk = sk.public_key()
  let msg = b"hello oaep round trip"
  // Fixed 32-byte seed (test only; production must use a CSPRNG).
  let seed = Bytes::makei(32, fn(i) { (i * 7 + 1).to_byte() })
  let ct = pk.encrypt_oaep(msg, seed)
  let back = sk.decrypt_oaep(ct)
  assert_eq(back.length(), msg.length())
  for i in 0..<msg.length() {
    assert_eq(back[i], msg[i])
  }
}

///|
// Parameter-confusion attacks: a ciphertext is bound to its (hash, label).
// Decrypting under a different hash or label must fail, not silently return
// garbage or a partial plaintext.
test "RSA-OAEP rejects hash mismatch (encrypt SHA-256, decrypt SHA-1)" {
  let sk = @rsa.RsaPrivateKey::from_pkcs8_pem(oaep_sk_pem)
  let pk = sk.public_key()
  let seed = Bytes::makei(32, fn(i) { (i + 3).to_byte() })
  let ct = pk.encrypt_oaep(b"param confusion", seed, hash=@rsa.OaepHash::Sha256)
  let mut rejected = false
  let _ = sk.decrypt_oaep(ct, hash=@rsa.OaepHash::Sha1) catch {
    _ => {
      rejected = true
      b""
    }
  }
  inspect(rejected, content="true")
}

///|
test "RSA-OAEP rejects label mismatch" {
  let sk = @rsa.RsaPrivateKey::from_pkcs8_pem(oaep_sk_pem)
  let pk = sk.public_key()
  let seed = Bytes::makei(32, fn(i) { (i + 9).to_byte() })
  let ct = pk.encrypt_oaep(b"labeled", seed, label=oaep_hex("aabb"))
  // Right key + right hash, wrong label.
  let mut rejected = false
  let _ = sk.decrypt_oaep(ct, label=oaep_hex("aabbcc")) catch {
    _ => {
      rejected = true
      b""
    }
  }
  inspect(rejected, content="true")
  // Sanity: the matching label still decrypts.
  let ok = sk.decrypt_oaep(ct, label=oaep_hex("aabb"))
  inspect(ok.length(), content="7")
}

///|
test "RSA-OAEP decrypt rejects a tampered ciphertext" {
  let sk = @rsa.RsaPrivateKey::from_pkcs8_pem(oaep_sk_pem)
  let pk = sk.public_key()
  let seed = Bytes::makei(32, fn(i) { i.to_byte() })
  let ct = pk.encrypt_oaep(b"tamper me", seed)
  let bad = Bytes::makei(ct.length(), fn(i) {
    if i == ct.length() - 1 {
      (ct[i].to_int() ^ 0x01).to_byte()
    } else {
      ct[i]
    }
  })
  let mut rejected = false
  let _ = sk.decrypt_oaep(bad) catch {
    _ => {
      rejected = true
      b""
    }
  }
  inspect(rejected, content="true")
}
