// Structured fuzz tests for JWE compact boundaries. Random compact strings
// should never panic; generated dir-mode tokens must round-trip and reject
// key/size tampering at the authentication boundary.

///|
fn fuzz_jwe_bytes(raw : Bytes, len : Int) -> Bytes {
  Bytes::makei(len, fn(i) {
    if raw.length() == 0 {
      ((i * 31 + 7) & 0xff).to_byte()
    } else {
      ((raw[i % raw.length()].to_int() + i * 31) & 0xff).to_byte()
    }
  })
}

///|
fn fuzz_jwe_flip_first(b : Bytes) -> Bytes {
  Bytes::makei(b.length(), fn(i) {
    if i == 0 {
      (b[i].to_int() ^ 0x01).to_byte()
    } else {
      b[i]
    }
  })
}

///|
let fuzz_jwe_b64u_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

///|
fn fuzz_jwe_mutate_b64u_char(c : Char, entropy : Int) -> Char {
  let candidate = fuzz_jwe_b64u_alphabet.get_char(entropy & 63).unwrap()
  if candidate == c {
    fuzz_jwe_b64u_alphabet.get_char((entropy + 1) & 63).unwrap()
  } else {
    candidate
  }
}

///|
fn fuzz_jwe_mutate_compact_token(token : String, entropy : Bytes) -> String {
  let mut b64u_chars = 0
  for c in token {
    if c != '.' {
      b64u_chars = b64u_chars + 1
    }
  }
  if b64u_chars == 0 {
    token
  } else {
    let seed = if entropy.length() == 0 { 0 } else { entropy[0].to_int() }
    let tweak = if entropy.length() < 2 {
      seed + 1
    } else {
      entropy[1].to_int()
    }
    let target = seed % b64u_chars
    let out = StringBuilder::new()
    let mut seen = 0
    let mut done = false
    for c in token {
      if c != '.' && seen == target && !done {
        out.write_char(fuzz_jwe_mutate_b64u_char(c, tweak))
        done = true
      } else {
        out.write_char(c)
      }
      if c != '.' {
        seen = seen + 1
      }
    }
    out.to_string()
  }
}

///|
test "fuzz jwe: decrypt never panics on random compact strings" {
  let key = fuzz_jwe_bytes(b"fixed-jwe-key", 32)
  for input in (@quickcheck.samples(200) : Array[String]) {
    let _ = try? @jwe.decrypt(input, @jwe.DecryptionKey::DecDir(cek=key))
  }
}

///|
test "fuzz jwe: dir A128GCM round-trip on generated keys and IVs" {
  for triple in (@quickcheck.samples(80) : Array[(Bytes, Bytes, Bytes)]) {
    let (plaintext, key_raw, iv_raw) = triple
    let cek = fuzz_jwe_bytes(key_raw, 16)
    let iv = fuzz_jwe_bytes(iv_raw, 12)
    let token = @jwe.encrypt(
      plaintext,
      @jwe.JweAlg::Dir,
      @jwe.JweEnc::A128gcm,
      @jwe.EncryptionKey::EncDir(cek~),
      iv~,
    )
    let decoded = @jwe.decrypt(token, @jwe.DecryptionKey::DecDir(cek~))
    @debug.assert_eq(decoded, plaintext)
  }
}

///|
test "fuzz jwe: dir A256GCM round-trip on generated keys and IVs" {
  for triple in (@quickcheck.samples(80) : Array[(Bytes, Bytes, Bytes)]) {
    let (plaintext, key_raw, iv_raw) = triple
    let cek = fuzz_jwe_bytes(key_raw, 32)
    let iv = fuzz_jwe_bytes(iv_raw, 12)
    let token = @jwe.encrypt(
      plaintext,
      @jwe.JweAlg::Dir,
      @jwe.JweEnc::A256gcm,
      @jwe.EncryptionKey::EncDir(cek~),
      iv~,
    )
    let decoded = @jwe.decrypt(token, @jwe.DecryptionKey::DecDir(cek~))
    @debug.assert_eq(decoded, plaintext)
  }
}

///|
test "fuzz jwe: mutated compact token never authenticates" {
  for quad in (@quickcheck.samples(80) : Array[(Bytes, Bytes, Bytes, Bytes)]) {
    let (plaintext, key_raw, iv_raw, entropy) = quad
    let cek = fuzz_jwe_bytes(key_raw, 32)
    let iv = fuzz_jwe_bytes(iv_raw, 12)
    let token = @jwe.encrypt(
      plaintext,
      @jwe.JweAlg::Dir,
      @jwe.JweEnc::A256gcm,
      @jwe.EncryptionKey::EncDir(cek~),
      iv~,
    )
    let mutated = fuzz_jwe_mutate_compact_token(token, entropy)
    try @jwe.decrypt(mutated, @jwe.DecryptionKey::DecDir(cek~)) catch {
      _ => ()
    } noraise {
      _ => abort("mutated compact JWE authenticated")
    }
  }
}

///|
test "fuzz jwe: wrong dir key rejects as authentication failure" {
  for triple in (@quickcheck.samples(60) : Array[(Bytes, Bytes, Bytes)]) {
    let (plaintext, key_raw, iv_raw) = triple
    let cek = fuzz_jwe_bytes(key_raw, 32)
    let wrong = fuzz_jwe_flip_first(cek)
    let iv = fuzz_jwe_bytes(iv_raw, 12)
    let token = @jwe.encrypt(
      plaintext,
      @jwe.JweAlg::Dir,
      @jwe.JweEnc::A256gcm,
      @jwe.EncryptionKey::EncDir(cek~),
      iv~,
    )
    let rejected = try {
      let _ = @jwe.decrypt(token, @jwe.DecryptionKey::DecDir(cek=wrong))
      false
    } catch {
      @jwe.AuthenticationFailed => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "fuzz jwe: A256KW A256GCM round-trip on generated KEKs, CEKs, and IVs" {
  for quad in (@quickcheck.samples(50) : Array[(Bytes, Bytes, Bytes, Bytes)]) {
    let (plaintext, kek_raw, cek_raw, iv_raw) = quad
    let kek = fuzz_jwe_bytes(kek_raw, 32)
    let cek = fuzz_jwe_bytes(cek_raw, 32)
    let iv = fuzz_jwe_bytes(iv_raw, 12)
    let token = @jwe.encrypt(
      plaintext,
      @jwe.JweAlg::A256kw,
      @jwe.JweEnc::A256gcm,
      @jwe.EncryptionKey::EncAes256Kw(kek~),
      cek~,
      iv~,
    )
    let decoded = @jwe.decrypt(token, @jwe.DecryptionKey::DecAes256Kw(kek~))
    @debug.assert_eq(decoded, plaintext)
  }
}

///|
test "fuzz jwe: wrong A256KW KEK rejects as authentication failure" {
  for quad in (@quickcheck.samples(50) : Array[(Bytes, Bytes, Bytes, Bytes)]) {
    let (plaintext, kek_raw, cek_raw, iv_raw) = quad
    let kek = fuzz_jwe_bytes(kek_raw, 32)
    let wrong = fuzz_jwe_flip_first(kek)
    let cek = fuzz_jwe_bytes(cek_raw, 32)
    let iv = fuzz_jwe_bytes(iv_raw, 12)
    let token = @jwe.encrypt(
      plaintext,
      @jwe.JweAlg::A256kw,
      @jwe.JweEnc::A256gcm,
      @jwe.EncryptionKey::EncAes256Kw(kek~),
      cek~,
      iv~,
    )
    let rejected = try {
      let _ = @jwe.decrypt(token, @jwe.DecryptionKey::DecAes256Kw(kek=wrong))
      false
    } catch {
      @jwe.AuthenticationFailed => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "fuzz jwe: invalid dir CEK and IV sizes reject before encryption" {
  for pair in (@quickcheck.samples(80) : Array[(Bytes, Bytes)]) {
    let (key_raw, iv_raw) = pair
    let bad_key = fuzz_jwe_bytes(key_raw, key_raw.length() % 15)
    let good_iv = fuzz_jwe_bytes(iv_raw, 12)
    let bad_key_rejected = try {
      let _ = @jwe.encrypt(
        b"payload",
        @jwe.JweAlg::Dir,
        @jwe.JweEnc::A128gcm,
        @jwe.EncryptionKey::EncDir(cek=bad_key),
        iv=good_iv,
      )
      false
    } catch {
      @jwe.InvalidKeySize(_) => true
      _ => false
    }
    assert_true(bad_key_rejected)

    let good_key = fuzz_jwe_bytes(key_raw, 16)
    let bad_iv = fuzz_jwe_bytes(iv_raw, iv_raw.length() % 12)
    let bad_iv_rejected = try {
      let _ = @jwe.encrypt(
        b"payload",
        @jwe.JweAlg::Dir,
        @jwe.JweEnc::A128gcm,
        @jwe.EncryptionKey::EncDir(cek=good_key),
        iv=bad_iv,
      )
      false
    } catch {
      @jwe.InvalidIvSize(_) => true
      _ => false
    }
    assert_true(bad_iv_rejected)
  }
}
