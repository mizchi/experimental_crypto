// Blackbox tests for mizchi/aead. RFC 8439 §2.8.2 and §A.5 test vectors.

///|
fn hex(s : String) -> Bytes {
  let clean_chars : Array[Char] = []
  for c in s {
    if c != ' ' && c != '\n' && c != ':' {
      clean_chars.push(c)
    }
  }
  let n = clean_chars.length() / 2
  Bytes::makei(n, fn(i) {
    let hi = hex_nibble(clean_chars[i * 2])
    let lo = hex_nibble(clean_chars[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn hex_nibble(c : Char) -> Int {
  let code = c.to_int()
  if code >= '0'.to_int() && code <= '9'.to_int() {
    code - '0'.to_int()
  } else if code >= 'a'.to_int() && code <= 'f'.to_int() {
    code - 'a'.to_int() + 10
  } else if code >= 'A'.to_int() && code <= 'F'.to_int() {
    code - 'A'.to_int() + 10
  } else {
    abort("non-hex char")
  }
}

///|
fn to_hex(b : Bytes) -> String {
  let buf = StringBuilder::new()
  let table : Array[Char] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  ]
  for i in 0..<b.length() {
    let v = b[i].to_int()
    buf.write_char(table[v >> 4])
    buf.write_char(table[v & 0xF])
  }
  buf.to_string()
}

///|
test "RFC 8439 §2.8.2 sunscreen ChaCha20-Poly1305 seal" {
  let key = hex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex("070000004041424344454647")
  let aad = hex("50515253c0c1c2c3c4c5c6c7")
  // RFC 8439 §2.8.2 plaintext: 114-byte string.
  let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
  let pt_bytes = Bytes::makei(plaintext.length(), fn(i) { plaintext[i] })
  let expected_ct = hex(
    "d31a8d34648e60db7b86afbc53ef7ec2" +
    "a4aded51296e08fea9e2b5a736ee62d6" +
    "3dbea45e8ca9671282fafb69da92728b" +
    "1a71de0a9e060b2905d6a5b67ecd3b36" +
    "92ddbd7f2d778b8c9803aee328091b58" +
    "fab324e4fad675945585808b4831d7bc" +
    "3ff4def08e4b7a9de576d26586cec64b" +
    "6116",
  )
  let expected_tag = hex("1ae10b594f09e26a7e902ecbd0600691")
  let (ct, tag) = @aead.seal_detached(
    @aead.ChaCha20Poly1305,
    key,
    nonce,
    aad,
    pt_bytes,
  )
  assert_eq(to_hex(ct), to_hex(expected_ct))
  assert_eq(to_hex(tag), to_hex(expected_tag))

  // attached form
  let combined = @aead.seal(@aead.ChaCha20Poly1305, key, nonce, aad, pt_bytes)
  let expected_combined_hex = to_hex(expected_ct) + to_hex(expected_tag)
  assert_eq(to_hex(combined), expected_combined_hex)
}

///|
test "RFC 8439 §2.8.2 sunscreen open round-trip" {
  let key = hex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex("070000004041424344454647")
  let aad = hex("50515253c0c1c2c3c4c5c6c7")
  let plaintext_lit = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
  let pt_bytes = Bytes::makei(plaintext_lit.length(), fn(i) { plaintext_lit[i] })
  let ct = hex(
    "d31a8d34648e60db7b86afbc53ef7ec2" +
    "a4aded51296e08fea9e2b5a736ee62d6" +
    "3dbea45e8ca9671282fafb69da92728b" +
    "1a71de0a9e060b2905d6a5b67ecd3b36" +
    "92ddbd7f2d778b8c9803aee328091b58" +
    "fab324e4fad675945585808b4831d7bc" +
    "3ff4def08e4b7a9de576d26586cec64b" +
    "6116",
  )
  let tag = hex("1ae10b594f09e26a7e902ecbd0600691")
  let recovered = @aead.open_detached(
    @aead.ChaCha20Poly1305,
    key,
    nonce,
    aad,
    ct,
    tag,
  )
  assert_eq(to_hex(recovered), to_hex(pt_bytes))

  // attached open
  let combined_arr : Array[Byte] = []
  for i in 0..<ct.length() {
    combined_arr.push(ct[i])
  }
  for i in 0..<tag.length() {
    combined_arr.push(tag[i])
  }
  let combined = Bytes::makei(combined_arr.length(), fn(i) { combined_arr[i] })
  let recovered2 = @aead.open(@aead.ChaCha20Poly1305, key, nonce, aad, combined)
  assert_eq(to_hex(recovered2), to_hex(pt_bytes))
}

///|
test "RFC 8439 §A.5 ChaCha20-Poly1305 AEAD decryption vector" {
  // RFC 8439 Appendix A.5. Decryption of a longer message.
  let key = hex(
    "1c9240a5eb55d38af333888604f6b5f0" + "473917c1402b80099dca5cbc207075c0",
  )
  let nonce = hex("000000000102030405060708")
  let aad = hex("f33388860000000000004e91")
  let ciphertext = hex(
    "64a0861575861af460f062c79be643bd" +
    "5e805cfd345cf389f108670ac76c8cb2" +
    "4c6cfc18755d43eea09ee94e382d26b0" +
    "bdb7b73c321b0100d4f03b7f355894cf" +
    "332f830e710b97ce98c8a84abd0b9481" +
    "14ad176e008d33bd60f982b1ff37c855" +
    "9797a06ef4f0ef61c186324e2b350638" +
    "3606907b6a7c02b0f9f6157b53c867e4" +
    "b9166c767b804d46a59b5216cde7a4e9" +
    "9040c5a40433225ee282a1b0a06c523e" +
    "af4534d7f83fa1155b0047718cbc546a" +
    "0d072b04b3564eea1b422273f548271a" +
    "0bb2316053fa76991955ebd63159434e" +
    "cebb4e466dae5a1073a6727627097a10" +
    "49e617d91d361094fa68f0ff77987130" +
    "305beaba2eda04df997b714d6c6f2c29" +
    "a6ad5cb4022b02709b",
  )
  let tag = hex("eead9d67890cbb22392336fea1851f38")
  let expected_pt = hex(
    "496e7465726e65742d44726166747320" +
    "61726520647261667420646f63756d65" +
    "6e74732076616c696420666f72206120" +
    "6d6178696d756d206f6620736978206d" +
    "6f6e74687320616e64206d6179206265" +
    "20757064617465642c207265706c6163" +
    "65642c206f72206f62736f6c65746564" +
    "206279206f7468657220646f63756d65" +
    "6e747320617420616e792074696d652e" +
    "20497420697320696e617070726f7072" +
    "6961746520746f2075736520496e7465" +
    "726e65742d4472616674732061732072" +
    "65666572656e6365206d617465726961" +
    "6c206f7220746f206369746520746865" +
    "6d206f74686572207468616e20617320" +
    "2fe2809c776f726b20696e2070726f67" +
    "726573732e2fe2809d",
  )
  let recovered = @aead.open_detached(
    @aead.ChaCha20Poly1305,
    key,
    nonce,
    aad,
    ciphertext,
    tag,
  )
  assert_eq(to_hex(recovered), to_hex(expected_pt))
}

///|
test "ChaCha20-Poly1305 authentication failure on tag tamper" {
  let key = hex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex("070000004041424344454647")
  let aad = hex("50515253c0c1c2c3c4c5c6c7")
  let pt = b"hello world"
  let pt_bytes = Bytes::makei(pt.length(), fn(i) { pt[i] })
  let (ct, tag) = @aead.seal_detached(
    @aead.ChaCha20Poly1305,
    key,
    nonce,
    aad,
    pt_bytes,
  )
  // Flip one bit in the tag.
  let bad_tag = Bytes::makei(tag.length(), fn(i) {
    if i == 0 {
      (tag[i].to_int() ^ 0x01).to_byte()
    } else {
      tag[i]
    }
  })
  let result : Result[Bytes, @aead.AeadError] = try? @aead.open_detached(
    @aead.ChaCha20Poly1305,
    key,
    nonce,
    aad,
    ct,
    bad_tag,
  )
  match result {
    Ok(_) => abort("expected AuthenticationFailed but open succeeded")
    Err(@aead.AuthenticationFailed) => ()
    Err(e) => abort("expected AuthenticationFailed but got " + e.to_string())
  }
  ignore(ct)
}

///|
test "ChaCha20-Poly1305 authentication failure on aad tamper" {
  let key = hex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex("070000004041424344454647")
  let aad = hex("50515253c0c1c2c3c4c5c6c7")
  let pt = b"hello world"
  let pt_bytes = Bytes::makei(pt.length(), fn(i) { pt[i] })
  let (ct, tag) = @aead.seal_detached(
    @aead.ChaCha20Poly1305,
    key,
    nonce,
    aad,
    pt_bytes,
  )
  let bad_aad = hex("00515253c0c1c2c3c4c5c6c7")
  let result : Result[Bytes, @aead.AeadError] = try? @aead.open_detached(
    @aead.ChaCha20Poly1305,
    key,
    nonce,
    bad_aad,
    ct,
    tag,
  )
  match result {
    Ok(_) => abort("expected AuthenticationFailed but open succeeded")
    Err(@aead.AuthenticationFailed) => ()
    Err(e) => abort("expected AuthenticationFailed but got " + e.to_string())
  }
}

///|
test "round-trip empty plaintext and empty aad" {
  let key = hex(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  let nonce = hex("000000000000000000000000")
  let aad = b""
  let pt = b""
  let (ct, tag) = @aead.seal_detached(
    @aead.ChaCha20Poly1305,
    key,
    nonce,
    aad,
    pt,
  )
  assert_eq(ct.length(), 0)
  assert_eq(tag.length(), 16)
  let recovered = @aead.open_detached(
    @aead.ChaCha20Poly1305,
    key,
    nonce,
    aad,
    ct,
    tag,
  )
  assert_eq(recovered.length(), 0)
}

///|
test "AES-128-GCM empty round-trip" {
  // AES-GCM is now implemented; empty PT + empty AAD must round-trip.
  let key = Bytes::makei(16, fn(_) { b'\x00' })
  let nonce = Bytes::makei(12, fn(_) { b'\x00' })
  let aad = b""
  let pt = b""
  let sealed = @aead.seal(@aead.Aes128Gcm, key, nonce, aad, pt)
  // Tag is 16 bytes, no ciphertext.
  assert_eq(sealed.length(), 16)
  let opened = @aead.open(@aead.Aes128Gcm, key, nonce, aad, sealed)
  assert_eq(opened.length(), 0)
}

///|
test "XChaCha20-Poly1305 raises UnsupportedAlgorithm" {
  let key = Bytes::makei(32, fn(_) { b'\x00' })
  let nonce = Bytes::makei(24, fn(_) { b'\x00' })
  let aad = b""
  let pt = b""
  let result : Result[Bytes, @aead.AeadError] = try? @aead.seal(
    @aead.XChaCha20Poly1305,
    key,
    nonce,
    aad,
    pt,
  )
  match result {
    Ok(_) => abort("expected UnsupportedAlgorithm but seal succeeded")
    Err(@aead.UnsupportedAlgorithm(@aead.XChaCha20Poly1305)) => ()
    Err(e) => abort("expected UnsupportedAlgorithm but got " + e.to_string())
  }
}

///|
test "invalid key size for ChaCha20-Poly1305" {
  let key = Bytes::makei(16, fn(_) { b'\x00' })
  let nonce = Bytes::makei(12, fn(_) { b'\x00' })
  let pt = b""
  let result : Result[Bytes, @aead.AeadError] = try? @aead.seal(
    @aead.ChaCha20Poly1305,
    key,
    nonce,
    b"",
    pt,
  )
  match result {
    Ok(_) => abort("expected InvalidKeySize")
    Err(@aead.InvalidKeySize(expected=32, got=16)) => ()
    Err(e) => abort("expected InvalidKeySize but got " + e.to_string())
  }
}

///|
test "invalid nonce size for ChaCha20-Poly1305" {
  let key = Bytes::makei(32, fn(_) { b'\x00' })
  let nonce = Bytes::makei(8, fn(_) { b'\x00' })
  let pt = b""
  let result : Result[Bytes, @aead.AeadError] = try? @aead.seal(
    @aead.ChaCha20Poly1305,
    key,
    nonce,
    b"",
    pt,
  )
  match result {
    Ok(_) => abort("expected InvalidNonceSize")
    Err(@aead.InvalidNonceSize(expected=12, got=8)) => ()
    Err(e) => abort("expected InvalidNonceSize but got " + e.to_string())
  }
}
