// NIST SP 800-38A §F.2 AES-CBC test vectors (AES-128 and AES-256).
// Confirms the AES inverse cipher + CBC mode match the reference.

///|
fn cbc_hex(s : String) -> Bytes {
  let clean : Array[Char] = []
  for c in s {
    if c != ' ' && c != '\n' {
      clean.push(c)
    }
  }
  let n = clean.length() / 2
  Bytes::makei(n, fn(i) {
    let hi = cbc_hex_nibble(clean[i * 2])
    let lo = cbc_hex_nibble(clean[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn cbc_hex_nibble(c : Char) -> Int {
  let code = c.to_int()
  if code >= '0'.to_int() && code <= '9'.to_int() {
    code - '0'.to_int()
  } else if code >= 'a'.to_int() && code <= 'f'.to_int() {
    code - 'a'.to_int() + 10
  } else if code >= 'A'.to_int() && code <= 'F'.to_int() {
    code - 'A'.to_int() + 10
  } else {
    abort("bad hex: " + c.to_string())
  }
}

///|
test "aes-128-cbc: NIST SP 800-38A §F.2.1/F.2.2 round trip" {
  // F.2.1 CBC-AES128.Encrypt
  let key = cbc_hex("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = cbc_hex("000102030405060708090a0b0c0d0e0f")
  let plaintext = cbc_hex(
    "6bc1bee22e409f96e93d7e117393172a" +
    "ae2d8a571e03ac9c9eb76fac45af8e51" +
    "30c81c46a35ce411e5fbc1191a0a52ef" +
    "f69f2445df4f9b17ad2b417be66c3710",
  )
  let expected_ct = cbc_hex(
    "7649abac8119b246cee98e9b12e9197d" +
    "5086cb9b507219ee95db113a917678b2" +
    "73bed6b8e3c1743b7116e69e22229516" +
    "3ff1caa1681fac09120eca307586e1a7",
  )
  let ct = @aead.aes_cbc_encrypt(key, iv, plaintext)
  @debug.assert_eq(ct, expected_ct)
  let pt = @aead.aes_cbc_decrypt(key, iv, ct)
  @debug.assert_eq(pt, plaintext)
}

///|
test "aes-256-cbc: NIST SP 800-38A §F.2.5/F.2.6 round trip" {
  // F.2.5 CBC-AES256.Encrypt
  let key = cbc_hex(
    "603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4",
  )
  let iv = cbc_hex("000102030405060708090a0b0c0d0e0f")
  let plaintext = cbc_hex(
    "6bc1bee22e409f96e93d7e117393172a" +
    "ae2d8a571e03ac9c9eb76fac45af8e51" +
    "30c81c46a35ce411e5fbc1191a0a52ef" +
    "f69f2445df4f9b17ad2b417be66c3710",
  )
  let expected_ct = cbc_hex(
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6" +
    "9cfc4e967edb808d679f777bc6702c7d" +
    "39f23369a9d9bacfa530e26304231461" +
    "b2eb05e2c39be9fcda6c19078c6a9d1b",
  )
  let ct = @aead.aes_cbc_encrypt(key, iv, plaintext)
  @debug.assert_eq(ct, expected_ct)
  let pt = @aead.aes_cbc_decrypt(key, iv, ct)
  @debug.assert_eq(pt, plaintext)
}

///|
test "aes-cbc: rejects bad IV length" {
  let key = cbc_hex("2b7e151628aed2a6abf7158809cf4f3c")
  try
    @aead.aes_cbc_encrypt(
      key, b"\x00", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    )
  catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidNonceSize")
  }
}

///|
test "aes-cbc: rejects non-multiple-of-16 plaintext" {
  let key = cbc_hex("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = cbc_hex("000102030405060708090a0b0c0d0e0f")
  try @aead.aes_cbc_encrypt(key, iv, b"\x00\x01\x02") catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected PlaintextTooLong")
  }
}
