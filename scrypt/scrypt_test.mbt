// RFC 7914 §11 scrypt test vectors.

///|
test "scrypt: RFC 7914 §11 vector 1 (P='', S='', N=16, r=1, p=1, dkLen=64)" {
  let params : @scrypt.Params = { log_n: 4, r: 1, p: 1, dk_len: 64 }
  let dk = @scrypt.derive_key(params, b"", b"")
  let expected : Bytes = b"\x77\xd6\x57\x62\x38\x65\x7b\x20\x3b\x19\xca\x42\xc1\x8a\x04\x97\xf1\x6b\x48\x44\xe3\x07\x4a\xe8\xdf\xdf\xfa\x3f\xed\xe2\x14\x42\xfc\xd0\x06\x9d\xed\x09\x48\xf8\x32\x6a\x75\x3a\x0f\xc8\x1f\x17\xe8\xd3\xe0\xfb\x2e\x0d\x36\x28\xcf\x35\xe2\x0c\x38\xd1\x89\x06"
  assert_eq(dk, expected)
}

///|
test "scrypt: RFC 7914 §11 vector 2 (P='password', S='NaCl', N=1024, r=8, p=16, dkLen=64)" {
  let params : @scrypt.Params = { log_n: 10, r: 8, p: 16, dk_len: 64 }
  let dk = @scrypt.derive_key(params, b"password", b"NaCl")
  let expected : Bytes = b"\xfd\xba\xbe\x1c\x9d\x34\x72\x00\x78\x56\xe7\x19\x0d\x01\xe9\xfe\x7c\x6a\xd7\xcb\xc8\x23\x78\x30\xe7\x73\x76\x63\x4b\x37\x31\x62\x2e\xaf\x30\xd9\x2e\x22\xa3\x88\x6f\xf1\x09\x27\x9d\x98\x30\xda\xc7\x27\xaf\xb9\x4a\x83\xee\x6d\x83\x60\xcb\xdf\xa2\xcc\x06\x40"
  assert_eq(dk, expected)
}

///|
test "scrypt: rejects invalid log_n" {
  let bad : @scrypt.Params = { log_n: 0, r: 8, p: 1, dk_len: 32 }
  match (try? @scrypt.derive_key(bad, b"", b"")) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected InvalidParams")
  }
}

///|
test "scrypt: rejects r < 1" {
  let bad : @scrypt.Params = { log_n: 4, r: 0, p: 1, dk_len: 32 }
  match (try? @scrypt.derive_key(bad, b"", b"")) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected InvalidParams")
  }
}

///|
test "scrypt: rejects dk_len < 1" {
  let bad : @scrypt.Params = { log_n: 4, r: 1, p: 1, dk_len: 0 }
  match (try? @scrypt.derive_key(bad, b"", b"")) {
    Err(_) => ()
    Ok(_) => assert_eq(true, false, msg="expected InvalidParams")
  }
}

///|
test "scrypt: recommended_interactive returns log_n=15, r=8, p=1, dk_len=32" {
  let p = @scrypt.Params::recommended_interactive()
  assert_eq(p.log_n, 15)
  assert_eq(p.r, 8)
  assert_eq(p.p, 1)
  assert_eq(p.dk_len, 32)
}

///|
test "scrypt: small dkLen truncates" {
  // Same N=16, r=1, p=1 as vector 1 but dkLen=16 → matches the first 16 bytes
  // of expected.
  let params : @scrypt.Params = { log_n: 4, r: 1, p: 1, dk_len: 16 }
  let dk = @scrypt.derive_key(params, b"", b"")
  let expected : Bytes = b"\x77\xd6\x57\x62\x38\x65\x7b\x20\x3b\x19\xca\x42\xc1\x8a\x04\x97"
  assert_eq(dk, expected)
}
