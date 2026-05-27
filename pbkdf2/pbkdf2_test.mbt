// PBKDF2-HMAC-SHA256 test vectors. RFC 6070 only covers SHA-1, but
// RFC 7914 §11 publishes vectors for SHA-256 (used by scrypt internally).

///|
test "pbkdf2: RFC 7914 §11 vector 1 (P=passwd, S=salt, c=1, dkLen=64)" {
  let dk = @pbkdf2.pbkdf2(Sha256, b"passwd", b"salt", 1, 64)
  let expected : Bytes = b"\x55\xac\x04\x6e\x56\xe3\x08\x9f\xec\x16\x91\xc2\x25\x44\xb6\x05\xf9\x41\x85\x21\x6d\xde\x04\x65\xe6\x8b\x9d\x57\xc2\x0d\xac\xbc\x49\xca\x9c\xcc\xf1\x79\xb6\x45\x99\x16\x64\xb3\x9d\x77\xef\x31\x7c\x71\xb8\x45\xb1\xe3\x0b\xd5\x09\x11\x20\x41\xd3\xa1\x97\x83"
  @debug.assert_eq(dk, expected)
}

///|
test "pbkdf2: RFC 7914 §11 vector 2 (P=Password, S=NaCl, c=80000, dkLen=64)" {
  let dk = @pbkdf2.pbkdf2(Sha256, b"Password", b"NaCl", 80000, 64)
  let expected : Bytes = b"\x4d\xdc\xd8\xf6\x0b\x98\xbe\x21\x83\x0c\xee\x5e\xf2\x27\x01\xf9\x64\x1a\x44\x18\xd0\x4c\x04\x14\xae\xff\x08\x87\x6b\x34\xab\x56\xa1\xd4\x25\xa1\x22\x58\x33\x54\x9a\xdb\x84\x1b\x51\xc9\xb3\x17\x6a\x27\x2b\xde\xbb\xa1\xd0\x78\x47\x8f\x62\xb3\x97\xf3\x3c\x8d"
  @debug.assert_eq(dk, expected)
}

///|
test "pbkdf2: dk_len shorter than one block (truncates)" {
  let dk = @pbkdf2.pbkdf2(Sha256, b"passwd", b"salt", 1, 10)
  let expected : Bytes = b"\x55\xac\x04\x6e\x56\xe3\x08\x9f\xec\x16"
  @debug.assert_eq(dk, expected)
}

///|
test "pbkdf2: dk_len exactly one block" {
  let dk = @pbkdf2.pbkdf2(Sha256, b"passwd", b"salt", 1, 32)
  let expected : Bytes = b"\x55\xac\x04\x6e\x56\xe3\x08\x9f\xec\x16\x91\xc2\x25\x44\xb6\x05\xf9\x41\x85\x21\x6d\xde\x04\x65\xe6\x8b\x9d\x57\xc2\x0d\xac\xbc"
  @debug.assert_eq(dk, expected)
}

///|
test "pbkdf2: rejects iterations < 1" {
  try @pbkdf2.pbkdf2(Sha256, b"p", b"s", 0, 32) catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidIterations")
  }
}

///|
test "pbkdf2: rejects negative dk_len" {
  try @pbkdf2.pbkdf2(Sha256, b"p", b"s", 1, -1) catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected InvalidLength")
  }
}

///|
test "pbkdf2: HMAC-SHA1 RFC 6070 vector 1" {
  let dk = @pbkdf2.pbkdf2(Sha1, b"password", b"salt", 1, 20)
  let expected : Bytes = b"\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6"
  @debug.assert_eq(dk, expected)
}

///|
test "pbkdf2: HMAC-SHA384 vector" {
  let dk = @pbkdf2.pbkdf2(Sha384, b"password", b"salt", 1, 48)
  let expected : Bytes = b"\xc0\xe1\x4f\x06\xe4\x9e\x32\xd7\x3f\x9f\x52\xdd\xf1\xd0\xc5\xc7\x19\x16\x09\x23\x36\x31\xda\xdd\x76\xa5\x67\xdb\x42\xb7\x86\x76\xb3\x8f\xc8\x00\xcc\x53\xdd\xb6\x42\xf5\xc7\x44\x42\xe6\x2b\xe4"
  @debug.assert_eq(dk, expected)
}

///|
test "pbkdf2: HMAC-SHA512 vector" {
  let dk = @pbkdf2.pbkdf2(Sha512, b"password", b"salt", 1, 64)
  let expected : Bytes = b"\x86\x7f\x70\xcf\x1a\xde\x02\xcf\xf3\x75\x25\x99\xa3\xa5\x3d\xc4\xaf\x34\xc7\xa6\x69\x81\x5a\xe5\xd5\x13\x55\x4e\x1c\x8c\xf2\x52\xc0\x2d\x47\x0a\x28\x5a\x05\x01\xba\xd9\x99\xbf\xe9\x43\xc0\x8f\x05\x02\x35\xd7\xd6\x8b\x1d\xa5\x5e\x63\xf7\x3b\x60\xa5\x7f\xce"
  @debug.assert_eq(dk, expected)
}
