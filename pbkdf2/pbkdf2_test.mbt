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
test "pbkdf2: SHA-1/384/512 are unsupported (placeholders)" {
  try @pbkdf2.pbkdf2(Sha1, b"p", b"s", 1, 20) catch {
    _ => ()
  } noraise {
    _ => @debug.assert_eq(true, false, msg="expected UnsupportedHash for Sha1")
  }
  try @pbkdf2.pbkdf2(Sha384, b"p", b"s", 1, 48) catch {
    _ => ()
  } noraise {
    _ =>
      @debug.assert_eq(true, false, msg="expected UnsupportedHash for Sha384")
  }
}
