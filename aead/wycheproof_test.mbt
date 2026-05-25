// Google Project Wycheproof external test vectors for ChaCha20-Poly1305.
// Source: https://github.com/google/wycheproof/blob/main/testvectors_v1/chacha20_poly1305_test.json
//
// Selection: 14 valid vectors covering key/nonce/aad/msg-length boundaries plus
// a 114-byte RFC 7539 KTV; 8 invalid vectors covering modified tags and
// non-12-byte nonce sizes.

///|
fn wp_concat(a : Bytes, b : Bytes) -> Bytes {
  let an = a.length()
  let bn = b.length()
  Bytes::makei(an + bn, fn(i) { if i < an { a[i] } else { b[i - an] } })
}

///|
test "wycheproof chacha20_poly1305 tcId=1 (valid)" {
  // RFC 7539
  // flags: Ktv
  let key : Bytes = b"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
  let iv : Bytes = b"\x07\x00\x00\x00\x40\x41\x42\x43\x44\x45\x46\x47"
  let aad : Bytes = b"\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7"
  let msg : Bytes = b"\x4c\x61\x64\x69\x65\x73\x20\x61\x6e\x64\x20\x47\x65\x6e\x74\x6c\x65\x6d\x65\x6e\x20\x6f\x66\x20\x74\x68\x65\x20\x63\x6c\x61\x73\x73\x20\x6f\x66\x20\x27\x39\x39\x3a\x20\x49\x66\x20\x49\x20\x63\x6f\x75\x6c\x64\x20\x6f\x66\x66\x65\x72\x20\x79\x6f\x75\x20\x6f\x6e\x6c\x79\x20\x6f\x6e\x65\x20\x74\x69\x70\x20\x66\x6f\x72\x20\x74\x68\x65\x20\x66\x75\x74\x75\x72\x65\x2c\x20\x73\x75\x6e\x73\x63\x72\x65\x65\x6e\x20\x77\x6f\x75\x6c\x64\x20\x62\x65\x20\x69\x74\x2e"
  let ct : Bytes = b"\xd3\x1a\x8d\x34\x64\x8e\x60\xdb\x7b\x86\xaf\xbc\x53\xef\x7e\xc2\xa4\xad\xed\x51\x29\x6e\x08\xfe\xa9\xe2\xb5\xa7\x36\xee\x62\xd6\x3d\xbe\xa4\x5e\x8c\xa9\x67\x12\x82\xfa\xfb\x69\xda\x92\x72\x8b\x1a\x71\xde\x0a\x9e\x06\x0b\x29\x05\xd6\xa5\xb6\x7e\xcd\x3b\x36\x92\xdd\xbd\x7f\x2d\x77\x8b\x8c\x98\x03\xae\xe3\x28\x09\x1b\x58\xfa\xb3\x24\xe4\xfa\xd6\x75\x94\x55\x85\x80\x8b\x48\x31\xd7\xbc\x3f\xf4\xde\xf0\x8e\x4b\x7a\x9d\xe5\x76\xd2\x65\x86\xce\xc6\x4b\x61\x16"
  let tag : Bytes = b"\x1a\xe1\x0b\x59\x4f\x09\xe2\x6a\x7e\x90\x2e\xcb\xd0\x60\x06\x91"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=2 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\x80\xba\x31\x92\xc8\x03\xce\x96\x5e\xa3\x71\xd5\xff\x07\x3c\xf0\xf4\x3b\x6a\x2a\xb5\x76\xb2\x08\x42\x6e\x11\x40\x9c\x09\xb9\xb0"
  let iv : Bytes = b"\x4d\xa5\xbf\x8d\xfd\x58\x52\xc1\xea\x12\x37\x9d"
  let aad : Bytes = b""
  let msg : Bytes = b""
  let ct : Bytes = b""
  let tag : Bytes = b"\x76\xac\xb3\x42\xcf\x31\x66\xa5\xb6\x3c\x0c\x0e\xa1\x38\x3c\x8d"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=3 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\x7a\x4c\xd7\x59\x17\x2e\x02\xeb\x20\x4d\xb2\xc3\xf5\xc7\x46\x22\x7d\xf5\x84\xfc\x13\x45\x19\x63\x91\xdb\xb9\x57\x7a\x25\x07\x42"
  let iv : Bytes = b"\xa9\x2e\xf0\xac\x99\x1d\xd5\x16\xa3\xc6\xf6\x89"
  let aad : Bytes = b"\xbd\x50\x67\x64\xf2\xd2\xc4\x10"
  let msg : Bytes = b""
  let ct : Bytes = b""
  let tag : Bytes = b"\x90\x6f\xa6\x28\x4b\x52\xf8\x7b\x73\x59\xcb\xaa\x75\x63\xc7\x09"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=4 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\xcc\x56\xb6\x80\x55\x2e\xb7\x50\x08\xf5\x48\x4b\x4c\xb8\x03\xfa\x50\x63\xeb\xd6\xea\xb9\x1f\x6a\xb6\xae\xf4\x91\x6a\x76\x62\x73"
  let iv : Bytes = b"\x99\xe2\x3e\xc4\x89\x85\xbc\xcd\xee\xab\x60\xf1"
  let aad : Bytes = b""
  let msg : Bytes = b"\x2a"
  let ct : Bytes = b"\x3a"
  let tag : Bytes = b"\xca\xc2\x7d\xec\x09\x68\x80\x1e\x9f\x6e\xde\xd6\x9d\x80\x75\x22"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=7 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\xc8\x83\x3d\xce\x5e\xa9\xf2\x48\xaa\x20\x30\xea\xcf\xe7\x2b\xff\xe6\x9a\x62\x0c\xaf\x79\x33\x44\xe5\x71\x8f\xe0\xd7\xab\x1a\x58"
  let iv : Bytes = b"\x61\x54\x6b\xa5\xf1\x72\x05\x90\xb6\x04\x0a\xc6"
  let aad : Bytes = b"\x88\x36\x4f\xc8\x06\x05\x18\xbf"
  let msg : Bytes = b"\xdd\xf2"
  let ct : Bytes = b"\xb6\x0d"
  let tag : Bytes = b"\xea\xd0\xfd\x46\x97\xec\x2e\x55\x58\x23\x77\x19\xd0\x24\x37\xa2"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=19 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\x11\x31\xc1\x41\x85\x77\xa0\x54\xde\x7a\x4a\xc5\x51\x95\x0f\x1a\x05\x3f\x9a\xe4\x6e\x5b\x75\xfe\x4a\xbd\x56\x08\xd7\xcd\xda\xdd"
  let iv : Bytes = b"\xb4\xea\x66\x6e\xe1\x19\x56\x33\x66\x48\x4a\x78"
  let aad : Bytes = b"\x66\xc0\xae\x70\x07\x6c\xb1\x4d"
  let msg : Bytes = b"\xa4\xc9\xc2\x80\x1b\x71\xf7\xdf"
  let ct : Bytes = b"\xb9\xb9\x10\x43\x3a\xf0\x52\xb0"
  let tag : Bytes = b"\x45\x30\xf5\x1a\xee\xe0\x24\xe0\xa4\x45\xa6\x32\x8f\xa6\x7a\x18"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=30 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\x47\x0f\x9c\xe3\xd2\x25\x0b\xd6\x0c\xbb\xef\xdb\x2e\x6a\x11\x78\xc0\x12\x29\x9b\x55\x90\x63\x9c\x77\x97\xb6\x02\x4f\xa7\x03\xd8"
  let iv : Bytes = b"\xa9\xea\x4d\x61\x9f\xe4\x05\xd0\x4c\xba\x7d\x7a"
  let aad : Bytes = b""
  let msg : Bytes = b"\x6c\xa6\x7d\xd0\x23\xfb\xa6\x50\x7b\x9f\x9a\x1f\x66\x7e"
  let ct : Bytes = b"\xd3\x01\x7e\x0b\xb1\x70\x5b\x38\x0b\x34\xcc\x33\x34\x50"
  let tag : Bytes = b"\x57\x08\xe7\x2c\xa2\xbd\x35\x4f\x48\x7f\x82\xf6\x7f\xbc\x3a\xcb"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=34 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\x59\xd4\xea\xfb\x4d\xe0\xcf\xc7\xd3\xdb\x99\xa8\xf5\x4b\x15\xd7\xb3\x9f\x0a\xcc\x8d\xa6\x97\x63\xb0\x19\xc1\x69\x9f\x87\x67\x4a"
  let iv : Bytes = b"\x2f\xcb\x1b\x38\xa9\x9e\x71\xb8\x47\x40\xad\x9b"
  let aad : Bytes = b""
  let msg : Bytes = b"\x54\x9b\x36\x5a\xf9\x13\xf3\xb0\x81\x13\x1c\xcb\x6b\x82\x55\x88"
  let ct : Bytes = b"\xe9\x11\x0e\x9f\x56\xab\x3c\xa4\x83\x50\x0c\xea\xba\xb6\x7a\x13"
  let tag : Bytes = b"\x83\x6c\xca\xbf\x15\xa6\xa2\x2a\x51\xc1\x07\x1c\xfa\x68\xfa\x0c"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=35 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\xb9\x07\xa4\x50\x75\x51\x3f\xe8\xa8\x01\x9e\xde\xe3\xf2\x59\x14\x87\xb2\xa0\x30\xb0\x3c\x6e\x1d\x77\x1c\x86\x25\x71\xd2\xea\x1e"
  let iv : Bytes = b"\x11\x8a\x69\x64\xc2\xd3\xe3\x80\x07\x1f\x52\x66"
  let aad : Bytes = b"\x03\x45\x85\x62\x1a\xf8\xd7\xff"
  let msg : Bytes = b"\x55\xa4\x65\x64\x4f\x5b\x65\x09\x28\xcb\xee\x7c\x06\x32\x14\xd6"
  let ct : Bytes = b"\xe4\xb1\x13\xcb\x77\x59\x45\xf3\xd3\xa8\xae\x9e\xc1\x41\xc0\x0c"
  let tag : Bytes = b"\x7c\x43\xf1\x6c\xe0\x96\xd0\xdc\x27\xc9\x58\x49\xdc\x38\x3b\x7d"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=38 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\x37\xce\xb5\x74\xcc\xb0\xb7\x01\xdd\x11\x36\x93\x88\xca\x27\x10\x17\x32\x33\x9f\x49\xd8\xd9\x08\xac\xe4\xb2\x3a\xf0\xb7\xce\x89"
  let iv : Bytes = b"\x37\x27\x0b\x36\x8f\x6b\x1e\x3e\x2c\xa5\x17\x44"
  let aad : Bytes = b""
  let msg : Bytes = b"\xf2\x69\x91\x53\x72\x57\x37\x81\x51\xf4\x77\x6a\xad\x28\xae\x8b\xd1\x6b"
  let ct : Bytes = b"\xb6\x21\xd7\x6a\x8d\xac\xff\x00\xb3\xf8\x40\xcd\xf2\x6c\x89\x4c\xc5\xd1"
  let tag : Bytes = b"\xe0\xa2\x17\x16\xed\x94\xc0\x38\x2f\xa9\xb0\x90\x3d\x15\xbb\x68"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=39 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\x68\x88\x83\x61\x91\x9b\xc1\x06\x22\xf4\x5d\xf1\x68\xe5\xf6\xa0\x3b\xd8\xe8\x84\xc0\x61\x1b\xea\x2f\x34\xc1\x88\x2e\xd9\x83\x2b"
  let iv : Bytes = b"\xbf\xd6\xff\x40\xf2\xdf\x8c\xa7\x84\x59\x80\xcc"
  let aad : Bytes = b"\xb8\x37\x34\x38\xdd\xb2\xd6\xc3"
  let msg : Bytes = b"\xff\x97\xf2\xee\xfb\x34\x01\xac\x31\xfc\x8d\xc1\x59\x0d\x1a\x92\xcb\xc1"
  let ct : Bytes = b"\xe0\xa7\x45\x18\x6c\x1a\x7b\x14\x7f\x74\xfa\xff\x2a\x71\x5d\xf5\xc1\x9d"
  let tag : Bytes = b"\x91\x7b\xaf\x70\x3e\x35\x5d\x4d\x95\x0e\x6c\x05\xfe\x8f\x34\x9f"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=47 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\xa6\x09\x24\x10\x1b\x42\xac\x24\x15\x4a\x88\xde\x42\x14\x2b\x23\x34\xcf\x59\x91\x76\xca\xf4\xd1\x22\x6f\x71\x2d\xd9\x17\x29\x30"
  let iv : Bytes = b"\x8b\xa7\x76\x44\xb0\x8d\x65\xd5\xe9\xf3\x19\x42"
  let aad : Bytes = b"\xb2\xa4\xe1\x2a\x19\xa6\x1c\x75"
  let msg : Bytes = b"\xc9\x49\x95\x7e\x66\x43\x9d\xee\xe4\xb2\xac\x1d\x4a\x6c\x98\xa6\xc5\x27\xb9\x0f\x52\xab"
  let ct : Bytes = b"\xdb\x4c\x70\x05\x13\x81\x89\x72\xb0\xdc\x0e\x53\x1b\x1c\x28\x1c\xa0\x3e\x40\xc6\x0d\xea"
  let tag : Bytes = b"\x63\xf4\x47\x8b\xba\x2a\xf4\x69\xa7\xa4\xdc\x3b\x4f\x14\x13\x60"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=72 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\x5b\x1d\x10\x35\xc0\xb1\x7e\xe0\xb0\x44\x47\x67\xf8\x0a\x25\xb8\xc1\xb7\x41\xf4\xb5\x0a\x4d\x30\x52\x22\x6b\xaa\x1c\x6f\xb7\x01"
  let iv : Bytes = b"\xd6\x10\x40\xa3\x13\xed\x49\x28\x23\xcc\x06\x5b"
  let aad : Bytes = b""
  let msg : Bytes = b"\xd0\x96\x80\x31\x81\xbe\xef\x9e\x00\x8f\xf8\x5d\x5d\xdc\x38\xdd\xac\xf0\xf0\x9e\xe5\xf7\xe0\x7f\x1e\x40\x79\xcb\x64\xd0\xdc\x8f\x5e\x67\x11\xcd\x49\x21\xa7\x88\x7d\xe7\x6e\x26\x78\xfd\xc6\x76\x18\xf1\x18\x55\x86\xbf\xea\x9d\x4c\x68\x5d\x50\xe4\xbb\x9a\x82"
  let ct : Bytes = b"\x9a\x4e\xf2\x2b\x18\x16\x77\xb5\x75\x5c\x08\xf7\x47\xc0\xf8\xd8\xe8\xd4\xc1\x8a\x9c\xc2\x40\x5c\x12\xbb\x51\xbb\x18\x72\xc8\xe8\xb8\x77\x67\x8b\xec\x44\x2c\xfc\xbb\x0f\xf4\x64\xa6\x4b\x74\x33\x2c\xf0\x72\x89\x8c\x7e\x0e\xdd\xf6\x23\x2e\xa6\xe2\x7e\xfe\x50"
  let tag : Bytes = b"\x9f\xf3\x42\x7a\x0f\x32\xfa\x56\x6d\x9c\xa0\xa7\x8a\xef\xc0\x13"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=73 (valid)" {
  // flags: Pseudorandom
  let key : Bytes = b"\x97\xd6\x35\xc4\xf4\x75\x74\xd9\x99\x8a\x90\x87\x5d\xa1\xd3\xa2\x84\xb7\x55\xb2\xd3\x92\x97\xa5\x72\x52\x35\x19\x0e\x10\xa9\x7e"
  let iv : Bytes = b"\xd3\x1c\x21\xab\xa1\x75\xb7\x0d\xe4\xeb\xb1\x9c"
  let aad : Bytes = b"\x71\x93\xf6\x23\x66\x33\x21\xa2"
  let msg : Bytes = b"\x94\xee\x16\x6d\x6d\x6e\xcf\x88\x32\x43\x71\x36\xb4\xae\x80\x5d\x42\x88\x64\x35\x95\x86\xd9\x19\x3a\x25\x01\x62\x93\xed\xba\x44\x3c\x58\xe0\x7e\x7b\x71\x95\xec\x5b\xd8\x45\x82\xa9\xd5\x6c\x8d\x4a\x10\x8c\x7d\x7c\xe3\x4e\x6c\x6f\x8e\xa1\xbe\xc0\x56\x73\x17"
  let ct : Bytes = b"\x5f\xbb\xde\xcc\x34\xbe\x20\x16\x14\xf6\x36\x03\x1e\xeb\x42\xf1\xca\xce\x3c\x79\xa1\x2c\xff\xd8\x71\xee\x8e\x73\x82\x0c\x82\x97\x49\xf1\xab\xb4\x29\x43\x67\x84\x9f\xb6\xc2\xaa\x56\xbd\xa8\xa3\x07\x8f\x72\x3d\x7c\x1c\x85\x20\x24\xb0\x17\xb5\x89\x73\xfb\x1e"
  let tag : Bytes = b"\x09\x26\x3d\xa7\xb4\xcb\x92\x14\x52\xf9\x7d\xca\x40\xf5\x80\xec"
  let expected_sealed = wp_concat(ct, tag)
  let sealed = @aead.seal(@aead.ChaCha20Poly1305, key, iv, aad, msg)
  assert_eq(sealed, expected_sealed)
  let opened = @aead.open(@aead.ChaCha20Poly1305, key, iv, aad, expected_sealed)
  assert_eq(opened, msg)
}

///|
test "wycheproof chacha20_poly1305 tcId=146 (invalid)" {
  // Flipped bit 0 in tag expected tag:f4409bb729039d0814ac514054323f44
  // flags: ModifiedTag
  let key : Bytes = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  let iv : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
  let aad : Bytes = b"\x00\x01\x02"
  let ct : Bytes = b""
  let tag : Bytes = b"\xf5\x40\x9b\xb7\x29\x03\x9d\x08\x14\xac\x51\x40\x54\x32\x3f\x44"
  let sealed = wp_concat(ct, tag)
  let result : Result[Bytes, @aead.AeadError] = try? @aead.open(
    @aead.ChaCha20Poly1305,
    key,
    iv,
    aad,
    sealed,
  )
  match result {
    Err(@aead.AuthenticationFailed) => ()
    Err(e) => abort("expected AuthenticationFailed, got " + e.to_string())
    Ok(_) => abort("expected rejection but open succeeded")
  }
}

///|
test "wycheproof chacha20_poly1305 tcId=166 (invalid)" {
  // Flipped bit 0 in tag expected tag:29914007a6119dd3f109bba21ce9a7d6
  // flags: ModifiedTag
  let key : Bytes = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  let iv : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
  let aad : Bytes = b"\x00\x01\x02"
  let ct : Bytes = b"\xd0\x3b\xcb\x3c\xa5\x2d\x48\xd1\xd2\x03\xb1\xe7\xb1\xa5\x99\x5a"
  let tag : Bytes = b"\x28\x91\x40\x07\xa6\x11\x9d\xd3\xf1\x09\xbb\xa2\x1c\xe9\xa7\xd6"
  let sealed = wp_concat(ct, tag)
  let result : Result[Bytes, @aead.AeadError] = try? @aead.open(
    @aead.ChaCha20Poly1305,
    key,
    iv,
    aad,
    sealed,
  )
  match result {
    Err(@aead.AuthenticationFailed) => ()
    Err(e) => abort("expected AuthenticationFailed, got " + e.to_string())
    Ok(_) => abort("expected rejection but open succeeded")
  }
}

///|
test "wycheproof chacha20_poly1305 tcId=317 (invalid)" {
  // nonce has size 0.
  // flags: InvalidNonceSize
  let key : Bytes = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  let iv : Bytes = b""
  let aad : Bytes = b""
  let ct : Bytes = b""
  let tag : Bytes = b""
  let sealed = wp_concat(ct, tag)
  // Implementation must reject the non-12-byte nonce.
  let result : Result[Bytes, @aead.AeadError] = try? @aead.open(
    @aead.ChaCha20Poly1305,
    key,
    iv,
    aad,
    sealed,
  )
  match result {
    Err(@aead.InvalidNonceSize(_)) => ()
    Err(@aead.CiphertextTooShort) => ()
    Err(e) => abort("expected InvalidNonceSize, got " + e.to_string())
    Ok(_) => abort("expected rejection but open succeeded")
  }
}

///|
test "wycheproof chacha20_poly1305 tcId=318 (invalid)" {
  // nonce has size 8.
  // flags: InvalidNonceSize
  let key : Bytes = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  let iv : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07"
  let aad : Bytes = b""
  let ct : Bytes = b""
  let tag : Bytes = b""
  let sealed = wp_concat(ct, tag)
  // Implementation must reject the non-12-byte nonce.
  let result : Result[Bytes, @aead.AeadError] = try? @aead.open(
    @aead.ChaCha20Poly1305,
    key,
    iv,
    aad,
    sealed,
  )
  match result {
    Err(@aead.InvalidNonceSize(_)) => ()
    Err(@aead.CiphertextTooShort) => ()
    Err(e) => abort("expected InvalidNonceSize, got " + e.to_string())
    Ok(_) => abort("expected rejection but open succeeded")
  }
}

///|
test "wycheproof chacha20_poly1305 tcId=320 (invalid)" {
  // nonce has size 13.
  // flags: InvalidNonceSize
  let key : Bytes = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  let iv : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
  let aad : Bytes = b""
  let ct : Bytes = b""
  let tag : Bytes = b""
  let sealed = wp_concat(ct, tag)
  // Implementation must reject the non-12-byte nonce.
  let result : Result[Bytes, @aead.AeadError] = try? @aead.open(
    @aead.ChaCha20Poly1305,
    key,
    iv,
    aad,
    sealed,
  )
  match result {
    Err(@aead.InvalidNonceSize(_)) => ()
    Err(@aead.CiphertextTooShort) => ()
    Err(e) => abort("expected InvalidNonceSize, got " + e.to_string())
    Ok(_) => abort("expected rejection but open succeeded")
  }
}

///|
test "wycheproof chacha20_poly1305 tcId=322 (invalid)" {
  // nonce has size 16.
  // flags: InvalidNonceSize
  let key : Bytes = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  let iv : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  let aad : Bytes = b""
  let ct : Bytes = b""
  let tag : Bytes = b""
  let sealed = wp_concat(ct, tag)
  // Implementation must reject the non-12-byte nonce.
  let result : Result[Bytes, @aead.AeadError] = try? @aead.open(
    @aead.ChaCha20Poly1305,
    key,
    iv,
    aad,
    sealed,
  )
  match result {
    Err(@aead.InvalidNonceSize(_)) => ()
    Err(@aead.CiphertextTooShort) => ()
    Err(e) => abort("expected InvalidNonceSize, got " + e.to_string())
    Ok(_) => abort("expected rejection but open succeeded")
  }
}

///|
test "wycheproof chacha20_poly1305 tcId=323 (invalid)" {
  // nonce has size 24.
  // flags: InvalidNonceSize
  let key : Bytes = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  let iv : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17"
  let aad : Bytes = b""
  let ct : Bytes = b""
  let tag : Bytes = b""
  let sealed = wp_concat(ct, tag)
  // Implementation must reject the non-12-byte nonce.
  let result : Result[Bytes, @aead.AeadError] = try? @aead.open(
    @aead.ChaCha20Poly1305,
    key,
    iv,
    aad,
    sealed,
  )
  match result {
    Err(@aead.InvalidNonceSize(_)) => ()
    Err(@aead.CiphertextTooShort) => ()
    Err(e) => abort("expected InvalidNonceSize, got " + e.to_string())
    Ok(_) => abort("expected rejection but open succeeded")
  }
}

///|
test "wycheproof chacha20_poly1305 tcId=325 (invalid)" {
  // nonce has size 32.
  // flags: InvalidNonceSize
  let key : Bytes = b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  let iv : Bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
  let aad : Bytes = b""
  let ct : Bytes = b""
  let tag : Bytes = b""
  let sealed = wp_concat(ct, tag)
  // Implementation must reject the non-12-byte nonce.
  let result : Result[Bytes, @aead.AeadError] = try? @aead.open(
    @aead.ChaCha20Poly1305,
    key,
    iv,
    aad,
    sealed,
  )
  match result {
    Err(@aead.InvalidNonceSize(_)) => ()
    Err(@aead.CiphertextTooShort) => ()
    Err(e) => abort("expected InvalidNonceSize, got " + e.to_string())
    Ok(_) => abort("expected rejection but open succeeded")
  }
}
