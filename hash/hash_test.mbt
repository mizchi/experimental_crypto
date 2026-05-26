// Test vectors:
//   - SHA-256, SHA-384, SHA-512 "abc" / "" from FIPS 180-4 appendix
//   - HMAC-SHA256 RFC 4231 test case 1

///|
fn hex_to_bytes(s : String) -> Bytes {
  fn nibble(c : Char) -> Int {
    let n = c.to_int()
    if n >= 0x30 && n <= 0x39 {
      n - 0x30
    } else if n >= 0x61 && n <= 0x66 {
      n - 0x61 + 10
    } else if n >= 0x41 && n <= 0x46 {
      n - 0x41 + 10
    } else {
      abort("bad hex")
    }
  }

  let len = s.length() / 2
  let out = FixedArray::make(len, b'\x00')
  let mut i = 0
  while i < len {
    let hi = nibble(s.get_char(i * 2).unwrap())
    let lo = nibble(s.get_char(i * 2 + 1).unwrap())
    out[i] = (hi * 16 + lo).to_byte()
    i = i + 1
  }
  Bytes::makei(len, fn(j) { out[j] })
}

///|
test "sha256: empty" {
  let h = @hash.sha256(b"")
  assert_eq(
    h,
    hex_to_bytes(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
  )
}

///|
test "sha256: abc" {
  let h = @hash.sha256(b"abc")
  assert_eq(
    h,
    hex_to_bytes(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
  )
}

///|
test "sha256: 1-million 'a'" {
  let buf = Bytes::makei(1_000_000, fn(_i) { b'a' })
  let h = @hash.sha256(buf)
  assert_eq(
    h,
    hex_to_bytes(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    ),
  )
}

///|
test "sha384: empty" {
  let h = @hash.sha384(b"")
  assert_eq(
    h,
    hex_to_bytes(
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    ),
  )
}

///|
test "sha384: abc" {
  let h = @hash.sha384(b"abc")
  assert_eq(
    h,
    hex_to_bytes(
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    ),
  )
}

///|
test "sha512: empty" {
  let h = @hash.sha512(b"")
  assert_eq(
    h,
    hex_to_bytes(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ),
  )
}

///|
test "sha512: abc" {
  let h = @hash.sha512(b"abc")
  assert_eq(
    h,
    hex_to_bytes(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
  )
}

///|
test "hmac_sha256: RFC 4231 case 1" {
  // key = 0x0b * 20, msg = "Hi There"
  let key = Bytes::makei(20, fn(_i) { b'\x0b' })
  let msg = b"Hi There"
  let tag = @hash.hmac_sha256(key, msg)
  assert_eq(
    tag,
    hex_to_bytes(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    ),
  )
}

///|
test "hmac_sha256: RFC 4231 case 4 (long msg)" {
  // key = 0x01..0x19, msg = 0xcd * 50
  let key = Bytes::makei(25, fn(i) { (i + 1).to_byte() })
  let msg = Bytes::makei(50, fn(_i) { b'\xcd' })
  let tag = @hash.hmac_sha256(key, msg)
  assert_eq(
    tag,
    hex_to_bytes(
      "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    ),
  )
}

///|
test "ct_eq: equal" {
  assert_true(@hash.ct_eq(b"abc", b"abc"))
}

///|
test "ct_eq: unequal same length" {
  assert_false(@hash.ct_eq(b"abc", b"abd"))
}

///|
test "ct_eq: different length" {
  assert_false(@hash.ct_eq(b"abc", b"abcd"))
}

///|
test "hmac_sha256_compute reuses context" {
  let ctx = @hash.hmac_sha256_init(b"key")
  let a = @hash.hmac_sha256_compute(ctx, b"msg1")
  let b = @hash.hmac_sha256_compute(ctx, b"msg2")
  let c = @hash.hmac_sha256_compute(ctx, b"msg1")
  assert_eq(a, c)
  assert_false(a == b)
}

///|
test "hmac_sha384: RFC 4231 case 1" {
  // key=0x0b*20, msg="Hi There"
  let key = Bytes::makei(20, fn(_) { b'\x0b' })
  let tag = @hash.hmac_sha384(key, b"Hi There")
  assert_eq(
    tag,
    hex_to_bytes(
      "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
    ),
  )
}

///|
test "hmac_sha512: RFC 4231 case 1" {
  let key = Bytes::makei(20, fn(_) { b'\x0b' })
  let tag = @hash.hmac_sha512(key, b"Hi There")
  assert_eq(
    tag,
    hex_to_bytes(
      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    ),
  )
}

///|
test "sha1: empty" {
  // FIPS 180-4 / RFC 3174: SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
  let h = @hash.sha1(b"")
  assert_eq(h, hex_to_bytes("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
}

///|
test "sha1: abc" {
  // FIPS 180-4 appendix A.1: SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
  let h = @hash.sha1(b"abc")
  assert_eq(h, hex_to_bytes("a9993e364706816aba3e25717850c26c9cd0d89d"))
}

///|
test "sha1: 448-bit message (multi-block)" {
  // FIPS 180-4 appendix A.2: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  // → 84983e441c3bd26ebaae4aa1f95129e5e54670f1
  let h = @hash.sha1(
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  )
  assert_eq(h, hex_to_bytes("84983e441c3bd26ebaae4aa1f95129e5e54670f1"))
}

///|
test "ripemd160: empty" {
  // Published vector: RIPEMD-160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
  let h = @hash.ripemd160(b"")
  assert_eq(h, hex_to_bytes("9c1185a5c5e9fc54612808977ee8f548b2258d31"))
}

///|
test "ripemd160: abc" {
  // RIPEMD-160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
  let h = @hash.ripemd160(b"abc")
  assert_eq(h, hex_to_bytes("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"))
}

///|
test "ripemd160: message digest" {
  // RIPEMD-160("message digest") = 5d0689ef49d2fae572b881b123a85ffa21595f36
  let h = @hash.ripemd160(b"message digest")
  assert_eq(h, hex_to_bytes("5d0689ef49d2fae572b881b123a85ffa21595f36"))
}

///|
test "ripemd160: 56-byte message (cross block boundary)" {
  // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56 bytes)
  // → 12a053384a9c0c88e405a06c27dcf49ada62eb2b
  let h = @hash.ripemd160(
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  )
  assert_eq(h, hex_to_bytes("12a053384a9c0c88e405a06c27dcf49ada62eb2b"))
}

///|
test "ripemd160: a-z lowercase" {
  // RIPEMD-160("abcdefghijklmnopqrstuvwxyz") = f71c27109c692c1b56bbdceb5b9d2865b3708dbc
  let h = @hash.ripemd160(b"abcdefghijklmnopqrstuvwxyz")
  assert_eq(h, hex_to_bytes("f71c27109c692c1b56bbdceb5b9d2865b3708dbc"))
}

///|
test "hash160: empty" {
  // hash160("") = ripemd160(sha256("")) = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
  let h = @hash.hash160(b"")
  assert_eq(h, hex_to_bytes("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"))
}
