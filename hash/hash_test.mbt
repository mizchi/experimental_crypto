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
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
  )
}

///|
test "sha256: abc" {
  let h = @hash.sha256(b"abc")
  @debug.assert_eq(
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
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    ),
  )
}

///|
test "sha384: empty" {
  let h = @hash.sha384(b"")
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    ),
  )
}

///|
test "sha384: abc" {
  let h = @hash.sha384(b"abc")
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    ),
  )
}

///|
test "sha512: empty" {
  let h = @hash.sha512(b"")
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ),
  )
}

///|
test "sha512: abc" {
  let h = @hash.sha512(b"abc")
  @debug.assert_eq(
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
  @debug.assert_eq(
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
  @debug.assert_eq(
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
  @debug.assert_eq(a, c)
  assert_false(a == b)
}

///|
test "hmac_sha384: RFC 4231 case 1" {
  // key=0x0b*20, msg="Hi There"
  let key = Bytes::makei(20, fn(_) { b'\x0b' })
  let tag = @hash.hmac_sha384(key, b"Hi There")
  @debug.assert_eq(
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
  @debug.assert_eq(
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
  @debug.assert_eq(h, hex_to_bytes("da39a3ee5e6b4b0d3255bfef95601890afd80709"))
}

///|
test "sha1: abc" {
  // FIPS 180-4 appendix A.1: SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
  let h = @hash.sha1(b"abc")
  @debug.assert_eq(h, hex_to_bytes("a9993e364706816aba3e25717850c26c9cd0d89d"))
}

///|
test "sha1: 448-bit message (multi-block)" {
  // FIPS 180-4 appendix A.2: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  // → 84983e441c3bd26ebaae4aa1f95129e5e54670f1
  let h = @hash.sha1(
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  )
  @debug.assert_eq(h, hex_to_bytes("84983e441c3bd26ebaae4aa1f95129e5e54670f1"))
}

///|
test "ripemd160: empty" {
  // Published vector: RIPEMD-160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
  let h = @hash.ripemd160(b"")
  @debug.assert_eq(h, hex_to_bytes("9c1185a5c5e9fc54612808977ee8f548b2258d31"))
}

///|
test "ripemd160: abc" {
  // RIPEMD-160("abc") = 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
  let h = @hash.ripemd160(b"abc")
  @debug.assert_eq(h, hex_to_bytes("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"))
}

///|
test "ripemd160: message digest" {
  // RIPEMD-160("message digest") = 5d0689ef49d2fae572b881b123a85ffa21595f36
  let h = @hash.ripemd160(b"message digest")
  @debug.assert_eq(h, hex_to_bytes("5d0689ef49d2fae572b881b123a85ffa21595f36"))
}

///|
test "ripemd160: 56-byte message (cross block boundary)" {
  // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56 bytes)
  // → 12a053384a9c0c88e405a06c27dcf49ada62eb2b
  let h = @hash.ripemd160(
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  )
  @debug.assert_eq(h, hex_to_bytes("12a053384a9c0c88e405a06c27dcf49ada62eb2b"))
}

///|
test "ripemd160: a-z lowercase" {
  // RIPEMD-160("abcdefghijklmnopqrstuvwxyz") = f71c27109c692c1b56bbdceb5b9d2865b3708dbc
  let h = @hash.ripemd160(b"abcdefghijklmnopqrstuvwxyz")
  @debug.assert_eq(h, hex_to_bytes("f71c27109c692c1b56bbdceb5b9d2865b3708dbc"))
}

///|
test "hash160: empty" {
  // hash160("") = ripemd160(sha256("")) = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
  let h = @hash.hash160(b"")
  @debug.assert_eq(h, hex_to_bytes("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"))
}

///|
test "blake2b: RFC 7693 §A.1 abc (64-byte digest)" {
  // BLAKE2b("abc", 64) =
  //   BA80A53F981C4D0D6A2797B69F12F6E9 4C212F14685AC4B74B12BB6FDBFFA2D1
  //   7D87C5392AAB792DC252D5DE4533CC95 18D38AA8DBF1925AB92386EDD4009923
  let h = @hash.blake2b(b"abc", 64)
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    ),
  )
}

///|
test "blake2b: empty input (BLAKE2b-512)" {
  // Reference vector from the BLAKE2 spec / OpenSSL EVP_blake2b512 of "":
  //   786A02F742015903C6C6FD852552D272 912F4740E15847618A86E217F71F5419
  //   D25E1031AFEE585313896444934EB04B 903A685B1448B755D56F701AFE9BE2CE
  let h = @hash.blake2b(b"", 64)
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    ),
  )
}

///|
test "blake2b_256: abc matches truncated 64-byte digest" {
  // BLAKE2b is a single algorithm — varying out_len just truncates / shrinks
  // the parameter block. Importantly, BLAKE2b(abc, 32) is NOT the same as the
  // first 32 bytes of BLAKE2b(abc, 64): the parameter block embeds out_len, so
  // out_len = 32 produces a different digest entirely. This test fixes the
  // 32-byte canonical value.
  let h = @hash.blake2b_256(b"abc")
  // Verified against Python hashlib.blake2b(b"abc", digest_size=32):
  //   bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    ),
  )
}

///|
test "blake2b_512: matches blake2b(_, 64)" {
  let a = @hash.blake2b_512(b"abc")
  let b = @hash.blake2b(b"abc", 64)
  @debug.assert_eq(a, b)
}

///|
test "blake2b: output length 1 (smallest)" {
  let h = @hash.blake2b(b"abc", 1)
  @debug.assert_eq(h.length(), 1)
}

///|
test "blake2b: out_len = 0 raises" {
  let result = try? @hash.blake2b(b"abc", 0)
  match result {
    Ok(_) => abort("expected error")
    Err(_) => ()
  }
}

///|
test "blake2b: out_len = 65 raises" {
  let result = try? @hash.blake2b(b"abc", 65)
  match result {
    Ok(_) => abort("expected error")
    Err(_) => ()
  }
}

///|
test "blake2b_keyed: key length 65 raises" {
  let key = Bytes::makei(65, fn(_) { b'\x00' })
  let result = try? @hash.blake2b_keyed(b"abc", key, 32)
  match result {
    Ok(_) => abort("expected error")
    Err(_) => ()
  }
}

///|
test "blake2b_keyed: empty key == unkeyed" {
  let a = @hash.blake2b_keyed(b"abc", b"", 32) catch {
    _ => abort("unexpected error")
  }
  let b = @hash.blake2b_256(b"abc")
  @debug.assert_eq(a, b)
}

///|
test "blake2b_keyed: different keys produce different outputs" {
  let k1 = b"key1"
  let k2 = b"key2"
  let a = @hash.blake2b_keyed(b"abc", k1, 32) catch {
    _ => abort("unexpected error")
  }
  let b = @hash.blake2b_keyed(b"abc", k2, 32) catch {
    _ => abort("unexpected error")
  }
  assert_false(a == b)
}

///|
test "blake2b_keyed: RFC 7693 §A.2 single-block keyed reference" {
  // Vector from the BLAKE2 reference suite (libsodium / openssl test):
  //   key = 64 bytes 0x00,0x01,...,0x3f
  //   input = empty
  //   BLAKE2b(in=empty, key, out_len=64) =
  //     10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786
  //     b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568
  let key = Bytes::makei(64, fn(i) { i.to_byte() })
  let h = @hash.blake2b_keyed(b"", key, 64) catch {
    _ => abort("unexpected error")
  }
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
    ),
  )
}

// ─── BLAKE3 ────────────────────────────────────────────────────────────────
//
// Vectors come from the official BLAKE3 reference test_vectors.json
// (https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json).
// Input convention: the i-th byte is `i mod 251` (so input[0]=0, input[1]=1,
// ..., input[250]=250, input[251]=0, ...).

///|
fn blake3_canonical_input(n : Int) -> Bytes {
  Bytes::makei(n, fn(i) { (i % 251).to_byte() })
}

///|
test "blake3: empty input → 32-byte digest" {
  // Official: input_len=0, hash[0..32] =
  //   af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
  let h = @hash.blake3(b"")
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    ),
  )
}

///|
test "blake3: 1-byte input" {
  // Official: input_len=1, hash[0..32] =
  //   2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213
  let h = @hash.blake3(blake3_canonical_input(1))
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
    ),
  )
}

///|
test "blake3: 63-byte input (single block - 1)" {
  // Official: input_len=63, hash[0..32] =
  //   e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b
  let h = @hash.blake3(blake3_canonical_input(63))
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
    ),
  )
}

///|
test "blake3: 64-byte input (exactly one block)" {
  // Official: input_len=64, hash[0..32] =
  //   4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98
  let h = @hash.blake3(blake3_canonical_input(64))
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
    ),
  )
}

///|
test "blake3: 1023-byte input (chunk boundary - 1)" {
  // Official: input_len=1023, hash[0..32] =
  //   10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11
  let h = @hash.blake3(blake3_canonical_input(1023))
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
    ),
  )
}

///|
test "blake3: 1024-byte input (exactly one chunk)" {
  // Official: input_len=1024, hash[0..32] =
  //   42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7
  let h = @hash.blake3(blake3_canonical_input(1024))
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
    ),
  )
}

///|
test "blake3: 1025-byte input (chunk boundary + 1)" {
  // Official: input_len=1025, hash[0..32] =
  //   d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444
  let h = @hash.blake3(blake3_canonical_input(1025))
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
    ),
  )
}

///|
test "blake3: 2048-byte input (two chunks)" {
  // Official: input_len=2048, hash[0..32] =
  //   e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a
  let h = @hash.blake3(blake3_canonical_input(2048))
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
    ),
  )
}

///|
test "blake3: 3072-byte input (three chunks, exercises cv_stack merging)" {
  // Official: input_len=3072, hash[0..32] =
  //   b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2
  let h = @hash.blake3(blake3_canonical_input(3072))
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
    ),
  )
}

///|
test "blake3: 5120-byte input (five chunks)" {
  // Official: input_len=5120, hash[0..32] =
  //   9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833
  let h = @hash.blake3(blake3_canonical_input(5120))
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833",
    ),
  )
}

///|
test "blake3: 31744-byte input (31 chunks, deep cv_stack)" {
  // Official: input_len=31744, hash[0..32] =
  //   62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47
  let h = @hash.blake3(blake3_canonical_input(31744))
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47",
    ),
  )
}

///|
test "blake3_xof: empty input, 131-byte output (exercises XOF counter)" {
  // The default 32-byte hash MUST equal the XOF output truncated to 32 bytes.
  let h_default = @hash.blake3(b"")
  let h_long = @hash.blake3_xof(b"", 131)
  @debug.assert_eq(h_long.length(), 131)
  let h_long_prefix = Bytes::makei(32, fn(i) { h_long[i] })
  @debug.assert_eq(h_long_prefix, h_default)
}

///|
test "blake3_xof: 0-byte output" {
  let h = @hash.blake3_xof(b"abc", 0)
  @debug.assert_eq(h.length(), 0)
}

///|
test "blake3_xof: agrees with blake3() at 32 bytes" {
  // For any input, blake3_xof(data, 32) MUST equal blake3(data).
  let data = blake3_canonical_input(100)
  let a = @hash.blake3(data)
  let b = @hash.blake3_xof(data, 32)
  @debug.assert_eq(a, b)
}

///|
test "blake3_keyed: 32-byte key, empty input" {
  // Official keyed vector: key = ASCII "whats the Elvish word for friend"
  //                       (exactly 32 bytes),  input_len = 0
  //   hash[0..32] =
  //   92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26
  let key = b"whats the Elvish word for friend"
  let h = @hash.blake3_keyed(key, b"", 32) catch {
    _ => abort("unexpected error")
  }
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
    ),
  )
}

///|
test "blake3_keyed: 32-byte key, 1-byte input" {
  // Official keyed: key = "whats the Elvish word for friend", input_len = 1
  //   hash[0..32] =
  //   6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b
  let key = b"whats the Elvish word for friend"
  let h = @hash.blake3_keyed(key, blake3_canonical_input(1), 32) catch {
    _ => abort("unexpected error")
  }
  @debug.assert_eq(
    h,
    hex_to_bytes(
      "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
    ),
  )
}

///|
test "blake3_keyed: wrong key length raises" {
  let result = try? @hash.blake3_keyed(b"short", b"abc", 32)
  match result {
    Ok(_) => abort("expected error")
    Err(_) => ()
  }
}

///|
test "blake3_derive_key: official KDF vector, empty material" {
  // Official KDF context: "BLAKE3 2019-12-27 16:29:52 test vectors context"
  //   key_material_len = 0
  //   derive_key[0..32] =
  //   2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d
  let ctx = "BLAKE3 2019-12-27 16:29:52 test vectors context"
  let dk = @hash.blake3_derive_key(ctx, b"")
  @debug.assert_eq(
    dk,
    hex_to_bytes(
      "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d",
    ),
  )
}

///|
test "blake3_derive_key: official KDF, 1-byte material" {
  // derive_key[0..32] for input_len=1:
  //   b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c
  let ctx = "BLAKE3 2019-12-27 16:29:52 test vectors context"
  let dk = @hash.blake3_derive_key(ctx, blake3_canonical_input(1))
  @debug.assert_eq(
    dk,
    hex_to_bytes(
      "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c",
    ),
  )
}

///|
test "blake3_derive_key: non-ASCII context uses UTF-8 bytes" {
  // Reference produced by the upstream Python `blake3` package with
  // derive_key_context="ctx-é" and input "material".
  let dk = @hash.blake3_derive_key("ctx-é", b"material")
  @debug.assert_eq(
    dk,
    hex_to_bytes(
      "ba663c284a2153ebb37628fd5403c82c0ec394fd80a7c8acb700f7b2e3d2a10b",
    ),
  )
}
