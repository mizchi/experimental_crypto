// Whitebox tests for internal helpers.

///|
fn hex_wb(s : String) -> Bytes {
  let clean : Array[Char] = []
  for c in s {
    if c != ' ' {
      clean.push(c)
    }
  }
  let n = clean.length() / 2
  Bytes::makei(n, fn(i) {
    let hi = hex_nibble_wb(clean[i * 2])
    let lo = hex_nibble_wb(clean[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn hex_nibble_wb(c : Char) -> Int {
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
fn to_hex_wb(b : Bytes) -> String {
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
test "RFC 8439 §2.5.2 Poly1305 known-answer" {
  let key = hex_wb(
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
  )
  // "Cryptographic Forum Research Group"
  let msg_lit = b"Cryptographic Forum Research Group"
  let msg = Bytes::makei(msg_lit.length(), fn(i) { msg_lit[i] })
  let tag = poly1305(key, msg)
  assert_eq(to_hex_wb(tag), "a8061dc1305136c6c22b8baf0c0127a9")
}

///|
test "AES-128 FIPS 197 KAT" {
  // FIPS 197 §C.1 sample: 128-bit key, 128-bit PT.
  let key = hex_wb("2b7e151628aed2a6abf7158809cf4f3c")
  let pt = hex_wb("3243f6a8885a308d313198a2e0370734")
  let ct = aes_encrypt(key, pt)
  assert_eq(to_hex_wb(ct), "3925841d02dc09fbdc118597196a0b32")
}

///|
test "AES-128 NIST KAT zero key zero PT" {
  // AES-128 zero key, zero input → 66e94bd4ef8a2c3b884cfa59ca342b2e
  let key = Bytes::makei(16, fn(_) { b'\x00' })
  let pt = Bytes::makei(16, fn(_) { b'\x00' })
  let ct = aes_encrypt(key, pt)
  assert_eq(to_hex_wb(ct), "66e94bd4ef8a2c3b884cfa59ca342b2e")
}

///|
test "AES-128 NIST SP 800-38D B.1 known H and E_K(J0)" {
  let key = hex_wb("feffe9928665731c6d6a8f9467308308")
  let zero = Bytes::makei(16, fn(_) { b'\x00' })
  assert_eq(
    to_hex_wb(aes_encrypt(key, zero)),
    "b83b533708bf535d0aa6e52980d53b78",
  )
  let j0 = hex_wb("cafebabefacedbaddecaf88800000001")
  assert_eq(to_hex_wb(aes_encrypt(key, j0)), "3247184b3c4f69a44dbcd22887bbb418")
}

///|
test "gf128_mul identity (NIST polynomial 1)" {
  // The NIST "1" polynomial has X_0 = 1 (the leftmost / MSB of x_hi in big-endian
  // bit-order). X * H = H for X = (0x8000_0000_0000_0000, 0).
  let h_hi : UInt64 = 0xb83b533708bf535dUL
  let h_lo : UInt64 = 0x0aa6e52980d53b78UL
  let (z_hi, z_lo) = gf128_mul(0x8000000000000000UL, 0UL, h_hi, h_lo)
  assert_eq(z_hi, h_hi)
  assert_eq(z_lo, h_lo)
}

///|
test "gf128_mul X_1 NIST SP 800-38D Test Case 3 intermediate" {
  // X_1 = CT0 * H per NIST SP 800-38D Appendix B Test Case 3.
  let h_hi : UInt64 = 0xb83b533708bf535dUL
  let h_lo : UInt64 = 0x0aa6e52980d53b78UL
  let c_hi : UInt64 = 0x42831ec221777424UL
  let c_lo : UInt64 = 0x4b7221b784d0d49cUL
  let (z_hi, z_lo) = gf128_mul(c_hi, c_lo, h_hi, h_lo)
  let buf = FixedArray::make(16, b'\x00')
  be_store_u64(buf, 0, z_hi)
  be_store_u64(buf, 8, z_lo)
  let z = Bytes::makei(16, fn(i) { buf[i] })
  assert_eq(to_hex_wb(z), "59ed3f2bb1a0aaa07c9f56c6a504647b")
}

///|
test "GHASH empty empty = 0" {
  let h_hi : UInt64 = 0x12345678abcdef00UL
  let h_lo : UInt64 = 0xdeadbeefcafebabeUL
  let (g_hi, g_lo) = ghash(h_hi, h_lo, b"", b"")
  assert_eq(g_hi, 0UL)
  assert_eq(g_lo, 0UL)
}

///|
test "debug GHASH NIST Test Case 4 (with AAD)" {
  let key = hex_wb("feffe9928665731c6d6a8f9467308308")
  let zero16 = Bytes::makei(16, fn(_) { b'\x00' })
  let h = aes_encrypt(key, zero16)
  let h_hi = be_load_u64(h, 0)
  let h_lo = be_load_u64(h, 8)
  let aad = hex_wb("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let ct = hex_wb(
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e" +
    "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
  )
  let (ghash_hi, ghash_lo) = ghash(h_hi, h_lo, aad, ct)
  let g_buf = FixedArray::make(16, b'\x00')
  be_store_u64(g_buf, 0, ghash_hi)
  be_store_u64(g_buf, 8, ghash_lo)
  let g = Bytes::makei(16, fn(i) { g_buf[i] })
  // Expected GHASH(Case 4) = 698e57f70e6ecc7fd9463b7260a9ae5f
  assert_eq(to_hex_wb(g), "698e57f70e6ecc7fd9463b7260a9ae5f")
}

///|
test "RFC 8439 §2.6.2 Poly1305 key generation" {
  let key = hex_wb(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex_wb("000000000001020304050607")
  let otk = poly1305_key_gen(key, nonce)
  assert_eq(
    to_hex_wb(otk),
    "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646",
  )
}

///|
test "RFC 8439 §2.8.2 mac_data matches expected layout" {
  let aad = hex_wb("50515253c0c1c2c3c4c5c6c7")
  let ct = hex_wb(
    "d31a8d34648e60db7b86afbc53ef7ec2" +
    "a4aded51296e08fea9e2b5a736ee62d6" +
    "3dbea45e8ca9671282fafb69da92728b" +
    "1a71de0a9e060b2905d6a5b67ecd3b36" +
    "92ddbd7f2d778b8c9803aee328091b58" +
    "fab324e4fad675945585808b4831d7bc" +
    "3ff4def08e4b7a9de576d26586cec64b" +
    "6116",
  )
  // Reconstruct mac_data the same way poly1305_aead_tag does and inspect it.
  let aad_pad = (16 - aad.length() % 16) % 16
  let ct_pad = (16 - ct.length() % 16) % 16
  let total = aad.length() + aad_pad + ct.length() + ct_pad + 8 + 8
  let aad_len_off = aad.length() + aad_pad + ct.length() + ct_pad
  let ct_len_off = aad_len_off + 8
  let aad_len = aad.length().to_int64()
  let ct_len = ct.length().to_int64()
  let mac_data = Bytes::makei(total, fn(i) {
    if i < aad.length() {
      aad[i]
    } else if i < aad.length() + aad_pad {
      b'\x00'
    } else if i < aad.length() + aad_pad + ct.length() {
      ct[i - aad.length() - aad_pad]
    } else if i < aad_len_off {
      b'\x00'
    } else if i < ct_len_off {
      let shift = (i - aad_len_off) * 8
      ((aad_len >> shift) & 0xFFL).to_int().to_byte()
    } else {
      let shift = (i - ct_len_off) * 8
      ((ct_len >> shift) & 0xFFL).to_int().to_byte()
    }
  })
  // RFC 8439 §2.8.2: aad || pad16(aad) || ct || pad16(ct)
  //                  || len(aad)_LE_64 || len(ct)_LE_64
  // ct_pad = 14 zero bytes (since len(ct) = 114 ≡ 2 mod 16).
  let ct_pad_hex = "00000000000000000000000000000000".substring(end=28)
  let expected = "50515253c0c1c2c3c4c5c6c700000000" +
    "d31a8d34648e60db7b86afbc53ef7ec2" +
    "a4aded51296e08fea9e2b5a736ee62d6" +
    "3dbea45e8ca9671282fafb69da92728b" +
    "1a71de0a9e060b2905d6a5b67ecd3b36" +
    "92ddbd7f2d778b8c9803aee328091b58" +
    "fab324e4fad675945585808b4831d7bc" +
    "3ff4def08e4b7a9de576d26586cec64b" +
    "6116" +
    ct_pad_hex +
    "0c000000000000007200000000000000"
  assert_eq(to_hex_wb(mac_data), expected)
}

///|
test "RFC 8439 §2.8.2 poly1305_aead_tag matches expected" {
  // Use the otk that comes from key+nonce of §2.8.2.
  let key = hex_wb(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex_wb("070000004041424344454647")
  let otk = poly1305_key_gen(key, nonce)
  // RFC 8439 §2.8.2 says this OTK should be:
  //   7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff
  assert_eq(
    to_hex_wb(otk),
    "7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff",
  )
  let aad = hex_wb("50515253c0c1c2c3c4c5c6c7")
  let ct = hex_wb(
    "d31a8d34648e60db7b86afbc53ef7ec2" +
    "a4aded51296e08fea9e2b5a736ee62d6" +
    "3dbea45e8ca9671282fafb69da92728b" +
    "1a71de0a9e060b2905d6a5b67ecd3b36" +
    "92ddbd7f2d778b8c9803aee328091b58" +
    "fab324e4fad675945585808b4831d7bc" +
    "3ff4def08e4b7a9de576d26586cec64b" +
    "6116",
  )
  let tag = poly1305_aead_tag(otk, aad, ct)
  assert_eq(to_hex_wb(tag), "1ae10b594f09e26a7e902ecbd0600691")
}
