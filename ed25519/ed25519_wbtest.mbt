// Whitebox tests run within the package scope.

///|
fn fa_to_hex(fa : FixedArray[Byte]) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder::new()
  for i = 0; i < fa.length(); i = i + 1 {
    let b = fa[i].to_int()
    let hi = (b >> 4) & 0xF
    let lo = b & 0xF
    buf.write_char(digits.code_unit_at(hi).to_int() |> Int::unsafe_to_char)
    buf.write_char(digits.code_unit_at(lo).to_int() |> Int::unsafe_to_char)
  }
  buf.to_string()
}

///|
test "sha512 empty" {
  let out = sha512_bytes(b"")
  inspect(
    fa_to_hex(out),
    content="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  )
}

///|
test "sha512 abc" {
  let out = sha512_bytes(b"abc")
  inspect(
    fa_to_hex(out),
    content="ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
}

///|
test "sha512 32 bytes" {
  // SHA-512 of 32 zero bytes; well-known.
  let buf = FixedArray::make(32, b'\x00')
  let out = sha512_fa(buf)
  inspect(
    fa_to_hex(out),
    content="5046adc1dba838867b2bbbfdd0c3423e58b57970b5267a90f57960924a87f1960a6a85eaa642dac835424b5d7c8d637c00408c7a73da672b7f498521420b6dd3",
  )
}

///|
test "sha512 1000 'a'" {
  let buf = FixedArray::make(1000, b'a')
  let out = sha512_fa(buf)
  inspect(
    fa_to_hex(out),
    content="67ba5535a46e3f86dbfbed8cbbaf0125c76ed549ff8b0b9e03e0c88cf90fa634fa7b12b47d77b694de488ace8d9a65967dc96df599727d3292a8d9d447709c97",
  )
}

///|
test "sqrt(-1) squared equals -1" {
  // sanity-check the field constant
  let s = fe_mul(ed_sqrt_m1, ed_sqrt_m1)
  inspect(s == ed_p - BigInt::from_int(1), content="true")
}

///|
test "base point compresses+decompresses to itself" {
  let enc1 = point_compress(ed_base)
  let dec = point_decompress(enc1).unwrap()
  let enc2 = point_compress(dec)
  for i = 0; i < 32; i = i + 1 {
    assert_eq(enc1[i], enc2[i])
  }
}
