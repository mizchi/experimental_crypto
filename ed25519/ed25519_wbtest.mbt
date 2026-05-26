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
fn sha512_bytes_for_test(data : Bytes) -> FixedArray[Byte] {
  let ctx = SHA512::new()
  ctx.update_bytes(data)
  ctx.finalize()
}

///|
test "sha512 empty" {
  let out = sha512_bytes_for_test(b"")
  inspect(
    fa_to_hex(out),
    content="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  )
}

///|
test "sha512 abc" {
  let out = sha512_bytes_for_test(b"abc")
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
  // sanity-check the field constant: I^2 == -1 (mod p).
  let s = fe_mul(ed_sqrt_m1, ed_sqrt_m1)
  // -1 = p - 1; in canonical 32-byte LE form that is
  //   ec ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
  //   ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 7f
  let neg_one = FixedArray::make(32, b'\xff')
  neg_one[0] = b'\xec'
  neg_one[31] = b'\x7f'
  let bytes = fe_to_bytes(s)
  for i in 0..<32 {
    assert_eq(bytes[i], neg_one[i])
  }
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

///|
test "fe_cmov(a, b, 0) == a, fe_cmov(a, b, 1) == b" {
  let a = fe_one()
  let b = ed_d // arbitrary non-zero, non-one
  let r0 = fe_cmov(a, b, 0UL)
  let r1 = fe_cmov(a, b, 1UL)
  assert_true(fe_eq(r0, a))
  assert_true(fe_eq(r1, b))
}

///|
test "ed_point_cmov selects branch by bit" {
  let p = ed_identity()
  let q = ed_base
  let r0 = ed_point_cmov(p, q, 0UL)
  let r1 = ed_point_cmov(p, q, 1UL)
  assert_true(ed_points_equal(r0, p))
  assert_true(ed_points_equal(r1, q))
}

///|
test "ed_point_double of identity is identity (projectively)" {
  // Regression: a previous version of ed_point_double underflowed inside
  // fe_neg / fe_sub when the input point was the doubled-identity
  // `(0, -1, -1, 0)`. fe_sqr of the "p"-encoded zero produces limbs that,
  // after fe_add(a, b), exceed two_p_limb[0] and turn fe_neg into a
  // ~2^64-1 garbage limb. Fixed by canonicalizing ab and c2 with
  // fe_carry_full before the subtractions.
  let id = ed_identity()
  let d1 = ed_point_double(id)
  let d2 = ed_point_double(d1)
  let d3 = ed_point_double(d2)
  assert_true(ed_points_equal(d1, id))
  assert_true(ed_points_equal(d2, id))
  assert_true(ed_points_equal(d3, id))
}

///|
test "ed_scalar_mult_point: scalar 0 yields identity" {
  let r = ed_scalar_mult_point(BigInt::from_int(0), ed_base)
  assert_true(ed_points_equal(r, ed_identity()))
}

///|
test "ed_scalar_mult_point: scalar 1 yields base" {
  let r = ed_scalar_mult_point(BigInt::from_int(1), ed_base)
  assert_true(ed_points_equal(r, ed_base))
}

///|
test "ed_scalar_mult_point: scalar 2 yields 2*base" {
  let r = ed_scalar_mult_point(BigInt::from_int(2), ed_base)
  let expected = ed_point_double(ed_base)
  assert_true(ed_points_equal(r, expected))
}

///|
test "ed_scalar_mult_point: k*base for small k matches repeated addition" {
  // Cross-check the always-add ladder against the bare ed_point_add
  // chain for the first few multiples of the base point.
  let mut acc = ed_identity()
  for k = 0; k < 16; k = k + 1 {
    let r = ed_scalar_mult_point(BigInt::from_int(k), ed_base)
    assert_true(ed_points_equal(r, acc))
    acc = ed_point_add(acc, ed_base)
  }
}

///|
test "ed_scalar_mult_point: doubling commutes with the ladder" {
  // 2 * (k * B) == (2 * k) * B for a handful of k.
  for k = 1; k < 6; k = k + 1 {
    let kp = ed_scalar_mult_point(BigInt::from_int(k), ed_base)
    let doubled = ed_point_double(kp)
    let two_k = ed_scalar_mult_point(BigInt::from_int(2 * k), ed_base)
    assert_true(ed_points_equal(doubled, two_k))
  }
}
