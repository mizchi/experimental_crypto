// Blackbox tests run against the package's public API. Use `@crypto_bigint` to import.
// Prefer high-level behaviors over implementation details.
// Run `moon test` to execute and `moon test --update` to refresh snapshots.

///|
fn make_uint(limb_count : Int, limbs : Array[UInt64]) -> @crypto_bigint.Uint {
  let arr = FixedArray::make(limb_count, 0UL)
  for i in 0..<limbs.length() {
    if i < limb_count {
      arr[i] = limbs[i]
    }
  }
  { limbs: arr }
}

///|
test "zero and one constructors" {
  let z = @crypto_bigint.Uint::zero(4)
  let o = @crypto_bigint.Uint::one(4)
  @debug.assert_eq(z.bit_len(), 0)
  @debug.assert_eq(o.bit_len(), 1)
  assert_true(z != o)
  assert_true(@crypto_bigint.Uint::ct_eq(z, @crypto_bigint.Uint::zero(4)))
  assert_true(@crypto_bigint.Uint::ct_eq(o, @crypto_bigint.Uint::one(4)))
}

///|
test "bit_len" {
  @debug.assert_eq(@crypto_bigint.Uint::zero(4).bit_len(), 0)
  @debug.assert_eq(@crypto_bigint.Uint::one(4).bit_len(), 1)
  // 0x80 in the lowest limb → 8 bits.
  let v = make_uint(2, [0x80UL])
  @debug.assert_eq(v.bit_len(), 8)
  // bit in second limb.
  let v2 = make_uint(2, [0UL, 1UL])
  @debug.assert_eq(v2.bit_len(), 65)
  let v3 = make_uint(2, [0UL, 0x8000_0000_0000_0000UL])
  @debug.assert_eq(v3.bit_len(), 128)
}

///|
test "from_be_bytes / to_be_bytes round-trip" {
  let bytes : Bytes = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
    0x54, 0x32, 0x10,
  ]
  let u = @crypto_bigint.Uint::from_be_bytes(bytes, 2)
  let out = u.to_be_bytes()
  @debug.assert_eq(out.length(), 16)
  for i in 0..<16 {
    @debug.assert_eq(out[i], bytes[i])
  }
}

///|
test "from_le_bytes / to_le_bytes round-trip" {
  let bytes : Bytes = [
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67,
    0x45, 0x23, 0x01,
  ]
  let u = @crypto_bigint.Uint::from_le_bytes(bytes, 2)
  let out = u.to_le_bytes()
  @debug.assert_eq(out.length(), 16)
  for i in 0..<16 {
    @debug.assert_eq(out[i], bytes[i])
  }
}

///|
test "be / le encode the same number" {
  let be : Bytes = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
    0x54, 0x32, 0x10,
  ]
  let le : Bytes = [
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67,
    0x45, 0x23, 0x01,
  ]
  let from_be = @crypto_bigint.Uint::from_be_bytes(be, 2)
  let from_le = @crypto_bigint.Uint::from_le_bytes(le, 2)
  assert_true(@crypto_bigint.Uint::ct_eq(from_be, from_le))
}

///|
test "from_be_bytes shorter than limb capacity" {
  // 3 bytes => 0x010203, still fits in 1 limb.
  let bytes : Bytes = [0x01, 0x02, 0x03]
  let u = @crypto_bigint.Uint::from_be_bytes(bytes, 2)
  @debug.assert_eq(u.bit_len(), 17)
  // to_be_bytes always pads to full limb width.
  let out = u.to_be_bytes()
  @debug.assert_eq(out.length(), 16)
  // The low 3 bytes should be 0x01,0x02,0x03 and the rest zero.
  for i in 0..<13 {
    @debug.assert_eq(out[i], b'\x00')
  }
  @debug.assert_eq(out[13], b'\x01')
  @debug.assert_eq(out[14], b'\x02')
  @debug.assert_eq(out[15], b'\x03')
}

///|
test "from_be_bytes rejects oversized input" {
  let too_big : Bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]
  let res = try? @crypto_bigint.Uint::from_be_bytes(too_big, 1)
  match res {
    Err(_) => ()
    Ok(_) => assert_true(false)
  }
}

///|
test "ct_lt ordering" {
  let a = make_uint(2, [5UL])
  let b = make_uint(2, [7UL])
  let c = make_uint(2, [5UL])
  let d = make_uint(2, [0UL, 1UL])
  assert_true(@crypto_bigint.Uint::ct_lt(a, b))
  assert_true(!@crypto_bigint.Uint::ct_lt(b, a))
  assert_true(!@crypto_bigint.Uint::ct_lt(a, c))
  assert_true(@crypto_bigint.Uint::ct_lt(b, d))
  assert_true(!@crypto_bigint.Uint::ct_lt(d, b))
}

///|
test "add_mod" {
  let a = make_uint(2, [100UL])
  let b = make_uint(2, [200UL])
  let m = make_uint(2, [97UL])
  // (100 + 200) % 97 = 300 % 97 = 9.
  let r = @crypto_bigint.Uint::add_mod(a, b, m)
  assert_true(@crypto_bigint.Uint::ct_eq(r, make_uint(2, [9UL])))
}

///|
test "sub_mod with wrap" {
  let a = make_uint(2, [3UL])
  let b = make_uint(2, [10UL])
  let m = make_uint(2, [97UL])
  // (3 - 10) mod 97 = 90.
  let r = @crypto_bigint.Uint::sub_mod(a, b, m)
  assert_true(@crypto_bigint.Uint::ct_eq(r, make_uint(2, [90UL])))
}

///|
test "mul_mod" {
  let a = make_uint(2, [123UL])
  let b = make_uint(2, [456UL])
  let m = make_uint(2, [1009UL])
  // (123 * 456) % 1009 = 56088 % 1009 = 56088 - 55 * 1009 = 56088 - 55495 = 593.
  let r = @crypto_bigint.Uint::mul_mod(a, b, m)
  assert_true(@crypto_bigint.Uint::ct_eq(r, make_uint(2, [593UL])))
}

///|
test "pow_mod fermat" {
  // 3^(p-1) mod p == 1 for prime p = 1009.
  let g = make_uint(2, [3UL])
  let p = make_uint(2, [1009UL])
  let e = make_uint(2, [1008UL])
  let r = @crypto_bigint.Uint::pow_mod(g, e, p)
  assert_true(@crypto_bigint.Uint::ct_eq(r, @crypto_bigint.Uint::one(2)))
}

///|
test "pow_mod base case" {
  let g = make_uint(2, [5UL])
  let p = make_uint(2, [97UL])
  let e0 = @crypto_bigint.Uint::zero(2)
  // x^0 == 1.
  let r0 = @crypto_bigint.Uint::pow_mod(g, e0, p)
  assert_true(@crypto_bigint.Uint::ct_eq(r0, @crypto_bigint.Uint::one(2)))
  // x^1 == x % p.
  let e1 = @crypto_bigint.Uint::one(2)
  let r1 = @crypto_bigint.Uint::pow_mod(g, e1, p)
  assert_true(@crypto_bigint.Uint::ct_eq(r1, g))
}

///|
test "inv_mod product is one" {
  let a = make_uint(2, [123UL])
  let m = make_uint(2, [1_000_003UL]) // prime
  let inv = a.inv_mod(m)
  let prod = a.mul_mod(inv, m)
  assert_true(@crypto_bigint.Uint::ct_eq(prod, @crypto_bigint.Uint::one(2)))
}

///|
test "inv_mod rejects non-coprime" {
  let a = make_uint(2, [6UL])
  let m = make_uint(2, [9UL]) // gcd(6, 9) = 3
  let res = try? a.inv_mod(m)
  match res {
    Err(_) => ()
    Ok(_) => assert_true(false)
  }
}

///|
test "Montgomery round-trip and mul" {
  let m = make_uint(2, [1_000_003UL])
  let mont = @crypto_bigint.Montgomery::new(m)
  let a = make_uint(2, [12345UL])
  let b = make_uint(2, [67890UL])
  // (a * b) % m via the Montgomery wrapper should match plain mul_mod.
  let mont_a = mont.to_mont(a)
  let mont_b = mont.to_mont(b)
  let prod_m = mont.mul(mont_a, mont_b)
  let prod = mont.from_mont(prod_m)
  let expected = a.mul_mod(b, m)
  assert_true(@crypto_bigint.Uint::ct_eq(prod, expected))
}

///|
test "Montgomery pow matches pow_mod" {
  let m = make_uint(2, [1_000_003UL])
  let mont = @crypto_bigint.Montgomery::new(m)
  let g = make_uint(2, [7UL])
  let e = make_uint(2, [12345UL])
  let r1 = mont.pow(g, e)
  let r2 = g.pow_mod(e, m)
  assert_true(@crypto_bigint.Uint::ct_eq(r1, r2))
}

///|
test "Show prints hex" {
  let u = make_uint(2, [0xDEAD_BEEFUL])
  let s = u.to_string()
  // Top limb (limb 1) is 0 -> printed unpadded as "0".
  // Bottom limb (limb 0) is 0xdeadbeef -> printed padded to 16 hex chars.
  @debug.assert_eq(s, "0x000000000deadbeef")
}

///|
test "Show prints zero" {
  let z = @crypto_bigint.Uint::zero(2)
  let s = z.to_string()
  // Top limb 0 unpadded -> "0"; second limb padded to 16 zeros.
  @debug.assert_eq(s, "0x00000000000000000")
}
