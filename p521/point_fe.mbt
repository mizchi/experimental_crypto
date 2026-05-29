// P-521 homogeneous-projective point helpers backed by `crypto_bigint.Uint`.
//
// This mirrors the P-384 complete-addition scalar path, but uses 9 fixed
// 64-bit limbs in Montgomery form. It is fixed-iteration /
// branchless-intended, not externally measured constant-clock.

///|
type Fe521 = @crypto_bigint.Uint

///|
priv struct Fe521Point {
  x : Fe521
  y : Fe521
  z : Fe521
}

///|
fn fe521_p_uint() -> Fe521 {
  {
    limbs: [
      0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL,
      0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL,
      0x00000000000001ffUL,
    ],
  }
}

///|
fn fe521_mont() -> @crypto_bigint.Montgomery {
  @crypto_bigint.Montgomery::{
    modulus: fe521_p_uint(),
    r2: {
      limbs: [0UL, 0x0000_4000_0000_0000UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL],
    },
    inv: 1UL,
  }
}

///|
fn fe521_zero() -> Fe521 {
  @crypto_bigint.Uint::zero(9)
}

///|
fn fe521_one() -> Fe521 {
  { limbs: [0x0080_0000_0000_0000UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL] }
}

///|
fn fe521_b3() -> Fe521 {
  {
    limbs: [
      0x803d_2fef_0b09_2a95UL, 0x6ae6_e7af_bea0_f85eUL, 0x8ad0_2dcf_4c5b_c24fUL,
      0x38a1_7c21_1bd9_8a9eUL, 0xd201_25d5_fae2_bdddUL, 0xed95_0ece_5a56_698eUL,
      0x65f4_47ab_8966_8ca0UL, 0x2f5b_e732_7111_c7e1UL, 0x0000_0000_0000_00e7UL,
    ],
  }
}

///|
fn fe521_u64_lt_01(a : UInt64, b : UInt64) -> UInt64 {
  let diff = a - b
  (((a.lnot() & b) | ((a ^ b).lnot() & diff)) >> 63) & 1UL
}

///|
fn fe521_select_u64(a : UInt64, b : UInt64, bit : UInt64) -> UInt64 {
  let mask = 0UL - (bit & 1UL)
  (a & mask.lnot()) | (b & mask)
}

///|
fn fe521_add_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> (FixedArray[UInt64], UInt64) {
  let out = FixedArray::make(9, 0UL)
  let mut carry = 0UL
  for i = 0; i < 9; i = i + 1 {
    let av = a[i]
    let bv = b[i]
    let s1 = av + bv
    let c1 = fe521_u64_lt_01(s1, av)
    let s2 = s1 + carry
    let c2 = fe521_u64_lt_01(s2, s1)
    out[i] = s2
    carry = c1 | c2
  }
  (out, carry)
}

///|
fn fe521_sub_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> (FixedArray[UInt64], UInt64) {
  let out = FixedArray::make(9, 0UL)
  let mut borrow = 0UL
  for i = 0; i < 9; i = i + 1 {
    let av = a[i]
    let bv = b[i]
    let d1 = av - bv
    let b1 = fe521_u64_lt_01(av, bv)
    let d2 = d1 - borrow
    let b2 = fe521_u64_lt_01(d1, borrow)
    out[i] = d2
    borrow = b1 | b2
  }
  (out, borrow)
}

///|
fn fe521_select_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  bit : UInt64,
) -> FixedArray[UInt64] {
  let out = FixedArray::make(9, 0UL)
  for i = 0; i < 9; i = i + 1 {
    out[i] = fe521_select_u64(a[i], b[i], bit)
  }
  out
}

///|
fn fe521_from_bigint(v : BigInt) -> Fe521 {
  let x = @crypto_bigint.Uint::from_be_bytes(v.to_octets(length=66), 9) catch {
    _ => abort("P-521 field element must fit 66 bytes")
  }
  fe521_mont().to_mont(x)
}

///|
fn fe521_to_bigint(v : Fe521) -> BigInt {
  fixed_bigint_from_octets(fe521_mont().from_mont(v).to_be_bytes()[:])
}

///|
fn fe521_is_zero(v : Fe521) -> Bool {
  @crypto_bigint.Uint::ct_eq(v, fe521_zero())
}

///|
fn fe521_select(a : Fe521, b : Fe521, bit : UInt64) -> Fe521 {
  { limbs: fe521_select_limbs(a.limbs, b.limbs, bit) }
}

///|
fn fe521_add(a : Fe521, b : Fe521) -> Fe521 {
  let (sum, carry) = fe521_add_limbs(a.limbs, b.limbs)
  let (reduced, borrow) = fe521_sub_limbs(sum, fe521_p_uint().limbs)
  { limbs: fe521_select_limbs(sum, reduced, carry | (borrow ^ 1UL)) }
}

///|
fn fe521_sub(a : Fe521, b : Fe521) -> Fe521 {
  let (diff, borrow) = fe521_sub_limbs(a.limbs, b.limbs)
  let (wrapped, _) = fe521_add_limbs(diff, fe521_p_uint().limbs)
  { limbs: fe521_select_limbs(diff, wrapped, borrow) }
}

///|
fn fe521_neg(a : Fe521) -> Fe521 {
  fe521_sub(fe521_zero(), a)
}

///|
fn fe521_mul(a : Fe521, b : Fe521) -> Fe521 {
  fe521_mont().mul_reduced(a, b)
}

///|
fn fe521_inv(a : Fe521) -> Fe521 {
  let normal = fe521_mont().from_mont(a)
  let inv = normal.inv_mod(fe521_p_uint()) catch {
    _ => abort("P-521 field inverse does not exist")
  }
  fe521_mont().to_mont(inv)
}

///|
fn fe521_mul_small(a : Fe521, n : Int) -> Fe521 {
  let mut r = fe521_zero()
  for _ in 0..<n {
    r = fe521_add(r, a)
  }
  r
}

///|
fn fe521_mul_minus3(a : Fe521) -> Fe521 {
  fe521_neg(fe521_mul_small(a, 3))
}

///|
fn fe521_point_infinity() -> Fe521Point {
  { x: fe521_zero(), y: fe521_one(), z: fe521_zero() }
}

///|
fn fe521_point_is_infinity(p : Fe521Point) -> Bool {
  fe521_is_zero(p.z)
}

///|
#warnings("-unused_value")
fn fe521_point_select(
  a : Fe521Point,
  b : Fe521Point,
  bit : UInt64,
) -> Fe521Point {
  {
    x: fe521_select(a.x, b.x, bit),
    y: fe521_select(a.y, b.y, bit),
    z: fe521_select(a.z, b.z, bit),
  }
}

///|
#warnings("-unused_value")
fn fe521_point_from_affine(p : Point) -> Fe521Point {
  if p.inf {
    fe521_point_infinity()
  } else {
    { x: fe521_from_bigint(p.x), y: fe521_from_bigint(p.y), z: fe521_one() }
  }
}

///|
#warnings("-unused_value")
fn fe521_point_to_affine(p : Fe521Point) -> Point {
  if fe521_point_is_infinity(p) {
    return point_infinity()
  }
  let z_inv = fe521_inv(p.z)
  {
    x: fe521_to_bigint(fe521_mul(p.x, z_inv)),
    y: fe521_to_bigint(fe521_mul(p.y, z_inv)),
    inf: false,
  }
}

///|
#warnings("-unused_value")
fn fe521_point_add_complete(p : Fe521Point, q : Fe521Point) -> Fe521Point {
  // Renes-Costello-Batina 2015 complete addition formula for prime-order
  // short Weierstrass curves in homogeneous projective coordinates. P-521 has
  // a = -3; the formula uses b3 = 3*b.
  let b3 = fe521_b3()
  let mut t0 = fe521_mul(p.x, q.x)
  let mut t1 = fe521_mul(p.y, q.y)
  let mut t2 = fe521_mul(p.z, q.z)
  let mut t3 = fe521_add(p.x, p.y)
  let mut t4 = fe521_add(q.x, q.y)
  t3 = fe521_mul(t3, t4)
  t4 = fe521_add(t0, t1)
  t3 = fe521_sub(t3, t4)
  t4 = fe521_add(p.x, p.z)
  let mut t5 = fe521_add(q.x, q.z)
  t4 = fe521_mul(t4, t5)
  t5 = fe521_add(t0, t2)
  t4 = fe521_sub(t4, t5)
  t5 = fe521_add(p.y, p.z)
  let mut x3 = fe521_add(q.y, q.z)
  t5 = fe521_mul(t5, x3)
  x3 = fe521_add(t1, t2)
  t5 = fe521_sub(t5, x3)
  let mut z3 = fe521_mul_minus3(t4)
  x3 = fe521_mul(b3, t2)
  z3 = fe521_add(x3, z3)
  x3 = fe521_sub(t1, z3)
  z3 = fe521_add(t1, z3)
  let mut y3 = fe521_mul(x3, z3)
  t1 = fe521_add(t0, t0)
  t1 = fe521_add(t1, t0)
  t2 = fe521_mul_minus3(t2)
  t4 = fe521_mul(b3, t4)
  t1 = fe521_add(t1, t2)
  t2 = fe521_sub(t0, t2)
  t2 = fe521_mul_minus3(t2)
  t4 = fe521_add(t4, t2)
  t0 = fe521_mul(t1, t4)
  y3 = fe521_add(y3, t0)
  t0 = fe521_mul(t5, t4)
  x3 = fe521_mul(t3, x3)
  x3 = fe521_sub(x3, t0)
  t0 = fe521_mul(t3, t1)
  z3 = fe521_mul(t5, z3)
  z3 = fe521_add(z3, t0)
  { x: x3, y: y3, z: z3 }
}

///|
fn fe521_scalar_bit_be66(bytes : Bytes, bit_index : Int) -> UInt64 {
  let byte_index = bit_index / 8
  let bit_in_byte = 7 - bit_index % 8
  ((bytes[byte_index].to_int() >> bit_in_byte) & 1).to_uint64()
}

///|
#warnings("-unused_value")
fn fe521_scalar_mult_fixed_complete(k : BigInt, p : Fe521Point) -> Fe521Point {
  let bytes = k.to_octets(length=66)
  let mut r = fe521_point_infinity()
  for bit_index = 0; bit_index < 528; bit_index = bit_index + 1 {
    let doubled = fe521_point_add_complete(r, r)
    let added = fe521_point_add_complete(doubled, p)
    r = fe521_point_select(
      doubled,
      added,
      fe521_scalar_bit_be66(bytes, bit_index),
    )
  }
  r
}

///|
#warnings("-unused_value")
fn fe521_scalar_mult_base_fixed(k : BigInt) -> Point {
  fe521_point_to_affine(
    fe521_scalar_mult_fixed_complete(k, fe521_point_from_affine(generator())),
  )
}
