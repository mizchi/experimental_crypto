// P-384 homogeneous-projective point helpers backed by `crypto_bigint.Uint`.
//
// This mirrors the P-256 complete-addition scalar path, but uses 6 fixed
// 64-bit limbs directly instead of a dedicated radix field implementation.
// It is fixed-iteration / branchless-intended, not externally measured
// constant-clock.

///|
type Fe384 = @crypto_bigint.Uint

///|
priv struct Fe384Point {
  x : Fe384
  y : Fe384
  z : Fe384
}

///|
fn fe384_p_uint() -> Fe384 {
  {
    limbs: [
      0x00000000ffffffffUL, 0xffffffff00000000UL, 0xfffffffffffffffeUL, 0xffffffffffffffffUL,
      0xffffffffffffffffUL, 0xffffffffffffffffUL,
    ],
  }
}

///|
fn fe384_b_uint() -> Fe384 {
  {
    limbs: [
      0x2a85c8edd3ec2aefUL, 0xc656398d8a2ed19dUL, 0x0314088f5013875aUL, 0x181d9c6efe814112UL,
      0x988e056be3f82d19UL, 0xb3312fa7e23ee7e4UL,
    ],
  }
}

///|
fn fe384_zero() -> Fe384 {
  @crypto_bigint.Uint::zero(6)
}

///|
fn fe384_one() -> Fe384 {
  @crypto_bigint.Uint::one(6)
}

///|
fn fe384_from_bigint(v : BigInt) -> Fe384 {
  @crypto_bigint.Uint::from_be_bytes(v.to_octets(length=48), 6) catch {
    _ => abort("P-384 field element must fit 48 bytes")
  }
}

///|
fn fe384_to_bigint(v : Fe384) -> BigInt {
  fixed_bigint_from_octets(v.to_be_bytes()[:])
}

///|
fn fe384_is_zero(v : Fe384) -> Bool {
  @crypto_bigint.Uint::ct_eq(v, fe384_zero())
}

///|
fn fe384_select(a : Fe384, b : Fe384, bit : UInt64) -> Fe384 {
  @crypto_bigint.Uint::ct_select(a, b, bit)
}

///|
fn fe384_add(a : Fe384, b : Fe384) -> Fe384 {
  a.add_mod(b, fe384_p_uint())
}

///|
fn fe384_sub(a : Fe384, b : Fe384) -> Fe384 {
  a.sub_mod(b, fe384_p_uint())
}

///|
fn fe384_neg(a : Fe384) -> Fe384 {
  fe384_zero().sub_mod(a, fe384_p_uint())
}

///|
fn fe384_mul(a : Fe384, b : Fe384) -> Fe384 {
  a.mul_mod(b, fe384_p_uint())
}

///|
fn fe384_inv(a : Fe384) -> Fe384 {
  a.inv_mod(fe384_p_uint()) catch {
    _ => abort("P-384 field inverse does not exist")
  }
}

///|
fn fe384_mul_small(a : Fe384, n : Int) -> Fe384 {
  let mut r = fe384_zero()
  for _ in 0..<n {
    r = fe384_add(r, a)
  }
  r
}

///|
fn fe384_mul_minus3(a : Fe384) -> Fe384 {
  fe384_neg(fe384_mul_small(a, 3))
}

///|
fn fe384_b3() -> Fe384 {
  fe384_mul_small(fe384_b_uint(), 3)
}

///|
fn fe384_point_infinity() -> Fe384Point {
  { x: fe384_zero(), y: fe384_one(), z: fe384_zero() }
}

///|
fn fe384_point_is_infinity(p : Fe384Point) -> Bool {
  fe384_is_zero(p.z)
}

///|
#warnings("-unused_value")
fn fe384_point_select(
  a : Fe384Point,
  b : Fe384Point,
  bit : UInt64,
) -> Fe384Point {
  {
    x: fe384_select(a.x, b.x, bit),
    y: fe384_select(a.y, b.y, bit),
    z: fe384_select(a.z, b.z, bit),
  }
}

///|
#warnings("-unused_value")
fn fe384_point_from_affine(p : Point) -> Fe384Point {
  if p.inf {
    fe384_point_infinity()
  } else {
    { x: fe384_from_bigint(p.x), y: fe384_from_bigint(p.y), z: fe384_one() }
  }
}

///|
#warnings("-unused_value")
fn fe384_point_to_affine(p : Fe384Point) -> Point {
  if fe384_point_is_infinity(p) {
    return point_infinity()
  }
  let z_inv = fe384_inv(p.z)
  {
    x: fe384_to_bigint(fe384_mul(p.x, z_inv)),
    y: fe384_to_bigint(fe384_mul(p.y, z_inv)),
    inf: false,
  }
}

///|
#warnings("-unused_value")
fn fe384_point_add_complete(p : Fe384Point, q : Fe384Point) -> Fe384Point {
  // Renes-Costello-Batina 2015 complete addition formula for prime-order
  // short Weierstrass curves in homogeneous projective coordinates. P-384 has
  // a = -3; the formula uses b3 = 3*b.
  let b3 = fe384_b3()
  let mut t0 = fe384_mul(p.x, q.x)
  let mut t1 = fe384_mul(p.y, q.y)
  let mut t2 = fe384_mul(p.z, q.z)
  let mut t3 = fe384_add(p.x, p.y)
  let mut t4 = fe384_add(q.x, q.y)
  t3 = fe384_mul(t3, t4)
  t4 = fe384_add(t0, t1)
  t3 = fe384_sub(t3, t4)
  t4 = fe384_add(p.x, p.z)
  let mut t5 = fe384_add(q.x, q.z)
  t4 = fe384_mul(t4, t5)
  t5 = fe384_add(t0, t2)
  t4 = fe384_sub(t4, t5)
  t5 = fe384_add(p.y, p.z)
  let mut x3 = fe384_add(q.y, q.z)
  t5 = fe384_mul(t5, x3)
  x3 = fe384_add(t1, t2)
  t5 = fe384_sub(t5, x3)
  let mut z3 = fe384_mul_minus3(t4)
  x3 = fe384_mul(b3, t2)
  z3 = fe384_add(x3, z3)
  x3 = fe384_sub(t1, z3)
  z3 = fe384_add(t1, z3)
  let mut y3 = fe384_mul(x3, z3)
  t1 = fe384_add(t0, t0)
  t1 = fe384_add(t1, t0)
  t2 = fe384_mul_minus3(t2)
  t4 = fe384_mul(b3, t4)
  t1 = fe384_add(t1, t2)
  t2 = fe384_sub(t0, t2)
  t2 = fe384_mul_minus3(t2)
  t4 = fe384_add(t4, t2)
  t0 = fe384_mul(t1, t4)
  y3 = fe384_add(y3, t0)
  t0 = fe384_mul(t5, t4)
  x3 = fe384_mul(t3, x3)
  x3 = fe384_sub(x3, t0)
  t0 = fe384_mul(t3, t1)
  z3 = fe384_mul(t5, z3)
  z3 = fe384_add(z3, t0)
  { x: x3, y: y3, z: z3 }
}

///|
fn fe384_scalar_bit_be48(bytes : Bytes, bit_index : Int) -> UInt64 {
  let byte_index = bit_index / 8
  let bit_in_byte = 7 - bit_index % 8
  ((bytes[byte_index].to_int() >> bit_in_byte) & 1).to_uint64()
}

///|
#warnings("-unused_value")
fn fe384_scalar_mult_fixed_complete(k : BigInt, p : Fe384Point) -> Fe384Point {
  let bytes = k.to_octets(length=48)
  let mut r = fe384_point_infinity()
  for bit_index = 0; bit_index < 384; bit_index = bit_index + 1 {
    let doubled = fe384_point_add_complete(r, r)
    let added = fe384_point_add_complete(doubled, p)
    r = fe384_point_select(
      doubled,
      added,
      fe384_scalar_bit_be48(bytes, bit_index),
    )
  }
  r
}

///|
#warnings("-unused_value")
fn fe384_scalar_mult_base_fixed(k : BigInt) -> Point {
  fe384_point_to_affine(
    fe384_scalar_mult_fixed_complete(k, fe384_point_from_affine(generator())),
  )
}
