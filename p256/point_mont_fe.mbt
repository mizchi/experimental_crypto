// P-256 homogeneous-projective point helpers backed by crypto_bigint
// Montgomery-domain field elements.
//
// The older `point_fe.mbt` keeps the 10-limb field rewrite and its oracle
// tests. This file is the sign-side fast path: fixed-width Montgomery
// multiplication avoids the generic `mul_mod` reducer used by that interim
// field implementation. It is fixed-iteration / branchless-intended, not
// externally measured constant-clock.

///|
type Fe256Mont = @crypto_bigint.Uint

///|
priv struct Fe256MontPoint {
  x : Fe256Mont
  y : Fe256Mont
  z : Fe256Mont
}

///|
fn fe_mont_p_uint() -> Fe256Mont {
  {
    limbs: [
      0xffffffffffffffffUL, 0x00000000ffffffffUL, 0x0000000000000000UL, 0xffffffff00000001UL,
    ],
  }
}

///|
fn fe_mont_ctx() -> @crypto_bigint.Montgomery {
  @crypto_bigint.Montgomery::{
    modulus: fe_mont_p_uint(),
    r2: {
      limbs: [
        0x0000000000000003UL, 0xfffffffbffffffffUL, 0xfffffffffffffffeUL, 0x00000004fffffffdUL,
      ],
    },
    inv: 0x0000000000000001UL,
  }
}

///|
fn fe_mont_zero() -> Fe256Mont {
  @crypto_bigint.Uint::zero(4)
}

///|
fn fe_mont_one() -> Fe256Mont {
  {
    limbs: [
      0x0000000000000001UL, 0xffffffff00000000UL, 0xffffffffffffffffUL, 0x00000000fffffffeUL,
    ],
  }
}

///|
fn fe_mont_b3() -> Fe256Mont {
  {
    limbs: [
      0x89d69e267d4e399fUL, 0x06d01166698c91b2UL, 0xb0e66203e5638c84UL, 0x949012590d95d89cUL,
    ],
  }
}

///|
fn fe_mont_u64_lt_01(a : UInt64, b : UInt64) -> UInt64 {
  let diff = a - b
  (((a.lnot() & b) | ((a ^ b).lnot() & diff)) >> 63) & 1UL
}

///|
fn fe_mont_select_u64(a : UInt64, b : UInt64, bit : UInt64) -> UInt64 {
  let mask = 0UL - (bit & 1UL)
  (a & mask.lnot()) | (b & mask)
}

///|
fn fe_mont_add_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> (FixedArray[UInt64], UInt64) {
  let out = FixedArray::make(4, 0UL)
  let mut carry = 0UL
  for i = 0; i < 4; i = i + 1 {
    let av = a[i]
    let bv = b[i]
    let s1 = av + bv
    let c1 = fe_mont_u64_lt_01(s1, av)
    let s2 = s1 + carry
    let c2 = fe_mont_u64_lt_01(s2, s1)
    out[i] = s2
    carry = c1 | c2
  }
  (out, carry)
}

///|
fn fe_mont_sub_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> (FixedArray[UInt64], UInt64) {
  let out = FixedArray::make(4, 0UL)
  let mut borrow = 0UL
  for i = 0; i < 4; i = i + 1 {
    let av = a[i]
    let bv = b[i]
    let d1 = av - bv
    let b1 = fe_mont_u64_lt_01(av, bv)
    let d2 = d1 - borrow
    let b2 = fe_mont_u64_lt_01(d1, borrow)
    out[i] = d2
    borrow = b1 | b2
  }
  (out, borrow)
}

///|
fn fe_mont_select_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  bit : UInt64,
) -> FixedArray[UInt64] {
  let out = FixedArray::make(4, 0UL)
  for i = 0; i < 4; i = i + 1 {
    out[i] = fe_mont_select_u64(a[i], b[i], bit)
  }
  out
}

///|
fn fe_mont_from_bigint(v : BigInt) -> Fe256Mont {
  let x = @crypto_bigint.Uint::from_be_bytes(v.to_octets(length=32), 4) catch {
    _ => abort("P-256 Montgomery field element must fit 32 bytes")
  }
  fe_mont_ctx().to_mont(x)
}

///|
fn fe_mont_to_bigint(v : Fe256Mont) -> BigInt {
  fixed_bigint_from_octets(fe_mont_ctx().from_mont(v).to_be_bytes()[:])
}

///|
fn fe_mont_is_zero(v : Fe256Mont) -> Bool {
  @crypto_bigint.Uint::ct_eq(v, fe_mont_zero())
}

///|
fn fe_mont_select(a : Fe256Mont, b : Fe256Mont, bit : UInt64) -> Fe256Mont {
  { limbs: fe_mont_select_limbs(a.limbs, b.limbs, bit) }
}

///|
fn fe_mont_add(a : Fe256Mont, b : Fe256Mont) -> Fe256Mont {
  let (sum, carry) = fe_mont_add_limbs(a.limbs, b.limbs)
  let (reduced, borrow) = fe_mont_sub_limbs(sum, fe_mont_p_uint().limbs)
  { limbs: fe_mont_select_limbs(sum, reduced, carry | (borrow ^ 1UL)) }
}

///|
fn fe_mont_sub(a : Fe256Mont, b : Fe256Mont) -> Fe256Mont {
  let (diff, borrow) = fe_mont_sub_limbs(a.limbs, b.limbs)
  let (wrapped, _) = fe_mont_add_limbs(diff, fe_mont_p_uint().limbs)
  { limbs: fe_mont_select_limbs(diff, wrapped, borrow) }
}

///|
fn fe_mont_neg(a : Fe256Mont) -> Fe256Mont {
  fe_mont_sub(fe_mont_zero(), a)
}

///|
fn fe_mont_mul(a : Fe256Mont, b : Fe256Mont) -> Fe256Mont {
  fe_mont_ctx().mul_reduced(a, b)
}

///|
fn fe_mont_inv(a : Fe256Mont) -> Fe256Mont {
  let normal = fe_mont_ctx().from_mont(a)
  let inv = normal.inv_mod(fe_mont_p_uint()) catch {
    _ => abort("P-256 Montgomery field inverse does not exist")
  }
  fe_mont_ctx().to_mont(inv)
}

///|
fn fe_mont_mul_small(a : Fe256Mont, n : Int) -> Fe256Mont {
  let mut r = fe_mont_zero()
  for _ in 0..<n {
    r = fe_mont_add(r, a)
  }
  r
}

///|
fn fe_mont_mul_minus3(a : Fe256Mont) -> Fe256Mont {
  fe_mont_neg(fe_mont_mul_small(a, 3))
}

///|
fn fe_mont_point_infinity() -> Fe256MontPoint {
  { x: fe_mont_zero(), y: fe_mont_one(), z: fe_mont_zero() }
}

///|
fn fe_mont_point_is_infinity(p : Fe256MontPoint) -> Bool {
  fe_mont_is_zero(p.z)
}

///|
#warnings("-unused_value")
fn fe_mont_point_select(
  a : Fe256MontPoint,
  b : Fe256MontPoint,
  bit : UInt64,
) -> Fe256MontPoint {
  {
    x: fe_mont_select(a.x, b.x, bit),
    y: fe_mont_select(a.y, b.y, bit),
    z: fe_mont_select(a.z, b.z, bit),
  }
}

///|
#warnings("-unused_value")
fn fe_mont_point_from_affine(p : Point) -> Fe256MontPoint {
  if p.inf {
    fe_mont_point_infinity()
  } else {
    {
      x: fe_mont_from_bigint(p.x),
      y: fe_mont_from_bigint(p.y),
      z: fe_mont_one(),
    }
  }
}

///|
#warnings("-unused_value")
fn fe_mont_point_to_affine(p : Fe256MontPoint) -> Point {
  if fe_mont_point_is_infinity(p) {
    return point_infinity()
  }
  let z_inv = fe_mont_inv(p.z)
  {
    x: fe_mont_to_bigint(fe_mont_mul(p.x, z_inv)),
    y: fe_mont_to_bigint(fe_mont_mul(p.y, z_inv)),
    inf: false,
  }
}

///|
#warnings("-unused_value")
fn fe_mont_point_add_complete(
  p : Fe256MontPoint,
  q : Fe256MontPoint,
) -> Fe256MontPoint {
  let b3 = fe_mont_b3()
  let mut t0 = fe_mont_mul(p.x, q.x)
  let mut t1 = fe_mont_mul(p.y, q.y)
  let mut t2 = fe_mont_mul(p.z, q.z)
  let mut t3 = fe_mont_add(p.x, p.y)
  let mut t4 = fe_mont_add(q.x, q.y)
  t3 = fe_mont_mul(t3, t4)
  t4 = fe_mont_add(t0, t1)
  t3 = fe_mont_sub(t3, t4)
  t4 = fe_mont_add(p.x, p.z)
  let mut t5 = fe_mont_add(q.x, q.z)
  t4 = fe_mont_mul(t4, t5)
  t5 = fe_mont_add(t0, t2)
  t4 = fe_mont_sub(t4, t5)
  t5 = fe_mont_add(p.y, p.z)
  let mut x3 = fe_mont_add(q.y, q.z)
  t5 = fe_mont_mul(t5, x3)
  x3 = fe_mont_add(t1, t2)
  t5 = fe_mont_sub(t5, x3)
  let mut z3 = fe_mont_mul_minus3(t4)
  x3 = fe_mont_mul(b3, t2)
  z3 = fe_mont_add(x3, z3)
  x3 = fe_mont_sub(t1, z3)
  z3 = fe_mont_add(t1, z3)
  let mut y3 = fe_mont_mul(x3, z3)
  t1 = fe_mont_add(t0, t0)
  t1 = fe_mont_add(t1, t0)
  t2 = fe_mont_mul_minus3(t2)
  t4 = fe_mont_mul(b3, t4)
  t1 = fe_mont_add(t1, t2)
  t2 = fe_mont_sub(t0, t2)
  t2 = fe_mont_mul_minus3(t2)
  t4 = fe_mont_add(t4, t2)
  t0 = fe_mont_mul(t1, t4)
  y3 = fe_mont_add(y3, t0)
  t0 = fe_mont_mul(t5, t4)
  x3 = fe_mont_mul(t3, x3)
  x3 = fe_mont_sub(x3, t0)
  t0 = fe_mont_mul(t3, t1)
  z3 = fe_mont_mul(t5, z3)
  z3 = fe_mont_add(z3, t0)
  { x: x3, y: y3, z: z3 }
}

///|
fn fe_mont_scalar_bit_be32(bytes : Bytes, bit_index : Int) -> UInt64 {
  let byte_index = bit_index / 8
  let bit_in_byte = 7 - bit_index % 8
  ((bytes[byte_index].to_int() >> bit_in_byte) & 1).to_uint64()
}

///|
#warnings("-unused_value")
fn fe_mont_scalar_mult_fixed_complete(
  k : BigInt,
  p : Fe256MontPoint,
) -> Fe256MontPoint {
  let bytes = k.to_octets(length=32)
  let mut r = fe_mont_point_infinity()
  for bit_index = 0; bit_index < 256; bit_index = bit_index + 1 {
    let doubled = fe_mont_point_add_complete(r, r)
    let added = fe_mont_point_add_complete(doubled, p)
    r = fe_mont_point_select(
      doubled,
      added,
      fe_mont_scalar_bit_be32(bytes, bit_index),
    )
  }
  r
}

///|
#warnings("-unused_value")
fn fe_mont_scalar_mult_base_fixed(k : BigInt) -> Point {
  fe_mont_point_to_affine(
    fe_mont_scalar_mult_fixed_complete(
      k,
      fe_mont_point_from_affine(generator()),
    ),
  )
}
