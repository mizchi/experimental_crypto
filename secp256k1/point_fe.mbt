// secp256k1 homogeneous-projective point helpers backed by
// `crypto_bigint.Uint`.
//
// This uses Renes-Costello-Batina complete addition for the a=0 short
// Weierstrass curve y^2 = x^3 + 7. It is fixed-iteration /
// branchless-intended, not externally measured constant-clock.
//
// FeK1 values are stored in Montgomery form so repeated point-formula
// multiplication uses the crypto_bigint 32-bit-word Montgomery path instead of
// the generic double-and-add modular multiplier.

///|
type FeK1 = @crypto_bigint.Uint

///|
priv struct FeK1Point {
  x : FeK1
  y : FeK1
  z : FeK1
}

///|
fn fe_k1_p_uint() -> FeK1 {
  {
    limbs: [
      0xfffffffefffffc2fUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL,
    ],
  }
}

///|
fn fe_k1_mont() -> @crypto_bigint.Montgomery {
  @crypto_bigint.Montgomery::{
    modulus: fe_k1_p_uint(),
    r2: { limbs: [0x000007a2000e90a1UL, 1UL, 0UL, 0UL] },
    inv: 0xd838091dd2253531UL,
  }
}

///|
fn fe_k1_zero() -> FeK1 {
  @crypto_bigint.Uint::zero(4)
}

///|
fn fe_k1_one() -> FeK1 {
  { limbs: [0x1000003d1UL, 0UL, 0UL, 0UL] }
}

///|
fn fe_k1_b3() -> FeK1 {
  { limbs: [0x1500005025UL, 0UL, 0UL, 0UL] }
}

///|
fn fe_k1_u64_lt_01(a : UInt64, b : UInt64) -> UInt64 {
  let diff = a - b
  (((a.lnot() & b) | ((a ^ b).lnot() & diff)) >> 63) & 1UL
}

///|
fn fe_k1_select_u64(a : UInt64, b : UInt64, bit : UInt64) -> UInt64 {
  let mask = 0UL - (bit & 1UL)
  (a & mask.lnot()) | (b & mask)
}

///|
fn fe_k1_add_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> (FixedArray[UInt64], UInt64) {
  let out = FixedArray::make(4, 0UL)
  let mut carry = 0UL
  for i = 0; i < 4; i = i + 1 {
    let av = a[i]
    let bv = b[i]
    let s1 = av + bv
    let c1 = fe_k1_u64_lt_01(s1, av)
    let s2 = s1 + carry
    let c2 = fe_k1_u64_lt_01(s2, s1)
    out[i] = s2
    carry = c1 | c2
  }
  (out, carry)
}

///|
fn fe_k1_sub_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> (FixedArray[UInt64], UInt64) {
  let out = FixedArray::make(4, 0UL)
  let mut borrow = 0UL
  for i = 0; i < 4; i = i + 1 {
    let av = a[i]
    let bv = b[i]
    let d1 = av - bv
    let b1 = fe_k1_u64_lt_01(av, bv)
    let d2 = d1 - borrow
    let b2 = fe_k1_u64_lt_01(d1, borrow)
    out[i] = d2
    borrow = b1 | b2
  }
  (out, borrow)
}

///|
fn fe_k1_select_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  bit : UInt64,
) -> FixedArray[UInt64] {
  let out = FixedArray::make(4, 0UL)
  for i = 0; i < 4; i = i + 1 {
    out[i] = fe_k1_select_u64(a[i], b[i], bit)
  }
  out
}

///|
fn fe_k1_from_bigint(v : BigInt) -> FeK1 {
  let x = @crypto_bigint.Uint::from_be_bytes(v.to_octets(length=32), 4) catch {
    _ => abort("secp256k1 field element must fit 32 bytes")
  }
  fe_k1_mont().to_mont(x)
}

///|
fn fe_k1_to_bigint(v : FeK1) -> BigInt {
  fixed_bigint_from_octets(fe_k1_mont().from_mont(v).to_be_bytes()[:])
}

///|
fn fe_k1_is_zero(v : FeK1) -> Bool {
  @crypto_bigint.Uint::ct_eq(v, fe_k1_zero())
}

///|
fn fe_k1_select(a : FeK1, b : FeK1, bit : UInt64) -> FeK1 {
  { limbs: fe_k1_select_limbs(a.limbs, b.limbs, bit) }
}

///|
fn fe_k1_add(a : FeK1, b : FeK1) -> FeK1 {
  let (sum, carry) = fe_k1_add_limbs(a.limbs, b.limbs)
  let (reduced, borrow) = fe_k1_sub_limbs(sum, fe_k1_p_uint().limbs)
  { limbs: fe_k1_select_limbs(sum, reduced, carry | (borrow ^ 1UL)) }
}

///|
fn fe_k1_sub(a : FeK1, b : FeK1) -> FeK1 {
  let (diff, borrow) = fe_k1_sub_limbs(a.limbs, b.limbs)
  let (wrapped, _) = fe_k1_add_limbs(diff, fe_k1_p_uint().limbs)
  { limbs: fe_k1_select_limbs(diff, wrapped, borrow) }
}

///|
fn fe_k1_mul(a : FeK1, b : FeK1) -> FeK1 {
  fe_k1_mont().mul_reduced(a, b)
}

///|
fn fe_k1_inv(a : FeK1) -> FeK1 {
  let normal = fe_k1_mont().from_mont(a)
  let inv = normal.inv_mod(fe_k1_p_uint()) catch {
    _ => abort("secp256k1 field inverse does not exist")
  }
  fe_k1_mont().to_mont(inv)
}

///|
fn fe_k1_point_infinity() -> FeK1Point {
  { x: fe_k1_zero(), y: fe_k1_one(), z: fe_k1_zero() }
}

///|
fn fe_k1_point_is_infinity(p : FeK1Point) -> Bool {
  fe_k1_is_zero(p.z)
}

///|
#warnings("-unused_value")
fn fe_k1_point_select(a : FeK1Point, b : FeK1Point, bit : UInt64) -> FeK1Point {
  {
    x: fe_k1_select(a.x, b.x, bit),
    y: fe_k1_select(a.y, b.y, bit),
    z: fe_k1_select(a.z, b.z, bit),
  }
}

///|
#warnings("-unused_value")
fn fe_k1_point_from_affine(p : Point) -> FeK1Point {
  if p.inf {
    fe_k1_point_infinity()
  } else {
    { x: fe_k1_from_bigint(p.x), y: fe_k1_from_bigint(p.y), z: fe_k1_one() }
  }
}

///|
#warnings("-unused_value")
fn fe_k1_point_to_affine(p : FeK1Point) -> Point {
  if fe_k1_point_is_infinity(p) {
    return point_infinity()
  }
  let z_inv = fe_k1_inv(p.z)
  {
    x: fe_k1_to_bigint(fe_k1_mul(p.x, z_inv)),
    y: fe_k1_to_bigint(fe_k1_mul(p.y, z_inv)),
    inf: false,
  }
}

///|
#warnings("-unused_value")
fn fe_k1_point_add_complete(p : FeK1Point, q : FeK1Point) -> FeK1Point {
  // Renes-Costello-Batina 2015 complete addition formula in homogeneous
  // projective coordinates. secp256k1 has a = 0, so all a*t terms are zero;
  // b3 = 3*b = 21.
  let b3 = fe_k1_b3()
  let mut t0 = fe_k1_mul(p.x, q.x)
  let mut t1 = fe_k1_mul(p.y, q.y)
  let mut t2 = fe_k1_mul(p.z, q.z)
  let mut t3 = fe_k1_add(p.x, p.y)
  let mut t4 = fe_k1_add(q.x, q.y)
  t3 = fe_k1_mul(t3, t4)
  t4 = fe_k1_add(t0, t1)
  t3 = fe_k1_sub(t3, t4)
  t4 = fe_k1_add(p.x, p.z)
  let mut t5 = fe_k1_add(q.x, q.z)
  t4 = fe_k1_mul(t4, t5)
  t5 = fe_k1_add(t0, t2)
  t4 = fe_k1_sub(t4, t5)
  t5 = fe_k1_add(p.y, p.z)
  let mut x3 = fe_k1_add(q.y, q.z)
  t5 = fe_k1_mul(t5, x3)
  x3 = fe_k1_add(t1, t2)
  t5 = fe_k1_sub(t5, x3)
  let mut z3 = fe_k1_zero()
  x3 = fe_k1_mul(b3, t2)
  z3 = fe_k1_add(x3, z3)
  x3 = fe_k1_sub(t1, z3)
  z3 = fe_k1_add(t1, z3)
  let mut y3 = fe_k1_mul(x3, z3)
  t1 = fe_k1_add(t0, t0)
  t1 = fe_k1_add(t1, t0)
  t2 = fe_k1_zero()
  t4 = fe_k1_mul(b3, t4)
  t1 = fe_k1_add(t1, t2)
  t2 = fe_k1_sub(t0, t2)
  t2 = fe_k1_zero()
  t4 = fe_k1_add(t4, t2)
  t0 = fe_k1_mul(t1, t4)
  y3 = fe_k1_add(y3, t0)
  t0 = fe_k1_mul(t5, t4)
  x3 = fe_k1_mul(t3, x3)
  x3 = fe_k1_sub(x3, t0)
  t0 = fe_k1_mul(t3, t1)
  z3 = fe_k1_mul(t5, z3)
  z3 = fe_k1_add(z3, t0)
  { x: x3, y: y3, z: z3 }
}

///|
fn fe_k1_scalar_bit_be32(bytes : Bytes, bit_index : Int) -> UInt64 {
  let byte_index = bit_index / 8
  let bit_in_byte = 7 - bit_index % 8
  ((bytes[byte_index].to_int() >> bit_in_byte) & 1).to_uint64()
}

///|
#warnings("-unused_value")
fn fe_k1_scalar_mult_fixed_complete(k : BigInt, p : FeK1Point) -> FeK1Point {
  let bytes = k.to_octets(length=32)
  let mut r = fe_k1_point_infinity()
  for bit_index = 0; bit_index < 256; bit_index = bit_index + 1 {
    let doubled = fe_k1_point_add_complete(r, r)
    let added = fe_k1_point_add_complete(doubled, p)
    r = fe_k1_point_select(
      doubled,
      added,
      fe_k1_scalar_bit_be32(bytes, bit_index),
    )
  }
  r
}

///|
#warnings("-unused_value")
fn fe_k1_scalar_mult_base_fixed(k : BigInt) -> Point {
  fe_k1_point_to_affine(
    fe_k1_scalar_mult_fixed_complete(k, fe_k1_point_from_affine(generator())),
  )
}
