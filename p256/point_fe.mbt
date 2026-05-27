// P-256 projective point helpers backed by `Fe`.
//
// This is the 10-limb field rewrite correctness baseline and oracle suite.
// Sign-side scalar multiplication now uses the faster Montgomery-domain
// complete-addition path in `point_mont_fe.mbt`.

///|
priv struct FePoint {
  x : Fe
  y : Fe
  z : Fe
}

///|
priv struct FeProjPoint {
  x : Fe
  y : Fe
  z : Fe
}

///|
fn fe_zero() -> Fe {
  FixedArray::make(10, 0UL)
}

///|
fn fe_one() -> Fe {
  let r = FixedArray::make(10, 0UL)
  r[0] = 1UL
  r
}

///|
fn fe_from_bigint(v : BigInt) -> Fe {
  let b = v.to_octets(length=32)
  fe_from_bytes(FixedArray::makei(32, fn(i) { b[i] }))
}

///|
fn fe_to_bigint(v : Fe) -> BigInt {
  let b = Bytes::from_array(fe_to_bytes(v))
  fixed_bigint_from_octets(b[:])
}

///|
fn fe_is_zero(v : Fe) -> Bool {
  let b = fe_to_bytes(v)
  let mut acc = 0
  for i = 0; i < 32; i = i + 1 {
    acc = acc | b[i].to_int()
  }
  acc == 0
}

///|
fn fe_mul_small(a : Fe, n : Int) -> Fe {
  let mut r = fe_zero()
  for _ in 0..<n {
    r = fe_add(r, a)
  }
  r
}

///|
fn fe_mul_minus3(a : Fe) -> Fe {
  fe_neg(fe_mul_small(a, 3))
}

///|
fn fe_p256_b3() -> Fe {
  fe_mul_small(fe_from_bigint(p256_b()), 3)
}

///|
fn fe_point_infinity() -> FePoint {
  { x: fe_zero(), y: fe_one(), z: fe_zero() }
}

///|
fn fe_point_is_infinity(p : FePoint) -> Bool {
  fe_is_zero(p.z)
}

///|
#warnings("-unused_value")
fn fe_point_select(a : FePoint, b : FePoint, bit : UInt64) -> FePoint {
  {
    x: fe_select(a.x, b.x, bit),
    y: fe_select(a.y, b.y, bit),
    z: fe_select(a.z, b.z, bit),
  }
}

///|
#warnings("-unused_value")
fn fe_point_from_affine(p : Point) -> FePoint {
  if p.inf {
    fe_point_infinity()
  } else {
    { x: fe_from_bigint(p.x), y: fe_from_bigint(p.y), z: fe_one() }
  }
}

///|
#warnings("-unused_value")
fn fe_point_to_affine(p : FePoint) -> Point {
  if fe_point_is_infinity(p) {
    return point_infinity()
  }
  let z_inv = fe_inv(p.z)
  let z2 = fe_square(z_inv)
  let z3 = fe_mul(z2, z_inv)
  {
    x: fe_to_bigint(fe_mul(p.x, z2)),
    y: fe_to_bigint(fe_mul(p.y, z3)),
    inf: false,
  }
}

///|
fn fe_proj_point_infinity() -> FeProjPoint {
  { x: fe_zero(), y: fe_one(), z: fe_zero() }
}

///|
fn fe_proj_point_is_infinity(p : FeProjPoint) -> Bool {
  fe_is_zero(p.z)
}

///|
#warnings("-unused_value")
fn fe_proj_point_select(
  a : FeProjPoint,
  b : FeProjPoint,
  bit : UInt64,
) -> FeProjPoint {
  {
    x: fe_select(a.x, b.x, bit),
    y: fe_select(a.y, b.y, bit),
    z: fe_select(a.z, b.z, bit),
  }
}

///|
#warnings("-unused_value")
fn fe_proj_point_from_affine(p : Point) -> FeProjPoint {
  if p.inf {
    fe_proj_point_infinity()
  } else {
    { x: fe_from_bigint(p.x), y: fe_from_bigint(p.y), z: fe_one() }
  }
}

///|
#warnings("-unused_value")
fn fe_proj_point_to_affine(p : FeProjPoint) -> Point {
  if fe_proj_point_is_infinity(p) {
    return point_infinity()
  }
  let z_inv = fe_inv(p.z)
  {
    x: fe_to_bigint(fe_mul(p.x, z_inv)),
    y: fe_to_bigint(fe_mul(p.y, z_inv)),
    inf: false,
  }
}

///|
#warnings("-unused_value")
fn fe_proj_point_add_complete(p : FeProjPoint, q : FeProjPoint) -> FeProjPoint {
  // Renes-Costello-Batina 2015 complete addition formula for prime-order
  // short Weierstrass curves in homogeneous projective coordinates.
  //
  // Coordinates are x = X/Z, y = Y/Z. P-256 has a = -3, and the EFD formula
  // uses b3 = 3*b.
  let b3 = fe_p256_b3()
  let mut t0 = fe_mul(p.x, q.x)
  let mut t1 = fe_mul(p.y, q.y)
  let mut t2 = fe_mul(p.z, q.z)
  let mut t3 = fe_add(p.x, p.y)
  let mut t4 = fe_add(q.x, q.y)
  t3 = fe_mul(t3, t4)
  t4 = fe_add(t0, t1)
  t3 = fe_sub(t3, t4)
  t4 = fe_add(p.x, p.z)
  let mut t5 = fe_add(q.x, q.z)
  t4 = fe_mul(t4, t5)
  t5 = fe_add(t0, t2)
  t4 = fe_sub(t4, t5)
  t5 = fe_add(p.y, p.z)
  let mut x3 = fe_add(q.y, q.z)
  t5 = fe_mul(t5, x3)
  x3 = fe_add(t1, t2)
  t5 = fe_sub(t5, x3)
  let mut z3 = fe_mul_minus3(t4)
  x3 = fe_mul(b3, t2)
  z3 = fe_add(x3, z3)
  x3 = fe_sub(t1, z3)
  z3 = fe_add(t1, z3)
  let mut y3 = fe_mul(x3, z3)
  t1 = fe_add(t0, t0)
  t1 = fe_add(t1, t0)
  t2 = fe_mul_minus3(t2)
  t4 = fe_mul(b3, t4)
  t1 = fe_add(t1, t2)
  t2 = fe_sub(t0, t2)
  t2 = fe_mul_minus3(t2)
  t4 = fe_add(t4, t2)
  t0 = fe_mul(t1, t4)
  y3 = fe_add(y3, t0)
  t0 = fe_mul(t5, t4)
  x3 = fe_mul(t3, x3)
  x3 = fe_sub(x3, t0)
  t0 = fe_mul(t3, t1)
  z3 = fe_mul(t5, z3)
  z3 = fe_add(z3, t0)
  { x: x3, y: y3, z: z3 }
}

///|
fn fe_point_double(p : FePoint) -> FePoint {
  if fe_point_is_infinity(p) || fe_is_zero(p.y) {
    return fe_point_infinity()
  }
  // dbl-2001-b for a = -3:
  // delta = Z1^2
  // gamma = Y1^2
  // beta = X1*gamma
  // alpha = 3*(X1-delta)*(X1+delta)
  // X3 = alpha^2 - 8*beta
  // Z3 = (Y1+Z1)^2 - gamma - delta
  // Y3 = alpha*(4*beta-X3) - 8*gamma^2
  let delta = fe_square(p.z)
  let gamma = fe_square(p.y)
  let beta = fe_mul(p.x, gamma)
  let alpha = fe_mul_small(fe_mul(fe_sub(p.x, delta), fe_add(p.x, delta)), 3)
  let x3 = fe_sub(fe_square(alpha), fe_mul_small(beta, 8))
  let z3 = fe_sub(fe_sub(fe_square(fe_add(p.y, p.z)), gamma), delta)
  let y3 = fe_sub(
    fe_mul(alpha, fe_sub(fe_mul_small(beta, 4), x3)),
    fe_mul_small(fe_square(gamma), 8),
  )
  { x: x3, y: y3, z: z3 }
}

///|
#warnings("-unused_value")
fn fe_point_add(p : FePoint, q : FePoint) -> FePoint {
  if fe_point_is_infinity(p) {
    return q
  }
  if fe_point_is_infinity(q) {
    return p
  }
  // add-2007-bl.
  let z1z1 = fe_square(p.z)
  let z2z2 = fe_square(q.z)
  let u1 = fe_mul(p.x, z2z2)
  let u2 = fe_mul(q.x, z1z1)
  let s1 = fe_mul(fe_mul(p.y, q.z), z2z2)
  let s2 = fe_mul(fe_mul(q.y, p.z), z1z1)
  let h = fe_sub(u2, u1)
  let s2_minus_s1 = fe_sub(s2, s1)
  if fe_is_zero(h) {
    if fe_is_zero(s2_minus_s1) {
      return fe_point_double(p)
    }
    return fe_point_infinity()
  }
  let i = fe_square(fe_mul_small(h, 2))
  let j = fe_mul(h, i)
  let r = fe_mul_small(s2_minus_s1, 2)
  let v = fe_mul(u1, i)
  let x3 = fe_sub(fe_sub(fe_square(r), j), fe_mul_small(v, 2))
  let y3 = fe_sub(fe_mul(r, fe_sub(v, x3)), fe_mul_small(fe_mul(s1, j), 2))
  let z3 = fe_mul(fe_sub(fe_sub(fe_square(fe_add(p.z, q.z)), z1z1), z2z2), h)
  { x: x3, y: y3, z: z3 }
}

///|
#warnings("-unused_value")
fn fe_scalar_mult_variable(k : BigInt, p : FePoint) -> FePoint {
  if fe_point_is_infinity(p) || k.is_zero() {
    return fe_point_infinity()
  }
  let bytes = k.to_octets(length=32)
  let mut r = fe_point_infinity()
  let mut started = false
  for i = 0; i < 32; i = i + 1 {
    let byte = bytes[i].to_int()
    for j = 7; j >= 0; j = j - 1 {
      if started {
        r = fe_point_double(r)
      }
      let bit = (byte >> j) & 1
      if bit == 1 {
        if started {
          r = fe_point_add(r, p)
        } else {
          r = p
          started = true
        }
      }
    }
  }
  r
}

///|
fn fe_scalar_bit_be32(bytes : Bytes, bit_index : Int) -> UInt64 {
  let byte_index = bit_index / 8
  let bit_in_byte = 7 - bit_index % 8
  ((bytes[byte_index].to_int() >> bit_in_byte) & 1).to_uint64()
}

///|
#warnings("-unused_value")
fn fe_scalar_mult_fixed_branchy(k : BigInt, p : FePoint) -> FePoint {
  // Fixed 256-iteration skeleton, but not constant-time: `fe_point_add` still
  // has exceptional-case branches depending on the secret accumulator state.
  let bytes = k.to_octets(length=32)
  let mut r = fe_point_infinity()
  for bit_index = 0; bit_index < 256; bit_index = bit_index + 1 {
    let doubled = fe_point_double(r)
    let added = fe_point_add(doubled, p)
    r = fe_point_select(doubled, added, fe_scalar_bit_be32(bytes, bit_index))
  }
  r
}

///|
#warnings("-unused_value")
fn fe_scalar_mult_fixed_complete(k : BigInt, p : FeProjPoint) -> FeProjPoint {
  let bytes = k.to_octets(length=32)
  let mut r = fe_proj_point_infinity()
  for bit_index = 0; bit_index < 256; bit_index = bit_index + 1 {
    let doubled = fe_proj_point_add_complete(r, r)
    let added = fe_proj_point_add_complete(doubled, p)
    r = fe_proj_point_select(
      doubled,
      added,
      fe_scalar_bit_be32(bytes, bit_index),
    )
  }
  r
}

///|
#warnings("-unused_value")
fn fe_scalar_mult_base_fixed(k : BigInt) -> Point {
  fe_proj_point_to_affine(
    fe_scalar_mult_fixed_complete(k, fe_proj_point_from_affine(generator())),
  )
}
