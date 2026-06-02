// X448 ECDH (RFC 7748) — the Montgomery-ladder Diffie–Hellman on Curve448.
//
// Field arithmetic is the 16-limb radix-2^28 Goldilocks field in field448.mbt
// (no @bigint), so this is far faster than a generic big-integer ladder. It is
// a clear, not fully constant-time implementation: the field cswap is
// branch-free on the limbs, but inversion uses a plain square-and-multiply.

///|
let a24 : UInt64 = 39081

///|
pub suberror X448Error {
  InvalidLength(Int)
} derive(Debug)

///|
/// Compute X448(scalar, u): both inputs 56-byte little-endian, output 56-byte
/// little-endian (RFC 7748 §5). The scalar is clamped per the spec.
pub fn x448(scalar : Bytes, u : Bytes) -> Bytes raise X448Error {
  if scalar.length() != 56 {
    raise InvalidLength(scalar.length())
  }
  if u.length() != 56 {
    raise InvalidLength(u.length())
  }
  // decodeScalar448: clamp.
  let k = FixedArray::makei(56, fn(i) { scalar[i] })
  k[0] = (k[0].to_int() & 252).to_byte()
  k[55] = (k[55].to_int() | 128).to_byte()
  let x1 = fe_from_bytes(FixedArray::makei(56, fn(i) { u[i] }))
  let mut x2 = fe_one()
  let mut z2 = fe_zero()
  let mut x3 = fe_copy(x1)
  let mut z3 = fe_one()
  let mut swap = 0
  let mut t = 447
  while t >= 0 {
    let bit = (k[t >> 3].to_int() >> (t & 7)) & 1
    swap = swap ^ bit
    fe_cswap(x2, x3, swap)
    fe_cswap(z2, z3, swap)
    swap = bit
    // RFC 7748 §5 Montgomery ladder step.
    let aa = fe_add(x2, z2)
    let aaa = fe_sqr(aa)
    let bb = fe_sub(x2, z2)
    let bbb = fe_sqr(bb)
    let e = fe_sub(aaa, bbb)
    let c = fe_add(x3, z3)
    let d = fe_sub(x3, z3)
    let da = fe_mul(d, aa)
    let cb = fe_mul(c, bb)
    let da_cb = fe_add(da, cb)
    x3 = fe_sqr(da_cb)
    let da_sub_cb = fe_sub(da, cb)
    z3 = fe_mul(x1, fe_sqr(da_sub_cb))
    x2 = fe_mul(aaa, bbb)
    z2 = fe_mul(e, fe_add(aaa, fe_mul_small(e, a24)))
    t = t - 1
  }
  fe_cswap(x2, x3, swap)
  fe_cswap(z2, z3, swap)
  let res = fe_mul(x2, fe_inv(z2))
  let out = fe_to_bytes(res)
  Bytes::makei(56, fn(i) { out[i] })
}

///|
/// The X448 base point u = 5 (RFC 7748 §4.2), as a 56-byte little-endian value.
pub fn base_point() -> Bytes {
  Bytes::makei(56, fn(i) { if i == 0 { b'\x05' } else { b'\x00' } })
}

///|
/// Derive the X448 public key from a 56-byte private scalar: X448(scalar, 5).
pub fn public_key(scalar : Bytes) -> Bytes raise X448Error {
  x448(scalar, base_point())
}
