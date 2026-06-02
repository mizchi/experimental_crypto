// Ed448 signature verification (RFC 8032, pure EdDSA / no prehash) on the
// edwards448 curve. Field arithmetic is the 16-limb radix-2^28 Goldilocks field
// (field448.mbt, no @bigint); points are projective (X:Y:Z) with one
// inversion-free unified add and comparison by cross-multiply, so a
// double-scalar verify needs only the one final-ish inversion inside decompress.
// Scalars (S and k = H mod L) stay as @bigint values reduced modulo the prime
// group order L. Hashing is SHAKE256 with the "SigEd448" dom4 prefix. Clear (not
// constant-time) — verification only.

///|
fn l_order() -> BigInt {
  BigInt::from_string(
    "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
    radix=16,
  )
}

///|
// Base point B (RFC 8032 §5.2) as field elements.
let bx_hex : String = "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e"

///|
let by_hex : String = "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14"

///|
fn base_x() -> Fe {
  fe_from_hex_be(bx_hex)
}

///|
fn base_y() -> Fe {
  fe_from_hex_be(by_hex)
}

///|
// The edwards448 d = -39081 mod p.
fn d_param() -> Fe {
  fe_neg(fe_from_small(39081))
}

///|
// Projective Edwards point (X:Y:Z), affine = (X/Z, Y/Z). a = 1 (untwisted).
priv struct Pt {
  x : Fe
  y : Fe
  z : Fe
}

///|
fn identity() -> Pt {
  { x: fe_zero(), y: fe_one(), z: fe_one() }
}

///|
// Unified projective add for x^2+y^2 = 1 + d x^2 y^2 (works for doubling too).
fn padd(p1 : Pt, p2 : Pt) -> Pt {
  let a = fe_mul(p1.z, p2.z)
  let b = fe_sqr(a)
  let c = fe_mul(p1.x, p2.x)
  let dd = fe_mul(p1.y, p2.y)
  let e = fe_mul(d_param(), fe_mul(c, dd))
  let f = fe_sub(b, e)
  let g = fe_add(b, e)
  let xs = fe_sub(fe_sub(fe_mul(fe_add(p1.x, p1.y), fe_add(p2.x, p2.y)), c), dd)
  let x3 = fe_mul(fe_mul(a, f), xs)
  let y3 = fe_mul(fe_mul(a, g), fe_sub(dd, c))
  let z3 = fe_mul(f, g)
  { x: x3, y: y3, z: z3 }
}

///|
fn bit_at(x : BigInt, t : Int) -> Int {
  ((x >> t) % BigInt::from_int(2)).to_int()
}

///|
// Shamir / Straus double-scalar multiplication: [s]P + [k]Q in one high-to-low
// pass (one doubling per bit, shared between both scalars), with a 4-entry table
// {0, P, Q, P+Q}. Halves the doublings versus two independent scalar mults.
fn double_scalar_mult(s : BigInt, p : Pt, k : BigInt, q : Pt) -> Pt {
  let pq = padd(p, q)
  let mut r = identity()
  // Scalars are < L < 2^446; 448 bits covers them (top bits are zero).
  for t = 447; t >= 0; t = t - 1 {
    r = padd(r, r)
    let sb = bit_at(s, t)
    let kb = bit_at(k, t)
    if sb == 1 && kb == 1 {
      r = padd(r, pq)
    } else if sb == 1 {
      r = padd(r, p)
    } else if kb == 1 {
      r = padd(r, q)
    }
  }
  r
}

///|
fn pt_equal(p1 : Pt, p2 : Pt) -> Bool {
  // X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1
  fe_equal(fe_mul(p1.x, p2.z), fe_mul(p2.x, p1.z)) &&
  fe_equal(fe_mul(p1.y, p2.z), fe_mul(p2.y, p1.z))
}

///|
fn le_to_int(b : Bytes, len : Int) -> BigInt {
  let mut acc = BigInt::from_int(0)
  let mut shift = 0
  for i in 0..<len {
    acc = acc + (BigInt::from_int(b[i].to_int()) << shift)
    shift = shift + 8
  }
  acc
}

///|
// Decompress a 57-byte Ed448 point encoding to projective coords; None if the
// y is out of range, non-canonical, or no square root exists.
fn decompress(enc : Bytes, off : Int) -> Pt? {
  let le = FixedArray::makei(56, fn(i) { enc[off + i] })
  let y = fe_from_bytes(le)
  // Reject a non-canonical y (the encoded integer must be < p, RFC 8032 §5.2.3).
  let canon = fe_to_bytes(y)
  for i in 0..<56 {
    if canon[i] != le[i] {
      return None
    }
  }
  let sign = (enc[off + 56].to_int() >> 7) & 1
  // x^2 = (y^2 - 1) / (d y^2 - 1)
  let y2 = fe_sqr(y)
  let one_fe = fe_one()
  let u = fe_sub(y2, one_fe)
  let v = fe_sub(fe_mul(d_param(), y2), one_fe)
  let w = fe_mul(u, fe_inv(v))
  let mut x = fe_sqrt(w)
  if !fe_equal(fe_sqr(x), w) {
    return None // no square root
  }
  if fe_parity(x) != sign {
    x = fe_neg(x)
  }
  if fe_is_zero(x) && sign == 1 {
    return None
  }
  Some({ x, y, z: one_fe })
}

///|
fn cat(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for p in parts {
    total += p.length()
  }
  let out = FixedArray::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i in 0..<p.length() {
      out[off + i] = p[i]
    }
    off += p.length()
  }
  Bytes::makei(total, fn(i) { out[i] })
}

///|
// dom4(phflag, context) = "SigEd448" || phflag(1) || len(context)(1) || context
fn dom4(phflag : Int, context : Bytes) -> Bytes {
  cat([
    b"SigEd448",
    Bytes::makei(1, fn(_i) { phflag.to_byte() }),
    Bytes::makei(1, fn(_i) { context.length().to_byte() }),
    context,
  ])
}

///|
/// Verify an Ed448 signature (pure EdDSA). `public_key` is 57 bytes, `sig` is
/// 114 bytes (R ‖ S), `context` is the optional context string (≤255 bytes,
/// empty for the common case). Returns true iff the signature is valid.
pub fn verify(
  public_key : Bytes,
  message : Bytes,
  sig : Bytes,
  context? : Bytes = b"",
) -> Bool {
  if public_key.length() != 57 || sig.length() != 114 || context.length() > 255 {
    return false
  }
  let r_enc = Bytes::makei(57, fn(i) { sig[i] })
  let s = le_to_int(Bytes::makei(57, fn(i) { sig[57 + i] }), 57)
  if s.compare(l_order()) >= 0 {
    return false // non-canonical S
  }
  let a_pt = match decompress(public_key, 0) {
    Some(pt) => pt
    None => return false
  }
  let r_pt = match decompress(r_enc, 0) {
    Some(pt) => pt
    None => return false
  }
  // k = SHAKE256(dom4(0,ctx) || R || A || M, 114) mod L
  let h = @sha3.shake256(
    cat([dom4(0, context), r_enc, public_key, message]),
    114,
  )
  let l = l_order()
  let k = le_to_int(h, 114) % l
  // cofactorless check [S]B == R + [k]A, rearranged to [S]B + [L-k]A == R so it
  // is a single double-scalar multiplication (Shamir's trick).
  let base = { x: base_x(), y: base_y(), z: fe_one() }
  let neg_k = (l - k) % l
  let combined = double_scalar_mult(s, base, neg_k, a_pt)
  pt_equal(combined, r_pt)
}
