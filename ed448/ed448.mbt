// Ed448 signature verification (RFC 8032, pure EdDSA / no prehash) on the
// edwards448 curve. Field/scalar arithmetic via @bigint; points in projective
// coordinates (one inversion-free add formula, comparison by cross-multiply) so
// a double-scalar verify needs no modular inversion. Hashing is SHAKE256 with
// the "SigEd448" dom4 prefix. Clear (not constant-time) — verification only.

///|
fn p() -> BigInt {
  BigInt::from_string(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    radix=16,
  )
}

///|
fn l_order() -> BigInt {
  BigInt::from_string(
    "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
    radix=16,
  )
}

///|
fn d_param() -> BigInt {
  BigInt::from_string(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff6756",
    radix=16,
  )
}

///|
fn bx() -> BigInt {
  BigInt::from_string(
    "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e",
    radix=16,
  )
}

///|
fn by() -> BigInt {
  BigInt::from_string(
    "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14",
    radix=16,
  )
}

///|
fn zero() -> BigInt {
  BigInt::from_int(0)
}

///|
fn one() -> BigInt {
  BigInt::from_int(1)
}

///|
fn md(x : BigInt) -> BigInt {
  let pp = p()
  let r = x % pp
  if r.compare(zero()) < 0 {
    r + pp
  } else {
    r
  }
}

///|
// Projective Edwards point (X:Y:Z), affine = (X/Z, Y/Z). a = 1 (untwisted).
priv struct Pt {
  x : BigInt
  y : BigInt
  z : BigInt
}

///|
fn identity() -> Pt {
  { x: zero(), y: one(), z: one() }
}

///|
// Unified projective add for x^2+y^2 = 1 + d x^2 y^2 (works for doubling too).
fn padd(p1 : Pt, p2 : Pt) -> Pt {
  let a = md(p1.z * p2.z)
  let b = md(a * a)
  let c = md(p1.x * p2.x)
  let dd = md(p1.y * p2.y)
  let e = md(d_param() * c * dd)
  let f = md(b - e)
  let g = md(b + e)
  let xs = md((p1.x + p1.y) * (p2.x + p2.y) - c - dd)
  let x3 = md(a * f * xs)
  let y3 = md(a * g * (dd - c))
  let z3 = md(f * g)
  { x: x3, y: y3, z: z3 }
}

///|
fn scalar_mult(k : BigInt, point : Pt) -> Pt {
  let mut r = identity()
  let mut acc = point
  let mut kk = k
  let two = BigInt::from_int(2)
  // process low to high bit
  while kk.compare(zero()) > 0 {
    if (kk % two).compare(one()) == 0 {
      r = padd(r, acc)
    }
    acc = padd(acc, acc)
    kk = kk / two
  }
  r
}

///|
fn pt_equal(p1 : Pt, p2 : Pt) -> Bool {
  // X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1
  md(p1.x * p2.z).compare(md(p2.x * p1.z)) == 0 &&
  md(p1.y * p2.z).compare(md(p2.y * p1.z)) == 0
}

///|
fn le_to_int(b : Bytes, len : Int) -> BigInt {
  let mut acc = zero()
  let mut shift = 0
  for i in 0..<len {
    acc = acc + (BigInt::from_int(b[i].to_int()) << shift)
    shift = shift + 8
  }
  acc
}

///|
// Decompress a 57-byte Ed448 point encoding to projective coords; None if the
// y is out of range or no square root exists.
fn decompress(enc : Bytes, off : Int) -> Pt? {
  let pp = p()
  let y = le_to_int(Bytes::makei(56, fn(i) { enc[off + i] }), 56)
  if y.compare(pp) >= 0 {
    return None
  }
  let sign = (enc[off + 56].to_int() >> 7) & 1
  // x^2 = (y^2 - 1) / (d y^2 - 1)
  let y2 = md(y * y)
  let u = md(y2 - one())
  let v = md(d_param() * y2 - one())
  // x = (u/v)^((p+1)/4) = (u * v^(p-2))^((p+1)/4)
  let vinv = v.pow(pp - BigInt::from_int(2), modulus=pp)
  let w = md(u * vinv)
  let exp = (pp + one()) / BigInt::from_int(4)
  let mut x = w.pow(exp, modulus=pp)
  if md(x * x).compare(w) != 0 {
    return None // no square root
  }
  let two = BigInt::from_int(2)
  let x_odd = (x % two).compare(one()) == 0
  let want_odd = sign == 1
  if x_odd != want_odd {
    x = md(pp - x)
  }
  if x.compare(zero()) == 0 && sign == 1 {
    return None
  }
  Some({ x, y, z: one() })
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
  let k = le_to_int(h, 114) % l_order()
  // cofactorless check: [S]B == R + [k]A
  let base = { x: bx(), y: by(), z: one() }
  let lhs = scalar_mult(s, base)
  let rhs = padd(r_pt, scalar_mult(k, a_pt))
  pt_equal(lhs, rhs)
}
