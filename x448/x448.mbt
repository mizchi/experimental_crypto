// X448 ECDH (RFC 7748) — the Montgomery-ladder Diffie–Hellman on Curve448.
//
// Field arithmetic is via @bigint (modulo p = 2^448 - 2^224 - 1); this is a
// clear, not constant-time implementation (the conditional swap branches on the
// scalar bit). For the high-volume X25519 path see the dedicated 10-limb module;
// X448 is provided for completeness (TLS / COSE x448).

///|
fn p448() -> BigInt {
  BigInt::from_string(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    radix=16,
  )
}

///|
let a24 : Int = 39081

///|
pub suberror X448Error {
  InvalidLength(Int)
} derive(Debug)

///|
// Little-endian 56 bytes -> BigInt.
fn le_to_int(b : Bytes) -> BigInt {
  let mut acc = BigInt::from_int(0)
  let mut shift = 0
  for i in 0..<b.length() {
    acc = acc + (BigInt::from_int(b[i].to_int()) << shift)
    shift = shift + 8
  }
  acc
}

///|
// BigInt -> 56-byte little-endian.
fn int_to_le56(n : BigInt) -> Bytes {
  let be = n.to_octets(length=56) // big-endian, 56 bytes
  Bytes::makei(56, fn(i) { be[55 - i] })
}

///|
fn modp(x : BigInt, p : BigInt) -> BigInt {
  let r = x % p
  if r.compare(BigInt::from_int(0)) < 0 {
    r + p
  } else {
    r
  }
}

///|
fn inv(x : BigInt, p : BigInt) -> BigInt {
  // Fermat: x^(p-2) mod p
  x.pow(p - BigInt::from_int(2), modulus=p)
}

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
  let p = p448()
  // decodeScalar448: clamp.
  let k = FixedArray::makei(56, fn(i) { scalar[i] })
  k[0] = (k[0].to_int() & 252).to_byte()
  k[55] = (k[55].to_int() | 128).to_byte()
  let kb = le_to_int(Bytes::makei(56, fn(i) { k[i] }))
  let x1 = modp(le_to_int(u), p)
  let mut x2 = BigInt::from_int(1)
  let mut z2 = BigInt::from_int(0)
  let mut x3 = x1
  let mut z3 = BigInt::from_int(1)
  let mut swap = 0
  let a24b = BigInt::from_int(a24)
  let mut t = 447
  while t >= 0 {
    let bit = ((kb >> t) % BigInt::from_int(2)).to_int()
    swap = swap ^ bit
    if swap == 1 {
      let tx = x2
      x2 = x3
      x3 = tx
      let tz = z2
      z2 = z3
      z3 = tz
    }
    swap = bit
    let aa = modp(x2 + z2, p)
    let aaa = modp(aa * aa, p)
    let bb = modp(x2 - z2, p)
    let bbb = modp(bb * bb, p)
    let e = modp(aaa - bbb, p)
    let c = modp(x3 + z3, p)
    let d = modp(x3 - z3, p)
    let da = modp(d * aa, p)
    let cb = modp(c * bb, p)
    let dacb = da + cb
    x3 = modp(dacb * dacb, p)
    let dasub = da - cb
    z3 = modp(x1 * modp(dasub * dasub, p), p)
    x2 = modp(aaa * bbb, p)
    z2 = modp(e * modp(aaa + a24b * e, p), p)
    t = t - 1
  }
  if swap == 1 {
    let tx = x2
    x2 = x3
    x3 = tx
    let tz = z2
    z2 = z3
    z3 = tz
  }
  let res = modp(x2 * inv(z2, p), p)
  int_to_le56(res)
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
