// NIST P-384 (secp384r1) ECDSA signature verification (verify-only).
//
// Curve: y² = x³ - 3x + b over GF(p) with p, b, n, G from FIPS 186-5 §D.1.2.4.
//
// Scope and structure mirror `mizchi/p256`:
//   - verify  (FIPS 186-5 §6.4.2 / ANSI X9.62)
//   - public key parsing: uncompressed (04 || X || Y), 97 bytes total; SPKI
//   - signature parsing: JWT/JOSE raw (r||s, 96B) and X.509 DER SEQUENCE
//
// Out of scope: sign, key generation, point compression, ECDH.

// ─── curve constants (NIST FIPS 186-5 §D.1.2.4) ──────────────────────────

///|
fn p384_p() -> BigInt {
  BigInt::from_hex(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
  )
}

///|
fn p384_b() -> BigInt {
  BigInt::from_hex(
    "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
  )
}

///|
fn p384_n() -> BigInt {
  // Order of the base point.
  BigInt::from_hex(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
  )
}

///|
fn p384_gx() -> BigInt {
  BigInt::from_hex(
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
  )
}

///|
fn p384_gy() -> BigInt {
  BigInt::from_hex(
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
  )
}

// ─── affine point ────────────────────────────────────────────────────────

///|
struct Point {
  x : BigInt
  y : BigInt
  inf : Bool
}

///|
fn point_infinity() -> Point {
  { x: BigInt::from_int(0), y: BigInt::from_int(0), inf: true }
}

///|
fn generator() -> Point {
  { x: p384_gx(), y: p384_gy(), inf: false }
}

///|
fn mod_pos(a : BigInt, m : BigInt) -> BigInt {
  let r = a % m
  if r.compare_int(0) < 0 {
    r + m
  } else {
    r
  }
}

///|
fn mod_inverse(a : BigInt, m : BigInt) -> BigInt {
  let exp = m - BigInt::from_int(2)
  a.pow(exp, modulus=m)
}

///|
fn is_on_curve(p_pt : Point) -> Bool {
  if p_pt.inf {
    return true
  }
  let p = p384_p()
  let lhs = (p_pt.y * p_pt.y) % p
  let x3 = (p_pt.x * p_pt.x % p * p_pt.x) % p
  let three_x = (BigInt::from_int(3) * p_pt.x) % p
  let rhs = mod_pos(x3 - three_x + p384_b(), p)
  lhs == rhs
}

///|
fn point_neg(pt : Point) -> Point {
  if pt.inf {
    return pt
  }
  let p = p384_p()
  { x: pt.x, y: mod_pos(p - pt.y, p), inf: false }
}

///|
fn point_double(pt : Point) -> Point {
  if pt.inf {
    return pt
  }
  if pt.y.is_zero() {
    return point_infinity()
  }
  let p = p384_p()
  // slope = (3x² + a) / (2y), a = -3.
  let three_x2 = mod_pos(BigInt::from_int(3) * pt.x * pt.x, p)
  let num = mod_pos(three_x2 - BigInt::from_int(3), p)
  let den = mod_pos(BigInt::from_int(2) * pt.y, p)
  let s = num * mod_inverse(den, p) % p
  let x3 = mod_pos(s * s - BigInt::from_int(2) * pt.x, p)
  let y3 = mod_pos(s * (pt.x - x3) - pt.y, p)
  { x: x3, y: y3, inf: false }
}

///|
fn point_add(p1 : Point, p2 : Point) -> Point {
  if p1.inf {
    return p2
  }
  if p2.inf {
    return p1
  }
  let p = p384_p()
  if p1.x == p2.x {
    if p1.y == p2.y {
      return point_double(p1)
    } else {
      return point_infinity()
    }
  }
  let dy = mod_pos(p2.y - p1.y, p)
  let dx = mod_pos(p2.x - p1.x, p)
  let s = dy * mod_inverse(dx, p) % p
  let x3 = mod_pos(s * s - p1.x - p2.x, p)
  let y3 = mod_pos(s * (p1.x - x3) - p1.y, p)
  { x: x3, y: y3, inf: false }
}

///|
// Variable-time double-and-add. Verify uses only public inputs. P-384
// scalars (< n < 2^384) fit in 48 bytes.
fn scalar_mult(k : BigInt, pt : Point) -> Point {
  if pt.inf {
    return pt
  }
  if k.is_zero() {
    return point_infinity()
  }
  let bytes = k.to_octets(length=48)
  let mut r = point_infinity()
  let mut started = false
  for i = 0; i < 48; i = i + 1 {
    let byte = bytes[i].to_int()
    for j = 7; j >= 0; j = j - 1 {
      if started {
        r = point_double(r)
      }
      let bit = (byte >> j) & 1
      if bit == 1 {
        if started {
          r = point_add(r, pt)
        } else {
          r = pt
          started = true
        }
      }
    }
  }
  ignore(point_neg)
  r
}

// ─── public key ──────────────────────────────────────────────────────────

///|
pub struct PublicKey {
  point : Point
}

///|
pub suberror P384Error {
  InvalidPublicKeyLength(Int)
  InvalidSignatureLength(Int)
  InvalidPointEncoding(String)
  PointNotOnCurve
  InvalidDerSignature(String)
  UnexpectedSpkiOid(String)
  Asn1(@asn1.Asn1Error)
} derive(Show)

///|
/// Parse an uncompressed SEC1 point `04 || X(48) || Y(48)` (97 bytes total).
pub fn PublicKey::from_uncompressed(b : Bytes) -> PublicKey raise P384Error {
  if b.length() != 97 {
    raise InvalidPublicKeyLength(b.length())
  }
  if b[0].to_int() != 0x04 {
    raise InvalidPointEncoding("expected uncompressed (0x04)")
  }
  let x_bytes = Bytes::makei(48, fn(i) { b[i + 1] })
  let y_bytes = Bytes::makei(48, fn(i) { b[i + 49] })
  let x = BigInt::from_octets(x_bytes[:])
  let y = BigInt::from_octets(y_bytes[:])
  let point : Point = { x, y, inf: false }
  if not(is_on_curve(point)) {
    raise PointNotOnCurve
  }
  { point, }
}

///|
/// Serialize the public key as SEC1 uncompressed: `04 || X(48) || Y(48)`.
pub fn PublicKey::to_uncompressed(self : PublicKey) -> Bytes {
  let x_bytes = self.point.x.to_octets(length=48)
  let y_bytes = self.point.y.to_octets(length=48)
  let out = FixedArray::make(97, b'\x00')
  out.unsafe_set(0, b'\x04')
  for i = 0; i < 48; i = i + 1 {
    out.unsafe_set(1 + i, x_bytes[i])
  }
  for i = 0; i < 48; i = i + 1 {
    out.unsafe_set(49 + i, y_bytes[i])
  }
  Bytes::makei(97, fn(j) { out.unsafe_get(j) })
}

///|
let id_ec_public_key_str : String = "1.2.840.10045.2.1"

///|
let secp384r1_named_curve_str : String = "1.3.132.0.34"

///|
fn decode_one_asn1(der : Bytes) -> @asn1.Element raise P384Error {
  @asn1.decode_der(der) catch {
    e => raise Asn1(e)
  }
}

///|
/// Decode a SubjectPublicKeyInfo DER blob for a P-384 key:
///   SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm  AlgorithmIdentifier {
///       algorithm  OID 1.2.840.10045.2.1   -- id-ecPublicKey
///       parameters OID 1.3.132.0.34        -- secp384r1 namedCurve
///     }
///     subjectPublicKey BIT STRING -- 04 || X(48) || Y(48)
///   }
pub fn PublicKey::from_spki_der(der : Bytes) -> PublicKey raise P384Error {
  let elem = decode_one_asn1(der)
  let items = match elem.value {
    Sequence(xs) => xs
    _ => raise InvalidPointEncoding("SPKI: expected SEQUENCE")
  }
  if items.length() != 2 {
    raise InvalidPointEncoding("SPKI: arity 2")
  }
  let alg_items = match items[0].value {
    Sequence(xs) => xs
    _ => raise InvalidPointEncoding("SPKI: algorithm not SEQUENCE")
  }
  if alg_items.length() != 2 {
    raise InvalidPointEncoding("SPKI: algorithm arity 2")
  }
  let alg_oid = match alg_items[0].value {
    Oid(o) => o.to_string()
    _ => raise InvalidPointEncoding("SPKI: expected algorithm OID")
  }
  if alg_oid != id_ec_public_key_str {
    raise UnexpectedSpkiOid(alg_oid)
  }
  let curve_oid = match alg_items[1].value {
    Oid(o) => o.to_string()
    _ =>
      raise InvalidPointEncoding(
        "SPKI: expected namedCurve OID in parameters",
      )
  }
  if curve_oid != secp384r1_named_curve_str {
    raise UnexpectedSpkiOid(curve_oid)
  }
  let bs = match items[1].value {
    BitString(b) => b
    _ => raise InvalidPointEncoding("SPKI: expected BIT STRING")
  }
  if bs.unused_bits != 0 {
    raise InvalidPointEncoding("SPKI: BIT STRING must have 0 unused bits")
  }
  PublicKey::from_uncompressed(bs.bytes)
}

// ─── signature parsing ───────────────────────────────────────────────────

///|
pub(all) enum SignatureFormat {
  // JWT / JOSE per RFC 7518 §3.4: r || s, each 48 bytes BE, total 96 bytes.
  Raw
  // X.509 / CMS / PKIX: ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }.
  Der
} derive(Eq, Show)

///|
fn integer_to_bigint(bytes : Bytes) -> BigInt raise P384Error {
  if bytes.length() == 0 {
    raise InvalidDerSignature("empty INTEGER")
  }
  if (bytes[0].to_int() & 0x80) != 0 {
    raise InvalidDerSignature("negative INTEGER not permitted")
  }
  let start = if bytes.length() > 1 && bytes[0] == b'\x00' { 1 } else { 0 }
  BigInt::from_octets(bytes[start:])
}

///|
fn parse_signature(
  sig : Bytes,
  fmt : SignatureFormat,
) -> (BigInt, BigInt) raise P384Error {
  match fmt {
    Raw => {
      if sig.length() != 96 {
        raise InvalidSignatureLength(sig.length())
      }
      let r_bytes = Bytes::makei(48, fn(i) { sig[i] })
      let s_bytes = Bytes::makei(48, fn(i) { sig[i + 48] })
      let r = BigInt::from_octets(r_bytes[:])
      let s = BigInt::from_octets(s_bytes[:])
      (r, s)
    }
    Der => {
      let elem = decode_one_asn1(sig)
      let items = match elem.value {
        Sequence(xs) => xs
        _ => raise InvalidDerSignature("expected SEQUENCE")
      }
      if items.length() != 2 {
        raise InvalidDerSignature("expected 2 INTEGERs")
      }
      let r_bytes = match items[0].value {
        Integer(b) => b
        _ => raise InvalidDerSignature("r not INTEGER")
      }
      let s_bytes = match items[1].value {
        Integer(b) => b
        _ => raise InvalidDerSignature("s not INTEGER")
      }
      let r = integer_to_bigint(r_bytes)
      let s = integer_to_bigint(s_bytes)
      (r, s)
    }
  }
}

// ─── ECDSA verify ────────────────────────────────────────────────────────

///|
/// Verify an ECDSA-with-SHA384 signature over `message` against `pubkey`.
pub fn verify(
  pubkey : PublicKey,
  message : Bytes,
  signature : Bytes,
  format : SignatureFormat,
) -> Bool raise P384Error {
  if not(is_on_curve(pubkey.point)) {
    return false
  }
  let (r, s) = parse_signature(signature, format)
  let n = p384_n()
  if r.compare_int(0) <= 0 || r.compare(n) >= 0 {
    return false
  }
  if s.compare_int(0) <= 0 || s.compare(n) >= 0 {
    return false
  }
  // e = SHA-384(M). FIPS 186-5 §6.4.2 step 4: qlen = 384 here, so the full
  // 48-byte digest IS e (no truncation, no zero-padding).
  let e_bytes = sha384(message)
  let e = BigInt::from_octets(e_bytes[:])
  let w = mod_inverse(s, n)
  let u1 = e * w % n
  let u2 = r * w % n
  let p1 = scalar_mult(u1, generator())
  let p2 = scalar_mult(u2, pubkey.point)
  let sum = point_add(p1, p2)
  if sum.inf {
    return false
  }
  sum.x % n == r
}
