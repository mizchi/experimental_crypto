// NIST P-521 (secp521r1) ECDSA signature verification and signing.
//
// Curve: y² = x³ - 3x + b over GF(p) with p, b, n, G from FIPS 186-5 §D.1.2.4.
//
// Scope and structure mirror `mizchi/p256`:
//   - verify  (FIPS 186-5 §6.4.2 / ANSI X9.62)
//   - sign    (RFC 6979 deterministic nonce)
//   - public key parsing: uncompressed (04 || X || Y), 133 bytes total; SPKI
//   - signature parsing: JWT/JOSE raw (r||s, 132B) and X.509 DER SEQUENCE
//
// Out of scope: key generation, point compression, ECDH.

// ─── curve constants (NIST FIPS 186-5 §D.1.2.4) ──────────────────────────

///|
fn p521_p() -> BigInt {
  BigInt::from_string(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    radix=16,
  )
}

///|
fn p521_b() -> BigInt {
  BigInt::from_string(
    "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
    radix=16,
  )
}

///|
fn p521_n() -> BigInt {
  // Order of the base point.
  BigInt::from_string(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    radix=16,
  )
}

///|
fn p521_gx() -> BigInt {
  BigInt::from_string(
    "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
    radix=16,
  )
}

///|
fn p521_gy() -> BigInt {
  BigInt::from_string(
    "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
    radix=16,
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
  { x: p521_gx(), y: p521_gy(), inf: false }
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
// Modular inverse via Fermat's little theorem. This implementation is
// functional and fail-closed for public-input affine verify arithmetic.
// Sign-side nonce inversion uses `scalar_inverse` instead.
fn mod_inverse(a : BigInt, m : BigInt) -> BigInt {
  let exp = m - BigInt::from_int(2)
  a.pow(exp, modulus=m)
}

///|
fn scalar_inverse(a : BigInt, m : BigInt) -> BigInt {
  let a_u = @crypto_bigint.Uint::from_be_bytes(
    mod_pos(a, m).to_octets(length=66),
    9,
  ) catch {
    _ => abort("P-521 inverse input does not fit 66 bytes")
  }
  let m_u = @crypto_bigint.Uint::from_be_bytes(m.to_octets(length=66), 9) catch {
    _ => abort("P-521 modulus does not fit 66 bytes")
  }
  let inv = a_u.inv_mod(m_u) catch {
    _ => abort("P-521 inverse does not exist")
  }
  fixed_bigint_from_octets(inv.to_be_bytes()[:])
}

///|
fn is_on_curve(p_pt : Point) -> Bool {
  if p_pt.inf {
    return true
  }
  let p = p521_p()
  let lhs = p_pt.y * p_pt.y % p
  let x3 = p_pt.x * p_pt.x % p * p_pt.x % p
  let three_x = BigInt::from_int(3) * p_pt.x % p
  let rhs = mod_pos(x3 - three_x + p521_b(), p)
  lhs == rhs
}

///|
fn point_double(pt : Point) -> Point {
  if pt.inf {
    return pt
  }
  if pt.y.is_zero() {
    return point_infinity()
  }
  let p = p521_p()
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
  let p = p521_p()
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
// Variable-time double-and-add. Verify uses only public inputs. P-521 signing
// routes base-point multiplication through `fe521_scalar_mult_base_fixed`
// instead of this affine helper.
fn scalar_mult(k : BigInt, pt : Point) -> Point {
  if pt.inf {
    return pt
  }
  if k.is_zero() {
    return point_infinity()
  }
  let bytes = k.to_octets(length=66)
  let mut r = point_infinity()
  let mut started = false
  for i = 0; i < 66; i = i + 1 {
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
  r
}

// ─── public key ──────────────────────────────────────────────────────────

///|
pub struct PublicKey {
  point : Point
}

///|
pub suberror P521Error {
  InvalidPublicKeyLength(Int)
  InvalidSignatureLength(Int)
  InvalidPointEncoding(String)
  PointNotOnCurve
  InvalidDerSignature(String)
  UnexpectedSpkiOid(String)
  InvalidPrivateKey(String)
  Asn1(@asn1.Asn1Error)
} derive(Debug)

///|
fn coordinate_from_bytes(b : Bytes, offset : Int) -> BigInt raise P521Error {
  let coord_bytes = Bytes::makei(66, fn(i) { b[offset + i] })
  let coord = BigInt::from_octets(coord_bytes[:])
  if coord.compare(p521_p()) >= 0 {
    raise InvalidPointEncoding("coordinate must be canonical field element")
  }
  coord
}

///|
/// Parse an uncompressed SEC1 point `04 || X(66) || Y(66)` (133 bytes total).
pub fn PublicKey::from_uncompressed(b : Bytes) -> PublicKey raise P521Error {
  if b.length() != 133 {
    raise InvalidPublicKeyLength(b.length())
  }
  if b[0].to_int() != 0x04 {
    raise InvalidPointEncoding("expected uncompressed (0x04)")
  }
  let x = coordinate_from_bytes(b, 1)
  let y = coordinate_from_bytes(b, 67)
  let point : Point = { x, y, inf: false }
  if !is_on_curve(point) {
    raise PointNotOnCurve
  }
  { point, }
}

///|
/// Serialize the public key as SEC1 uncompressed: `04 || X(66) || Y(66)`.
pub fn PublicKey::to_uncompressed(self : PublicKey) -> Bytes {
  let x_bytes = self.point.x.to_octets(length=66)
  let y_bytes = self.point.y.to_octets(length=66)
  let out = FixedArray::make(133, b'\x00')
  out.unsafe_set(0, b'\x04')
  for i = 0; i < 66; i = i + 1 {
    out.unsafe_set(1 + i, x_bytes[i])
  }
  for i = 0; i < 66; i = i + 1 {
    out.unsafe_set(67 + i, y_bytes[i])
  }
  Bytes::makei(133, fn(j) { out.unsafe_get(j) })
}

///|
let id_ec_public_key_str : String = "1.2.840.10045.2.1"

///|
let secp521r1_named_curve_str : String = "1.3.132.0.35"

///|
fn decode_one_asn1(der : Bytes) -> @asn1.Element raise P521Error {
  @asn1.decode_der(der) catch {
    e => raise Asn1(e)
  }
}

///|
/// Decode a SubjectPublicKeyInfo DER blob for a P-521 key:
///   SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm  AlgorithmIdentifier {
///       algorithm  OID 1.2.840.10045.2.1   -- id-ecPublicKey
///       parameters OID 1.3.132.0.35        -- secp521r1 namedCurve
///     }
///     subjectPublicKey BIT STRING -- 04 || X(66) || Y(66)
///   }
pub fn PublicKey::from_spki_der(der : Bytes) -> PublicKey raise P521Error {
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
      raise InvalidPointEncoding("SPKI: expected namedCurve OID in parameters")
  }
  if curve_oid != secp521r1_named_curve_str {
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
fn bytes_all_zero(b : BytesView) -> Bool {
  for i in 0..<b.length() {
    if b[i] != b'\x00' {
      return false
    }
  }
  true
}

///|
fn fixed_bigint_from_octets(b : BytesView) -> BigInt {
  if bytes_all_zero(b) {
    BigInt::from_int(0)
  } else {
    BigInt::from_octets(b[:])
  }
}

///|
pub(all) enum SignatureFormat {
  // JWT / JOSE per RFC 7518 §3.4: r || s, each 66 bytes BE, total 132 bytes.
  Raw
  // X.509 / CMS / PKIX: ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }.
  Der
} derive(Eq, Debug)

///|
fn integer_to_bigint(bytes : Bytes) -> BigInt raise P521Error {
  if bytes.length() == 0 {
    raise InvalidDerSignature("empty INTEGER")
  }
  if (bytes[0].to_int() & 0x80) != 0 {
    raise InvalidDerSignature("negative INTEGER not permitted")
  }
  let start = if bytes.length() > 1 && bytes[0] == b'\x00' { 1 } else { 0 }
  fixed_bigint_from_octets(bytes[start:])
}

///|
fn parse_signature(
  sig : Bytes,
  fmt : SignatureFormat,
) -> (BigInt, BigInt) raise P521Error {
  match fmt {
    Raw => {
      if sig.length() != 132 {
        raise InvalidSignatureLength(sig.length())
      }
      let r_bytes = Bytes::makei(66, fn(i) { sig[i] })
      let s_bytes = Bytes::makei(66, fn(i) { sig[i + 66] })
      let r = fixed_bigint_from_octets(r_bytes[:])
      let s = fixed_bigint_from_octets(s_bytes[:])
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
/// Verify an ECDSA-with-SHA512 signature over `message` against `pubkey`.
pub fn verify(
  pubkey : PublicKey,
  message : Bytes,
  signature : Bytes,
  format : SignatureFormat,
) -> Bool raise P521Error {
  if !is_on_curve(pubkey.point) {
    return false
  }
  let (r, s) = parse_signature(signature, format)
  let n = p521_n()
  if r.compare_int(0) <= 0 || r.compare(n) >= 0 {
    return false
  }
  if s.compare_int(0) <= 0 || s.compare(n) >= 0 {
    return false
  }
  // e = SHA-512(M). FIPS 186-5 §6.4.2 step 4: qlen = 521 here, so the full
  // 64-byte digest IS e (no truncation, no zero-padding).
  let e_bytes = @hash.sha512(message)
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

// ─── private key + sign (RFC 6979 deterministic ECDSA) ───────────────────

///|
pub struct PrivateKey {
  d : BigInt
}

///|
/// Construct a private key from a 66-byte big-endian scalar.
pub fn PrivateKey::from_bytes(b : Bytes) -> PrivateKey raise P521Error {
  if b.length() != 66 {
    raise InvalidPrivateKey(
      "expected 66-byte scalar, got " + b.length().to_string(),
    )
  }
  let mut all_zero = true
  for i = 0; i < 66; i = i + 1 {
    if b[i] != b'\x00' {
      all_zero = false
      break
    }
  }
  if all_zero {
    raise InvalidPrivateKey("scalar is zero")
  }
  let d = BigInt::from_octets(b[:])
  let n = p521_n()
  if d.compare(n) >= 0 {
    raise InvalidPrivateKey("scalar >= n")
  }
  { d, }
}

///|
pub fn PrivateKey::public_key(self : PrivateKey) -> PublicKey {
  let point = fe521_scalar_mult_base_fixed(self.d)
  { point, }
}

///|
/// ECDSA-SHA-512 sign with RFC 6979 deterministic nonce.
///
/// The sign-side base-point multiplication and final nonce inverse use
/// fixed-limb / fixed-iteration `crypto_bigint` paths. This is not external
/// constant-time evidence; see `docs/CONSTANT_TIME.md`.
pub fn PrivateKey::sign(
  self : PrivateKey,
  message : Bytes,
  format? : SignatureFormat = Raw,
) -> Bytes {
  let n = p521_n()
  let e_bytes = @hash.sha512(message)
  let e = BigInt::from_octets(e_bytes[:])
  let mut k_ctr = 0
  let mut r = BigInt::from_int(0)
  let mut s = BigInt::from_int(0)
  let max_iter = 16
  let mut found = false
  let mut nonce_state = rfc6979_init_521(self.d, e_bytes, 66, n)
  while !found && k_ctr < max_iter {
    let (k, next_state) = rfc6979_next_521(nonce_state, 66, n)
    nonce_state = next_state
    let r_point = fe521_scalar_mult_base_fixed(k)
    if !r_point.inf {
      r = r_point.x % n
      if r.compare(BigInt::from_int(0)) > 0 {
        let k_inv = scalar_inverse(k, n)
        let s_calc = k_inv * ((e + r * self.d) % n) % n
        if s_calc.compare(BigInt::from_int(0)) > 0 {
          s = s_calc
          found = true
        }
      }
    }
    k_ctr = k_ctr + 1
  }
  if !found {
    abort("ECDSA P-521 sign: nonce loop diverged")
  }
  encode_signature_p521(r, s, format)
}

///|
fn encode_signature_p521(
  r : BigInt,
  s : BigInt,
  format : SignatureFormat,
) -> Bytes {
  match format {
    Raw => {
      let r_bytes = r.to_octets(length=66)
      let s_bytes = s.to_octets(length=66)
      Bytes::makei(132, fn(i) {
        if i < 66 {
          r_bytes[i]
        } else {
          s_bytes[i - 66]
        }
      })
    }
    Der => encode_signature_der_p521(r, s)
  }
}

///|
fn encode_signature_der_p521(r : BigInt, s : BigInt) -> Bytes {
  let r_bytes = encode_der_integer_p521(r)
  let s_bytes = encode_der_integer_p521(s)
  let inner_len = r_bytes.length() + s_bytes.length()
  let len_prefix = encode_der_length_field_p521(inner_len)
  let total = 1 + len_prefix.length() + inner_len
  Bytes::makei(total, fn(i) {
    if i == 0 {
      b'\x30'
    } else if i < 1 + len_prefix.length() {
      len_prefix[i - 1]
    } else if i - 1 - len_prefix.length() < r_bytes.length() {
      r_bytes[i - 1 - len_prefix.length()]
    } else {
      s_bytes[i - 1 - len_prefix.length() - r_bytes.length()]
    }
  })
}

///|
fn encode_der_integer_p521(v : BigInt) -> Bytes {
  let mut mag = v.to_octets()
  let mut start = 0
  while start < mag.length() - 1 && mag[start] == b'\x00' {
    start = start + 1
  }
  if start > 0 {
    mag = Bytes::makei(mag.length() - start, fn(i) { mag[i + start] })
  }
  let needs_sign = (mag[0].to_int() & 0x80) != 0
  let body_len = mag.length() + (if needs_sign { 1 } else { 0 })
  let len_prefix = encode_der_length_field_p521(body_len)
  let total = 1 + len_prefix.length() + body_len
  Bytes::makei(total, fn(i) {
    if i == 0 {
      b'\x02'
    } else if i < 1 + len_prefix.length() {
      len_prefix[i - 1]
    } else if needs_sign && i == 1 + len_prefix.length() {
      b'\x00'
    } else {
      let mag_idx = i -
        1 -
        len_prefix.length() -
        (if needs_sign { 1 } else { 0 })
      mag[mag_idx]
    }
  })
}

///|
fn encode_der_length_field_p521(n : Int) -> Bytes {
  if n < 0x80 {
    Bytes::makei(1, fn(_) { n.to_byte() })
  } else if n < 0x100 {
    Bytes::makei(2, fn(i) { if i == 0 { b'\x81' } else { n.to_byte() } })
  } else if n < 0x10000 {
    Bytes::makei(3, fn(i) {
      if i == 0 {
        b'\x82'
      } else if i == 1 {
        ((n >> 8) & 0xff).to_byte()
      } else {
        (n & 0xff).to_byte()
      }
    })
  } else {
    abort("DER length too big")
  }
}

// ─── RFC 6979 (HMAC-SHA-512, 66-byte) ────────────────────────────────────

///|
priv struct Rfc6979State521 {
  v : Bytes
  k : Bytes
}

///|
fn rfc6979_init_521(
  d : BigInt,
  h1 : Bytes,
  rlen : Int,
  q : BigInt,
) -> Rfc6979State521 {
  let hlen = h1.length()
  let v0 = Bytes::makei(hlen, fn(_) { b'\x01' })
  let k0 = Bytes::makei(hlen, fn(_) { b'\x00' })
  let x_oct = d.to_octets(length=rlen)
  let bb_h1 = bits2octets_521(h1, q, rlen)
  let k1 = @hash.hmac_sha512(k0, concat4_521(v0, b"\x00", x_oct, bb_h1))
  let v1 = @hash.hmac_sha512(k1, v0)
  let k2 = @hash.hmac_sha512(k1, concat4_521(v1, b"\x01", x_oct, bb_h1))
  let v2 = @hash.hmac_sha512(k2, v1)
  { v: v2, k: k2 }
}

///|
fn rfc6979_next_521(
  state : Rfc6979State521,
  rlen : Int,
  q : BigInt,
) -> (BigInt, Rfc6979State521) {
  let qlen_bits = bit_length_521(q)
  let mut v = state.v
  let mut t : Bytes = b""
  while t.length() < rlen {
    v = @hash.hmac_sha512(state.k, v)
    t = concat2_521(t, v)
  }
  let k_int = bits2int_521(t, qlen_bits)
  if k_int.compare(BigInt::from_int(0)) > 0 && k_int.compare(q) < 0 {
    let new_k = @hash.hmac_sha512(state.k, concat2_521(v, b"\x00"))
    let new_v = @hash.hmac_sha512(new_k, v)
    return (k_int, { v: new_v, k: new_k })
  }
  let new_k = @hash.hmac_sha512(state.k, concat2_521(v, b"\x00"))
  let new_v = @hash.hmac_sha512(new_k, v)
  rfc6979_next_521({ v: new_v, k: new_k }, rlen, q)
}

///|
fn bits2octets_521(b : Bytes, q : BigInt, rlen : Int) -> Bytes {
  let z1 = bits2int_521(b, bit_length_521(q))
  let z2 = z1 % q
  let z3 = if z2.compare(BigInt::from_int(0)) < 0 { z2 + q } else { z2 }
  z3.to_octets(length=rlen)
}

///|
fn bits2int_521(b : Bytes, qlen_bits : Int) -> BigInt {
  let blen = b.length() * 8
  let mut v = BigInt::from_octets(b[:])
  if blen > qlen_bits {
    let shift = blen - qlen_bits
    v = v >> shift
  }
  v
}

///|
fn bit_length_521(x : BigInt) -> Int {
  let bytes = x.to_octets()
  let mut start = 0
  while start < bytes.length() && bytes[start] == b'\x00' {
    start = start + 1
  }
  if start >= bytes.length() {
    return 0
  }
  let leading = bytes[start].to_int()
  let mut bits = (bytes.length() - start - 1) * 8
  let mut b = leading
  while b > 0 {
    bits = bits + 1
    b = b >> 1
  }
  bits
}

///|
fn concat2_521(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
fn concat4_521(a : Bytes, b : Bytes, c : Bytes, d : Bytes) -> Bytes {
  let na = a.length()
  let nb = b.length()
  let nc = c.length()
  let nd = d.length()
  Bytes::makei(na + nb + nc + nd, fn(i) {
    if i < na {
      a[i]
    } else if i < na + nb {
      b[i - na]
    } else if i < na + nb + nc {
      c[i - na - nb]
    } else {
      d[i - na - nb - nc]
    }
  })
}

// ─── PKCS#8 / PEM loaders ────────────────────────────────────────────────

///|
fn ec_public_key_oid_for_pkcs8() -> @asn1.ObjectIdentifier {
  @asn1.ObjectIdentifier::from_arcs([1U, 2, 840, 10045, 2, 1])
}

///|
pub fn PrivateKey::from_pkcs8_der(der : Bytes) -> PrivateKey raise P521Error {
  let info = @pkcs8.parse_der(der) catch {
    e => raise InvalidPrivateKey("pkcs8: " + @debug.to_string(e))
  }
  private_key_from_pkcs8_info(info)
}

///|
fn private_key_from_pkcs8_info(
  info : @pkcs8.PrivateKeyInfo,
) -> PrivateKey raise P521Error {
  if info.algorithm.algorithm != ec_public_key_oid_for_pkcs8() {
    raise InvalidPrivateKey(
      "expected id-ecPublicKey, got " + info.algorithm.algorithm.to_string(),
    )
  }
  // RFC 5958 §2: validate the named-curve OID. See p256/p256.mbt for the
  // rationale (without this, a P-256 PKCS#8 blob would silently load as
  // P-521 whenever the scalar fits).
  match info.algorithm.parameters {
    Some(param_bytes) => {
      let elem = @asn1.decode_der(param_bytes) catch { e => raise Asn1(e) }
      let curve_oid = match elem.value {
        Oid(o) => o.to_string()
        _ => raise InvalidPrivateKey("PKCS#8 EC parameters not OID")
      }
      if curve_oid != secp521r1_named_curve_str {
        raise InvalidPrivateKey(
          "wrong namedCurve in PKCS#8 (expected " +
          secp521r1_named_curve_str +
          ", got " +
          curve_oid +
          ")",
        )
      }
    }
    None => raise InvalidPrivateKey("PKCS#8 EC parameters missing")
  }
  let inner_elem = @asn1.decode_der(info.private_key) catch {
    e => raise Asn1(e)
  }
  let items = match inner_elem.value {
    Sequence(xs) => xs
    _ => raise InvalidPrivateKey("SEC1 ECPrivateKey not a SEQUENCE")
  }
  if items.length() < 2 {
    raise InvalidPrivateKey("SEC1 ECPrivateKey arity < 2")
  }
  match items[0].value {
    Integer(b) =>
      if b != b"\x01" {
        raise InvalidPrivateKey("SEC1 ECPrivateKey version must be 1")
      }
    _ => raise InvalidPrivateKey("SEC1 ECPrivateKey version not INTEGER")
  }
  let scalar_bytes = match items[1].value {
    OctetString(b) => b
    _ => raise InvalidPrivateKey("SEC1 privateKey not OCTET STRING")
  }
  let mut seen_inner_parameters = false
  let mut seen_inner_public_key = false
  let mut inner_public_key : Bytes? = None
  for i = 2; i < items.length(); i = i + 1 {
    let it = items[i]
    if it.tag.class_ == @asn1.TagClass::ContextSpecific && it.tag.number == 0U {
      if !it.tag.constructed {
        raise InvalidPrivateKey("SEC1 inner parameters must be explicit")
      }
      if seen_inner_parameters {
        raise InvalidPrivateKey("duplicate SEC1 inner parameters")
      }
      seen_inner_parameters = true
      let inner_param_bytes = match it.value {
        Unknown(b) => b
        _ => raise InvalidPrivateKey("SEC1 inner parameters: unexpected shape")
      }
      let inner_param_elem = @asn1.decode_der(inner_param_bytes) catch {
        e => raise Asn1(e)
      }
      let inner_curve_oid = match inner_param_elem.value {
        Oid(o) => o.to_string()
        _ => raise InvalidPrivateKey("SEC1 inner parameters not OID")
      }
      if inner_curve_oid != secp521r1_named_curve_str {
        raise InvalidPrivateKey(
          "SEC1 inner namedCurve mismatch (expected " +
          secp521r1_named_curve_str +
          ", got " +
          inner_curve_oid +
          ")",
        )
      }
    } else if it.tag.class_ == @asn1.TagClass::ContextSpecific &&
      it.tag.number == 1U {
      if !it.tag.constructed {
        raise InvalidPrivateKey("SEC1 inner publicKey must be explicit")
      }
      if seen_inner_public_key {
        raise InvalidPrivateKey("duplicate SEC1 inner publicKey")
      }
      seen_inner_public_key = true
      let inner_public_bytes = match it.value {
        Unknown(b) => b
        _ => raise InvalidPrivateKey("SEC1 inner publicKey: unexpected shape")
      }
      let inner_public_elem = @asn1.decode_der(inner_public_bytes) catch {
        e => raise Asn1(e)
      }
      let bs = match inner_public_elem.value {
        BitString(bs) => bs
        _ => raise InvalidPrivateKey("SEC1 inner publicKey not BIT STRING")
      }
      if bs.unused_bits != 0 {
        raise InvalidPrivateKey("SEC1 inner publicKey unused bits must be zero")
      }
      inner_public_key = Some(bs.bytes)
    } else if it.tag.class_ == @asn1.TagClass::ContextSpecific {
      raise InvalidPrivateKey("unexpected SEC1 context-specific field")
    } else {
      raise InvalidPrivateKey("unexpected SEC1 ECPrivateKey field")
    }
  }
  let padded = if scalar_bytes.length() == 66 {
    scalar_bytes
  } else if scalar_bytes.length() < 66 {
    let pad = 66 - scalar_bytes.length()
    Bytes::makei(66, fn(i) {
      if i < pad {
        b'\x00'
      } else {
        scalar_bytes[i - pad]
      }
    })
  } else {
    raise InvalidPrivateKey(
      "EC scalar wider than 66 bytes: " + scalar_bytes.length().to_string(),
    )
  }
  let sk = PrivateKey::from_bytes(padded)
  let derived_public = sk.public_key().to_uncompressed()
  match inner_public_key {
    Some(b) =>
      if b != derived_public {
        raise InvalidPrivateKey(
          "SEC1 inner publicKey does not match privateKey",
        )
      }
    None => ()
  }
  match info.public_key {
    Some(bs) =>
      if bs.unused_bits != 0 || bs.bytes != derived_public {
        raise InvalidPrivateKey("PKCS#8 publicKey does not match privateKey")
      }
    None => ()
  }
  sk
}

///|
pub fn PrivateKey::from_pkcs8_pem(
  pem_str : String,
) -> PrivateKey raise P521Error {
  let info = @pkcs8.parse_pem(pem_str) catch {
    e => raise InvalidPrivateKey("pkcs8: " + @debug.to_string(e))
  }
  private_key_from_pkcs8_info(info)
}
