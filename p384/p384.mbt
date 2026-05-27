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
  BigInt::from_string(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
    radix=16,
  )
}

///|
fn p384_b() -> BigInt {
  BigInt::from_string(
    "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
    radix=16,
  )
}

///|
fn p384_n() -> BigInt {
  // Order of the base point.
  BigInt::from_string(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
    radix=16,
  )
}

///|
fn p384_gx() -> BigInt {
  BigInt::from_string(
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
    radix=16,
  )
}

///|
fn p384_gy() -> BigInt {
  BigInt::from_string(
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
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
  let lhs = p_pt.y * p_pt.y % p
  let x3 = p_pt.x * p_pt.x % p * p_pt.x % p
  let three_x = BigInt::from_int(3) * p_pt.x % p
  let rhs = mod_pos(x3 - three_x + p384_b(), p)
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
  InvalidPrivateKey(String)
  Asn1(@asn1.Asn1Error)
} derive(Debug)

///|
fn coordinate_from_bytes(b : Bytes, offset : Int) -> BigInt raise P384Error {
  let coord_bytes = Bytes::makei(48, fn(i) { b[offset + i] })
  let coord = BigInt::from_octets(coord_bytes[:])
  if coord.compare(p384_p()) >= 0 {
    raise InvalidPointEncoding("coordinate must be canonical field element")
  }
  coord
}

///|
/// Parse an uncompressed SEC1 point `04 || X(48) || Y(48)` (97 bytes total).
pub fn PublicKey::from_uncompressed(b : Bytes) -> PublicKey raise P384Error {
  if b.length() != 97 {
    raise InvalidPublicKeyLength(b.length())
  }
  if b[0].to_int() != 0x04 {
    raise InvalidPointEncoding("expected uncompressed (0x04)")
  }
  let x = coordinate_from_bytes(b, 1)
  let y = coordinate_from_bytes(b, 49)
  let point : Point = { x, y, inf: false }
  if !is_on_curve(point) {
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
      raise InvalidPointEncoding("SPKI: expected namedCurve OID in parameters")
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
} derive(Eq, Debug)

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
  if !is_on_curve(pubkey.point) {
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
  let e_bytes = @hash.sha384(message)
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
/// Construct a private key from a 48-byte big-endian scalar.
pub fn PrivateKey::from_bytes(b : Bytes) -> PrivateKey raise P384Error {
  if b.length() != 48 {
    raise InvalidPrivateKey(
      "expected 48-byte scalar, got " + b.length().to_string(),
    )
  }
  let mut all_zero = true
  for i = 0; i < 48; i = i + 1 {
    if b[i] != b'\x00' {
      all_zero = false
      break
    }
  }
  if all_zero {
    raise InvalidPrivateKey("scalar is zero")
  }
  let d = BigInt::from_octets(b[:])
  let n = p384_n()
  if d.compare(n) >= 0 {
    raise InvalidPrivateKey("scalar >= n")
  }
  { d, }
}

///|
pub fn PrivateKey::public_key(self : PrivateKey) -> PublicKey {
  let point = scalar_mult(self.d, generator())
  { point, }
}

///|
/// ECDSA-SHA-384 sign with RFC 6979 deterministic nonce.
///
/// Side-channel caveat: see `@p256.PrivateKey::sign`. The scalar mult is
/// variable-time on `k`; RFC 6979 only addresses nonce-bias, not timing.
pub fn PrivateKey::sign(
  self : PrivateKey,
  message : Bytes,
  format? : SignatureFormat = Raw,
) -> Bytes {
  let n = p384_n()
  let e_bytes = @hash.sha384(message)
  let e = BigInt::from_octets(e_bytes[:])
  let mut k_ctr = 0
  let mut r = BigInt::from_int(0)
  let mut s = BigInt::from_int(0)
  let max_iter = 16
  let mut found = false
  let mut nonce_state = rfc6979_init_384(self.d, e_bytes, 48, n)
  while !found && k_ctr < max_iter {
    let (k, next_state) = rfc6979_next_384(nonce_state, 48, n)
    nonce_state = next_state
    let r_point = scalar_mult(k, generator())
    if !r_point.inf {
      r = r_point.x % n
      if r.compare(BigInt::from_int(0)) > 0 {
        let k_inv = mod_inverse(k, n)
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
    abort("ECDSA P-384 sign: nonce loop diverged")
  }
  encode_signature_p384(r, s, format)
}

///|
fn encode_signature_p384(
  r : BigInt,
  s : BigInt,
  format : SignatureFormat,
) -> Bytes {
  match format {
    Raw => {
      let r_bytes = r.to_octets(length=48)
      let s_bytes = s.to_octets(length=48)
      Bytes::makei(96, fn(i) {
        if i < 48 {
          r_bytes[i]
        } else {
          s_bytes[i - 48]
        }
      })
    }
    Der => encode_signature_der_p384(r, s)
  }
}

///|
fn encode_signature_der_p384(r : BigInt, s : BigInt) -> Bytes {
  let r_bytes = encode_der_integer_p384(r)
  let s_bytes = encode_der_integer_p384(s)
  let inner_len = r_bytes.length() + s_bytes.length()
  let len_prefix = encode_der_length_field_p384(inner_len)
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
fn encode_der_integer_p384(v : BigInt) -> Bytes {
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
  let len_prefix = encode_der_length_field_p384(body_len)
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
fn encode_der_length_field_p384(n : Int) -> Bytes {
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

// ─── RFC 6979 (HMAC-SHA-384, 48-byte) ────────────────────────────────────

///|
priv struct Rfc6979State384 {
  v : Bytes
  k : Bytes
}

///|
fn rfc6979_init_384(
  d : BigInt,
  h1 : Bytes,
  rlen : Int,
  q : BigInt,
) -> Rfc6979State384 {
  let hlen = h1.length()
  let v0 = Bytes::makei(hlen, fn(_) { b'\x01' })
  let k0 = Bytes::makei(hlen, fn(_) { b'\x00' })
  let x_oct = d.to_octets(length=rlen)
  let bb_h1 = bits2octets_384(h1, q, rlen)
  let k1 = @hash.hmac_sha384(k0, concat4_384(v0, b"\x00", x_oct, bb_h1))
  let v1 = @hash.hmac_sha384(k1, v0)
  let k2 = @hash.hmac_sha384(k1, concat4_384(v1, b"\x01", x_oct, bb_h1))
  let v2 = @hash.hmac_sha384(k2, v1)
  { v: v2, k: k2 }
}

///|
fn rfc6979_next_384(
  state : Rfc6979State384,
  rlen : Int,
  q : BigInt,
) -> (BigInt, Rfc6979State384) {
  let qlen_bits = bit_length_384(q)
  let mut v = state.v
  let mut t : Bytes = b""
  while t.length() < rlen {
    v = @hash.hmac_sha384(state.k, v)
    t = concat2_384(t, v)
  }
  let k_int = bits2int_384(t, qlen_bits)
  if k_int.compare(BigInt::from_int(0)) > 0 && k_int.compare(q) < 0 {
    let new_k = @hash.hmac_sha384(state.k, concat2_384(v, b"\x00"))
    let new_v = @hash.hmac_sha384(new_k, v)
    return (k_int, { v: new_v, k: new_k })
  }
  let new_k = @hash.hmac_sha384(state.k, concat2_384(v, b"\x00"))
  let new_v = @hash.hmac_sha384(new_k, v)
  rfc6979_next_384({ v: new_v, k: new_k }, rlen, q)
}

///|
fn bits2octets_384(b : Bytes, q : BigInt, rlen : Int) -> Bytes {
  let z1 = bits2int_384(b, bit_length_384(q))
  let z2 = z1 % q
  let z3 = if z2.compare(BigInt::from_int(0)) < 0 { z2 + q } else { z2 }
  z3.to_octets(length=rlen)
}

///|
fn bits2int_384(b : Bytes, qlen_bits : Int) -> BigInt {
  let blen = b.length() * 8
  let mut v = BigInt::from_octets(b[:])
  if blen > qlen_bits {
    let shift = blen - qlen_bits
    v = v >> shift
  }
  v
}

///|
fn bit_length_384(x : BigInt) -> Int {
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
fn concat2_384(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
fn concat4_384(a : Bytes, b : Bytes, c : Bytes, d : Bytes) -> Bytes {
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
pub fn PrivateKey::from_pkcs8_der(der : Bytes) -> PrivateKey raise P384Error {
  let info = @pkcs8.parse_der(der) catch {
    e => raise InvalidPrivateKey("pkcs8: " + @debug.to_string(e))
  }
  private_key_from_pkcs8_info(info)
}

///|
fn private_key_from_pkcs8_info(
  info : @pkcs8.PrivateKeyInfo,
) -> PrivateKey raise P384Error {
  if info.algorithm.algorithm != ec_public_key_oid_for_pkcs8() {
    raise InvalidPrivateKey(
      "expected id-ecPublicKey, got " + info.algorithm.algorithm.to_string(),
    )
  }
  // RFC 5958 §2: validate the named-curve OID. See p256/p256.mbt for the
  // rationale (without this, a P-256 PKCS#8 blob would silently load as
  // P-384 whenever the scalar fits).
  match info.algorithm.parameters {
    Some(param_bytes) => {
      let elem = @asn1.decode_der(param_bytes) catch { e => raise Asn1(e) }
      let curve_oid = match elem.value {
        Oid(o) => o.to_string()
        _ => raise InvalidPrivateKey("PKCS#8 EC parameters not OID")
      }
      if curve_oid != secp384r1_named_curve_str {
        raise InvalidPrivateKey(
          "wrong namedCurve in PKCS#8 (expected " +
          secp384r1_named_curve_str +
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
  let scalar_bytes = match items[1].value {
    OctetString(b) => b
    _ => raise InvalidPrivateKey("SEC1 privateKey not OCTET STRING")
  }
  for i = 2; i < items.length(); i = i + 1 {
    let it = items[i]
    if it.tag.class_ == @asn1.TagClass::ContextSpecific && it.tag.number == 0U {
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
      if inner_curve_oid != secp384r1_named_curve_str {
        raise InvalidPrivateKey(
          "SEC1 inner namedCurve mismatch (expected " +
          secp384r1_named_curve_str +
          ", got " +
          inner_curve_oid +
          ")",
        )
      }
    }
  }
  let padded = if scalar_bytes.length() == 48 {
    scalar_bytes
  } else if scalar_bytes.length() < 48 {
    let pad = 48 - scalar_bytes.length()
    Bytes::makei(48, fn(i) {
      if i < pad {
        b'\x00'
      } else {
        scalar_bytes[i - pad]
      }
    })
  } else {
    raise InvalidPrivateKey(
      "EC scalar wider than 48 bytes: " + scalar_bytes.length().to_string(),
    )
  }
  let sk = PrivateKey::from_bytes(padded)
  match info.public_key {
    Some(bs) =>
      if bs.unused_bits != 0 || bs.bytes != sk.public_key().to_uncompressed() {
        raise InvalidPrivateKey("PKCS#8 publicKey does not match privateKey")
      }
    None => ()
  }
  sk
}

///|
pub fn PrivateKey::from_pkcs8_pem(
  pem_str : String,
) -> PrivateKey raise P384Error {
  let info = @pkcs8.parse_pem(pem_str) catch {
    e => raise InvalidPrivateKey("pkcs8: " + @debug.to_string(e))
  }
  private_key_from_pkcs8_info(info)
}
