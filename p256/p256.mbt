// NIST P-256 (secp256r1) ECDSA signature verification (verify-only).
//
// Curve: y² = x³ - 3x + b over GF(p) with p, b, n, G from FIPS 186-5 §D.1.2.3.
//
// Scope:
//   - verify  (RFC 6979 / FIPS 186-5 §6.4.2)
//   - public key parsing: uncompressed (04 || x || y) and SPKI
//   - signature parsing: JWT/JOSE raw (r||s, 64B) and X.509 DER SEQUENCE
//
// Out of scope: sign, key generation, point compression, ECDH.
//
// Implementation notes:
//   - Affine Weierstrass points with a separate "point at infinity" flag.
//     For verify the input is public, so variable-time scalar mult is fine
//     and the simpler representation pays for itself.
//   - All field arithmetic goes through @bigint with explicit `% p`. The hot
//     path (verify) does O(256) field muls per scalar_mult × 2 ladders;
//     measured cost is dominated by mod-exp inside `mod_inverse`.
//   - Modular inverse uses Fermat's little theorem (`a^(m-2) mod m`) since
//     both `p` and `n` are prime. Avoids an extended-Euclidean implementation.

// ─── curve constants (NIST FIPS 186-5 §D.1.2.3) ──────────────────────────

///|
fn p256_p() -> BigInt {
  BigInt::from_hex(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
  )
}

///|
fn p256_b() -> BigInt {
  BigInt::from_hex(
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
  )
}

///|
fn p256_n() -> BigInt {
  // Order of the base point.
  BigInt::from_hex(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
  )
}

///|
fn p256_gx() -> BigInt {
  BigInt::from_hex(
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
  )
}

///|
fn p256_gy() -> BigInt {
  BigInt::from_hex(
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
  )
}

// ─── affine point ────────────────────────────────────────────────────────

///|
// Affine Weierstrass point. Package-private (no `pub`): consumers should go
// through `PublicKey` and never touch `Point` directly.
struct Point {
  x : BigInt
  y : BigInt
  // Identity (point at infinity). When `inf == true` the x/y values are
  // ignored; we keep zeros there but no code path should rely on them.
  inf : Bool
}

///|
fn point_infinity() -> Point {
  { x: BigInt::from_int(0), y: BigInt::from_int(0), inf: true }
}

///|
fn generator() -> Point {
  { x: p256_gx(), y: p256_gy(), inf: false }
}

///|
// Reduce `a` into [0, m). Handles inputs from subtractions (which @bigint
// returns as a signed result) by adding `m` once when negative. We never
// produce inputs more than `m` below zero so a single fix-up suffices.
fn mod_pos(a : BigInt, m : BigInt) -> BigInt {
  let r = a % m
  if r.compare_int(0) < 0 {
    r + m
  } else {
    r
  }
}

///|
// Modular inverse via Fermat's little theorem: a^(m-2) mod m. Requires `m`
// prime, which is true for both `p` (field characteristic) and `n` (group
// order). Returns garbage for non-prime `m`; we never pass one.
fn mod_inverse(a : BigInt, m : BigInt) -> BigInt {
  let exp = m - BigInt::from_int(2)
  a.pow(exp, modulus=m)
}

///|
// y² ≟ x³ - 3x + b (mod p). Identity is considered on-curve.
fn is_on_curve(p_pt : Point) -> Bool {
  if p_pt.inf {
    return true
  }
  let p = p256_p()
  let lhs = (p_pt.y * p_pt.y) % p
  let x3 = (p_pt.x * p_pt.x % p * p_pt.x) % p
  // a = -3 (mod p), expressed as `(p - 3) * x mod p` to keep everything
  // non-negative before the final mod.
  let three_x = (BigInt::from_int(3) * p_pt.x) % p
  let rhs = mod_pos(x3 - three_x + p256_b(), p)
  lhs == rhs
}

///|
// Negation: (x, -y mod p). The identity negates to itself.
fn point_neg(pt : Point) -> Point {
  if pt.inf {
    return pt
  }
  let p = p256_p()
  { x: pt.x, y: mod_pos(p - pt.y, p), inf: false }
}

///|
// Affine doubling. For a = -3 the slope is (3x² + a) / 2y = (3x² - 3) / 2y
// = 3(x-1)(x+1) / 2y. We use the straightforward form so the formula
// matches FIPS 186-5 line-for-line; the `(x-1)(x+1)` factoring is not on
// the hot path.
fn point_double(pt : Point) -> Point {
  if pt.inf {
    return pt
  }
  if pt.y.is_zero() {
    return point_infinity()
  }
  let p = p256_p()
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
// Affine addition. Dispatches to double / infinity / negation as needed.
fn point_add(p1 : Point, p2 : Point) -> Point {
  if p1.inf {
    return p2
  }
  if p2.inf {
    return p1
  }
  let p = p256_p()
  if p1.x == p2.x {
    // Same x — either same point (double) or inverse (infinity).
    if p1.y == p2.y {
      return point_double(p1)
    } else {
      return point_infinity()
    }
  }
  // slope = (y2 - y1) / (x2 - x1)
  let dy = mod_pos(p2.y - p1.y, p)
  let dx = mod_pos(p2.x - p1.x, p)
  let s = dy * mod_inverse(dx, p) % p
  let x3 = mod_pos(s * s - p1.x - p2.x, p)
  let y3 = mod_pos(s * (p1.x - x3) - p1.y, p)
  { x: x3, y: y3, inf: false }
}

///|
// Variable-time double-and-add. Verify uses only public inputs, so a
// constant-time ladder is not required. Walks the scalar high byte → low,
// MSB → LSB within each byte.
//
// We extract bits via to_octets(length=32) — that's one BigInt allocation
// per scalar_mult instead of one per bit, which would be ~256× slower with
// @bigint's per-call overhead.
fn scalar_mult(k : BigInt, pt : Point) -> Point {
  if pt.inf {
    return pt
  }
  if k.is_zero() {
    return point_infinity()
  }
  // Scalars in ECDSA verify are reduced mod n < 2^256, so 32 bytes is
  // always sufficient. to_octets pads/truncates to that fixed length.
  let bytes = k.to_octets(length=32)
  let mut r = point_infinity()
  let mut started = false
  for i = 0; i < 32; i = i + 1 {
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
          // First 1 bit seen — start the ladder here. Skips leading
          // zeros so we don't double the identity 256 times for small k.
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
// PublicKey is opaque: construct via `from_uncompressed` / `from_spki_der`,
// inspect via `to_uncompressed`. The internal Point representation is not
// part of the public API.
pub struct PublicKey {
  point : Point
}

///|
pub suberror P256Error {
  InvalidPublicKeyLength(Int)
  InvalidSignatureLength(Int)
  InvalidPointEncoding(String)
  PointNotOnCurve
  InvalidDerSignature(String)
  UnexpectedSpkiOid(String)
  InvalidPrivateKey(String)
  Asn1(@asn1.Asn1Error)
} derive(Show)

///|
/// Parse an uncompressed SEC1 point `04 || X(32) || Y(32)` (65 bytes total).
/// Rejects the compressed (`02`/`03`) and hybrid (`06`/`07`) forms — none of
/// our consumers (JWT, X.509 for the named curves we care about) use them.
pub fn PublicKey::from_uncompressed(b : Bytes) -> PublicKey raise P256Error {
  if b.length() != 65 {
    raise InvalidPublicKeyLength(b.length())
  }
  if b[0].to_int() != 0x04 {
    raise InvalidPointEncoding("expected uncompressed (0x04)")
  }
  let x_bytes = Bytes::makei(32, fn(i) { b[i + 1] })
  let y_bytes = Bytes::makei(32, fn(i) { b[i + 33] })
  let x = BigInt::from_octets(x_bytes[:])
  let y = BigInt::from_octets(y_bytes[:])
  let point : Point = { x, y, inf: false }
  if not(is_on_curve(point)) {
    raise PointNotOnCurve
  }
  { point, }
}

///|
/// Serialize the public key as SEC1 uncompressed: `04 || X(32) || Y(32)`.
/// Raises nothing because we maintain the on-curve invariant at construction.
pub fn PublicKey::to_uncompressed(self : PublicKey) -> Bytes {
  let x_bytes = self.point.x.to_octets(length=32)
  let y_bytes = self.point.y.to_octets(length=32)
  let out = FixedArray::make(65, b'\x00')
  out.unsafe_set(0, b'\x04')
  for i = 0; i < 32; i = i + 1 {
    out.unsafe_set(1 + i, x_bytes[i])
  }
  for i = 0; i < 32; i = i + 1 {
    out.unsafe_set(33 + i, y_bytes[i])
  }
  Bytes::makei(65, fn(j) { out.unsafe_get(j) })
}

///|
// OIDs used in SPKI: ecPublicKey + namedCurve secp256r1.
let id_ec_public_key_str : String = "1.2.840.10045.2.1"

///|
let secp256r1_named_curve_str : String = "1.2.840.10045.3.1.7"

///|
fn decode_one_asn1(der : Bytes) -> @asn1.Element raise P256Error {
  @asn1.decode_der(der) catch {
    e => raise Asn1(e)
  }
}

///|
/// Decode a SubjectPublicKeyInfo DER blob for a P-256 key:
///   SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm  AlgorithmIdentifier {
///       algorithm  OID 1.2.840.10045.2.1   -- id-ecPublicKey
///       parameters OID 1.2.840.10045.3.1.7 -- secp256r1 namedCurve
///     }
///     subjectPublicKey BIT STRING -- 04 || X(32) || Y(32)
///   }
pub fn PublicKey::from_spki_der(der : Bytes) -> PublicKey raise P256Error {
  let elem = decode_one_asn1(der)
  let items = match elem.value {
    Sequence(xs) => xs
    _ => raise InvalidPointEncoding("SPKI: expected SEQUENCE")
  }
  if items.length() != 2 {
    raise InvalidPointEncoding("SPKI: arity 2")
  }
  // AlgorithmIdentifier { algorithm OID, parameters OID }
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
  if curve_oid != secp256r1_named_curve_str {
    raise UnexpectedSpkiOid(curve_oid)
  }
  // subjectPublicKey BIT STRING: the raw 04 || X || Y bytes.
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
  // JWT / JOSE per RFC 7515 §3.4 / RFC 7518 §3.4: r || s, each 32 bytes BE,
  // total 64 bytes.
  Raw
  // X.509 / CMS / PKIX: ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }.
  Der
} derive(Eq, Show)

///|
// Parse a DER INTEGER as a non-negative BigInt. ECDSA r and s are always
// non-negative (and < n), so we strip the optional 0x00 sign byte exactly
// like RSA does.
fn integer_to_bigint(bytes : Bytes) -> BigInt raise P256Error {
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
) -> (BigInt, BigInt) raise P256Error {
  match fmt {
    Raw => {
      if sig.length() != 64 {
        raise InvalidSignatureLength(sig.length())
      }
      let r_bytes = Bytes::makei(32, fn(i) { sig[i] })
      let s_bytes = Bytes::makei(32, fn(i) { sig[i + 32] })
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
/// Verify an ECDSA-with-SHA256 signature over `message` against `pubkey`.
///
/// Returns `true` iff the signature is valid. Returns `false` (rather than
/// raising) for any of the spec-defined "invalid" conditions:
///   - r or s out of [1, n-1],
///   - the recomputed point (u1·G + u2·Q) is the point at infinity,
///   - r ≠ (recomputed_x mod n).
///
/// Raises only for structural failures: malformed signature bytes, on-curve
/// check that the constructor missed (defense in depth), or ASN.1 decode
/// errors when `format == Der`.
pub fn verify(
  pubkey : PublicKey,
  message : Bytes,
  signature : Bytes,
  format : SignatureFormat,
) -> Bool raise P256Error {
  if not(is_on_curve(pubkey.point)) {
    return false
  }
  let (r, s) = parse_signature(signature, format)
  let n = p256_n()
  // 1 ≤ r, s < n
  if r.compare_int(0) <= 0 || r.compare(n) >= 0 {
    return false
  }
  if s.compare_int(0) <= 0 || s.compare(n) >= 0 {
    return false
  }
  // e = SHA-256(M). P-256 / FIPS 186-5 §6.4.2 step 4: take the leftmost
  // qlen bits — qlen = 256, so for SHA-256 the digest IS e (no truncation).
  let e_bytes = @hash.sha256(message)
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
/// Construct a private key from a 32-byte big-endian scalar. Rejects values
/// that are 0 or ≥ n.
pub fn PrivateKey::from_bytes(b : Bytes) -> PrivateKey raise P256Error {
  if b.length() != 32 {
    raise InvalidPrivateKey(
      "expected 32-byte scalar, got " + b.length().to_string(),
    )
  }
  // Reject all-zero input explicitly (defensive — BigInt's parsing of
  // a fully-zero buffer is not guaranteed to round-trip through compare).
  let mut all_zero = true
  for i = 0; i < 32; i = i + 1 {
    if b[i] != b'\x00' {
      all_zero = false
      break
    }
  }
  if all_zero {
    raise InvalidPrivateKey("scalar is zero")
  }
  let d = BigInt::from_octets(b[:])
  let n = p256_n()
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
/// Sign `message` with ECDSA-SHA-256 using RFC 6979 deterministic nonce.
///
/// Returns the signature in the requested format. The output is
/// reproducible: same key + same message ⇒ same signature, no RNG needed
/// (and so we sidestep the most common ECDSA footgun).
pub fn PrivateKey::sign(
  self : PrivateKey,
  message : Bytes,
  format~ : SignatureFormat = Raw,
) -> Bytes {
  let n = p256_n()
  let e_bytes = @hash.sha256(message)
  let e = BigInt::from_octets(e_bytes[:])
  // RFC 6979 nonce loop. We use the d/e values + 32-byte ECDSA reductions.
  let mut k_ctr = 0
  let mut r = BigInt::from_int(0)
  let mut s = BigInt::from_int(0)
  let max_iter = 16 // RFC 6979 guarantees a usable nonce well within this
  let mut found = false
  let mut nonce_state = rfc6979_init(self.d, e_bytes, 32, n)
  while not(found) && k_ctr < max_iter {
    let (k, next_state) = rfc6979_next(nonce_state, 32, n)
    nonce_state = next_state
    // R = k * G, r = R.x mod n
    let r_point = scalar_mult(k, generator())
    if not(r_point.inf) {
      r = r_point.x % n
      if r.compare_int(0) > 0 {
        // s = k^-1 * (e + r * d) mod n
        let k_inv = mod_inverse(k, n)
        let s_calc = (k_inv * ((e + r * self.d) % n)) % n
        if s_calc.compare_int(0) > 0 {
          s = s_calc
          found = true
        }
      }
    }
    k_ctr = k_ctr + 1
  }
  if not(found) {
    abort("ECDSA P-256 sign: nonce loop diverged (should be impossible)")
  }
  encode_signature(r, s, format)
}

///|
fn encode_signature(r : BigInt, s : BigInt, format : SignatureFormat) -> Bytes {
  match format {
    Raw => {
      let r_bytes = r.to_octets(length=32)
      let s_bytes = s.to_octets(length=32)
      Bytes::makei(64, fn(i) {
        if i < 32 {
          r_bytes[i]
        } else {
          s_bytes[i - 32]
        }
      })
    }
    Der => encode_signature_der(r, s)
  }
}

///|
fn encode_signature_der(r : BigInt, s : BigInt) -> Bytes {
  let r_bytes = encode_der_integer(r)
  let s_bytes = encode_der_integer(s)
  let inner_len = r_bytes.length() + s_bytes.length()
  let len_prefix = encode_der_length_field(inner_len)
  let total = 1 + len_prefix.length() + inner_len
  Bytes::makei(total, fn(i) {
    if i == 0 {
      b'\x30' // SEQUENCE
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
// Encode a positive BigInt as a DER INTEGER (tag + length + value), with
// the leading 0x00 sign byte inserted when the high bit of the magnitude
// is set.
fn encode_der_integer(v : BigInt) -> Bytes {
  // Get the magnitude as the smallest BE representation.
  let mut mag = v.to_octets()
  // Strip leading zero bytes (BigInt::to_octets may include them).
  let mut start = 0
  while start < mag.length() - 1 && mag[start] == b'\x00' {
    start = start + 1
  }
  if start > 0 {
    mag = Bytes::makei(mag.length() - start, fn(i) { mag[i + start] })
  }
  let needs_sign = (mag[0].to_int() & 0x80) != 0
  let body_len = mag.length() + (if needs_sign { 1 } else { 0 })
  let len_prefix = encode_der_length_field(body_len)
  let total = 1 + len_prefix.length() + body_len
  Bytes::makei(total, fn(i) {
    if i == 0 {
      b'\x02' // INTEGER
    } else if i < 1 + len_prefix.length() {
      len_prefix[i - 1]
    } else if needs_sign && i == 1 + len_prefix.length() {
      b'\x00'
    } else {
      let mag_idx = i - 1 - len_prefix.length() - (if needs_sign { 1 } else { 0 })
      mag[mag_idx]
    }
  })
}

///|
fn encode_der_length_field(n : Int) -> Bytes {
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
    abort("DER length too big for short-form encoding")
  }
}

// ─── RFC 6979 deterministic nonce derivation ─────────────────────────────

///|
priv struct Rfc6979State {
  v : Bytes
  k : Bytes
}

///|
fn rfc6979_init(
  d : BigInt,
  h1 : Bytes,
  rlen : Int,
  q : BigInt,
) -> Rfc6979State {
  let hlen = h1.length()
  // V = 0x01 0x01 ... (hlen)
  // K = 0x00 0x00 ... (hlen)
  let v0 = Bytes::makei(hlen, fn(_) { b'\x01' })
  let k0 = Bytes::makei(hlen, fn(_) { b'\x00' })
  let x_oct = int2octets(d, rlen)
  let bb_h1 = bits2octets(h1, q, rlen)
  // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
  let k1 = @hash.hmac_sha256(k0, concat4(v0, b"\x00", x_oct, bb_h1))
  let v1 = @hash.hmac_sha256(k1, v0)
  let k2 = @hash.hmac_sha256(k1, concat4(v1, b"\x01", x_oct, bb_h1))
  let v2 = @hash.hmac_sha256(k2, v1)
  { v: v2, k: k2 }
}

///|
fn rfc6979_next(
  state : Rfc6979State,
  rlen : Int,
  q : BigInt,
) -> (BigInt, Rfc6979State) {
  let qlen_bits = bit_length(q)
  let mut v = state.v
  // Build T of at least qlen bits.
  let mut t : Bytes = b""
  while t.length() < rlen {
    v = @hash.hmac_sha256(state.k, v)
    t = concat2(t, v)
  }
  let k_int = bits2int(t, qlen_bits)
  if k_int.compare_int(0) > 0 && k_int.compare(q) < 0 {
    // Successful candidate. Re-seed state so the *next* call resumes
    // correctly per RFC 6979 (only matters if signing retries).
    let new_k = @hash.hmac_sha256(state.k, concat2(v, b"\x00"))
    let new_v = @hash.hmac_sha256(new_k, v)
    return (k_int, { v: new_v, k: new_k })
  }
  // Reject this k, churn the state and try again.
  let new_k = @hash.hmac_sha256(state.k, concat2(v, b"\x00"))
  let new_v = @hash.hmac_sha256(new_k, v)
  rfc6979_next({ v: new_v, k: new_k }, rlen, q)
}

///|
fn int2octets(x : BigInt, rlen : Int) -> Bytes {
  x.to_octets(length=rlen)
}

///|
fn bits2octets(b : Bytes, q : BigInt, rlen : Int) -> Bytes {
  let z1 = bits2int(b, bit_length(q))
  let z2 = z1 % q
  let z3 = if z2.compare_int(0) < 0 { z2 + q } else { z2 }
  z3.to_octets(length=rlen)
}

///|
fn bits2int(b : Bytes, qlen_bits : Int) -> BigInt {
  // Interpret leftmost qlen_bits of b as an integer.
  let blen = b.length() * 8
  let mut v = BigInt::from_octets(b[:])
  if blen > qlen_bits {
    let shift = blen - qlen_bits
    v = v >> shift
  }
  v
}

///|
fn bit_length(x : BigInt) -> Int {
  let bytes = x.to_octets()
  // Strip leading zeros.
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
fn concat2(a : Bytes, b : Bytes) -> Bytes {
  Bytes::makei(a.length() + b.length(), fn(i) {
    if i < a.length() {
      a[i]
    } else {
      b[i - a.length()]
    }
  })
}

///|
fn concat4(a : Bytes, b : Bytes, c : Bytes, d : Bytes) -> Bytes {
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
