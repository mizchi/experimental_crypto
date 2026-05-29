// secp256k1 (SEC 2 §2.4.1) ECDSA sign + verify with BIP-62 low-s normalisation.
//
// Curve: y² = x³ + 7 over GF(p) with p = 2^256 - 2^32 - 977.
// Used by Bitcoin and Ethereum. `a = 0` (no `-3x` term in doubling) and the
// signature is canonicalised to "low-s" (s ≤ n/2) by default per BIP-62 §3 —
// post-BIP-66 Bitcoin nodes reject high-s sigs, and Ethereum follows the same
// convention via EIP-2.
//
// Scope:
//   - sign (RFC 6979 deterministic, SHA-256, low-s by default)
//   - verify
//   - public key parsing: uncompressed SEC1 (04 || X || Y) and SPKI with
//     namedCurve OID 1.3.132.0.10 (secp256k1)
//   - private key parsing: raw 32-byte scalar (no PKCS#8 — Bitcoin keys are
//     not typically wrapped this way)
//   - signature parsing/emission: Raw (r||s, 64B) and DER SEQUENCE
//
// Out of scope: key generation, point compression, ECDH, Schnorr (BIP-340),
// public-key recovery (eth `ecrecover`).

// ─── curve constants (SEC 2 §2.4.1) ──────────────────────────────────────

///|
fn k1_p() -> BigInt {
  // 2^256 - 2^32 - 977
  BigInt::from_string(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    radix=16,
  )
}

///|
fn k1_b() -> BigInt {
  BigInt::from_int(7)
}

///|
fn k1_n() -> BigInt {
  // Order of the base point.
  BigInt::from_string(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    radix=16,
  )
}

///|
fn k1_half_n() -> BigInt {
  // n / 2 (floor). Used by BIP-62 low-s test: s is canonical iff s ≤ n/2.
  // Computed once and embedded so we don't recompute on every sign call.
  BigInt::from_string(
    "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
    radix=16,
  )
}

///|
fn k1_gx() -> BigInt {
  BigInt::from_string(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
    radix=16,
  )
}

///|
fn k1_gy() -> BigInt {
  BigInt::from_string(
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
    radix=16,
  )
}

// ─── affine point ────────────────────────────────────────────────────────

///|
// Affine Weierstrass point. Package-private (no `pub`): consumers should go
// through `PublicKey` and never touch `Point` directly.
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
  { x: k1_gx(), y: k1_gy(), inf: false }
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
// Modular inverse via Fermat's little theorem. This remains for public verify
// and the affine point formulas. Sign-side base-point multiplication is routed
// through the fixed-iteration complete-addition field path in `point_fe.mbt`.
fn mod_inverse(a : BigInt, m : BigInt) -> BigInt {
  let exp = m - BigInt::from_int(2)
  a.pow(exp, modulus=m)
}

///|
fn scalar_inverse(a : BigInt, m : BigInt) -> BigInt {
  let a_u = @crypto_bigint.Uint::from_be_bytes(
    mod_pos(a, m).to_octets(length=32),
    4,
  ) catch {
    _ => abort("secp256k1 inverse input does not fit 32 bytes")
  }
  let m_u = @crypto_bigint.Uint::from_be_bytes(m.to_octets(length=32), 4) catch {
    _ => abort("secp256k1 modulus does not fit 32 bytes")
  }
  let inv = a_u.inv_mod(m_u) catch {
    _ => abort("secp256k1 inverse does not exist")
  }
  BigInt::from_octets(inv.to_be_bytes()[:])
}

///|
// y² ≟ x³ + 7 (mod p). a = 0 for secp256k1, so no `-3x` (or any `ax`) term.
fn is_on_curve(p_pt : Point) -> Bool {
  if p_pt.inf {
    return true
  }
  let p = k1_p()
  let lhs = p_pt.y * p_pt.y % p
  let x3 = p_pt.x * p_pt.x % p * p_pt.x % p
  let rhs = mod_pos(x3 + k1_b(), p)
  lhs == rhs
}

///|
// Affine doubling for a = 0: slope = 3x² / 2y.
fn point_double(pt : Point) -> Point {
  if pt.inf {
    return pt
  }
  if pt.y.is_zero() {
    return point_infinity()
  }
  let p = k1_p()
  let three_x2 = mod_pos(BigInt::from_int(3) * pt.x * pt.x, p)
  let den = mod_pos(BigInt::from_int(2) * pt.y, p)
  let s = three_x2 * mod_inverse(den, p) % p
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
  let p = k1_p()
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
// Variable-time double-and-add. Same caveats as the p256 version — the
// public verify path is fine with variable time. Sign-side base-point
// multiplication is routed through the fixed-iteration complete-addition
// field path in `point_fe.mbt` instead.
fn scalar_mult(k : BigInt, pt : Point) -> Point {
  if pt.inf {
    return pt
  }
  if k.is_zero() {
    return point_infinity()
  }
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
pub suberror Secp256k1Error {
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
/// Parse an uncompressed SEC1 point `04 || X(32) || Y(32)` (65 bytes total).
pub fn PublicKey::from_uncompressed(
  b : Bytes,
) -> PublicKey raise Secp256k1Error {
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
  if !is_on_curve(point) {
    raise PointNotOnCurve
  }
  { point, }
}

///|
/// Serialize the public key as SEC1 uncompressed: `04 || X(32) || Y(32)`.
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
/// Serialize the public key as SEC1 compressed: 33 bytes, `0x02 || X` when
/// Y is even and `0x03 || X` when Y is odd. Used by BIP-32 child key
/// derivation (which keys HMAC-SHA512 on the compressed serialisation in
/// the non-hardened branch) and Bitcoin block-chain pubkey hashes.
pub fn PublicKey::to_compressed(self : PublicKey) -> Bytes {
  let x_bytes = self.point.x.to_octets(length=32)
  let y_bytes = self.point.y.to_octets(length=32)
  // Y is even iff its big-endian LSB (byte 31) has bit 0 = 0.
  let prefix = if (y_bytes[31].to_int() & 1) == 0 { b'\x02' } else { b'\x03' }
  let out = FixedArray::make(33, b'\x00')
  out.unsafe_set(0, prefix)
  for i = 0; i < 32; i = i + 1 {
    out.unsafe_set(1 + i, x_bytes[i])
  }
  Bytes::makei(33, fn(j) { out.unsafe_get(j) })
}

///|
/// Add `scalar * G` to this public key and return the resulting public key.
/// This is the non-hardened BIP-32 CKDpub operation primitive. `scalar` is a
/// 32-byte big-endian integer in `[0, n)`. Zero is accepted and returns the
/// original key; a result at infinity is rejected.
pub fn PublicKey::add_generator_mul(
  self : PublicKey,
  scalar : Bytes,
) -> PublicKey raise Secp256k1Error {
  if scalar.length() != 32 {
    raise InvalidPrivateKey(
      "expected 32-byte generator tweak scalar, got " +
      scalar.length().to_string(),
    )
  }
  if !is_on_curve(self.point) {
    raise PointNotOnCurve
  }
  let k = BigInt::from_octets(scalar[:])
  let n = k1_n()
  if k.compare(n) >= 0 {
    raise InvalidPrivateKey("generator tweak scalar >= n")
  }
  let tweak = fe_k1_scalar_mult_base_fixed(k)
  let sum = point_add(self.point, tweak)
  if sum.inf {
    raise InvalidPointEncoding("generator tweak produced point at infinity")
  }
  if !is_on_curve(sum) {
    raise PointNotOnCurve
  }
  { point: sum }
}

///|
// OIDs used in SPKI: ecPublicKey + namedCurve secp256k1 (1.3.132.0.10).
let id_ec_public_key_str : String = "1.2.840.10045.2.1"

///|
let secp256k1_named_curve_str : String = "1.3.132.0.10"

///|
fn decode_one_asn1(der : Bytes) -> @asn1.Element raise Secp256k1Error {
  @asn1.decode_der(der) catch {
    e => raise Asn1(e)
  }
}

///|
/// Decode a SubjectPublicKeyInfo DER blob for a secp256k1 key.
///   SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm  AlgorithmIdentifier {
///       algorithm  OID 1.2.840.10045.2.1   -- id-ecPublicKey
///       parameters OID 1.3.132.0.10        -- secp256k1 namedCurve
///     }
///     subjectPublicKey BIT STRING -- 04 || X(32) || Y(32)
///   }
pub fn PublicKey::from_spki_der(der : Bytes) -> PublicKey raise Secp256k1Error {
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
  if curve_oid != secp256k1_named_curve_str {
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
  Raw
  Der
} derive(Eq, Debug)

///|
fn integer_to_bigint(bytes : Bytes) -> BigInt raise Secp256k1Error {
  if bytes.length() == 0 {
    raise InvalidDerSignature("empty INTEGER")
  }
  if (bytes[0].to_int() & 0x80) != 0 {
    raise InvalidDerSignature("negative INTEGER not permitted")
  }
  let start = if bytes.length() > 1 && bytes[0] == b'\x00' {
    if (bytes[1].to_int() & 0x80) == 0 {
      raise InvalidDerSignature("non-minimal INTEGER")
    }
    1
  } else {
    0
  }
  fixed_bigint_from_octets(bytes[start:])
}

///|
fn parse_signature(
  sig : Bytes,
  fmt : SignatureFormat,
) -> (BigInt, BigInt) raise Secp256k1Error {
  match fmt {
    Raw => {
      if sig.length() != 64 {
        raise InvalidSignatureLength(sig.length())
      }
      let r_bytes = Bytes::makei(32, fn(i) { sig[i] })
      let s_bytes = Bytes::makei(32, fn(i) { sig[i + 32] })
      let r = fixed_bigint_from_octets(r_bytes[:])
      let s = fixed_bigint_from_octets(s_bytes[:])
      (r, s)
    }
    Der => {
      let elem = @asn1.decode_der(sig) catch {
        _ => raise InvalidDerSignature("malformed DER signature")
      }
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
/// Accepts both low-s and high-s signatures. Callers that need strict
/// BIP-66 / EIP-2 enforcement (Bitcoin consensus, Ethereum tx pool) must
/// additionally check `s ≤ n/2` themselves; for application-layer use the
/// standard ECDSA range check (`1 ≤ s < n`) is what FIPS 186-5 requires
/// and is what we apply here.
pub fn verify(
  pubkey : PublicKey,
  message : Bytes,
  signature : Bytes,
  format : SignatureFormat,
) -> Bool raise Secp256k1Error {
  if !is_on_curve(pubkey.point) {
    return false
  }
  let (r, s) = parse_signature(signature, format)
  let n = k1_n()
  if r.compare_int(0) <= 0 || r.compare(n) >= 0 {
    return false
  }
  if s.compare_int(0) <= 0 || s.compare(n) >= 0 {
    return false
  }
  // e = SHA-256(M). qlen = 256 so the digest IS e (no truncation).
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
pub fn PrivateKey::from_bytes(b : Bytes) -> PrivateKey raise Secp256k1Error {
  if b.length() != 32 {
    raise InvalidPrivateKey(
      "expected 32-byte scalar, got " + b.length().to_string(),
    )
  }
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
  let n = k1_n()
  if d.compare(n) >= 0 {
    raise InvalidPrivateKey("scalar >= n")
  }
  { d, }
}

///|
pub fn PrivateKey::public_key(self : PrivateKey) -> PublicKey {
  let point = fe_k1_scalar_mult_base_fixed(self.d)
  { point, }
}

///|
// Core sign routine. `low_s = true` applies BIP-62 §3 normalisation (s →
// n - s when s > n/2). Returns (r, s) as BigInts so we can encode in either
// format and so tests can inspect the raw scalars.
fn sign_core(d : BigInt, message : Bytes, low_s : Bool) -> (BigInt, BigInt) {
  let n = k1_n()
  let e_bytes = @hash.sha256(message)
  let e = BigInt::from_octets(e_bytes[:])
  let mut k_ctr = 0
  let mut r = BigInt::from_int(0)
  let mut s = BigInt::from_int(0)
  let max_iter = 16
  let mut found = false
  let mut nonce_state = rfc6979_init(d, e_bytes, 32, n)
  while !found && k_ctr < max_iter {
    let (k, next_state) = rfc6979_next(nonce_state, 32, n)
    nonce_state = next_state
    let r_point = fe_k1_scalar_mult_base_fixed(k)
    if !r_point.inf {
      r = r_point.x % n
      if r.compare_int(0) > 0 {
        let k_inv = scalar_inverse(k, n)
        let s_calc = k_inv * ((e + r * d) % n) % n
        if s_calc.compare_int(0) > 0 {
          s = s_calc
          found = true
        }
      }
    }
    k_ctr = k_ctr + 1
  }
  if !found {
    abort("ECDSA secp256k1 sign: nonce loop diverged (should be impossible)")
  }
  if low_s && s.compare(k1_half_n()) > 0 {
    s = n - s
  }
  (r, s)
}

///|
/// Sign `message` with ECDSA-SHA-256 + RFC 6979 deterministic nonce, with
/// BIP-62 §3 low-s normalisation applied. Same key + same message ⇒ same
/// signature.
///
/// Bitcoin nodes since BIP-66 (and Ethereum since EIP-2) reject high-s
/// signatures, so this is the default. Use `sign_no_low_s` if you really
/// need the raw (possibly high-s) ECDSA output.
pub fn PrivateKey::sign(
  self : PrivateKey,
  message : Bytes,
  format? : SignatureFormat = Raw,
) -> Bytes {
  let (r, s) = sign_core(self.d, message, true)
  encode_signature(r, s, format)
}

///|
/// Sign without BIP-62 low-s normalisation. Output is whatever RFC 6979
/// produces (s may be in the upper half of `[1, n-1]`). Useful only for
/// interop tests against legacy implementations or to demonstrate the
/// canonicalisation behaviour.
pub fn PrivateKey::sign_no_low_s(
  self : PrivateKey,
  message : Bytes,
  format? : SignatureFormat = Raw,
) -> Bytes {
  let (r, s) = sign_core(self.d, message, false)
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
fn encode_der_integer(v : BigInt) -> Bytes {
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
  let len_prefix = encode_der_length_field(body_len)
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
fn rfc6979_init(d : BigInt, h1 : Bytes, rlen : Int, q : BigInt) -> Rfc6979State {
  let hlen = h1.length()
  let v0 = Bytes::makei(hlen, fn(_) { b'\x01' })
  let k0 = Bytes::makei(hlen, fn(_) { b'\x00' })
  let x_oct = int2octets(d, rlen)
  let bb_h1 = bits2octets(h1, q, rlen)
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
  let mut t : Bytes = b""
  while t.length() < rlen {
    v = @hash.hmac_sha256(state.k, v)
    t = concat2(t, v)
  }
  let k_int = bits2int(t, qlen_bits)
  if k_int.compare_int(0) > 0 && k_int.compare(q) < 0 {
    let new_k = @hash.hmac_sha256(state.k, concat2(v, b"\x00"))
    let new_v = @hash.hmac_sha256(new_k, v)
    return (k_int, { v: new_v, k: new_k })
  }
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
