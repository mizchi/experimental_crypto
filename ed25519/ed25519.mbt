// Ed25519 (RFC 8032 §5.1) signature scheme over Edwards Curve25519.
//
// Implementation note: field and scalar arithmetic delegate to @bigint, which
// is NOT constant-time. The API shape matches what crypto callers expect, but
// inner big-integer modular multiplication leaks timing. A radix-2^51 limb
// representation with constant-time point addition is the natural follow-up.
//
// This module performs SHA-512 with a self-contained implementation in
// `sha512.mbt`; no external hash dependency.

///|
pub(all) struct PrivateKey {
  // 32-byte seed as given by the user. All derived material (hashed scalar,
  // signing prefix, public key) is recomputed on demand.
  seed : FixedArray[Byte]
}

///|
pub impl Show for PrivateKey with fn output(self, logger) {
  ignore(self)
  logger.write_string("PrivateKey(<redacted>)")
}

///|
pub(all) struct PublicKey {
  bytes : FixedArray[Byte] // 32-byte compressed Edwards point
} derive(Eq)

///|
pub impl Show for PublicKey with fn output(self, logger) {
  let digits = "0123456789abcdef"
  logger.write_string("PublicKey(")
  for i = 0; i < 32; i = i + 1 {
    let b = self.bytes[i].to_int()
    logger.write_char(
      digits.code_unit_at((b >> 4) & 0xF).to_int() |> Int::unsafe_to_char,
    )
    logger.write_char(
      digits.code_unit_at(b & 0xF).to_int() |> Int::unsafe_to_char,
    )
  }
  logger.write_string(")")
}

///|
pub suberror Ed25519Error {
  InvalidSeedLength(Int)
  InvalidPublicKeyLength(Int)
  // Reserved for callers that want to opt into raise-on-bad-signature instead
  // of the boolean `verify` API.
  InvalidSignatureLength(Int)
  // Reserved for future strict-encoding errors (e.g. non-canonical R/A).
  InvalidEncoding(String)
}

///|
pub impl Show for Ed25519Error with fn output(self, logger) {
  match self {
    InvalidSeedLength(n) => logger.write_string("InvalidSeedLength(\{n})")
    InvalidPublicKeyLength(n) =>
      logger.write_string("InvalidPublicKeyLength(\{n})")
    InvalidSignatureLength(n) =>
      logger.write_string("InvalidSignatureLength(\{n})")
    InvalidEncoding(s) => logger.write_string("InvalidEncoding(\{s})")
  }
}

// ─── PrivateKey API ─────────────────────────────────────────────────────

///|
pub fn PrivateKey::from_seed(b : Bytes) -> PrivateKey raise Ed25519Error {
  if b.length() != 32 {
    raise InvalidSeedLength(b.length())
  }
  let fa = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    fa[i] = b[i]
  }
  { seed: fa }
}

///|
pub fn PrivateKey::seed_bytes(self : PrivateKey) -> Bytes {
  Bytes::makei(32, fn(i) { self.seed[i] })
}

///|
pub fn PrivateKey::public_key(self : PrivateKey) -> PublicKey {
  let h = sha512_fa(self.seed)
  let (scalar, _) = derive_scalar_and_prefix(h)
  let a_point = ed25519_scalar_base_mult(scalar)
  let encoded = point_compress(a_point)
  { bytes: encoded }
}

///|
pub fn PrivateKey::sign(self : PrivateKey, message : Bytes) -> Bytes {
  let h = sha512_fa(self.seed)
  let (a_scalar, prefix) = derive_scalar_and_prefix(h)
  let a_point = ed25519_scalar_base_mult(a_scalar)
  let a_encoded = point_compress(a_point)

  // r = SHA-512(prefix || M) interpreted as little-endian, reduced mod L
  let r_hash = {
    let ctx = SHA512::new()
    ctx.update_fa(prefix)
    ctx.update_bytes(message)
    ctx.finalize()
  }
  let r = scalar_from_64_le(r_hash)
  let r_point = ed25519_scalar_base_mult(r)
  let r_encoded = point_compress(r_point)

  // k = SHA-512(R || A || M) reduced mod L
  let k_hash = {
    let ctx = SHA512::new()
    ctx.update_fa(r_encoded)
    ctx.update_fa(a_encoded)
    ctx.update_bytes(message)
    ctx.finalize()
  }
  let k = scalar_from_64_le(k_hash)

  // S = (r + k * a) mod L
  let s = (r + k * a_scalar) % ed_l
  let s_bytes = scalar_to_le_bytes(s)

  // signature = R (32) || S (32)
  Bytes::makei(64, fn(i) { if i < 32 { r_encoded[i] } else { s_bytes[i - 32] } })
}

// ─── PublicKey API ──────────────────────────────────────────────────────

///|
pub fn PublicKey::from_bytes(b : Bytes) -> PublicKey raise Ed25519Error {
  if b.length() != 32 {
    raise InvalidPublicKeyLength(b.length())
  }
  let fa = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    fa[i] = b[i]
  }
  { bytes: fa }
}

///|
pub fn PublicKey::to_bytes(self : PublicKey) -> Bytes {
  Bytes::makei(32, fn(i) { self.bytes[i] })
}

///|
// Strict verify that raises `Ed25519Error` on malformed inputs (wrong length,
// non-canonical S, undecompressable R/A). Returns true/false on a
// well-formed signature attempt.
pub fn PublicKey::verify_strict(
  self : PublicKey,
  message : Bytes,
  signature : Bytes,
) -> Bool raise Ed25519Error {
  if signature.length() != 64 {
    raise InvalidSignatureLength(signature.length())
  }
  let r_bytes = FixedArray::make(32, b'\x00')
  let s_bytes = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    r_bytes[i] = signature[i]
    s_bytes[i] = signature[i + 32]
  }
  let s = scalar_from_32_le(s_bytes)
  if s >= ed_l {
    raise InvalidEncoding("S >= L (non-canonical signature)")
  }
  let r_point = match point_decompress(r_bytes) {
    Some(p) => p
    None => raise InvalidEncoding("R is not a valid Edwards point")
  }
  let a_point = match point_decompress(self.bytes) {
    Some(p) => p
    None => raise InvalidEncoding("public key is not a valid Edwards point")
  }
  let k_hash = {
    let ctx = SHA512::new()
    ctx.update_fa(r_bytes)
    ctx.update_fa(self.bytes)
    ctx.update_bytes(message)
    ctx.finalize()
  }
  let k = scalar_from_64_le(k_hash)
  let sb = ed25519_scalar_base_mult(s)
  let ka = ed25519_scalar_mult(k, a_point)
  let r_check = ed_point_add(r_point, ka)
  ed_points_equal(sb, r_check)
}

///|
pub fn PublicKey::verify(
  self : PublicKey,
  message : Bytes,
  signature : Bytes,
) -> Bool {
  if signature.length() != 64 {
    return false
  }
  // Split into R (first 32) and S (last 32)
  let r_bytes = FixedArray::make(32, b'\x00')
  let s_bytes = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    r_bytes[i] = signature[i]
    s_bytes[i] = signature[i + 32]
  }
  // S must be canonical: 0 <= S < L
  let s = scalar_from_32_le(s_bytes)
  if s >= ed_l {
    return false
  }
  // Decompress R and A
  let r_point = match point_decompress(r_bytes) {
    Some(p) => p
    None => return false
  }
  let a_point = match point_decompress(self.bytes) {
    Some(p) => p
    None => return false
  }
  // k = SHA-512(R || A || M) mod L
  let k_hash = {
    let ctx = SHA512::new()
    ctx.update_fa(r_bytes)
    ctx.update_fa(self.bytes)
    ctx.update_bytes(message)
    ctx.finalize()
  }
  let k = scalar_from_64_le(k_hash)

  // Check [S]B = R + [k]A by computing [S]B - [k]A and comparing to R.
  let sb = ed25519_scalar_base_mult(s)
  let ka = ed25519_scalar_mult(k, a_point)
  let r_check = ed_point_add(r_point, ka)
  ed_points_equal(sb, r_check)
}

// ─── helpers: seed → (scalar, prefix) ───────────────────────────────────

///|
fn derive_scalar_and_prefix(h : FixedArray[Byte]) -> (BigInt, FixedArray[Byte]) {
  // First 32 bytes -> clamped scalar; second 32 bytes -> signing prefix.
  let a_bytes = FixedArray::make(32, b'\x00')
  let prefix = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    a_bytes[i] = h[i]
    prefix[i] = h[i + 32]
  }
  // clamp per RFC 8032 §5.1.5
  a_bytes[0] = (a_bytes[0].to_int() & 0xF8).to_byte()
  a_bytes[31] = (a_bytes[31].to_int() & 0x7F).to_byte()
  a_bytes[31] = (a_bytes[31].to_int() | 0x40).to_byte()
  let scalar = scalar_from_32_le(a_bytes)
  (scalar, prefix)
}

// ─── field arithmetic GF(2^255 - 19) and scalar arithmetic mod L ────────

///|
let ed_p : BigInt = (BigInt::from_int(1) << 255) - BigInt::from_int(19)

///|
// Group order L = 2^252 + 27742317777372353535851937790883648493
let ed_l : BigInt = (BigInt::from_int(1) << 252) +
  BigInt::from_string("27742317777372353535851937790883648493")

///|
// d = -121665 / 121666 (mod p), precomputed
let ed_d : BigInt = BigInt::from_string(
  "37095705934669439343138083508754565189542113879843219016388785533085940283555",
)

///|
fn fe_add(a : BigInt, b : BigInt) -> BigInt {
  (a + b) % ed_p
}

///|
fn fe_sub(a : BigInt, b : BigInt) -> BigInt {
  ((a - b) % ed_p + ed_p) % ed_p
}

///|
fn fe_mul(a : BigInt, b : BigInt) -> BigInt {
  a * b % ed_p
}

///|
fn fe_inv(a : BigInt) -> BigInt {
  // Fermat: a^(p-2) mod p
  a.pow(ed_p - BigInt::from_int(2), modulus=ed_p)
}

///|
// I = sqrt(-1) mod p = 2^((p-1)/4) mod p
let ed_sqrt_m1 : BigInt = BigInt::from_string(
  "19681161376707505956807079304988542015446066515923890162744021073123829784752",
)

// ─── Edwards point operations ───────────────────────────────────────────

///|
// Extended (projective) coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z,
// x*y = T/Z.
priv struct EdPoint {
  x : BigInt
  y : BigInt
  z : BigInt
  t : BigInt
}

///|
fn ed_identity() -> EdPoint {
  {
    x: BigInt::from_int(0),
    y: BigInt::from_int(1),
    z: BigInt::from_int(1),
    t: BigInt::from_int(0),
  }
}

///|
// Base point B with y = 4/5 and positive x.
let ed_base : EdPoint = {
  let by = fe_mul(BigInt::from_int(4), fe_inv(BigInt::from_int(5)))
  let bx = recover_x(by, 0).unwrap()
  { x: bx, y: by, z: BigInt::from_int(1), t: fe_mul(bx, by) }
}

///|
// Edwards point addition in extended coordinates (RFC 8032 §5.1.4).
fn ed_point_add(p : EdPoint, q : EdPoint) -> EdPoint {
  let a = fe_mul(fe_sub(p.y, p.x), fe_sub(q.y, q.x))
  let b = fe_mul(fe_add(p.y, p.x), fe_add(q.y, q.x))
  let c = fe_mul(fe_mul(p.t, BigInt::from_int(2)), fe_mul(q.t, ed_d))
  let dd = fe_mul(fe_mul(p.z, BigInt::from_int(2)), q.z)
  let e = fe_sub(b, a)
  let f = fe_sub(dd, c)
  let g = fe_add(dd, c)
  let h = fe_add(b, a)
  { x: fe_mul(e, f), y: fe_mul(g, h), z: fe_mul(f, g), t: fe_mul(e, h) }
}

///|
fn ed_scalar_mult_point(scalar : BigInt, base : EdPoint) -> EdPoint {
  // Double-and-add. Variable-time.
  let mut q = ed_identity()
  let mut p = base
  let mut k = scalar
  let zero = BigInt::from_int(0)
  let one = BigInt::from_int(1)
  while k > zero {
    if (k & one) == one {
      q = ed_point_add(q, p)
    }
    p = ed_point_add(p, p)
    k = k >> 1
  }
  q
}

///|
fn ed25519_scalar_base_mult(scalar : BigInt) -> EdPoint {
  ed_scalar_mult_point(scalar % ed_l, ed_base)
}

///|
fn ed25519_scalar_mult(scalar : BigInt, p : EdPoint) -> EdPoint {
  ed_scalar_mult_point(scalar % ed_l, p)
}

///|
fn ed_points_equal(p : EdPoint, q : EdPoint) -> Bool {
  // (x1/z1, y1/z1) == (x2/z2, y2/z2)  iff  x1*z2 == x2*z1 AND y1*z2 == y2*z1
  let lhs1 = fe_mul(p.x, q.z)
  let rhs1 = fe_mul(q.x, p.z)
  let lhs2 = fe_mul(p.y, q.z)
  let rhs2 = fe_mul(q.y, p.z)
  fe_sub(lhs1, rhs1) == BigInt::from_int(0) &&
  fe_sub(lhs2, rhs2) == BigInt::from_int(0)
}

// ─── point compression and decompression (RFC 8032 §5.1.2 / §5.1.3) ─────

///|
fn point_compress(p : EdPoint) -> FixedArray[Byte] {
  let zinv = fe_inv(p.z)
  let x = fe_mul(p.x, zinv)
  let y = fe_mul(p.y, zinv)
  // encode y in little-endian; place sign bit of x in MSB of last byte.
  let out = fe_to_le_32(y)
  let x_lo = (x % BigInt::from_int(2)).to_int() & 1
  out[31] = (out[31].to_int() | (x_lo << 7)).to_byte()
  out
}

///|
fn point_decompress(b : FixedArray[Byte]) -> EdPoint? {
  // Extract sign bit, clear it, parse y.
  let sign = (b[31].to_int() >> 7) & 1
  let y_bytes = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    y_bytes[i] = b[i]
  }
  y_bytes[31] = (y_bytes[31].to_int() & 0x7F).to_byte()
  let y = fe_from_le_32(y_bytes)
  if y >= ed_p {
    return None
  }
  match recover_x(y, sign) {
    Some(x) => Some({ x, y, z: BigInt::from_int(1), t: fe_mul(x, y) })
    None => None
  }
}

///|
fn recover_x(y : BigInt, sign : Int) -> BigInt? {
  // x^2 = (y^2 - 1) / (d*y^2 + 1)  (mod p)
  let y2 = fe_mul(y, y)
  let num = fe_sub(y2, BigInt::from_int(1))
  let den = fe_add(fe_mul(ed_d, y2), BigInt::from_int(1))
  // x2 = num * den^-1
  let den_inv = fe_inv(den)
  let x2 = fe_mul(num, den_inv)
  if x2 == BigInt::from_int(0) {
    if sign == 1 {
      return None
    }
    return Some(BigInt::from_int(0))
  }
  // Tonelli for p ≡ 5 (mod 8): try x = x2^((p+3)/8).
  let exp = (ed_p + BigInt::from_int(3)) >> 3
  let mut x = x2.pow(exp, modulus=ed_p)
  // If x^2 != x2, multiply by sqrt(-1).
  if fe_sub(fe_mul(x, x), x2) != BigInt::from_int(0) {
    x = fe_mul(x, ed_sqrt_m1)
  }
  if fe_sub(fe_mul(x, x), x2) != BigInt::from_int(0) {
    return None
  }
  // Adjust sign.
  let x_lo = (x % BigInt::from_int(2)).to_int() & 1
  let mut x_out = x
  if x_lo != sign {
    x_out = fe_sub(BigInt::from_int(0), x)
  }
  Some(x_out)
}

// ─── byte ↔ scalar/field-element conversions ───────────────────────────

///|
fn fe_from_le_32(b : FixedArray[Byte]) -> BigInt {
  let mut v = BigInt::from_int(0)
  for i = 31; i >= 0; i = i - 1 {
    v = (v << 8) + BigInt::from_int(b[i].to_int())
  }
  v
}

///|
fn fe_to_le_32(v : BigInt) -> FixedArray[Byte] {
  let out = FixedArray::make(32, b'\x00')
  let mut x = (v % ed_p + ed_p) % ed_p
  let mask = BigInt::from_int(0xFF)
  for i = 0; i < 32; i = i + 1 {
    out[i] = ((x & mask).to_int() & 0xFF).to_byte()
    x = x >> 8
  }
  out
}

///|
fn scalar_from_32_le(b : FixedArray[Byte]) -> BigInt {
  let mut v = BigInt::from_int(0)
  for i = 31; i >= 0; i = i - 1 {
    v = (v << 8) + BigInt::from_int(b[i].to_int())
  }
  v
}

///|
fn scalar_from_64_le(b : FixedArray[Byte]) -> BigInt {
  let mut v = BigInt::from_int(0)
  for i = 63; i >= 0; i = i - 1 {
    v = (v << 8) + BigInt::from_int(b[i].to_int())
  }
  v % ed_l
}

///|
fn scalar_to_le_bytes(s : BigInt) -> FixedArray[Byte] {
  let out = FixedArray::make(32, b'\x00')
  let mut x = (s % ed_l + ed_l) % ed_l
  let mask = BigInt::from_int(0xFF)
  for i = 0; i < 32; i = i + 1 {
    out[i] = ((x & mask).to_int() & 0xFF).to_byte()
    x = x >> 8
  }
  out
}
