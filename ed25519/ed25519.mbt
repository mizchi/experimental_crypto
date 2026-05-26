// Ed25519 (RFC 8032 §5.1) signature scheme over Edwards Curve25519.
//
// Field arithmetic operates over GF(2^255 - 19) using a 10-limb,
// mixed-radix 2^25.5 representation (alternating 26 and 25 bit limbs),
// same shape as `mizchi/x25519`. This module additionally maintains a
// twisted-Edwards point group on top of that field, with extended
// coordinates (X:Y:Z:T) for sign / verify and a double-and-add scalar
// ladder.
//
// Scalar arithmetic (mod L) still uses @bigint; it runs O(1) times per
// sign / verify and is not on the hot path. Field arithmetic (255
// doublings × multiple fe_mul each) is what we cared about.
//
// SHA-512 is self-contained in `sha512.mbt`.
//
// TODO: extract the 10-limb fe core into a shared crate
// (`mizchi/curve25519_field` or similar) once we have a second consumer
// stable on the same representation.

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

// ─── scalar arithmetic mod L (still on @bigint) ────────────────────────

///|
// Group order L = 2^252 + 27742317777372353535851937790883648493
let ed_l : BigInt = (BigInt::from_int(1) << 252) +
  BigInt::from_string("27742317777372353535851937790883648493")

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

// ─── field arithmetic GF(2^255 - 19): 10-limb radix-2^25.5 ─────────────
//
// A field element is FixedArray[UInt64] of length 10. Limb bit widths
// (LSB → MSB): 26, 25, 26, 25, 26, 25, 26, 25, 26, 25. During arithmetic
// limbs may temporarily exceed their canonical bit budget; `fe_carry_full`
// brings them back. We do not do constant-time end-to-end execution; the
// goal here is speed, not side-channel hardness.

///|
type Fe = FixedArray[UInt64]

///|
fn fe_zero() -> Fe {
  FixedArray::make(10, 0UL)
}

///|
fn fe_one() -> Fe {
  let f = FixedArray::make(10, 0UL)
  f[0] = 1UL
  f
}

///|
// Decode a 32-byte little-endian integer to a Fe. Does NOT mask the
// high bit of byte 31 — the caller is responsible for stripping the
// sign bit if needed.
fn fe_from_bytes_no_mask(b : FixedArray[Byte]) -> Fe {
  fn ld4(off : Int) -> UInt64 {
    let b0 = b[off].to_uint64()
    let b1 = b[off + 1].to_uint64()
    let b2 = b[off + 2].to_uint64()
    let b3 = b[off + 3].to_uint64()
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
  }

  let mask25 : UInt64 = (1UL << 25) - 1UL
  let mask26 : UInt64 = (1UL << 26) - 1UL
  let h = FixedArray::make(10, 0UL)
  h[0] = ld4(0) & mask26
  h[1] = (ld4(3) >> 2) & mask25
  h[2] = (ld4(6) >> 3) & mask26
  h[3] = (ld4(9) >> 5) & mask25
  h[4] = (ld4(12) >> 6) & mask26
  h[5] = ld4(16) & mask25
  h[6] = (ld4(19) >> 1) & mask26
  h[7] = (ld4(22) >> 3) & mask25
  h[8] = (ld4(25) >> 4) & mask26
  let b28 = b[28].to_uint64()
  let b29 = b[29].to_uint64()
  let b30 = b[30].to_uint64()
  let b31 = b[31].to_uint64() // NOT masked
  let win = b28 | (b29 << 8) | (b30 << 16) | (b31 << 24)
  h[9] = (win >> 6) & mask25
  h
}

///|
fn fe_to_bytes(a : Fe) -> FixedArray[Byte] {
  let h = fe_carry_full(a)
  let q = FixedArray::make(10, 0UL)
  q[0] = h[0] + 19UL
  for i in 1..<10 {
    q[i] = h[i]
  }
  let mask25 : UInt64 = (1UL << 25) - 1UL
  let mask26 : UInt64 = (1UL << 26) - 1UL
  let mut c : UInt64 = q[0] >> 26
  q[0] = q[0] & mask26
  q[1] = q[1] + c
  c = q[1] >> 25
  q[1] = q[1] & mask25
  q[2] = q[2] + c
  c = q[2] >> 26
  q[2] = q[2] & mask26
  q[3] = q[3] + c
  c = q[3] >> 25
  q[3] = q[3] & mask25
  q[4] = q[4] + c
  c = q[4] >> 26
  q[4] = q[4] & mask26
  q[5] = q[5] + c
  c = q[5] >> 25
  q[5] = q[5] & mask25
  q[6] = q[6] + c
  c = q[6] >> 26
  q[6] = q[6] & mask26
  q[7] = q[7] + c
  c = q[7] >> 25
  q[7] = q[7] & mask25
  q[8] = q[8] + c
  c = q[8] >> 26
  q[8] = q[8] & mask26
  q[9] = q[9] + c
  let c2 = q[9] >> 25
  q[9] = q[9] & mask25
  let use_q = c2
  let out = FixedArray::make(10, 0UL)
  for i in 0..<10 {
    let mask : UInt64 = 0UL - use_q
    out[i] = (q[i] & mask) | (h[i] & mask.lnot())
  }
  let bytes = FixedArray::make(32, b'\x00')
  let w = FixedArray::make(4, 0UL)
  w[0] = out[0]
  w[0] = w[0] | (out[1] << 26)
  w[0] = w[0] | (out[2] << 51)
  w[1] = out[2] >> 13
  w[1] = w[1] | (out[3] << 13)
  w[1] = w[1] | (out[4] << 38)
  w[2] = out[4] >> 26
  w[2] = w[2] | (out[5] << 0)
  w[2] = w[2] | (out[6] << 25)
  w[2] = w[2] | (out[7] << 51)
  w[3] = out[7] >> 13
  w[3] = w[3] | (out[8] << 12)
  w[3] = w[3] | (out[9] << 38)
  for wi in 0..<4 {
    let v = w[wi]
    for bi in 0..<8 {
      bytes[wi * 8 + bi] = ((v >> (bi * 8)) & 0xFFUL).to_byte()
    }
  }
  bytes
}

///|
fn fe_carry_full(h : Fe) -> Fe {
  let mask25 : UInt64 = (1UL << 25) - 1UL
  let mask26 : UInt64 = (1UL << 26) - 1UL
  let r = FixedArray::make(10, 0UL)
  for i in 0..<10 {
    r[i] = h[i]
  }
  let mut c : UInt64 = r[0] >> 26
  r[0] = r[0] & mask26
  r[1] = r[1] + c
  c = r[1] >> 25
  r[1] = r[1] & mask25
  r[2] = r[2] + c
  c = r[2] >> 26
  r[2] = r[2] & mask26
  r[3] = r[3] + c
  c = r[3] >> 25
  r[3] = r[3] & mask25
  r[4] = r[4] + c
  c = r[4] >> 26
  r[4] = r[4] & mask26
  r[5] = r[5] + c
  c = r[5] >> 25
  r[5] = r[5] & mask25
  r[6] = r[6] + c
  c = r[6] >> 26
  r[6] = r[6] & mask26
  r[7] = r[7] + c
  c = r[7] >> 25
  r[7] = r[7] & mask25
  r[8] = r[8] + c
  c = r[8] >> 26
  r[8] = r[8] & mask26
  r[9] = r[9] + c
  c = r[9] >> 25
  r[9] = r[9] & mask25
  r[0] = r[0] + 19UL * c
  c = r[0] >> 26
  r[0] = r[0] & mask26
  r[1] = r[1] + c
  c = r[1] >> 25
  r[1] = r[1] & mask25
  r[2] = r[2] + c
  c = r[2] >> 26
  r[2] = r[2] & mask26
  r[3] = r[3] + c
  c = r[3] >> 25
  r[3] = r[3] & mask25
  r[4] = r[4] + c
  c = r[4] >> 26
  r[4] = r[4] & mask26
  r[5] = r[5] + c
  c = r[5] >> 25
  r[5] = r[5] & mask25
  r[6] = r[6] + c
  c = r[6] >> 26
  r[6] = r[6] & mask26
  r[7] = r[7] + c
  c = r[7] >> 25
  r[7] = r[7] & mask25
  r[8] = r[8] + c
  c = r[8] >> 26
  r[8] = r[8] & mask26
  r[9] = r[9] + c
  r
}

///|
fn fe_add(a : Fe, b : Fe) -> Fe {
  let r = FixedArray::make(10, 0UL)
  for i in 0..<10 {
    r[i] = a[i] + b[i]
  }
  r
}

///|
let two_p_limb : FixedArray[UInt64] = [
  0x7FFFFDAUL, 0x3FFFFFEUL, 0x7FFFFFEUL, 0x3FFFFFEUL, 0x7FFFFFEUL, 0x3FFFFFEUL,
  0x7FFFFFEUL, 0x3FFFFFEUL, 0x7FFFFFEUL, 0x3FFFFFEUL,
]

///|
fn fe_sub(a : Fe, b : Fe) -> Fe {
  let r = FixedArray::make(10, 0UL)
  for i in 0..<10 {
    r[i] = a[i] + two_p_limb[i] - b[i]
  }
  r
}

///|
// Negation: -a mod p, returned with limbs that fit within the next
// carry pass. Computed as 2p - a (i.e. fe_sub against zero).
fn fe_neg(a : Fe) -> Fe {
  let r = FixedArray::make(10, 0UL)
  for i in 0..<10 {
    r[i] = two_p_limb[i] - a[i]
  }
  r
}

///|
fn fe_mul(f : Fe, g : Fe) -> Fe {
  let f0 = f[0]
  let f1 = f[1]
  let f2 = f[2]
  let f3 = f[3]
  let f4 = f[4]
  let f5 = f[5]
  let f6 = f[6]
  let f7 = f[7]
  let f8 = f[8]
  let f9 = f[9]
  let g0 = g[0]
  let g1 = g[1]
  let g2 = g[2]
  let g3 = g[3]
  let g4 = g[4]
  let g5 = g[5]
  let g6 = g[6]
  let g7 = g[7]
  let g8 = g[8]
  let g9 = g[9]
  let g1_19 = 19UL * g1
  let g2_19 = 19UL * g2
  let g3_19 = 19UL * g3
  let g4_19 = 19UL * g4
  let g5_19 = 19UL * g5
  let g6_19 = 19UL * g6
  let g7_19 = 19UL * g7
  let g8_19 = 19UL * g8
  let g9_19 = 19UL * g9
  let f1_2 = 2UL * f1
  let f3_2 = 2UL * f3
  let f5_2 = 2UL * f5
  let f7_2 = 2UL * f7
  let f9_2 = 2UL * f9
  let h0 = f0 * g0 +
    f1_2 * g9_19 +
    f2 * g8_19 +
    f3_2 * g7_19 +
    f4 * g6_19 +
    f5_2 * g5_19 +
    f6 * g4_19 +
    f7_2 * g3_19 +
    f8 * g2_19 +
    f9_2 * g1_19
  let h1 = f0 * g1 +
    f1 * g0 +
    f2 * g9_19 +
    f3 * g8_19 +
    f4 * g7_19 +
    f5 * g6_19 +
    f6 * g5_19 +
    f7 * g4_19 +
    f8 * g3_19 +
    f9 * g2_19
  let h2 = f0 * g2 +
    f1_2 * g1 +
    f2 * g0 +
    f3_2 * g9_19 +
    f4 * g8_19 +
    f5_2 * g7_19 +
    f6 * g6_19 +
    f7_2 * g5_19 +
    f8 * g4_19 +
    f9_2 * g3_19
  let h3 = f0 * g3 +
    f1 * g2 +
    f2 * g1 +
    f3 * g0 +
    f4 * g9_19 +
    f5 * g8_19 +
    f6 * g7_19 +
    f7 * g6_19 +
    f8 * g5_19 +
    f9 * g4_19
  let h4 = f0 * g4 +
    f1_2 * g3 +
    f2 * g2 +
    f3_2 * g1 +
    f4 * g0 +
    f5_2 * g9_19 +
    f6 * g8_19 +
    f7_2 * g7_19 +
    f8 * g6_19 +
    f9_2 * g5_19
  let h5 = f0 * g5 +
    f1 * g4 +
    f2 * g3 +
    f3 * g2 +
    f4 * g1 +
    f5 * g0 +
    f6 * g9_19 +
    f7 * g8_19 +
    f8 * g7_19 +
    f9 * g6_19
  let h6 = f0 * g6 +
    f1_2 * g5 +
    f2 * g4 +
    f3_2 * g3 +
    f4 * g2 +
    f5_2 * g1 +
    f6 * g0 +
    f7_2 * g9_19 +
    f8 * g8_19 +
    f9_2 * g7_19
  let h7 = f0 * g7 +
    f1 * g6 +
    f2 * g5 +
    f3 * g4 +
    f4 * g3 +
    f5 * g2 +
    f6 * g1 +
    f7 * g0 +
    f8 * g9_19 +
    f9 * g8_19
  let h8 = f0 * g8 +
    f1_2 * g7 +
    f2 * g6 +
    f3_2 * g5 +
    f4 * g4 +
    f5_2 * g3 +
    f6 * g2 +
    f7_2 * g1 +
    f8 * g0 +
    f9_2 * g9_19
  let h9 = f0 * g9 +
    f1 * g8 +
    f2 * g7 +
    f3 * g6 +
    f4 * g5 +
    f5 * g4 +
    f6 * g3 +
    f7 * g2 +
    f8 * g1 +
    f9 * g0
  let r = FixedArray::make(10, 0UL)
  r[0] = h0
  r[1] = h1
  r[2] = h2
  r[3] = h3
  r[4] = h4
  r[5] = h5
  r[6] = h6
  r[7] = h7
  r[8] = h8
  r[9] = h9
  fe_carry_full(r)
}

///|
fn fe_sqr(f : Fe) -> Fe {
  let f0 = f[0]
  let f1 = f[1]
  let f2 = f[2]
  let f3 = f[3]
  let f4 = f[4]
  let f5 = f[5]
  let f6 = f[6]
  let f7 = f[7]
  let f8 = f[8]
  let f9 = f[9]
  let f0_2 = 2UL * f0
  let f1_2 = 2UL * f1
  let f2_2 = 2UL * f2
  let f3_2 = 2UL * f3
  let f4_2 = 2UL * f4
  let f5_2 = 2UL * f5
  let f6_2 = 2UL * f6
  let f7_2 = 2UL * f7
  let f5_38 = 38UL * f5
  let f6_19 = 19UL * f6
  let f7_38 = 38UL * f7
  let f8_19 = 19UL * f8
  let f9_38 = 38UL * f9
  let h0 = f0 * f0 +
    f1_2 * f9_38 +
    f2_2 * f8_19 +
    f3_2 * f7_38 +
    f4_2 * f6_19 +
    f5 * f5_38
  let h1 = f0_2 * f1 + f2 * f9_38 + f3_2 * f8_19 + f4 * f7_38 + f5_2 * f6_19
  let h2 = f0_2 * f2 +
    f1_2 * f1 +
    f3_2 * f9_38 +
    f4_2 * f8_19 +
    f5_2 * f7_38 +
    f6 * f6_19
  let h3 = f0_2 * f3 + f1_2 * f2 + f4 * f9_38 + f5_2 * f8_19 + f6 * f7_38
  let h4 = f0_2 * f4 +
    f1_2 * f3_2 +
    f2 * f2 +
    f5_2 * f9_38 +
    f6_2 * f8_19 +
    f7 * f7_38
  let h5 = f0_2 * f5 + f1_2 * f4 + f2_2 * f3 + f6 * f9_38 + f7_2 * f8_19
  let h6 = f0_2 * f6 +
    f1_2 * f5_2 +
    f2_2 * f4 +
    f3_2 * f3 +
    f7_2 * f9_38 +
    f8 * f8_19
  let h7 = f0_2 * f7 + f1_2 * f6 + f2_2 * f5 + f3_2 * f4 + f8 * f9_38
  let h8 = f0_2 * f8 +
    f1_2 * f7_2 +
    f2_2 * f6 +
    f3_2 * f5_2 +
    f4 * f4 +
    f9 * f9_38
  let h9 = f0_2 * f9 + f1_2 * f8 + f2_2 * f7 + f3_2 * f6 + f4_2 * f5
  let r = FixedArray::make(10, 0UL)
  r[0] = h0
  r[1] = h1
  r[2] = h2
  r[3] = h3
  r[4] = h4
  r[5] = h5
  r[6] = h6
  r[7] = h7
  r[8] = h8
  r[9] = h9
  fe_carry_full(r)
}

///|
fn fe_inv(z : Fe) -> Fe {
  let z2 = fe_sqr(z)
  let z9 = fe_mul(fe_sqr(fe_sqr(z2)), z)
  let z11 = fe_mul(z9, z2)
  let z2_5_0 = fe_mul(fe_sqr(z11), z9)
  let mut t = fe_sqr(z2_5_0)
  for _ in 0..<4 {
    t = fe_sqr(t)
  }
  let z2_10_0 = fe_mul(t, z2_5_0)
  t = fe_sqr(z2_10_0)
  for _ in 0..<9 {
    t = fe_sqr(t)
  }
  let z2_20_0 = fe_mul(t, z2_10_0)
  t = fe_sqr(z2_20_0)
  for _ in 0..<19 {
    t = fe_sqr(t)
  }
  t = fe_mul(t, z2_20_0)
  for _ in 0..<10 {
    t = fe_sqr(t)
  }
  let z2_50_0 = fe_mul(t, z2_10_0)
  t = fe_sqr(z2_50_0)
  for _ in 0..<49 {
    t = fe_sqr(t)
  }
  let z2_100_0 = fe_mul(t, z2_50_0)
  t = fe_sqr(z2_100_0)
  for _ in 0..<99 {
    t = fe_sqr(t)
  }
  t = fe_mul(t, z2_100_0)
  for _ in 0..<50 {
    t = fe_sqr(t)
  }
  t = fe_mul(t, z2_50_0)
  for _ in 0..<5 {
    t = fe_sqr(t)
  }
  fe_mul(t, z11)
}

///|
// Compare two field elements for equality after full canonical reduction.
// OR-accumulates the per-byte XOR with no early termination so the timing
// of this check does not leak which byte position differs. Inputs to all
// current call sites (point_decompress, ed_points_equal) are public, but
// this hygiene keeps the function safe for future secret-input callers.
fn fe_eq(a : Fe, b : Fe) -> Bool {
  let ab = fe_to_bytes(a)
  let bb = fe_to_bytes(b)
  let mut acc = 0
  for i in 0..<32 {
    acc = acc | (ab[i].to_int() ^ bb[i].to_int())
  }
  acc == 0
}

///|
// Parity of the canonical representation (least significant bit of the
// 32-byte little-endian encoding).
fn fe_is_negative(a : Fe) -> Int {
  let bytes = fe_to_bytes(a)
  bytes[0].to_int() & 1
}

///|
fn fe_is_zero(a : Fe) -> Bool {
  let bytes = fe_to_bytes(a)
  for i in 0..<32 {
    if bytes[i].to_int() != 0 {
      return false
    }
  }
  true
}

// ─── Edwards point group constants ─────────────────────────────────────

///|
// d = -121665 / 121666 (mod p), 10-limb form.
// Decimal: 37095705934669439343138083508754565189542113879843219016388785533085940283555
// LE bytes:
//   a3 78 59 13 ca 4d eb 75 ab d8 41 41 4d 0a 70 00
//   98 e8 79 77 79 40 c7 8c 73 fe 6f 2b ee 6c 03 52
// (top byte 0x52 = 0101 0010, no sign bit set)
let ed_d_bytes : FixedArray[Byte] = [
  b'\xa3', b'\x78', b'\x59', b'\x13', b'\xca', b'\x4d', b'\xeb', b'\x75', b'\xab',
  b'\xd8', b'\x41', b'\x41', b'\x4d', b'\x0a', b'\x70', b'\x00', b'\x98', b'\xe8',
  b'\x79', b'\x77', b'\x79', b'\x40', b'\xc7', b'\x8c', b'\x73', b'\xfe', b'\x6f',
  b'\x2b', b'\xee', b'\x6c', b'\x03', b'\x52',
]

///|
let ed_d : Fe = fe_from_bytes_no_mask(ed_d_bytes)

///|
// 2*d. Useful inside Edwards addition.
let ed_d2 : Fe = fe_carry_full(fe_add(ed_d, ed_d))

///|
// I = sqrt(-1) mod p = 2^((p-1)/4) mod p.
// Decimal: 19681161376707505956807079304988542015446066515923890162744021073123829784752
let ed_sqrt_m1_bytes : FixedArray[Byte] = [
  b'\xb0', b'\xa0', b'\x0e', b'\x4a', b'\x27', b'\x1b', b'\xee', b'\xc4', b'\x78',
  b'\xe4', b'\x2f', b'\xad', b'\x06', b'\x18', b'\x43', b'\x2f', b'\xa7', b'\xd7',
  b'\xfb', b'\x3d', b'\x99', b'\x00', b'\x4d', b'\x2b', b'\x0b', b'\xdf', b'\xc1',
  b'\x4f', b'\x80', b'\x24', b'\x83', b'\x2b',
]

///|
let ed_sqrt_m1 : Fe = fe_from_bytes_no_mask(ed_sqrt_m1_bytes)

// ─── Edwards point operations ───────────────────────────────────────────

///|
// Extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z.
priv struct EdPoint {
  x : Fe
  y : Fe
  z : Fe
  t : Fe
}

///|
fn ed_identity() -> EdPoint {
  { x: fe_zero(), y: fe_one(), z: fe_one(), t: fe_zero() }
}

///|
// Base point: y = 4/5, positive x. Compressed form (RFC 8032 §5.1):
//   58 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66
//   66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66
// (LSB-first; canonical Ed25519 base.)
let ed_base_bytes : FixedArray[Byte] = [
  b'\x58', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66',
  b'\x66', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66',
  b'\x66', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66', b'\x66',
  b'\x66', b'\x66', b'\x66', b'\x66', b'\x66',
]

///|
fn make_base_point() -> EdPoint {
  match point_decompress(ed_base_bytes) {
    Some(p) => p
    None => abort("base point must decompress")
  }
}

///|
let ed_base : EdPoint = make_base_point()

///|
// Edwards point addition in extended coordinates with the standard
// twisted formula (a = -1, d = ed_d).
//   A = (Y1 - X1) * (Y2 - X2)
//   B = (Y1 + X1) * (Y2 + X2)
//   C = T1 * 2d * T2
//   D = 2 * Z1 * Z2
//   E = B - A,  F = D - C,  G = D + C,  H = B + A
//   X3 = E * F,  Y3 = G * H,  T3 = E * H,  Z3 = F * G
fn ed_point_add(p : EdPoint, q : EdPoint) -> EdPoint {
  let a = fe_mul(fe_sub(p.y, p.x), fe_sub(q.y, q.x))
  let b = fe_mul(fe_add(p.y, p.x), fe_add(q.y, q.x))
  let c = fe_mul(fe_mul(p.t, ed_d2), q.t)
  let d = fe_mul(fe_add(p.z, p.z), q.z)
  let e = fe_sub(b, a)
  let f = fe_sub(d, c)
  let g = fe_add(d, c)
  let h = fe_add(b, a)
  { x: fe_mul(e, f), y: fe_mul(g, h), z: fe_mul(f, g), t: fe_mul(e, h) }
}

///|
// Dedicated doubling formula for extended coordinates on a twisted
// Edwards curve with a = -1 (RFC 8032 §5.1.4 / "edwards25519: 2P"):
//   A = X1^2;  B = Y1^2;  C = 2 * Z1^2;  H = A + B
//   E = H - (X1 + Y1)^2
//   G = A - B  (i.e. for a = -1: -A + B is -G, we negate appropriately)
//   F = C + G
//   X3 = E * F;  Y3 = G * H;  T3 = E * H;  Z3 = F * G
// Note: for a = -1, the formula is G = (-1)*A - B = -A - B, so we
// compute G = -(A + B) and pair signs as written below. We follow the
// reference (ref10 ge_p2_dbl / ge_p3_dbl) which expresses it as:
//   A = X1^2, B = Y1^2, C = 2 Z1^2
//   D = -A    (since a = -1)
//   E = (X1 + Y1)^2 - A - B
//   G = D + B = B - A
//   F = G - C
//   H = D - B = -A - B
//   X3 = E * F, Y3 = G * H, T3 = E * H, Z3 = F * G
fn ed_point_double(p : EdPoint) -> EdPoint {
  let a = fe_sqr(p.x)
  let b = fe_sqr(p.y)
  let c = fe_sqr(p.z)
  let c2 = fe_add(c, c)
  let xy = fe_add(p.x, p.y)
  let xy2 = fe_sqr(xy)
  let ab = fe_add(a, b)
  let e = fe_sub(xy2, ab) // (X+Y)^2 - A - B = 2 X Y
  let g = fe_sub(b, a) // B - A = Y^2 - X^2
  let f = fe_sub(g, c2) // G - 2 Z^2
  let h = fe_neg(ab) // -(A + B) = -X^2 - Y^2
  { x: fe_mul(e, f), y: fe_mul(g, h), z: fe_mul(f, g), t: fe_mul(e, h) }
}

///|
fn ed_scalar_mult_point(scalar : BigInt, base : EdPoint) -> EdPoint {
  // Double-and-add over the bits of `scalar`, MSB to LSB so we can use
  // the dedicated doubling formula. Variable time.
  let s = (scalar % ed_l + ed_l) % ed_l
  // Determine the bit length of s.
  let mut bitlen = 0
  let mut tmp = s
  let zero = BigInt::from_int(0)
  while tmp > zero {
    bitlen = bitlen + 1
    tmp = tmp >> 1
  }
  if bitlen == 0 {
    return ed_identity()
  }
  let mut q = ed_identity()
  let one = BigInt::from_int(1)
  for i = bitlen - 1; i >= 0; i = i - 1 {
    q = ed_point_double(q)
    let bit = ((s >> i) & one) == one
    if bit {
      q = ed_point_add(q, base)
    }
  }
  q
}

///|
fn ed25519_scalar_base_mult(scalar : BigInt) -> EdPoint {
  ed_scalar_mult_point(scalar, ed_base)
}

///|
fn ed25519_scalar_mult(scalar : BigInt, p : EdPoint) -> EdPoint {
  ed_scalar_mult_point(scalar, p)
}

///|
fn ed_points_equal(p : EdPoint, q : EdPoint) -> Bool {
  // x1*z2 == x2*z1 AND y1*z2 == y2*z1
  let lhs1 = fe_mul(p.x, q.z)
  let rhs1 = fe_mul(q.x, p.z)
  let lhs2 = fe_mul(p.y, q.z)
  let rhs2 = fe_mul(q.y, p.z)
  fe_eq(lhs1, rhs1) && fe_eq(lhs2, rhs2)
}

// ─── point compression and decompression (RFC 8032 §5.1.2 / §5.1.3) ─────

///|
fn point_compress(p : EdPoint) -> FixedArray[Byte] {
  let zinv = fe_inv(p.z)
  let x = fe_mul(p.x, zinv)
  let y = fe_mul(p.y, zinv)
  let out = fe_to_bytes(y)
  let x_lo = fe_is_negative(x)
  out[31] = (out[31].to_int() | (x_lo << 7)).to_byte()
  out
}

///|
fn point_decompress(b : FixedArray[Byte]) -> EdPoint? {
  let sign = (b[31].to_int() >> 7) & 1
  let y_bytes = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    y_bytes[i] = b[i]
  }
  y_bytes[31] = (y_bytes[31].to_int() & 0x7F).to_byte()
  // Verify y < p by re-encoding through fe_to_bytes(fe_from_bytes(y_bytes))
  // and comparing to the input. fe_from_bytes already masks the high
  // bit; we just confirm canonical encoding matches.
  let y = fe_from_bytes_no_mask(y_bytes)
  // y < p iff fe_to_bytes(y) == y_bytes after stripping the sign bit.
  let y_round = fe_to_bytes(y)
  for i in 0..<32 {
    if y_round[i] != y_bytes[i] {
      return None
    }
  }
  match recover_x(y, sign) {
    Some(x) => Some({ x, y, z: fe_one(), t: fe_mul(x, y) })
    None => None
  }
}

///|
fn recover_x(y : Fe, sign : Int) -> Fe? {
  // x^2 = (y^2 - 1) / (d*y^2 + 1)
  let y2 = fe_sqr(y)
  let num = fe_sub(y2, fe_one())
  let den = fe_add(fe_mul(ed_d, y2), fe_one())
  // x2 = num / den, computed as num * den^{p-2} (use combined sqrt-of-ratio
  // trick below to save an inversion).
  //
  // We use the standard "sqrt(u/v)" trick:
  //   candidate = u * v^3 * (u * v^7)^{(p-5)/8}
  // where u = num, v = den. This avoids one separate inversion.
  let v = den
  let u = num
  let v3 = fe_mul(fe_sqr(v), v) // v^3
  let v7 = fe_mul(fe_sqr(v3), v) // v^7
  let uv7 = fe_mul(u, v7)
  // (p-5)/8: standard chain. We compute uv7^((p-5)/8) via a Fermat-style
  // chain, but since we already have fe_inv (= a^(p-2)) we can derive a
  // dedicated exponent. For clarity, we'll just use fe_pow_p58 below.
  let p58 = fe_pow_p58(uv7)
  let mut x = fe_mul(fe_mul(u, v3), p58)
  // Verify: vx^2 == u? If not, try x * sqrt(-1).
  let vxx = fe_mul(v, fe_sqr(x))
  let check1 = fe_sub(vxx, u) // == 0 ?
  let check2 = fe_add(vxx, u) // == 0 ? (then x *= sqrt(-1))
  if fe_is_zero(check1) {
    // ok
    ()
  } else if fe_is_zero(check2) {
    x = fe_mul(x, ed_sqrt_m1)
  } else {
    return None
  }
  // Now x*x*v == ±u; we already enforced ==u above. Fix sign.
  if fe_is_zero(x) && sign == 1 {
    return None
  }
  if fe_is_negative(x) != sign {
    x = fe_neg(x)
  }
  Some(fe_carry_full(x))
}

///|
// a^((p-5)/8) via a hand-rolled addition chain. (p-5)/8 has the binary
// shape 11111...11 (250 ones) ending ...0110_1 etc — we just lift the
// well-known chain used in ref10/curve25519-donna.
fn fe_pow_p58(z : Fe) -> Fe {
  // (p-5)/8 = 2^252 - 3. We compute z^(2^252 - 3) = z^(2^252) * z^{-3}
  // but easier: use the same chain as fe_inv minus the final tail.
  // Actually a clean way: z^(2^252 - 3) = (z^(2^250 - 1))^4 * z.
  // Build z^(2^250 - 1) first.
  let z2 = fe_sqr(z)
  let z9 = fe_mul(fe_sqr(fe_sqr(z2)), z)
  let z11 = fe_mul(z9, z2)
  let z2_5_0 = fe_mul(fe_sqr(z11), z9)
  let mut t = fe_sqr(z2_5_0)
  for _ in 0..<4 {
    t = fe_sqr(t)
  }
  let z2_10_0 = fe_mul(t, z2_5_0)
  t = fe_sqr(z2_10_0)
  for _ in 0..<9 {
    t = fe_sqr(t)
  }
  let z2_20_0 = fe_mul(t, z2_10_0)
  t = fe_sqr(z2_20_0)
  for _ in 0..<19 {
    t = fe_sqr(t)
  }
  t = fe_mul(t, z2_20_0)
  for _ in 0..<10 {
    t = fe_sqr(t)
  }
  let z2_50_0 = fe_mul(t, z2_10_0)
  t = fe_sqr(z2_50_0)
  for _ in 0..<49 {
    t = fe_sqr(t)
  }
  let z2_100_0 = fe_mul(t, z2_50_0)
  t = fe_sqr(z2_100_0)
  for _ in 0..<99 {
    t = fe_sqr(t)
  }
  t = fe_mul(t, z2_100_0)
  for _ in 0..<50 {
    t = fe_sqr(t)
  }
  // Now t = z^(2^250 - 1).
  t = fe_mul(t, z2_50_0)
  // z^(2^252 - 3) = t^4 * z
  t = fe_sqr(t)
  t = fe_sqr(t)
  fe_mul(t, z)
}
