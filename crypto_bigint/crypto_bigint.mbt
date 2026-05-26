// Fixed-size unsigned BigInt for cryptographic primitives.
//
// NOTE on constant time:
//   The current implementation routes arithmetic through
//   `moonbitlang/core/bigint` for correctness and to lock down the public
//   surface. It is NOT constant time. Replacing the BigInt fallback with
//   per-limb constant-time arithmetic is a future task.

///|
pub(all) struct Uint {
  limbs : FixedArray[UInt64]
} derive(Eq)

///|
pub impl Show for Uint with fn output(self, logger) {
  logger.write_string("0x")
  let n = self.limbs.length()
  if n == 0 {
    logger.write_string("0")
    return
  }
  // Most significant limb first; trim leading zeros on the top limb only.
  let top = self.limbs[n - 1]
  logger.write_string(uint64_to_hex(top, pad=false))
  for i = n - 2; i >= 0; i = i - 1 {
    logger.write_string(uint64_to_hex(self.limbs[i], pad=true))
  }
}

///|
fn uint64_to_hex(v : UInt64, pad~ : Bool) -> String {
  fn nibble_char(n : Int) -> Char {
    if n < 10 {
      Int::unsafe_to_char(n + '0'.to_int())
    } else {
      Int::unsafe_to_char(n - 10 + 'a'.to_int())
    }
  }

  if v == 0UL && !pad {
    return "0"
  }
  let buf = StringBuilder::new()
  let mut started = pad
  for i = 15; i >= 0; i = i - 1 {
    let shift = i * 4
    let nibble = ((v >> shift) & 0xFUL).to_int()
    if !started && nibble != 0 {
      started = true
    }
    if started {
      buf.write_char(nibble_char(nibble))
    }
  }
  if !started {
    buf.write_char('0')
  }
  buf.to_string()
}

///|
pub suberror CryptoBigintError {
  InvalidLength
  NotInvertible
} derive(Debug)

// ---------------------------------------------------------------------------
// Limb <-> BigInt conversion helpers.
//
// Internal representation: `FixedArray[UInt64]` little-endian (least
// significant limb at index 0).
// ---------------------------------------------------------------------------

///|
fn limbs_to_bigint(limbs : FixedArray[UInt64]) -> @bigint.BigInt {
  let n = limbs.length()
  if n == 0 {
    return @bigint.BigInt::from_int(0)
  }
  // Build the integer limb-by-limb from MSB down. core/bigint's
  // `from_octets` does not robustly handle multi-limb leading zeros, so we
  // assemble via shifts which keeps internal invariants happy.
  let mut acc = @bigint.BigInt::from_int(0)
  for i = n - 1; i >= 0; i = i - 1 {
    acc = (acc << 64) + @bigint.BigInt::from_uint64(limbs[i])
  }
  acc
}

///|
fn bigint_to_limbs(x : @bigint.BigInt, limb_count : Int) -> FixedArray[UInt64] {
  let limbs = FixedArray::make(limb_count, 0UL)
  if limb_count == 0 {
    return limbs
  }
  let total_bytes = limb_count * 8
  // BigInt::to_octets returns big-endian, left-padded to `length`.
  let octets = x.to_octets(length=total_bytes)
  let off = octets.length() - total_bytes
  for i in 0..<limb_count {
    // Limb i is the (limb_count - 1 - i)-th 8-byte block from the MSB side.
    let base = off + (limb_count - 1 - i) * 8
    let mut v : UInt64 = 0UL
    for j in 0..<8 {
      v = (v << 8) | octets[base + j].to_uint64()
    }
    limbs[i] = v
  }
  limbs
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

///|
pub fn Uint::zero(limb_count : Int) -> Uint {
  { limbs: FixedArray::make(limb_count, 0UL) }
}

///|
pub fn Uint::one(limb_count : Int) -> Uint {
  let limbs = FixedArray::make(limb_count, 0UL)
  if limb_count > 0 {
    limbs[0] = 1UL
  }
  { limbs, }
}

///|
pub fn Uint::from_be_bytes(
  bytes : Bytes,
  limb_count : Int,
) -> Uint raise CryptoBigintError {
  if limb_count < 0 {
    raise InvalidLength
  }
  let cap = limb_count * 8
  if bytes.length() > cap {
    raise InvalidLength
  }
  let limbs = FixedArray::make(limb_count, 0UL)
  // The last byte of `bytes` is the LSB. Walk bytes from the back.
  let n = bytes.length()
  for i in 0..<n {
    let byte_index_from_lsb = n - 1 - i
    let limb_idx = byte_index_from_lsb / 8
    let shift = byte_index_from_lsb % 8 * 8
    let b = bytes[i].to_uint64()
    limbs[limb_idx] = limbs[limb_idx] | (b << shift)
  }
  { limbs, }
}

///|
pub fn Uint::from_le_bytes(
  bytes : Bytes,
  limb_count : Int,
) -> Uint raise CryptoBigintError {
  if limb_count < 0 {
    raise InvalidLength
  }
  let cap = limb_count * 8
  if bytes.length() > cap {
    raise InvalidLength
  }
  let limbs = FixedArray::make(limb_count, 0UL)
  let n = bytes.length()
  for i in 0..<n {
    let limb_idx = i / 8
    let shift = i % 8 * 8
    let b = bytes[i].to_uint64()
    limbs[limb_idx] = limbs[limb_idx] | (b << shift)
  }
  { limbs, }
}

///|
pub fn Uint::to_be_bytes(self : Uint) -> Bytes {
  let n = self.limbs.length()
  let buf = FixedArray::make(n * 8, b'\x00')
  for i in 0..<n {
    let v = self.limbs[n - 1 - i]
    let base = i * 8
    buf[base + 0] = ((v >> 56) & 0xFFUL).to_int().to_byte()
    buf[base + 1] = ((v >> 48) & 0xFFUL).to_int().to_byte()
    buf[base + 2] = ((v >> 40) & 0xFFUL).to_int().to_byte()
    buf[base + 3] = ((v >> 32) & 0xFFUL).to_int().to_byte()
    buf[base + 4] = ((v >> 24) & 0xFFUL).to_int().to_byte()
    buf[base + 5] = ((v >> 16) & 0xFFUL).to_int().to_byte()
    buf[base + 6] = ((v >> 8) & 0xFFUL).to_int().to_byte()
    buf[base + 7] = (v & 0xFFUL).to_int().to_byte()
  }
  Bytes::from_array(buf)
}

///|
pub fn Uint::to_le_bytes(self : Uint) -> Bytes {
  let n = self.limbs.length()
  let buf = FixedArray::make(n * 8, b'\x00')
  for i in 0..<n {
    let v = self.limbs[i]
    let base = i * 8
    buf[base + 0] = (v & 0xFFUL).to_int().to_byte()
    buf[base + 1] = ((v >> 8) & 0xFFUL).to_int().to_byte()
    buf[base + 2] = ((v >> 16) & 0xFFUL).to_int().to_byte()
    buf[base + 3] = ((v >> 24) & 0xFFUL).to_int().to_byte()
    buf[base + 4] = ((v >> 32) & 0xFFUL).to_int().to_byte()
    buf[base + 5] = ((v >> 40) & 0xFFUL).to_int().to_byte()
    buf[base + 6] = ((v >> 48) & 0xFFUL).to_int().to_byte()
    buf[base + 7] = ((v >> 56) & 0xFFUL).to_int().to_byte()
  }
  Bytes::from_array(buf)
}

///|
pub fn Uint::bit_len(self : Uint) -> Int {
  let n = self.limbs.length()
  for i = n - 1; i >= 0; i = i - 1 {
    let v = self.limbs[i]
    if v != 0UL {
      // Highest set bit within v (1-indexed).
      let mut top = 0
      let mut x = v
      while x != 0UL {
        top = top + 1
        x = x >> 1
      }
      return i * 64 + top
    }
  }
  0
}

// ---------------------------------------------------------------------------
// Comparisons.
//
// `ct_eq` / `ct_lt` are NOT constant time today. The names match the
// future API surface; tighten the implementation when constant-time work
// lands.
// ---------------------------------------------------------------------------

///|
pub fn Uint::ct_eq(self : Uint, other : Uint) -> Bool {
  let a = self.limbs
  let b = other.limbs
  if a.length() != b.length() {
    // Compare as if shorter side is zero-extended.
    let n = if a.length() > b.length() { a.length() } else { b.length() }
    for i in 0..<n {
      let av = if i < a.length() { a[i] } else { 0UL }
      let bv = if i < b.length() { b[i] } else { 0UL }
      if av != bv {
        return false
      }
    }
    return true
  }
  for i in 0..<a.length() {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
pub fn Uint::ct_lt(self : Uint, other : Uint) -> Bool {
  let a = self.limbs
  let b = other.limbs
  let n = if a.length() > b.length() { a.length() } else { b.length() }
  for i = n - 1; i >= 0; i = i - 1 {
    let av = if i < a.length() { a[i] } else { 0UL }
    let bv = if i < b.length() { b[i] } else { 0UL }
    if av != bv {
      return av < bv
    }
  }
  false
}

// ---------------------------------------------------------------------------
// Modular arithmetic.
//
// Internal helper: do the arithmetic via core/bigint, then re-pack into
// `limb_count` limbs based on the modulus' width. All inputs are assumed
// already reduced modulo `modulus` (mirrors the typical cryptographic
// invariant). We still reduce defensively on the result.
// ---------------------------------------------------------------------------

///|
fn mod_limb_count(modulus : Uint) -> Int {
  modulus.limbs.length()
}

///|
pub fn Uint::add_mod(self : Uint, other : Uint, modulus : Uint) -> Uint {
  let a = limbs_to_bigint(self.limbs)
  let b = limbs_to_bigint(other.limbs)
  let m = limbs_to_bigint(modulus.limbs)
  let r = (a + b) % m
  { limbs: bigint_to_limbs(r, mod_limb_count(modulus)) }
}

///|
pub fn Uint::sub_mod(self : Uint, other : Uint, modulus : Uint) -> Uint {
  let a = limbs_to_bigint(self.limbs)
  let b = limbs_to_bigint(other.limbs)
  let m = limbs_to_bigint(modulus.limbs)
  let mut r = (a - b) % m
  // Normalize to non-negative representative.
  let zero = @bigint.BigInt::from_int(0)
  if r < zero {
    r = r + m
  }
  { limbs: bigint_to_limbs(r, mod_limb_count(modulus)) }
}

///|
pub fn Uint::mul_mod(self : Uint, other : Uint, modulus : Uint) -> Uint {
  let a = limbs_to_bigint(self.limbs)
  let b = limbs_to_bigint(other.limbs)
  let m = limbs_to_bigint(modulus.limbs)
  let r = a * b % m
  { limbs: bigint_to_limbs(r, mod_limb_count(modulus)) }
}

///|
pub fn Uint::pow_mod(self : Uint, exponent : Uint, modulus : Uint) -> Uint {
  let base = limbs_to_bigint(self.limbs)
  let exp = limbs_to_bigint(exponent.limbs)
  let m = limbs_to_bigint(modulus.limbs)
  let r = base.pow(exp, modulus=m)
  { limbs: bigint_to_limbs(r, mod_limb_count(modulus)) }
}

///|
pub fn Uint::inv_mod(
  self : Uint,
  modulus : Uint,
) -> Uint raise CryptoBigintError {
  let a = limbs_to_bigint(self.limbs)
  let m = limbs_to_bigint(modulus.limbs)
  let zero = @bigint.BigInt::from_int(0)
  let one = @bigint.BigInt::from_int(1)
  if m <= one {
    raise NotInvertible
  }
  // Reduce `a` into [0, m).
  let mut a_red = a % m
  if a_red < zero {
    a_red = a_red + m
  }
  if a_red == zero {
    raise NotInvertible
  }
  // Extended Euclidean algorithm.
  // Track (old_r, r) and (old_s, s) such that old_r = old_s * a (mod m).
  let mut old_r = a_red
  let mut r = m
  let mut old_s = one
  let mut s = zero
  while r != zero {
    let q = old_r / r
    let new_r = old_r - q * r
    old_r = r
    r = new_r
    let new_s = old_s - q * s
    old_s = s
    s = new_s
  }
  if old_r != one {
    raise NotInvertible
  }
  // old_s is the inverse, but may be negative. Normalize.
  let mut inv = old_s % m
  if inv < zero {
    inv = inv + m
  }
  { limbs: bigint_to_limbs(inv, mod_limb_count(modulus)) }
}

// ---------------------------------------------------------------------------
// Montgomery form.
//
// Today this is a thin wrapper that stores the modulus and reuses
// `mul_mod` / `pow_mod`. The `r2` / `inv` fields are kept on the struct so
// that future native Montgomery multiplication can drop in without an API
// break.
// ---------------------------------------------------------------------------

///|
pub(all) struct Montgomery {
  modulus : Uint
  r2 : Uint
  inv : UInt64
}

///|
pub fn Montgomery::new(modulus : Uint) -> Montgomery {
  // Precompute r2 = (2^(64 * n))^2 mod modulus, even though current ops do
  // not consume it. This keeps the public surface aligned with the future
  // native implementation.
  let n = modulus.limbs.length()
  let m_big = limbs_to_bigint(modulus.limbs)
  let zero = @bigint.BigInt::from_int(0)
  let one = @bigint.BigInt::from_int(1)
  let r2_big = if m_big == zero || m_big == one {
    zero
  } else {
    let r = one << (64 * n)
    r * r % m_big
  }
  let r2 = { limbs: bigint_to_limbs(r2_big, n) }
  // inv = -modulus^-1 mod 2^64. If modulus is even, leave 0 (Montgomery is
  // undefined for even modulus, but we still need a value; the fallback
  // arithmetic path does not consume `inv`).
  let inv = if n == 0 || (modulus.limbs[0] & 1UL) == 0UL {
    0UL
  } else {
    mont_inv64(modulus.limbs[0])
  }
  { modulus, r2, inv }
}

///|
fn mont_inv64(m0 : UInt64) -> UInt64 {
  // Newton iteration for -m0^-1 mod 2^64. Five iterations suffice for 64 bits
  // (precision doubles each step from 4 bits).
  let mut y : UInt64 = 1UL
  for _ in 0..<6 {
    y = y * (2UL - m0 * y)
  }
  // y = m0^-1 mod 2^64; we want the negation.
  0UL - y
}

///|
pub fn Montgomery::to_mont(self : Montgomery, x : Uint) -> Uint {
  // Reduce x into the modulus' field while we're here.
  let m = limbs_to_bigint(self.modulus.limbs)
  let zero = @bigint.BigInt::from_int(0)
  if m == zero {
    return { limbs: FixedArray::make(self.modulus.limbs.length(), 0UL) }
  }
  let xb = limbs_to_bigint(x.limbs)
  let mut r = xb % m
  if r < zero {
    r = r + m
  }
  { limbs: bigint_to_limbs(r, self.modulus.limbs.length()) }
}

///|
pub fn Montgomery::from_mont(self : Montgomery, x : Uint) -> Uint {
  // The current to/from pair is the identity because we do not actually
  // multiply by R. This keeps `to_mont` / `from_mont` round-trips correct.
  self.to_mont(x)
}

///|
pub fn Montgomery::mul(self : Montgomery, a : Uint, b : Uint) -> Uint {
  a.mul_mod(b, self.modulus)
}

///|
pub fn Montgomery::pow(self : Montgomery, base : Uint, exponent : Uint) -> Uint {
  base.pow_mod(exponent, self.modulus)
}
