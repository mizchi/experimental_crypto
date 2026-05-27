// Fixed-size unsigned BigInt for cryptographic primitives.
//
// NOTE on constant time:
//   This is a source-level fixed-limb / fixed-iteration implementation, not a
//   measured constant-clock implementation. Modular add/sub/mul/pow avoid
//   secret-dependent branches on operand bits, and `inv_mod` uses a
//   fixed-iteration odd-modulus path. The MoonBit backend, allocator, GC, and
//   generated machine code still need external leakage measurement before this
//   package can be treated as production constant-time code.

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

///|
let word32_mask : UInt64 = 0xffff_ffffUL

// ---------------------------------------------------------------------------
// Limb helpers.
//
// Internal representation: `FixedArray[UInt64]` little-endian (least
// significant limb at index 0). Modular arithmetic works at the modulus'
// fixed limb width. Inputs with wider limb arrays are reduced bit-by-bit so
// high limbs are not silently truncated.
// ---------------------------------------------------------------------------

///|
fn limbs_is_zero(limbs : FixedArray[UInt64]) -> Bool {
  limbs_is_zero_bit(limbs) == 1UL
}

///|
fn limbs_is_zero_bit(limbs : FixedArray[UInt64]) -> UInt64 {
  let mut acc = 0UL
  for i in 0..<limbs.length() {
    acc = acc | limbs[i]
  }
  u64_nonzero_01(acc) ^ 1UL
}

///|
fn limbs_is_one(limbs : FixedArray[UInt64]) -> Bool {
  limbs_is_one_bit(limbs) == 1UL
}

///|
fn limbs_is_one_bit(limbs : FixedArray[UInt64]) -> UInt64 {
  if limbs.length() == 0 {
    return 0UL
  }
  let mut acc = limbs[0] ^ 1UL
  for i in 1..<limbs.length() {
    acc = acc | limbs[i]
  }
  u64_nonzero_01(acc) ^ 1UL
}

///|
fn limbs_is_even(limbs : FixedArray[UInt64]) -> Bool {
  limbs_is_even_bit(limbs) == 1UL
}

///|
fn limbs_is_even_bit(limbs : FixedArray[UInt64]) -> UInt64 {
  if limbs.length() == 0 {
    1UL
  } else {
    (limbs[0] & 1UL) ^ 1UL
  }
}

///|
fn require_nonzero_modulus(modulus : Uint) -> Unit {
  if limbs_is_zero(modulus.limbs) {
    abort("crypto_bigint: zero modulus")
  }
}

///|
fn ct_select_u64(a : UInt64, b : UInt64, bit : UInt64) -> UInt64 {
  let mask = 0UL - (bit & 1UL)
  (a & mask.lnot()) | (b & mask)
}

///|
fn ct_select_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  bit : UInt64,
) -> FixedArray[UInt64] {
  let n = a.length()
  let out = FixedArray::make(n, 0UL)
  for i in 0..<n {
    out[i] = ct_select_u64(a[i], b[i], bit)
  }
  out
}

///|
fn limb_bit(limbs : FixedArray[UInt64], bit_index : Int) -> UInt64 {
  let limb_idx = bit_index / 64
  let shift = bit_index % 64
  (limbs[limb_idx] >> shift) & 1UL
}

///|
fn limbs_add_n(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> (FixedArray[UInt64], UInt64) {
  let n = a.length()
  let out = FixedArray::make(n, 0UL)
  let mut carry = 0UL
  for i in 0..<n {
    let av = a[i]
    let bv = b[i]
    let s1 = av + bv
    let c1 = u64_lt_01(s1, av)
    let s2 = s1 + carry
    let c2 = u64_lt_01(s2, s1)
    out[i] = s2
    carry = c1 | c2
  }
  (out, carry)
}

///|
fn limbs_sub_n(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> (FixedArray[UInt64], UInt64) {
  let n = a.length()
  let out = FixedArray::make(n, 0UL)
  let mut borrow = 0UL
  for i in 0..<n {
    let av = a[i]
    let bv = b[i]
    let d1 = av - bv
    let b1 = u64_lt_01(av, bv)
    let d2 = d1 - borrow
    let b2 = u64_lt_01(d1, borrow)
    out[i] = d2
    borrow = b1 | b2
  }
  (out, borrow)
}

///|
fn limbs_geq_n_bit(a : FixedArray[UInt64], b : FixedArray[UInt64]) -> UInt64 {
  let (_, borrow) = limbs_sub_n(a, b)
  borrow ^ 1UL
}

///|
fn limbs_shr1_with_top_bit(
  limbs : FixedArray[UInt64],
  top_bit : UInt64,
) -> FixedArray[UInt64] {
  let n = limbs.length()
  let out = FixedArray::make(n, 0UL)
  let mut carry = top_bit & 1UL
  for i = n - 1; i >= 0; i = i - 1 {
    let next_carry = limbs[i] & 1UL
    out[i] = (limbs[i] >> 1) | (carry << 63)
    carry = next_carry
  }
  out
}

///|
fn add_mod_reduced_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  modulus : FixedArray[UInt64],
) -> FixedArray[UInt64] {
  if limbs_is_one(modulus) {
    return FixedArray::make(modulus.length(), 0UL)
  }
  let (sum, carry) = limbs_add_n(a, b)
  let (sub, borrow) = limbs_sub_n(sum, modulus)
  // `a,b < m`, so a single subtraction is enough. If the fixed-width add
  // overflowed, the mathematical sum is `2^(64n) + sum` and must subtract m.
  let use_sub = carry | (borrow ^ 1UL)
  ct_select_limbs(sum, sub, use_sub)
}

///|
fn sub_mod_reduced_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  modulus : FixedArray[UInt64],
) -> FixedArray[UInt64] {
  if limbs_is_one(modulus) {
    return FixedArray::make(modulus.length(), 0UL)
  }
  let (diff, borrow) = limbs_sub_n(a, b)
  let (wrapped, _) = limbs_add_n(diff, modulus)
  ct_select_limbs(diff, wrapped, borrow)
}

///|
fn half_mod_odd_limbs(
  x : FixedArray[UInt64],
  modulus : FixedArray[UInt64],
) -> FixedArray[UInt64] {
  let half = limbs_shr1_with_top_bit(x, 0UL)
  let (sum, carry) = limbs_add_n(x, modulus)
  let adjusted_half = limbs_shr1_with_top_bit(sum, carry)
  ct_select_limbs(half, adjusted_half, limbs_is_even_bit(x) ^ 1UL)
}

///|
fn one_mod_limbs(modulus : FixedArray[UInt64]) -> FixedArray[UInt64] {
  let n = modulus.length()
  let out = FixedArray::make(n, 0UL)
  if n > 0 && !limbs_is_one(modulus) {
    out[0] = 1UL
  }
  out
}

///|
fn reduce_limbs_mod(
  limbs : FixedArray[UInt64],
  modulus : FixedArray[UInt64],
) -> FixedArray[UInt64] {
  let n = modulus.length()
  let mut acc = FixedArray::make(n, 0UL)
  if n == 0 || limbs_is_zero(modulus) {
    abort("crypto_bigint: zero modulus")
  }
  if limbs_is_one(modulus) {
    return acc
  }
  let one = one_mod_limbs(modulus)
  for bit_index = limbs.length() * 64 - 1
      bit_index >= 0
      bit_index = bit_index - 1 {
    let doubled = add_mod_reduced_limbs(acc, acc, modulus)
    let plus_one = add_mod_reduced_limbs(doubled, one, modulus)
    acc = ct_select_limbs(doubled, plus_one, limb_bit(limbs, bit_index))
  }
  acc
}

///|
fn mul_mod_reduced_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  modulus : FixedArray[UInt64],
) -> FixedArray[UInt64] {
  let n = modulus.length()
  let mut acc = FixedArray::make(n, 0UL)
  if limbs_is_one(modulus) {
    return acc
  }
  let mut base = a
  for bit_index in 0..<(n * 64) {
    let sum = add_mod_reduced_limbs(acc, base, modulus)
    acc = ct_select_limbs(acc, sum, limb_bit(b, bit_index))
    base = add_mod_reduced_limbs(base, base, modulus)
  }
  acc
}

///|
fn limbs_to_words32(
  limbs : FixedArray[UInt64],
  word_count : Int,
) -> FixedArray[UInt64] {
  let out = FixedArray::make(word_count, 0UL)
  for i in 0..<limbs.length() {
    let lo = limbs[i] & word32_mask
    let hi = (limbs[i] >> 32) & word32_mask
    let j = i * 2
    if j < word_count {
      out[j] = lo
    }
    if j + 1 < word_count {
      out[j + 1] = hi
    }
  }
  out
}

///|
fn words32_to_limbs(
  words : FixedArray[UInt64],
  limb_count : Int,
) -> FixedArray[UInt64] {
  let out = FixedArray::make(limb_count, 0UL)
  for i in 0..<limb_count {
    let j = i * 2
    let lo = if j < words.length() { words[j] & word32_mask } else { 0UL }
    let hi = if j + 1 < words.length() {
      words[j + 1] & word32_mask
    } else {
      0UL
    }
    out[i] = lo | (hi << 32)
  }
  out
}

///|
fn words32_sub_n(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  n : Int,
) -> (FixedArray[UInt64], UInt64) {
  let out = FixedArray::make(n, 0UL)
  let mut borrow = 0UL
  for i in 0..<n {
    let av = a[i] & word32_mask
    let bv = b[i] & word32_mask
    let subtrahend = bv + borrow
    let next_borrow = u64_lt_01(av, subtrahend)
    out[i] = (av - subtrahend) & word32_mask
    borrow = next_borrow
  }
  (out, borrow)
}

///|
fn words32_select(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  bit : UInt64,
  n : Int,
) -> FixedArray[UInt64] {
  let out = FixedArray::make(n, 0UL)
  for i in 0..<n {
    out[i] = ct_select_u64(a[i], b[i], bit) & word32_mask
  }
  out
}

///|
fn mont_inv32(m0 : UInt64) -> UInt64 {
  let mut y = 1UL
  let x = m0 & word32_mask
  for _ in 0..<5 {
    y = (y * ((2UL - ((x * y) & word32_mask)) & word32_mask)) & word32_mask
  }
  (0UL - y) & word32_mask
}

///|
fn montgomery_mul_words32(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  modulus : FixedArray[UInt64],
  inv32 : UInt64,
  word_count : Int,
) -> FixedArray[UInt64] {
  let t = FixedArray::make(word_count + 2, 0UL)
  for i in 0..<word_count {
    let bi = b[i] & word32_mask
    let mut carry = 0UL
    for j in 0..<word_count {
      let uv = t[j] + (a[j] & word32_mask) * bi + carry
      t[j] = uv & word32_mask
      carry = uv >> 32
    }
    t[word_count] = t[word_count] + carry
    let q = (t[0] * inv32) & word32_mask
    carry = 0UL
    for j in 0..<word_count {
      let uv = t[j] + q * (modulus[j] & word32_mask) + carry
      t[j] = uv & word32_mask
      carry = uv >> 32
    }
    t[word_count] = t[word_count] + carry
    t[word_count + 1] = t[word_count + 1] + (t[word_count] >> 32)
    t[word_count] = t[word_count] & word32_mask
    for j in 0..<(word_count + 1) {
      t[j] = t[j + 1]
    }
    t[word_count + 1] = 0UL
  }
  let candidate = FixedArray::make(word_count, 0UL)
  for i in 0..<word_count {
    candidate[i] = t[i] & word32_mask
  }
  let (reduced, borrow) = words32_sub_n(candidate, modulus, word_count)
  let use_reduced = u64_nonzero_01(t[word_count]) | (borrow ^ 1UL)
  words32_select(candidate, reduced, use_reduced, word_count)
}

///|
fn montgomery_r2_limbs(modulus : FixedArray[UInt64]) -> FixedArray[UInt64] {
  let n = modulus.length()
  let r2_source = FixedArray::make(2 * n + 1, 0UL)
  r2_source[2 * n] = 1UL
  reduce_limbs_mod(r2_source, modulus)
}

///|
fn montgomery_pow_odd_limbs(
  base : FixedArray[UInt64],
  exponent : FixedArray[UInt64],
  modulus : FixedArray[UInt64],
) -> FixedArray[UInt64] {
  let limb_count = modulus.length()
  let word_count = limb_count * 2
  let modulus_words = limbs_to_words32(modulus, word_count)
  let inv32 = mont_inv32(modulus_words[0])
  let base_red = reduce_limbs_mod(base, modulus)
  let base_words = limbs_to_words32(base_red, word_count)
  let r2_words = limbs_to_words32(montgomery_r2_limbs(modulus), word_count)
  let one_words = limbs_to_words32(one_mod_limbs(modulus), word_count)
  let mut result = montgomery_mul_words32(
    one_words, r2_words, modulus_words, inv32, word_count,
  )
  let mut base_m = montgomery_mul_words32(
    base_words, r2_words, modulus_words, inv32, word_count,
  )
  for bit_index in 0..<(exponent.length() * 64) {
    let product = montgomery_mul_words32(
      result, base_m, modulus_words, inv32, word_count,
    )
    result = words32_select(
      result,
      product,
      limb_bit(exponent, bit_index),
      word_count,
    )
    base_m = montgomery_mul_words32(
      base_m, base_m, modulus_words, inv32, word_count,
    )
  }
  words32_to_limbs(
    montgomery_mul_words32(result, one_words, modulus_words, inv32, word_count),
    limb_count,
  )
}

///|
fn montgomery_mul_odd_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  modulus : FixedArray[UInt64],
  inv : UInt64,
) -> FixedArray[UInt64] {
  let limb_count = modulus.length()
  let word_count = limb_count * 2
  let modulus_words = limbs_to_words32(modulus, word_count)
  let a_words = limbs_to_words32(reduce_limbs_mod(a, modulus), word_count)
  let b_words = limbs_to_words32(reduce_limbs_mod(b, modulus), word_count)
  words32_to_limbs(
    montgomery_mul_words32(
      a_words,
      b_words,
      modulus_words,
      inv & word32_mask,
      word_count,
    ),
    limb_count,
  )
}

///|
fn montgomery_mul_odd_reduced_limbs(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  modulus : FixedArray[UInt64],
  inv : UInt64,
) -> FixedArray[UInt64] {
  let limb_count = modulus.length()
  let word_count = limb_count * 2
  let modulus_words = limbs_to_words32(modulus, word_count)
  let a_words = limbs_to_words32(a, word_count)
  let b_words = limbs_to_words32(b, word_count)
  words32_to_limbs(
    montgomery_mul_words32(
      a_words,
      b_words,
      modulus_words,
      inv & word32_mask,
      word_count,
    ),
    limb_count,
  )
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
// `ct_eq` / `ct_lt` walk every zero-extended limb and avoid early return on
// limb values.
// ---------------------------------------------------------------------------

///|
fn u64_nonzero_01(x : UInt64) -> UInt64 {
  ((x | (0UL - x)) >> 63) & 1UL
}

///|
fn u64_lt_01(a : UInt64, b : UInt64) -> UInt64 {
  let diff = a - b
  (((a.lnot() & b) | ((a ^ b).lnot() & diff)) >> 63) & 1UL
}

///|
pub fn Uint::ct_eq(self : Uint, other : Uint) -> Bool {
  let a = self.limbs
  let b = other.limbs
  let n = if a.length() > b.length() { a.length() } else { b.length() }
  let mut diff = 0UL
  for i in 0..<n {
    let av = if i < a.length() { a[i] } else { 0UL }
    let bv = if i < b.length() { b[i] } else { 0UL }
    diff = diff | (av ^ bv)
  }
  u64_nonzero_01(diff) == 0UL
}

///|
pub fn Uint::ct_select(a : Uint, b : Uint, bit : UInt64) -> Uint {
  let a_limbs = a.limbs
  let b_limbs = b.limbs
  let n = if a_limbs.length() > b_limbs.length() {
    a_limbs.length()
  } else {
    b_limbs.length()
  }
  let out = FixedArray::make(n, 0UL)
  for i in 0..<n {
    let av = if i < a_limbs.length() { a_limbs[i] } else { 0UL }
    let bv = if i < b_limbs.length() { b_limbs[i] } else { 0UL }
    out[i] = ct_select_u64(av, bv, bit)
  }
  { limbs: out }
}

///|
pub fn Uint::ct_lt(self : Uint, other : Uint) -> Bool {
  let a = self.limbs
  let b = other.limbs
  let n = if a.length() > b.length() { a.length() } else { b.length() }
  let mut borrow = 0UL
  for i in 0..<n {
    let av = if i < a.length() { a[i] } else { 0UL }
    let bv = if i < b.length() { b[i] } else { 0UL }
    let d1 = av - bv
    let b1 = u64_lt_01(av, bv)
    let b2 = u64_lt_01(d1, borrow)
    borrow = b1 | b2
  }
  borrow == 1UL
}

// ---------------------------------------------------------------------------
// Modular arithmetic.
// ---------------------------------------------------------------------------

///|
fn mod_limb_count(modulus : Uint) -> Int {
  modulus.limbs.length()
}

///|
pub fn Uint::add_mod(self : Uint, other : Uint, modulus : Uint) -> Uint {
  require_nonzero_modulus(modulus)
  let a = reduce_limbs_mod(self.limbs, modulus.limbs)
  let b = reduce_limbs_mod(other.limbs, modulus.limbs)
  { limbs: add_mod_reduced_limbs(a, b, modulus.limbs) }
}

///|
pub fn Uint::sub_mod(self : Uint, other : Uint, modulus : Uint) -> Uint {
  require_nonzero_modulus(modulus)
  let a = reduce_limbs_mod(self.limbs, modulus.limbs)
  let b = reduce_limbs_mod(other.limbs, modulus.limbs)
  { limbs: sub_mod_reduced_limbs(a, b, modulus.limbs) }
}

///|
pub fn Uint::mul_mod(self : Uint, other : Uint, modulus : Uint) -> Uint {
  require_nonzero_modulus(modulus)
  let a = reduce_limbs_mod(self.limbs, modulus.limbs)
  let b = reduce_limbs_mod(other.limbs, modulus.limbs)
  { limbs: mul_mod_reduced_limbs(a, b, modulus.limbs) }
}

///|
pub fn Uint::pow_mod(self : Uint, exponent : Uint, modulus : Uint) -> Uint {
  require_nonzero_modulus(modulus)
  let n = mod_limb_count(modulus)
  if limbs_is_one(modulus.limbs) {
    return { limbs: FixedArray::make(n, 0UL) }
  }
  if !limbs_is_even(modulus.limbs) {
    return {
      limbs: montgomery_pow_odd_limbs(self.limbs, exponent.limbs, modulus.limbs),
    }
  }
  let mut result = one_mod_limbs(modulus.limbs)
  let mut base = reduce_limbs_mod(self.limbs, modulus.limbs)
  for bit_index in 0..<(exponent.limbs.length() * 64) {
    let product = mul_mod_reduced_limbs(result, base, modulus.limbs)
    result = ct_select_limbs(
      result,
      product,
      limb_bit(exponent.limbs, bit_index),
    )
    base = mul_mod_reduced_limbs(base, base, modulus.limbs)
  }
  { limbs: result }
}

///|
pub fn Uint::inv_mod(
  self : Uint,
  modulus : Uint,
) -> Uint raise CryptoBigintError {
  require_nonzero_modulus(modulus)
  if limbs_is_one(modulus.limbs) || limbs_is_even(modulus.limbs) {
    raise NotInvertible
  }
  let n = mod_limb_count(modulus)
  let mut u = reduce_limbs_mod(self.limbs, modulus.limbs)
  // Fixed-iteration binary almost-inverse over limbs. This still uses the
  // caller-visible failure branch at the end for non-invertible values, but
  // the update loop itself always runs for the full limb width.
  let mut v = modulus.limbs
  let mut x1 = one_mod_limbs(modulus.limbs)
  let mut x2 = FixedArray::make(n, 0UL)
  let iterations = n * 128 + 1
  for _ in 0..<iterations {
    let done = limbs_is_one_bit(u) | limbs_is_one_bit(v)
    let active = done ^ 1UL
    let u_even = limbs_is_even_bit(u)
    let v_even = limbs_is_even_bit(v)
    let u_ge_v = limbs_geq_n_bit(u, v)
    let case_u_even = active & u_even
    let case_v_even = active & (u_even ^ 1UL) & v_even
    let case_u_sub = active & (u_even ^ 1UL) & (v_even ^ 1UL) & u_ge_v
    let case_v_sub = active & (u_even ^ 1UL) & (v_even ^ 1UL) & (u_ge_v ^ 1UL)

    let u_half = limbs_shr1_with_top_bit(u, 0UL)
    let v_half = limbs_shr1_with_top_bit(v, 0UL)
    let (u_minus_v, _) = limbs_sub_n(u, v)
    let (v_minus_u, _) = limbs_sub_n(v, u)
    let u_minus_v_half = limbs_shr1_with_top_bit(u_minus_v, 0UL)
    let v_minus_u_half = limbs_shr1_with_top_bit(v_minus_u, 0UL)
    let x1_half = half_mod_odd_limbs(x1, modulus.limbs)
    let x2_half = half_mod_odd_limbs(x2, modulus.limbs)
    let x1_minus_x2_half = half_mod_odd_limbs(
      sub_mod_reduced_limbs(x1, x2, modulus.limbs),
      modulus.limbs,
    )
    let x2_minus_x1_half = half_mod_odd_limbs(
      sub_mod_reduced_limbs(x2, x1, modulus.limbs),
      modulus.limbs,
    )

    let mut next_u = u
    next_u = ct_select_limbs(next_u, u_half, case_u_even)
    next_u = ct_select_limbs(next_u, u_minus_v_half, case_u_sub)
    let mut next_v = v
    next_v = ct_select_limbs(next_v, v_half, case_v_even)
    next_v = ct_select_limbs(next_v, v_minus_u_half, case_v_sub)
    let mut next_x1 = x1
    next_x1 = ct_select_limbs(next_x1, x1_half, case_u_even)
    next_x1 = ct_select_limbs(next_x1, x1_minus_x2_half, case_u_sub)
    let mut next_x2 = x2
    next_x2 = ct_select_limbs(next_x2, x2_half, case_v_even)
    next_x2 = ct_select_limbs(next_x2, x2_minus_x1_half, case_v_sub)
    u = next_u
    v = next_v
    x1 = next_x1
    x2 = next_x2
  }
  if limbs_is_one(u) {
    { limbs: x1 }
  } else if limbs_is_one(v) {
    { limbs: x2 }
  } else {
    raise NotInvertible
  }
}

// ---------------------------------------------------------------------------
// Montgomery form.
//
// Odd moduli use 32-bit-word Montgomery multiplication. Even moduli keep the
// generic modular-arithmetic fallback because Montgomery reduction is not
// defined for them.
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
  let r2 = if n == 0 ||
    limbs_is_zero(modulus.limbs) ||
    limbs_is_one(modulus.limbs) {
    { limbs: FixedArray::make(n, 0UL) }
  } else {
    { limbs: montgomery_r2_limbs(modulus.limbs) }
  }
  // inv = -modulus^-1 mod 2^64. If modulus is even, leave 0 (Montgomery is
  // undefined for even modulus, but we still need a value; the current
  // multiply/reduce path does not consume `inv`).
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
  if limbs_is_zero(self.modulus.limbs) {
    return { limbs: FixedArray::make(self.modulus.limbs.length(), 0UL) }
  }
  if limbs_is_one(self.modulus.limbs) {
    return { limbs: FixedArray::make(self.modulus.limbs.length(), 0UL) }
  }
  if limbs_is_even(self.modulus.limbs) {
    return { limbs: reduce_limbs_mod(x.limbs, self.modulus.limbs) }
  }
  {
    limbs: montgomery_mul_odd_limbs(
      x.limbs,
      self.r2.limbs,
      self.modulus.limbs,
      self.inv,
    ),
  }
}

///|
pub fn Montgomery::from_mont(self : Montgomery, x : Uint) -> Uint {
  if limbs_is_zero(self.modulus.limbs) {
    return { limbs: FixedArray::make(self.modulus.limbs.length(), 0UL) }
  }
  if limbs_is_one(self.modulus.limbs) {
    return { limbs: FixedArray::make(self.modulus.limbs.length(), 0UL) }
  }
  if limbs_is_even(self.modulus.limbs) {
    return { limbs: reduce_limbs_mod(x.limbs, self.modulus.limbs) }
  }
  {
    limbs: montgomery_mul_odd_limbs(
      x.limbs,
      one_mod_limbs(self.modulus.limbs),
      self.modulus.limbs,
      self.inv,
    ),
  }
}

///|
pub fn Montgomery::mul(self : Montgomery, a : Uint, b : Uint) -> Uint {
  if limbs_is_zero(self.modulus.limbs) {
    return { limbs: FixedArray::make(self.modulus.limbs.length(), 0UL) }
  }
  if limbs_is_one(self.modulus.limbs) {
    return { limbs: FixedArray::make(self.modulus.limbs.length(), 0UL) }
  }
  if limbs_is_even(self.modulus.limbs) {
    return a.mul_mod(b, self.modulus)
  }
  {
    limbs: montgomery_mul_odd_limbs(
      a.limbs,
      b.limbs,
      self.modulus.limbs,
      self.inv,
    ),
  }
}

///|
// Multiplication for callers that already hold reduced Montgomery-domain
// operands. This skips the generic input reduction in `mul`; do not pass
// arbitrary unreduced integers here.
pub fn Montgomery::mul_reduced(self : Montgomery, a : Uint, b : Uint) -> Uint {
  if limbs_is_zero(self.modulus.limbs) {
    return { limbs: FixedArray::make(self.modulus.limbs.length(), 0UL) }
  }
  if limbs_is_one(self.modulus.limbs) {
    return { limbs: FixedArray::make(self.modulus.limbs.length(), 0UL) }
  }
  if limbs_is_even(self.modulus.limbs) {
    return a.mul_mod(b, self.modulus)
  }
  {
    limbs: montgomery_mul_odd_reduced_limbs(
      a.limbs,
      b.limbs,
      self.modulus.limbs,
      self.inv,
    ),
  }
}

///|
pub fn Montgomery::pow(self : Montgomery, base : Uint, exponent : Uint) -> Uint {
  if limbs_is_zero(self.modulus.limbs) {
    return { limbs: FixedArray::make(self.modulus.limbs.length(), 0UL) }
  }
  if limbs_is_one(self.modulus.limbs) {
    return { limbs: FixedArray::make(self.modulus.limbs.length(), 0UL) }
  }
  if limbs_is_even(self.modulus.limbs) {
    return base.pow_mod(exponent, self.modulus)
  }
  {
    limbs: montgomery_pow_odd_limbs(
      base.limbs,
      exponent.limbs,
      self.modulus.limbs,
    ),
  }
}
