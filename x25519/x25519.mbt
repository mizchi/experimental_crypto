// X25519 (RFC 7748) ECDH using the Montgomery ladder on Curve25519.
//
// Field arithmetic operates over GF(2^255 - 19) using a 10-limb,
// mixed-radix 2^25.5 representation (alternating 26 and 25 bit limbs).
//
// Layout: a Fe (FixedArray[UInt64] length 10) represents
//   value = l[0]
//         + l[1] * 2^26
//         + l[2] * 2^51
//         + l[3] * 2^77
//         + l[4] * 2^102
//         + l[5] * 2^128
//         + l[6] * 2^153
//         + l[7] * 2^179
//         + l[8] * 2^204
//         + l[9] * 2^230
//
// Limb sizes (in bits): 26, 25, 26, 25, 26, 25, 26, 25, 26, 25.
// During multiplication intermediate products of two ~26-bit limbs fit in
// ~52 bits; the sum of 10 such products fits comfortably in 56 bits, well
// within a UInt64. Reduction folds the high half back via the identity
// 2^255 ≡ 19 (mod p), which appears in the schoolbook product as the
// 19 * l[i + 10 - j] terms.
//
// The ladder is structured to be branch-free at the limb level (constant
// time cswap), but MoonBit does not guarantee constant-time execution end
// to end; treat this as a same-shape rewrite that's also dramatically
// faster than the previous @bigint version.

///|
pub struct PrivateKey {
  bytes : FixedArray[Byte] // 32 bytes, clamped per RFC 7748 §5
} derive(Eq)

///|
pub impl Show for PrivateKey with fn output(self, logger) {
  ignore(self)
  logger.write_string("PrivateKey(<redacted>)")
}

///|
pub struct PublicKey {
  bytes : FixedArray[Byte] // 32 bytes
} derive(Eq, Debug)

///|
pub struct SharedSecret {
  bytes : FixedArray[Byte] // 32 bytes
} derive(Eq)

///|
pub impl Show for SharedSecret with fn output(self, logger) {
  ignore(self)
  logger.write_string("SharedSecret(<redacted>)")
}

///|
pub fn SharedSecret::to_bytes(self : SharedSecret) -> Bytes {
  Bytes::makei(32, fn(i) { self.bytes[i] })
}

///|
pub suberror X25519Error {
  InvalidScalarLength(Int)
  InvalidPointLength(Int)
  AllZeroSharedSecret // small-subgroup attack signal
} derive(Debug)

///|
fn ensure_32_bytes(
  b : Bytes,
  msg : (Int) -> X25519Error,
) -> FixedArray[Byte] raise X25519Error {
  if b.length() != 32 {
    raise msg(b.length())
  }
  let fa = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    fa[i] = b[i]
  }
  fa
}

///|
fn clamp_scalar(fa : FixedArray[Byte]) -> FixedArray[Byte] {
  let out = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    out[i] = fa[i]
  }
  out[0] = (out[0].to_int() & 248).to_byte()
  out[31] = (out[31].to_int() & 127).to_byte()
  out[31] = (out[31].to_int() | 64).to_byte()
  out
}

///|
pub fn PrivateKey::from_bytes(b : Bytes) -> PrivateKey raise X25519Error {
  let fa = ensure_32_bytes(b, fn(n) { InvalidScalarLength(n) })
  { bytes: clamp_scalar(fa) }
}

///|
pub fn PrivateKey::to_bytes(self : PrivateKey) -> Bytes {
  Bytes::makei(32, fn(i) { self.bytes[i] })
}

///|
pub fn PrivateKey::from_random(
  random_32_bytes : Bytes,
) -> PrivateKey raise X25519Error {
  PrivateKey::from_bytes(random_32_bytes)
}

///|
pub fn PrivateKey::public_key(self : PrivateKey) -> PublicKey {
  // X25519(scalar, base point u=9)
  let base = FixedArray::make(32, b'\x00')
  base[0] = b'\x09'
  let u_bytes = scalarmult_unchecked(self.bytes, base)
  { bytes: u_bytes }
}

///|
pub fn PublicKey::from_bytes(b : Bytes) -> PublicKey raise X25519Error {
  let fa = ensure_32_bytes(b, fn(n) { InvalidPointLength(n) })
  { bytes: fa }
}

///|
pub fn PublicKey::to_bytes(self : PublicKey) -> Bytes {
  Bytes::makei(32, fn(i) { self.bytes[i] })
}

///|
pub fn diffie_hellman(
  sk : PrivateKey,
  pk : PublicKey,
) -> SharedSecret raise X25519Error {
  let out = scalarmult_unchecked(sk.bytes, pk.bytes)
  // RFC 7748 §6.1: an all-zero output indicates a small-subgroup point.
  // OR-accumulate every byte (no early break) so the timing of this check
  // does not leak the position of the first non-zero byte in the shared
  // secret.
  let mut acc = 0
  for i in 0..<32 {
    acc = acc | out[i].to_int()
  }
  if acc == 0 {
    raise AllZeroSharedSecret
  }
  { bytes: out }
}

// ─── field arithmetic over GF(2^255 - 19): 10-limb radix-2^25.5 ────────

// A field element is FixedArray[UInt64] of length 10.
// Limb bit widths (LSB → MSB): 26, 25, 26, 25, 26, 25, 26, 25, 26, 25.
// Canonical form has each limb < 2^26 (even index) or < 2^25 (odd index).
// During arithmetic limbs may temporarily grow to ~57 bits before
// `fe_carry` brings them back.

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
fn fe_copy(a : Fe) -> Fe {
  let r = FixedArray::make(10, 0UL)
  for i in 0..<10 {
    r[i] = a[i]
  }
  r
}

// Decode a 32-byte little-endian integer to a Fe, masking off the
// high bit of byte 31 per RFC 7748 §5.

///|
fn fe_from_bytes(b : FixedArray[Byte]) -> Fe {
  // Reassemble the 256-bit input as ten limbs.
  // Strategy: load each pair of 26/25-bit chunks by reading enough bytes
  // (a 32-bit window covering 26..32 bits is fine for any limb) then
  // masking and shifting.
  //
  // We pull a 64-bit window starting at each byte offset, which avoids
  // careful per-limb byte arithmetic.
  fn ld4(off : Int) -> UInt64 {
    let b0 = b[off].to_uint64()
    let b1 = b[off + 1].to_uint64()
    let b2 = b[off + 2].to_uint64()
    let b3 = b[off + 3].to_uint64()
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
  }

  let mask25 : UInt64 = (1UL << 25) - 1UL
  let mask26 : UInt64 = (1UL << 26) - 1UL
  // Use ld4 + neighbor byte for any 26-bit window.
  // Limb i starts at total-bit offset s_i:
  //   s = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230]
  // bit width w = 26 for even i, 25 for odd i.
  // We extract by loading 5 bytes (40 bits) covering the window.
  fn ld5(off : Int) -> UInt64 {
    let b0 = b[off].to_uint64()
    let b1 = b[off + 1].to_uint64()
    let b2 = b[off + 2].to_uint64()
    let b3 = b[off + 3].to_uint64()
    let b4 = b[off + 4].to_uint64()
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32)
  }

  let h = FixedArray::make(10, 0UL)
  // s = 0  → byte 0, bit 0, w 26
  h[0] = ld4(0) & mask26
  // s = 26 → byte 3, bit 2, w 25
  h[1] = (ld4(3) >> 2) & mask25
  // s = 51 → byte 6, bit 3, w 26
  h[2] = (ld4(6) >> 3) & mask26
  // s = 77 → byte 9, bit 5, w 25
  h[3] = (ld4(9) >> 5) & mask25
  // s = 102 → byte 12, bit 6, w 26
  h[4] = (ld4(12) >> 6) & mask26
  // s = 128 → byte 16, bit 0, w 25
  h[5] = ld4(16) & mask25
  // s = 153 → byte 19, bit 1, w 26
  h[6] = (ld4(19) >> 1) & mask26
  // s = 179 → byte 22, bit 3, w 25
  h[7] = (ld4(22) >> 3) & mask25
  // s = 204 → byte 25, bit 4, w 26
  h[8] = (ld4(25) >> 4) & mask26
  // s = 230 → byte 28, bit 6, w 25, plus high-bit masked
  // ld5 because we need byte 32-equivalent semantics; here it's 28..32.
  // Byte 31 high bit is masked before assembling.
  let _ = ld5
  let b28 = b[28].to_uint64()
  let b29 = b[29].to_uint64()
  let b30 = b[30].to_uint64()
  let b31 = b[31].to_uint64() & 0x7FUL
  let win = b28 | (b29 << 8) | (b30 << 16) | (b31 << 24)
  h[9] = (win >> 6) & mask25
  h
}

// Encode a field element as 32 little-endian bytes, applying full
// canonical reduction to [0, p).

///|
fn fe_to_bytes(a : Fe) -> FixedArray[Byte] {
  let h = fe_carry_full(a)
  // After carry, each h[i] is in [0, 2^26) / [0, 2^25). But the value
  // may still be ≥ p. We do constant-time subtraction of p in limb
  // form and conditionally swap.
  //
  // p = 2^255 - 19. In our limb form,
  // p = (2^26 - 19) + (2^25 - 1)·2^26 + (2^26 - 1)·2^51 + ...
  // i.e. limb 0 = 2^26 - 19, limbs 1..9 are maximal.
  let q = FixedArray::make(10, 0UL)
  q[0] = h[0] + 19UL // tentative h + 19
  for i in 1..<10 {
    q[i] = h[i]
  }
  // carry chain on q to check if h ≥ p (which is equivalent to h + 19 ≥ 2^255)
  let mask25 : UInt64 = (1UL << 25) - 1UL
  let mask26 : UInt64 = (1UL << 26) - 1UL
  // propagate carries
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
  // After processing, c2 is what overflows past 2^255 in q = h + 19.
  let c2 = q[9] >> 25
  q[9] = q[9] & mask25
  // If c2 == 1, q (mod 2^255) is the canonical representative of h - p,
  // i.e. h was ≥ p, so we should use q. Otherwise keep h.
  let use_q = c2 // 0 or 1
  let out = FixedArray::make(10, 0UL)
  for i in 0..<10 {
    // Select q[i] when use_q == 1, else h[i].
    let mask : UInt64 = 0UL - use_q // 0 or 0xFFFF...
    out[i] = (q[i] & mask) | (h[i] & mask.lnot())
  }
  // Serialize 'out' (limbs) to 32 little-endian bytes.
  let bytes = FixedArray::make(32, b'\x00')
  // Pack limbs back into a single big-endian-by-bits stream and emit LE bytes.
  // Easier: write the limbs into a 64-bit running buffer.
  // We compute each byte by extracting the appropriate bits.
  // Construct a 4-word big buffer of 64-bit pieces and emit bytes.
  // Word layout (64 bits each, LE):
  //   word0 = bits 0..63
  //   word1 = bits 64..127
  //   word2 = bits 128..191
  //   word3 = bits 192..255
  let w = FixedArray::make(4, 0UL)
  // limb 0 (26 bits) at bit 0
  w[0] = out[0]
  // limb 1 (25 bits) at bit 26
  w[0] = w[0] | (out[1] << 26)
  // limb 2 (26 bits) at bit 51
  w[0] = w[0] | (out[2] << 51)
  // overflow into word1 from limb2 (bits >= 64)
  w[1] = out[2] >> 13
  // limb 3 (25 bits) at bit 77 → word1 bit 13
  w[1] = w[1] | (out[3] << 13)
  // limb 4 (26 bits) at bit 102 → word1 bit 38
  w[1] = w[1] | (out[4] << 38)
  // limb 5 (25 bits) at bit 128 → word2 bit 0
  // But limb 4 spans into word2 too: limb4 occupies bits 102..128. Bits 102..128 lie in word1 bits 38..64.
  // limb 4 has 26 bits; (out[4] << 38) takes bits 38..63 inclusive, which corresponds to bits 0..25 of limb 4. We lose bit 25.
  // So we need: w[2] |= out[4] >> (64 - 38) = out[4] >> 26 (only 1 bit if limb 4 saturates 26 bits; for canonical w[2] starts 0 so OK).
  w[2] = out[4] >> 26
  // limb 5 (25 bits) at bit 128 → word2 bit 0
  w[2] = w[2] | (out[5] << 0)
  // limb 6 (26 bits) at bit 153 → word2 bit 25
  w[2] = w[2] | (out[6] << 25)
  // limb 7 (25 bits) at bit 179 → word2 bit 51
  w[2] = w[2] | (out[7] << 51)
  // limb 7 high bits cross into word3 starting at word3 bit 0 = bit 192
  // limb 7 bits 13..24 are in word3 (12 bits)
  w[3] = out[7] >> 13
  // limb 8 (26 bits) at bit 204 → word3 bit 12
  w[3] = w[3] | (out[8] << 12)
  // limb 9 (25 bits) at bit 230 → word3 bit 38
  w[3] = w[3] | (out[9] << 38)
  // Now emit 32 LE bytes from w[0..4].
  for wi in 0..<4 {
    let v = w[wi]
    for bi in 0..<8 {
      bytes[wi * 8 + bi] = ((v >> (bi * 8)) & 0xFFUL).to_byte()
    }
  }
  bytes
}

// Carry propagation: bring each limb back to its canonical bit range.
// Two passes from limb 0 → 9, then fold the overflow back via 2^255 ≡ 19.

///|
fn fe_carry_full(h : Fe) -> Fe {
  let mask25 : UInt64 = (1UL << 25) - 1UL
  let mask26 : UInt64 = (1UL << 26) - 1UL
  let r = FixedArray::make(10, 0UL)
  for i in 0..<10 {
    r[i] = h[i]
  }
  // First pass.
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
  // Fold the top carry back: 2^255 ≡ 19 (mod p).
  r[0] = r[0] + 19UL * c
  // Second pass (single sweep is enough now since r[0] < 2^26 + 19*(small)).
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

// Subtraction: a - b mod p, computed as a + (2p - b) so all limbs stay
// non-negative even when a is small.
// 2p has the limb representation:
//   2p = 2^256 - 38
//      = (2^27 - 38) + (2^26 - 1)·2^26 + (2^27 - 1)·2^51 + ...
// More carefully: in our radix-2^25.5 layout, 2p's limbs are
//   2*(2^26 - 19, 2^25 - 1, 2^26 - 1, 2^25 - 1, ..., 2^25 - 1)
// Pre-computed constants are easier to inline.

///|
let two_p_limb : FixedArray[UInt64] = [
  0x7FFFFDAUL, // 2 * (2^26 - 19) = 2^27 - 38
   0x3FFFFFEUL, // 2 * (2^25 - 1)
   0x7FFFFFEUL, // 2 * (2^26 - 1)
   0x3FFFFFEUL, 0x7FFFFFEUL, 0x3FFFFFEUL, 0x7FFFFFEUL, 0x3FFFFFEUL, 0x7FFFFFEUL,
  0x3FFFFFEUL,
]

///|
fn fe_sub(a : Fe, b : Fe) -> Fe {
  let r = FixedArray::make(10, 0UL)
  for i in 0..<10 {
    r[i] = a[i] + two_p_limb[i] - b[i]
  }
  r
}

// Multiplication: 10x10 schoolbook, with the "high half" folded back via
// 2^255 ≡ 19. This matches the structure used in ref10 / curve25519-donna
// 32-bit, but we keep each limb in a UInt64 to absorb the larger 51..52
// bit partial products without juggling 32-bit halves.
//
// Even-indexed limbs are 26 bits; odd ones are 25 bits. Cross products
// behave differently depending on parity:
//   - even * even contributes at full weight
//   - even * odd (or odd * even) contributes at full weight (one shift of 25 = 2^(i+j) shift in mixed radix)
//   - odd * odd contributes shifted by *2 because two 25-bit limbs in the
//     mixed radix combine as (2^25)^2 = 2^50 instead of 2^51, so we
//     effectively double the product to align with the 51-bit step.
//
// Hence the well-known "odd-odd × 2" doubling pattern in 10-limb
// implementations.

///|
fn fe_mul(f : Fe, g : Fe) -> Fe {
  // Pre-scale odd limbs by 19 / 2 as needed; here we just unroll.
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
  // Pre-multiply g[1,3,5,7,9] by 19 for the "wraparound" parts.
  let g1_19 = 19UL * g1
  let g2_19 = 19UL * g2
  let g3_19 = 19UL * g3
  let g4_19 = 19UL * g4
  let g5_19 = 19UL * g5
  let g6_19 = 19UL * g6
  let g7_19 = 19UL * g7
  let g8_19 = 19UL * g8
  let g9_19 = 19UL * g9
  // The "*2" factors for odd-odd products.
  let f1_2 = 2UL * f1
  let f3_2 = 2UL * f3
  let f5_2 = 2UL * f5
  let f7_2 = 2UL * f7
  let f9_2 = 2UL * f9
  // h_i = sum of f_j * g_k where the "logical" index j + k ≡ i (mod 10),
  // and we apply *2 when both j and k are odd, *19 when j + k >= 10
  // (i.e. the wraparound through 2^255 ≡ 19).
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

// Square: same shape as mul but with f == g. Exploits symmetry by
// merging the off-diagonal terms (×2). We keep a straightforward form
// that matches the structure of fe_mul.

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

// Multiply by a small (≤ 2^24) scalar; used for a24 = 121665.

///|
fn fe_mul_small(a : Fe, c : UInt64) -> Fe {
  let r = FixedArray::make(10, 0UL)
  for i in 0..<10 {
    r[i] = a[i] * c
  }
  fe_carry_full(r)
}

// Inversion via Fermat: a^(p-2). The 254-step addition chain below is
// the standard one (e.g. ref10 / curve25519-donna). It costs 11M + 252S
// roughly, but we just write it readably.

///|
fn fe_inv(z : Fe) -> Fe {
  let z2 = fe_sqr(z) // 2
  let z9 = fe_mul(fe_sqr(fe_sqr(z2)), z) // 2^3 then *z = z^9
  let z11 = fe_mul(z9, z2) // z^11
  let z2_5_0 = fe_mul(fe_sqr(z11), z9) // z^31 = z^(2^5 - 1)
  // z^(2^10 - 1)
  let mut t = fe_sqr(z2_5_0)
  for _ in 0..<4 {
    t = fe_sqr(t)
  }
  let z2_10_0 = fe_mul(t, z2_5_0)
  // z^(2^20 - 1)
  t = fe_sqr(z2_10_0)
  for _ in 0..<9 {
    t = fe_sqr(t)
  }
  let z2_20_0 = fe_mul(t, z2_10_0)
  // z^(2^40 - 1)
  t = fe_sqr(z2_20_0)
  for _ in 0..<19 {
    t = fe_sqr(t)
  }
  t = fe_mul(t, z2_20_0)
  // z^(2^50 - 1)
  for _ in 0..<10 {
    t = fe_sqr(t)
  }
  let z2_50_0 = fe_mul(t, z2_10_0)
  // z^(2^100 - 1)
  t = fe_sqr(z2_50_0)
  for _ in 0..<49 {
    t = fe_sqr(t)
  }
  let z2_100_0 = fe_mul(t, z2_50_0)
  // z^(2^200 - 1)
  t = fe_sqr(z2_100_0)
  for _ in 0..<99 {
    t = fe_sqr(t)
  }
  t = fe_mul(t, z2_100_0)
  // z^(2^250 - 1)
  for _ in 0..<50 {
    t = fe_sqr(t)
  }
  t = fe_mul(t, z2_50_0)
  // z^(2^255 - 21) = z^(p - 2)
  for _ in 0..<5 {
    t = fe_sqr(t)
  }
  fe_mul(t, z11)
}

// Constant-time conditional swap of two limb arrays. The `swap` bit is
// 0 or 1; on 1 the two arrays are exchanged element-wise via the
// usual mask trick.

///|
fn fe_cswap(a : Fe, b : Fe, swap : Int) -> Unit {
  let mask : UInt64 = 0UL - swap.to_uint64()
  for i in 0..<10 {
    let t = mask & (a[i] ^ b[i])
    a[i] = a[i] ^ t
    b[i] = b[i] ^ t
  }
}

// ─── Montgomery ladder ─────────────────────────────────────────────

///|
fn scalarmult_unchecked(
  scalar : FixedArray[Byte],
  u : FixedArray[Byte],
) -> FixedArray[Byte] {
  let s = clamp_scalar(scalar)
  // Strip the high bit of u per RFC 7748 §5.
  let u_copy = FixedArray::make(32, b'\x00')
  for i in 0..<32 {
    u_copy[i] = u[i]
  }
  let x1 = fe_from_bytes(u_copy)
  let x2 = fe_one()
  let z2 = fe_zero()
  let x3 = fe_copy(x1)
  let z3 = fe_one()
  let mut swap_bit = 0
  for t = 254; t >= 0; t = t - 1 {
    let k_t = (s[t / 8].to_int() >> (t % 8)) & 1
    swap_bit = swap_bit ^ k_t
    fe_cswap(x2, x3, swap_bit)
    fe_cswap(z2, z3, swap_bit)
    swap_bit = k_t
    let a = fe_add(x2, z2)
    let aa = fe_sqr(a)
    let b = fe_sub(x2, z2)
    let bb = fe_sqr(b)
    let e = fe_sub(aa, bb)
    let c = fe_add(x3, z3)
    let d = fe_sub(x3, z3)
    let da = fe_mul(d, a)
    let cb = fe_mul(c, b)
    let sum = fe_add(da, cb)
    let diff = fe_sub(da, cb)
    let new_x3 = fe_sqr(sum)
    let diff2 = fe_sqr(diff)
    let new_z3 = fe_mul(x1, diff2)
    let new_x2 = fe_mul(aa, bb)
    let a24_e = fe_mul_small(e, 121665UL)
    let inner = fe_add(aa, a24_e)
    let new_z2 = fe_mul(e, inner)
    for i in 0..<10 {
      x2[i] = new_x2[i]
      z2[i] = new_z2[i]
      x3[i] = new_x3[i]
      z3[i] = new_z3[i]
    }
  }
  fe_cswap(x2, x3, swap_bit)
  fe_cswap(z2, z3, swap_bit)
  let z_inv = fe_inv(z2)
  let result = fe_mul(x2, z_inv)
  fe_to_bytes(result)
}
