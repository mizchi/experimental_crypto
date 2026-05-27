// P-256 field arithmetic in 10-limb radix-2^26 representation.
//
// A field element (Fe) is a FixedArray[UInt64] of length 10. Each limb
// holds a 26-bit chunk:
//   value = sum_{i=0..9} limb[i] * 2^(26*i)
//
// Total bit width is 10 * 26 = 260 bits, four bits more than the 256-bit
// prime. This headroom is what makes carry propagation cheap during
// schoolbook multiplication, where intermediate limbs can hold partial
// products well into the 50s before they need to be reduced.
//
// Wire format is 32 big-endian bytes (FIPS 186-5 / SEC1). The limb form
// is internally little-endian: limb 0 holds the least-significant 26
// bits. fe_from_bytes/fe_to_bytes do the BE ⇄ LE flip.
//
// Scope of this file (Milestone 1): the type, constants, I/O, copy,
// add/sub/neg, and a fe_carry_full that handles inputs whose limbs are already
// small (post-fe_from_bytes, or pre-multiplication). The wider-input fe_carry
// that takes ~2^62 limbs from fe_mul / fe_sqr lives in a follow-up commit so
// this file stays reviewable.

///|
type Fe = FixedArray[UInt64]

///|
// P-256 prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1, broken into 10
// limbs of radix 2^26. Derived once on the bit positions:
//   - bits 0..95   : 1 → limbs 0..2 fully set, limb 3 low 18 bits set
//   - bits 96..191 : 0
//   - bit 192      : 1 → limb 7 bit 10 set (192 - 7*26 = 10)
//   - bits 193..223: 0
//   - bits 224..255: 1 → limb 8 bits 16..25, limb 9 bits 0..21
let p256_p_limbs : FixedArray[UInt64] = [
  0x3FFFFFFUL, // limb 0: 2^26 - 1
   0x3FFFFFFUL, // limb 1
   0x3FFFFFFUL, // limb 2
   0x003FFFFUL, // limb 3: low 18 bits set (2^18 - 1)
   0x0UL, // limb 4
   0x0UL, // limb 5
   0x0UL, // limb 6
   0x0000400UL, // limb 7: bit 10 (= bit 192 of value)
   0x3FF0000UL, // limb 8: bits 16..25 (= bits 224..233 of value)
   0x03FFFFFUL, // limb 9: bits 0..21 (= bits 234..255 of value)
]

///|
fn fe_copy(a : Fe) -> Fe {
  let r = FixedArray::make(10, 0UL)
  for i in 0..<10 {
    r[i] = a[i]
  }
  r
}

///|
fn fe_u64_lt_01(a : UInt64, b : UInt64) -> UInt64 {
  let diff = a - b
  (((a.lnot() & b) | ((a ^ b).lnot() & diff)) >> 63) & 1UL
}

///|
#warnings("-unused_value")
fn fe_add(a : Fe, b : Fe) -> Fe {
  let h = FixedArray::make(10, 0UL)
  for i = 0; i < 10; i = i + 1 {
    h[i] = a[i] + b[i]
  }
  fe_carry_full(h)
}

///|
fn fe_sub(a : Fe, b : Fe) -> Fe {
  let mask26 : UInt64 = (1UL << 26) - 1UL
  // Compute a + p - b so the intermediate is non-negative for canonical
  // field elements. This handles a < b without introducing a sign branch.
  let sum = FixedArray::make(10, 0UL)
  let mut carry = 0UL
  for i = 0; i < 10; i = i + 1 {
    let v = a[i] + p256_p_limbs[i] + carry
    sum[i] = v & mask26
    carry = v >> 26
  }
  if carry != 0UL {
    abort("fe_sub: overflow above 2^260 not yet handled")
  }
  let h = FixedArray::make(10, 0UL)
  let mut borrow = 0UL
  for i = 0; i < 10; i = i + 1 {
    let subtrahend = b[i] + borrow
    let next_borrow = fe_u64_lt_01(sum[i], subtrahend)
    h[i] = (sum[i] - subtrahend) & mask26
    borrow = next_borrow
  }
  if borrow != 0UL {
    abort("fe_sub: underflow below zero")
  }
  fe_carry_full(h)
}

///|
#warnings("-unused_value")
fn fe_neg(a : Fe) -> Fe {
  fe_sub(FixedArray::make(10, 0UL), a)
}

///|
fn fe_p_uint() -> @crypto_bigint.Uint {
  let p_be : Bytes = b"\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
  @crypto_bigint.Uint::from_be_bytes(p_be, 4) catch {
    _ => abort("P-256 modulus must fit 32 bytes")
  }
}

///|
fn fe_to_uint(a : Fe) -> @crypto_bigint.Uint {
  @crypto_bigint.Uint::from_be_bytes(Bytes::from_array(fe_to_bytes(a)), 4) catch {
    _ => abort("P-256 field element must fit 32 bytes")
  }
}

///|
fn fe_from_uint(a : @crypto_bigint.Uint) -> Fe {
  let b = a.to_be_bytes()
  fe_from_bytes(FixedArray::makei(32, fn(i) { b[i] }))
}

///|
#warnings("-unused_value")
fn fe_mul(a : Fe, b : Fe) -> Fe {
  // Interim fixed-width implementation. This keeps field multiplication off
  // `@bigint` while the dedicated P-256 pseudo-Mersenne reducer is built.
  fe_from_uint(fe_to_uint(a).mul_mod(fe_to_uint(b), fe_p_uint()))
}

///|
#warnings("-unused_value")
fn fe_square(a : Fe) -> Fe {
  fe_mul(a, a)
}

///|
#warnings("-unused_value")
fn fe_inv(a : Fe) -> Fe {
  let inv = fe_to_uint(a).inv_mod(fe_p_uint()) catch {
    _ => abort("P-256 field inverse does not exist")
  }
  fe_from_uint(inv)
}

///|
// Decode 32 big-endian bytes into a Fe. The result's limbs are each <
// 2^26 (well-formed even before carry), but the value may be in
// [0, 2^256), i.e. potentially ≥ p. Callers that need a canonical
// representative must follow with fe_carry_full.
fn fe_from_bytes(b : FixedArray[Byte]) -> Fe {
  // Flip BE → LE so the rest of the decoder runs on the natural
  // little-endian limb stream.
  let le = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    le[i] = b[31 - i]
  }
  fn ld4(off : Int) -> UInt64 {
    le[off].to_uint64() |
    (le[off + 1].to_uint64() << 8) |
    (le[off + 2].to_uint64() << 16) |
    (le[off + 3].to_uint64() << 24)
  }

  let mask26 : UInt64 = (1UL << 26) - 1UL
  let h = FixedArray::make(10, 0UL)
  // Limb i covers bits [26i, 26i + 26) of the LE value. Starting bit
  // positions:  0, 26, 52, 78, 104, 130, 156, 182, 208, 234.
  h[0] = ld4(0) & mask26 // s=0,   byte 0,  bit 0
  h[1] = (ld4(3) >> 2) & mask26 // s=26,  byte 3,  bit 2
  h[2] = (ld4(6) >> 4) & mask26 // s=52,  byte 6,  bit 4
  h[3] = (ld4(9) >> 6) & mask26 // s=78,  byte 9,  bit 6
  h[4] = ld4(13) & mask26 // s=104, byte 13, bit 0
  h[5] = (ld4(16) >> 2) & mask26 // s=130, byte 16, bit 2
  h[6] = (ld4(19) >> 4) & mask26 // s=156, byte 19, bit 4
  h[7] = (ld4(22) >> 6) & mask26 // s=182, byte 22, bit 6
  h[8] = ld4(26) & mask26 // s=208, byte 26, bit 0
  // s=234 → byte 29, bit 2. We only need 22 of the high 26 bits
  // (bits 234..255). Bits 256..259 of the limb space are guaranteed
  // zero because the input is a 256-bit integer.
  let b29 = le[29].to_uint64()
  let b30 = le[30].to_uint64()
  let b31 = le[31].to_uint64()
  let win = b29 | (b30 << 8) | (b31 << 16)
  h[9] = (win >> 2) & mask26
  h
}

///|
// Encode a Fe as 32 big-endian bytes. Applies a full canonical
// reduction first so the output is the unique representative of the
// value mod p.
fn fe_to_bytes(a : Fe) -> FixedArray[Byte] {
  let h = fe_carry_full(a)
  // Pack the 10 26-bit limbs into a 32-byte little-endian buffer by
  // OR-merging each limb at its bit position. Adjacent limbs share at
  // most one destination byte, so OR (not overwrite) is required.
  let le = FixedArray::make(32, b'\x00')
  let starts : FixedArray[Int] = [0, 26, 52, 78, 104, 130, 156, 182, 208, 234]
  for i = 0; i < 10; i = i + 1 {
    let s = starts[i]
    let byte_off = s / 8
    let bit_off = s % 8
    let v = h[i] << bit_off
    // A 26-bit limb shifted by ≤7 spans at most 5 bytes. The top byte
    // (k=4) only carries data when bit_off > 0.
    for k = 0; k < 5; k = k + 1 {
      let dst = byte_off + k
      if dst < 32 {
        let byte_v = (v >> (8 * k)) & 0xFFUL
        le[dst] = (le[dst].to_uint64() | byte_v).to_byte()
      }
    }
  }
  // Flip back to big-endian for the wire.
  let be = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    be[i] = le[31 - i]
  }
  be
}

///|
// Full canonical reduction for inputs whose limbs are already in the
// 26-bit range (or close to it — anything < 2^32 is fine here).
//
// This is the Milestone-1 variant. After fe_mul we will get limbs up
// to ~2^62, which require a different carry/reduce path; that path
// will replace this function in a later commit.
fn fe_carry_full(h : Fe) -> Fe {
  let mask26 : UInt64 = (1UL << 26) - 1UL
  let r = fe_copy(h)
  // Single carry pass — each input limb is small, so one sweep
  // settles them all into [0, 2^26).
  let mut c : UInt64 = 0UL
  for i = 0; i < 10; i = i + 1 {
    r[i] = r[i] + c
    c = r[i] >> 26
    r[i] = r[i] & mask26
  }
  // c carries bits past position 260. With Milestone-1 inputs (≤ 2^32
  // per limb) this overflow cannot happen — assert to catch misuse.
  if c != 0UL {
    abort("fe_carry_full: overflow above 2^260 not yet handled")
  }
  // Conditional subtract of p. Compute q = r - p with branch-free
  // limb-wise borrow propagation; if the final borrow is 1 the
  // original r was already < p, so we keep r. Otherwise we use q.
  // Sign of (r[i] - p[i] - borrow) decides the per-limb borrow-out
  // through bit 63 of the signed difference.
  let q = FixedArray::make(10, 0UL)
  let mut borrow : Int64 = 0L
  for i = 0; i < 10; i = i + 1 {
    let d = r[i].reinterpret_as_int64() -
      p256_p_limbs[i].reinterpret_as_int64() -
      borrow
    let b_out : Int64 = (d >> 63) & 1L
    q[i] = (d + (b_out << 26)).reinterpret_as_uint64()
    borrow = b_out
  }
  // mask = all-1s when borrow == 0 (use q), 0 when borrow == 1 (keep r).
  let mask : UInt64 = (borrow - 1L).reinterpret_as_uint64()
  let out = FixedArray::make(10, 0UL)
  for i = 0; i < 10; i = i + 1 {
    out[i] = (q[i] & mask) | (r[i] & mask.lnot())
  }
  out
}
