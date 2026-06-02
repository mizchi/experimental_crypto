// Field arithmetic over GF(p) for Curve448, p = 2^448 - 2^224 - 1 (the
// "Goldilocks" prime). 16-limb representation in radix-2^28: an element is a
// FixedArray[UInt64] of length 16, each limb nominally < 2^28. Unlike the
// Curve25519 radix-2^25.5 layout, all limbs share the same width, so there is no
// odd/odd doubling — and the reduction is exceptionally clean because
//   2^448 ≡ 2^224 + 1 (mod p)   and   224 = 8 * 28,
// i.e. a high limb at position k folds onto positions k-16 (the "+1") and k-8
// (the "+2^224"), both on exact limb boundaries.
//
// This field backs the x448 Montgomery ladder (ed448 keeps its own copy). It is
// written branch-free for the secret-scalar path: every operation here is
// straight-line over the limbs (no value-dependent skips), the final reduction
// in fe_to_bytes is mask-selected, and the only "conditional" — fe_cswap — is
// mask-based. See the constant-time note in x448.mbt.

///|
type Fe = FixedArray[UInt64]

///|
let mask28 : UInt64 = (1UL << 28) - 1UL

///|
// p in 28-bit limbs: (2^448-1) - 2^224 = all-ones limbs with limb 8 decremented.
let p_limb : FixedArray[UInt64] = [
  0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL,
  0xFFFFFFFUL, 0xFFFFFFEUL, // limb 8 = 2^28 - 2
   0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL,
  0xFFFFFFFUL,
]

///|
// 2p in 28-bit limbs (used by fe_sub so every limb stays non-negative).
let two_p_limb : FixedArray[UInt64] = [
  0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL,
  0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFCUL, // 2 * (2^28 - 2)
   0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL,
  0x1FFFFFFEUL,
]

///|
fn fe_zero() -> Fe {
  FixedArray::make(16, 0UL)
}

///|
fn fe_one() -> Fe {
  let f = FixedArray::make(16, 0UL)
  f[0] = 1UL
  f
}

///|
fn fe_copy(a : Fe) -> Fe {
  FixedArray::makei(16, fn(i) { a[i] })
}

///|
// Decode 56 little-endian bytes to a field element (value may be >= p; that is
// fine, it is just a representative — arithmetic reduces it).
fn fe_from_bytes(b : FixedArray[Byte]) -> Fe {
  fn ld4(off : Int) -> UInt64 {
    b[off].to_uint64() |
    (b[off + 1].to_uint64() << 8) |
    (b[off + 2].to_uint64() << 16) |
    (b[off + 3].to_uint64() << 24)
  }

  let h = FixedArray::make(16, 0UL)
  for i in 0..<16 {
    let bit = 28 * i
    let byte = bit >> 3
    let shift = bit & 7
    // A 32-bit window >> shift (shift is 0 or 4) always exposes 28 bits.
    h[i] = (ld4(byte) >> shift) & mask28
  }
  h
}

///|
// One carry sweep over the 16 limbs, folding the top overflow back via
// 2^448 ≡ 2^224 + 1 (so a carry out of limb 15 lands on limbs 0 and 8).
fn fe_carry_once(h : Fe) -> Unit {
  let mut c = 0UL
  for i in 0..<16 {
    let v = h[i] + c
    h[i] = v & mask28
    c = v >> 28
  }
  // c is the carry beyond 2^448; fold it onto limb 0 and limb 8.
  h[0] = h[0] + c
  h[8] = h[8] + c
}

///|
// Full carry: limbs become < 2^28 and the value drops below 2^448. Three sweeps
// are sufficient because each fold strictly shrinks the residual top carry.
fn fe_carry(h : Fe) -> Unit {
  fe_carry_once(h)
  fe_carry_once(h)
  fe_carry_once(h)
}

///|
fn fe_add(a : Fe, b : Fe) -> Fe {
  let r = FixedArray::makei(16, fn(i) { a[i] + b[i] })
  fe_carry(r)
  r
}

///|
fn fe_sub(a : Fe, b : Fe) -> Fe {
  // a - b = a + (2p - b); 2p ≡ 0 (mod p) and keeps every limb non-negative.
  let r = FixedArray::makei(16, fn(i) { a[i] + two_p_limb[i] - b[i] })
  fe_carry(r)
  r
}

///|
// Multiply with Goldilocks reduction. Inputs are assumed < 2^29 (the case after
// fe_add/fe_sub/fe_carry), so each column sum stays well within UInt64. The
// inner loop runs unconditionally (no `if a[i] != 0` skip) so the control flow
// does not depend on the secret limb values — see the constant-time note on the
// ladder.
fn fe_mul(a : Fe, b : Fe) -> Fe {
  let t = FixedArray::make(31, 0UL)
  for i in 0..<16 {
    let ai = a[i]
    for j in 0..<16 {
      t[i + j] = t[i + j] + ai * b[j]
    }
  }
  // Stage A: fold columns 16..30 onto k-16 (×1) and k-8 (×2^224).
  for k = 30; k >= 16; k = k - 1 {
    let v = t[k]
    t[k - 16] = t[k - 16] + v
    t[k - 8] = t[k - 8] + v
    t[k] = 0UL
  }
  // Stage B: the k-8 folds re-populated columns 16..22; fold those once more.
  for k = 22; k >= 16; k = k - 1 {
    let v = t[k]
    t[k - 16] = t[k - 16] + v
    t[k - 8] = t[k - 8] + v
    t[k] = 0UL
  }
  let r = FixedArray::makei(16, fn(i) { t[i] })
  fe_carry(r)
  r
}

///|
fn fe_sqr(f : Fe) -> Fe {
  // Squaring: off-diagonal products a[i]*a[j] (i<j) are counted twice, so we
  // compute them once and double — roughly half the multiplies of fe_mul.
  let t = FixedArray::make(31, 0UL)
  for i in 0..<16 {
    let ai = f[i]
    t[2 * i] = t[2 * i] + ai * ai
    let ai2 = ai << 1
    for j = i + 1; j < 16; j = j + 1 {
      t[i + j] = t[i + j] + ai2 * f[j]
    }
  }
  for k = 30; k >= 16; k = k - 1 {
    let v = t[k]
    t[k - 16] = t[k - 16] + v
    t[k - 8] = t[k - 8] + v
    t[k] = 0UL
  }
  for k = 22; k >= 16; k = k - 1 {
    let v = t[k]
    t[k - 16] = t[k - 16] + v
    t[k - 8] = t[k - 8] + v
    t[k] = 0UL
  }
  let r = FixedArray::makei(16, fn(i) { t[i] })
  fe_carry(r)
  r
}

///|
// Multiply by a small (< 2^32) constant, e.g. the Montgomery a24 = 39081.
fn fe_mul_small(a : Fe, c : UInt64) -> Fe {
  let r = FixedArray::makei(16, fn(i) { a[i] * c })
  fe_carry(r)
  r
}

///|
// p - 2 (big-endian hex), the Fermat inversion exponent.
let p_minus_2_hex : String = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffd"

///|
// Modular inverse via x^(p-2). Plain square-and-multiply over the 448-bit
// exponent — inversion happens once per scalar multiplication, so the simple
// (non-optimal-chain) version is negligible against the ladder.
fn fe_inv(z : Fe) -> Fe {
  fn hexval(ch : Char) -> Int {
    let n = ch.to_int()
    if n >= 0x30 && n <= 0x39 {
      n - 0x30
    } else {
      n - 0x61 + 10
    }
  }

  let mut acc = fe_one()
  for i in 0..<p_minus_2_hex.length() {
    let nib = hexval(p_minus_2_hex.get_char(i).unwrap())
    for bit = 3; bit >= 0; bit = bit - 1 {
      acc = fe_sqr(acc)
      if ((nib >> bit) & 1) == 1 {
        acc = fe_mul(acc, z)
      }
    }
  }
  acc
}

///|
// Constant-time conditional swap of a and b when swap == 1.
fn fe_cswap(a : Fe, b : Fe, swap : Int) -> Unit {
  let mask = 0UL - swap.to_uint64()
  for i in 0..<16 {
    let t = mask & (a[i] ^ b[i])
    a[i] = a[i] ^ t
    b[i] = b[i] ^ t
  }
}

///|
// Reduce to the canonical [0, p) representative and emit 56 little-endian bytes.
fn fe_to_bytes(a : Fe) -> FixedArray[Byte] {
  let h = fe_copy(a)
  fe_carry(h) // limbs < 2^28, value < 2^448
  // Conditionally subtract p once (value < 2^448 < 2p), branch-free: compute
  // h - p with a biased borrow, then mask-select between (h-p) and h.
  let t = FixedArray::make(16, 0UL)
  let mut borrow = 0UL
  for i in 0..<16 {
    // h[i] - p_limb[i] - borrow, biased by 2^28 to stay non-negative in UInt64.
    let d = h[i] + (1UL << 28) - p_limb[i] - borrow
    t[i] = d & mask28
    borrow = 1UL - (d >> 28)
  }
  // borrow == 0 -> h >= p, select t (= h - p); borrow == 1 -> h < p, select h.
  let mask_t = 0UL - (1UL - borrow)
  let c = FixedArray::makei(16, fn(i) {
    (mask_t & t[i]) | (mask_t.lnot() & h[i])
  })
  let out = FixedArray::make(56, b'\x00')
  let mut acc = 0UL
  let mut accbits = 0
  let mut oi = 0
  for i in 0..<16 {
    acc = acc | (c[i] << accbits)
    accbits = accbits + 28
    while accbits >= 8 {
      out[oi] = (acc & 0xFFUL).to_int().to_byte()
      oi = oi + 1
      acc = acc >> 8
      accbits = accbits - 8
    }
  }
  out
}
