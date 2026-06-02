// Field arithmetic over GF(p) for edwards448 / Curve448, p = 2^448-2^224-1 (the
// "Goldilocks" prime). 16-limb radix-2^28 (each limb < 2^28). Reduction folds a
// high limb at position k onto k-16 (the "+1") and k-8 (the "+2^224") on exact
// limb boundaries since 2^448 ≡ 2^224+1 and 224 = 8*28.
//
// Self-contained copy of the x448 field plus the extra operations Ed448 needs
// (negation, square root, equality, hex/small constructors). Clear, not
// constant-time — Ed448 here is verification only.

///|
type Fe = FixedArray[UInt64]

///|
let mask28 : UInt64 = (1UL << 28) - 1UL

///|
let p_limb : FixedArray[UInt64] = [
  0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL,
  0xFFFFFFFUL, 0xFFFFFFEUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL, 0xFFFFFFFUL,
  0xFFFFFFFUL, 0xFFFFFFFUL,
]

///|
let two_p_limb : FixedArray[UInt64] = [
  0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL,
  0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFCUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL,
  0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL, 0x1FFFFFFEUL,
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
fn fe_from_small(v : UInt64) -> Fe {
  let f = FixedArray::make(16, 0UL)
  f[0] = v
  f
}

///|
fn fe_copy(a : Fe) -> Fe {
  FixedArray::makei(16, fn(i) { a[i] })
}

///|
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
    h[i] = (ld4(byte) >> shift) & mask28
  }
  h
}

///|
// Parse a 112-char big-endian hex constant into a field element.
fn fe_from_hex_be(hex : String) -> Fe {
  fn hexval(ch : Char) -> Int {
    let n = ch.to_int()
    if n >= 0x30 && n <= 0x39 {
      n - 0x30
    } else {
      n - 0x61 + 10
    }
  }

  // 112 hex chars = 56 bytes big-endian; reverse to little-endian for decode.
  let le = FixedArray::make(56, b'\x00')
  for i in 0..<56 {
    let hi = hexval(hex.get_char(i * 2).unwrap())
    let lo = hexval(hex.get_char(i * 2 + 1).unwrap())
    le[55 - i] = ((hi << 4) | lo).to_byte()
  }
  fe_from_bytes(le)
}

///|
fn fe_carry_once(h : Fe) -> Unit {
  let mut c = 0UL
  for i in 0..<16 {
    let v = h[i] + c
    h[i] = v & mask28
    c = v >> 28
  }
  h[0] = h[0] + c
  h[8] = h[8] + c
}

///|
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
  let r = FixedArray::makei(16, fn(i) { a[i] + two_p_limb[i] - b[i] })
  fe_carry(r)
  r
}

///|
fn fe_neg(a : Fe) -> Fe {
  fe_sub(fe_zero(), a)
}

///|
fn fe_mul(a : Fe, b : Fe) -> Fe {
  let t = FixedArray::make(31, 0UL)
  for i in 0..<16 {
    let ai = a[i]
    if ai != 0UL {
      for j in 0..<16 {
        t[i + j] = t[i + j] + ai * b[j]
      }
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
fn fe_sqr(f : Fe) -> Fe {
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
// Square-and-multiply over a big-endian hex exponent.
fn fe_pow_hex(z : Fe, exp_hex : String) -> Fe {
  fn hexval(ch : Char) -> Int {
    let n = ch.to_int()
    if n >= 0x30 && n <= 0x39 {
      n - 0x30
    } else {
      n - 0x61 + 10
    }
  }

  let mut acc = fe_one()
  for i in 0..<exp_hex.length() {
    let nib = hexval(exp_hex.get_char(i).unwrap())
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
let p_minus_2_hex : String = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffd"

///|
fn fe_inv(z : Fe) -> Fe {
  fe_pow_hex(z, p_minus_2_hex)
}

///|
// (p+1)/4 = 2^446 - 2^222; for p ≡ 3 (mod 4), sqrt(z) = z^((p+1)/4).
let sqrt_exp_hex : String = "3fffffffffffffffffffffffffffffffffffffffffffffffffffffffc0000000000000000000000000000000000000000000000000000000"

///|
fn fe_sqrt(z : Fe) -> Fe {
  fe_pow_hex(z, sqrt_exp_hex)
}

///|
fn fe_equal(a : Fe, b : Fe) -> Bool {
  let ab = fe_to_bytes(a)
  let bb = fe_to_bytes(b)
  let mut diff = 0
  for i in 0..<56 {
    diff = diff | (ab[i].to_int() ^ bb[i].to_int())
  }
  diff == 0
}

///|
fn fe_is_zero(a : Fe) -> Bool {
  fe_equal(a, fe_zero())
}

///|
// Low bit of the canonical representative (the Ed448 x-coordinate sign).
fn fe_parity(a : Fe) -> Int {
  fe_to_bytes(a)[0].to_int() & 1
}

///|
fn fe_to_bytes(a : Fe) -> FixedArray[Byte] {
  let h = fe_copy(a)
  fe_carry(h)
  let t = FixedArray::make(16, 0UL)
  let mut borrow = 0UL
  for i in 0..<16 {
    let sub = p_limb[i] + borrow
    if h[i] >= sub {
      t[i] = h[i] - sub
      borrow = 0UL
    } else {
      t[i] = h[i] + (1UL << 28) - sub
      borrow = 1UL
    }
  }
  let c = if borrow == 0UL { t } else { h }
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
