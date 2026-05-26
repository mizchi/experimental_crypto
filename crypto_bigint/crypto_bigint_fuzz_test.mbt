// Property-based fuzz tests for the fixed-size Uint and Montgomery wrappers.
// We exercise algebraic identities that must hold regardless of the random
// inputs:
//   (1) add_mod / mul_mod are commutative.
//   (2) sub_mod is the inverse of add_mod: (a + b) - b ≡ a (mod m).
//   (3) from_be_bytes / to_be_bytes round-trip exactly when the input width
//       matches limb_count * 8 bytes; same for the little-endian variant.
//   (4) pow_mod with exponent 0 returns 1 (mod m); exponent 1 returns a mod m.
//   (5) inv_mod composes with mul_mod to yield 1 (mod m) whenever the
//       inversion succeeds.
//   (6) Montgomery::to_mont / from_mont round-trips for already-reduced inputs.
//
// All randomness flows through helpers that coerce arbitrary bytes into the
// canonical representation:
//   - `bytes_to_uint(bytes, limb_count)` packs up to `limb_count * 8` LSBs of
//     `bytes` into a Uint.
//   - `make_odd_modulus(...)` builds a Uint that is guaranteed to be odd and
//     greater than 1 so Montgomery construction is well defined and inv_mod
//     can succeed for arbitrary coprime `a`.

///|
const LIMB_COUNT : Int = 2

///|
fn ensure_bytes(b : Bytes, target : Int) -> Bytes {
  if b.length() == target {
    b
  } else if b.length() == 0 {
    Bytes::makei(target, fn(_) { b'\x00' })
  } else if b.length() > target {
    Bytes::makei(target, fn(i) { b[i] })
  } else {
    let n = b.length()
    Bytes::makei(target, fn(i) { b[i % n] })
  }
}

///|
fn bytes_to_uint(b : Bytes, limb_count : Int) -> @crypto_bigint.Uint {
  let target = limb_count * 8
  let padded = ensure_bytes(b, target)
  @crypto_bigint.Uint::from_be_bytes(padded, limb_count) catch {
    _ => abort("unreachable: padded.length() == limb_count * 8")
  }
}

///|
/// Build an odd modulus > 1 from arbitrary bytes. We force the LSB to 1 so
/// the result is odd, and ensure at least one upper bit so the value is > 1.
fn make_odd_modulus(b : Bytes, limb_count : Int) -> @crypto_bigint.Uint {
  let target = limb_count * 8
  let padded = ensure_bytes(b, target)
  let buf = FixedArray::make(target, b'\x00')
  for i in 0..<target {
    buf[i] = padded[i]
  }
  // Force the most significant byte to have its high bit set so the modulus
  // is comfortably > 1 regardless of the random draw.
  buf[0] = (buf[0].to_int() | 0x80).to_byte()
  // Force the least significant byte to be odd.
  buf[target - 1] = (buf[target - 1].to_int() | 0x01).to_byte()
  @crypto_bigint.Uint::from_be_bytes(Bytes::from_array(buf), limb_count) catch {
    _ => abort("unreachable")
  }
}

///|
/// Reduce `x` modulo `m` by computing (x + 0) mod m. Lets us start from a
/// canonical representative for subsequent identity checks.
fn reduce(
  x : @crypto_bigint.Uint,
  m : @crypto_bigint.Uint,
) -> @crypto_bigint.Uint {
  let zero = @crypto_bigint.Uint::zero(m.limbs.length())
  x.add_mod(zero, m)
}

///|
test "fuzz crypto_bigint: add_mod is commutative" {
  for triple in (@quickcheck.samples(30) : Array[(Bytes, Bytes, Bytes)]) {
    let (ba, bb, bm) = triple
    let m = make_odd_modulus(bm, LIMB_COUNT)
    let a = bytes_to_uint(ba, LIMB_COUNT)
    let b = bytes_to_uint(bb, LIMB_COUNT)
    let ab = a.add_mod(b, m)
    let ba2 = b.add_mod(a, m)
    assert_true(@crypto_bigint.Uint::ct_eq(ab, ba2))
  }
}

///|
test "fuzz crypto_bigint: mul_mod is commutative" {
  for triple in (@quickcheck.samples(30) : Array[(Bytes, Bytes, Bytes)]) {
    let (ba, bb, bm) = triple
    let m = make_odd_modulus(bm, LIMB_COUNT)
    let a = bytes_to_uint(ba, LIMB_COUNT)
    let b = bytes_to_uint(bb, LIMB_COUNT)
    let ab = a.mul_mod(b, m)
    let ba2 = b.mul_mod(a, m)
    assert_true(@crypto_bigint.Uint::ct_eq(ab, ba2))
  }
}

///|
test "fuzz crypto_bigint: (a + b) - b == a (mod m)" {
  for triple in (@quickcheck.samples(30) : Array[(Bytes, Bytes, Bytes)]) {
    let (ba, bb, bm) = triple
    let m = make_odd_modulus(bm, LIMB_COUNT)
    let a = reduce(bytes_to_uint(ba, LIMB_COUNT), m)
    let b = reduce(bytes_to_uint(bb, LIMB_COUNT), m)
    let sum = a.add_mod(b, m)
    let back = sum.sub_mod(b, m)
    assert_true(@crypto_bigint.Uint::ct_eq(back, a))
  }
}

///|
test "fuzz crypto_bigint: from_be_bytes / to_be_bytes round-trip" {
  for raw in (@quickcheck.samples(50) : Array[Bytes]) {
    let target = LIMB_COUNT * 8
    let b = ensure_bytes(raw, target)
    let u = @crypto_bigint.Uint::from_be_bytes(b, LIMB_COUNT) catch {
      _ => abort("unreachable")
    }
    let out = u.to_be_bytes()
    @debug.assert_eq(out, b)
  }
}

///|
test "fuzz crypto_bigint: from_le_bytes / to_le_bytes round-trip" {
  for raw in (@quickcheck.samples(50) : Array[Bytes]) {
    let target = LIMB_COUNT * 8
    let b = ensure_bytes(raw, target)
    let u = @crypto_bigint.Uint::from_le_bytes(b, LIMB_COUNT) catch {
      _ => abort("unreachable")
    }
    let out = u.to_le_bytes()
    @debug.assert_eq(out, b)
  }
}

///|
test "fuzz crypto_bigint: pow_mod(a, 0, m) == 1 mod m" {
  for pair in (@quickcheck.samples(20) : Array[(Bytes, Bytes)]) {
    let (ba, bm) = pair
    let m = make_odd_modulus(bm, LIMB_COUNT)
    let a = bytes_to_uint(ba, LIMB_COUNT)
    let r = a.pow_mod(@crypto_bigint.Uint::zero(LIMB_COUNT), m)
    assert_true(
      @crypto_bigint.Uint::ct_eq(r, @crypto_bigint.Uint::one(LIMB_COUNT)),
    )
  }
}

///|
test "fuzz crypto_bigint: pow_mod(a, 1, m) == a mod m" {
  for pair in (@quickcheck.samples(20) : Array[(Bytes, Bytes)]) {
    let (ba, bm) = pair
    let m = make_odd_modulus(bm, LIMB_COUNT)
    let a = bytes_to_uint(ba, LIMB_COUNT)
    let r = a.pow_mod(@crypto_bigint.Uint::one(LIMB_COUNT), m)
    let a_red = reduce(a, m)
    assert_true(@crypto_bigint.Uint::ct_eq(r, a_red))
  }
}

///|
test "fuzz crypto_bigint: inv_mod(a, m) * a == 1 mod m when invertible" {
  for pair in (@quickcheck.samples(30) : Array[(Bytes, Bytes)]) {
    let (ba, bm) = pair
    let m = make_odd_modulus(bm, LIMB_COUNT)
    let a = reduce(bytes_to_uint(ba, LIMB_COUNT), m)
    // Skip a == 0 — uninvertible by definition.
    if @crypto_bigint.Uint::ct_eq(a, @crypto_bigint.Uint::zero(LIMB_COUNT)) {
      continue
    }
    try a.inv_mod(m) catch {
      _ =>
        // gcd(a, m) != 1: legitimate failure, nothing to check.
        ()
    } noraise {
      inv => {
        let prod = a.mul_mod(inv, m)
        assert_true(
          @crypto_bigint.Uint::ct_eq(prod, @crypto_bigint.Uint::one(LIMB_COUNT)),
        )
      }
    }
  }
}

///|
test "fuzz crypto_bigint: Montgomery to_mont / from_mont round-trip" {
  for pair in (@quickcheck.samples(30) : Array[(Bytes, Bytes)]) {
    let (ba, bm) = pair
    let m = make_odd_modulus(bm, LIMB_COUNT)
    let a = reduce(bytes_to_uint(ba, LIMB_COUNT), m)
    let mont = @crypto_bigint.Montgomery::new(m)
    let r = mont.from_mont(mont.to_mont(a))
    assert_true(@crypto_bigint.Uint::ct_eq(r, a))
  }
}
