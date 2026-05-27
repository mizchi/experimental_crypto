// Whitebox tests for the 10-limb radix-2^26 field arithmetic. We
// validate the I/O round-trip and the canonical-reduction behavior by
// differential testing against the @bigint reference (which is what
// the rest of the p256 module still uses).

///|
fn bigint_to_be32(v : BigInt) -> FixedArray[Byte] {
  // Direct byte-extraction via shift; sidesteps any to_octets quirks
  // around the zero value.
  let out = FixedArray::make(32, b'\x00')
  let mut acc = v
  for i = 0; i < 32; i = i + 1 {
    let low = (acc & BigInt::from_int(0xFF)).to_int()
    out[31 - i] = low.to_byte()
    acc = acc >> 8
  }
  out
}

///|
fn be32_to_bigint(b : FixedArray[Byte]) -> BigInt {
  let mut acc = BigInt::from_int(0)
  for i = 0; i < 32; i = i + 1 {
    acc = (acc << 8) | BigInt::from_int(b[i].to_int())
  }
  acc
}

///|
fn assert_point_eq(
  got : Point,
  expected : Point,
  context : String,
) -> Unit raise {
  @debug.assert_eq(got.inf, expected.inf)
  if !expected.inf {
    @debug.assert_eq(got.x.to_string(), expected.x.to_string())
    @debug.assert_eq(got.y.to_string(), expected.y.to_string())
  } else if !got.inf {
    abort(context + ": expected infinity")
  }
}

///|
test "fe zero / one round-trip through bytes" {
  let zero = FixedArray::make(10, 0UL)
  let zero_be = fe_to_bytes(zero)
  for i = 0; i < 32; i = i + 1 {
    @debug.assert_eq(zero_be[i], b'\x00')
  }
  let one = FixedArray::make(10, 0UL)
  one[0] = 1UL
  let one_be = fe_to_bytes(one)
  for i = 0; i < 31; i = i + 1 {
    @debug.assert_eq(one_be[i], b'\x00')
  }
  @debug.assert_eq(one_be[31], b'\x01')
}

///|
test "fe_from_bytes / fe_to_bytes round-trip on generator coordinates" {
  // P-256 Gx and Gy from FIPS 186-4. These are already < p so the
  // round-trip must reproduce the exact input.
  let gx_be : FixedArray[Byte] = [
    b'\x6b', b'\x17', b'\xd1', b'\xf2', b'\xe1', b'\x2c', b'\x42', b'\x47', b'\xf8',
    b'\xbc', b'\xe6', b'\xe5', b'\x63', b'\xa4', b'\x40', b'\xf2', b'\x77', b'\x03',
    b'\x7d', b'\x81', b'\x2d', b'\xeb', b'\x33', b'\xa0', b'\xf4', b'\xa1', b'\x39',
    b'\x45', b'\xd8', b'\x98', b'\xc2', b'\x96',
  ]
  let gx_round = fe_to_bytes(fe_from_bytes(gx_be))
  for i = 0; i < 32; i = i + 1 {
    @debug.assert_eq(gx_round[i], gx_be[i])
  }
  let gy_be : FixedArray[Byte] = [
    b'\x4f', b'\xe3', b'\x42', b'\xe2', b'\xfe', b'\x1a', b'\x7f', b'\x9b', b'\x8e',
    b'\xe7', b'\xeb', b'\x4a', b'\x7c', b'\x0f', b'\x9e', b'\x16', b'\x2b', b'\xce',
    b'\x33', b'\x57', b'\x6b', b'\x31', b'\x5e', b'\xce', b'\xcb', b'\xb6', b'\x40',
    b'\x68', b'\x37', b'\xbf', b'\x51', b'\xf5',
  ]
  let gy_round = fe_to_bytes(fe_from_bytes(gy_be))
  for i = 0; i < 32; i = i + 1 {
    @debug.assert_eq(gy_round[i], gy_be[i])
  }
}

///|
test "fe round-trip vs @bigint for random values mod p" {
  let p = BigInt::from_string(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    radix=16,
  )
  // Fixed deterministic seeds; pick values that exercise different
  // bit patterns (low values, near-p values, mid-range).
  let seeds : Array[String] = [
    "0", "1", "2", "ffff", "100000000", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "fffffffe0000000000000000000000000000000000000000fffffffffffffffe", "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    // Values straddling p (mod-reduce in the test so the round-trip
    // matches; fe_to_bytes emits the canonical [0,p) representative).
     "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
  ]
  for s in seeds {
    let v_raw = BigInt::from_string(s, radix=16)
    let v = v_raw % p
    let be = bigint_to_be32(v)
    let h = fe_from_bytes(be)
    let round = fe_to_bytes(h)
    let v_back = be32_to_bigint(round)
    // BigInt equality via string normalisation. (BigInt::== seems to
    // reject when one operand is from to_octets on all-zero bytes.)
    @debug.assert_eq(v_back.to_string() == v.to_string(), true)
  }
}

///|
test "fe_to_bytes reduces values >= p down to the canonical representative" {
  let p = BigInt::from_string(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    radix=16,
  )
  // 2^256 - 1 is just above 2^256 - 2^224 + 2^192 + 2^96 - 1 = p, so
  // (2^256 - 1) mod p = 2^224 - 2^192 - 2^96.
  let max_be : FixedArray[Byte] = FixedArray::make(32, b'\xff')
  let h = fe_from_bytes(max_be)
  let canonical = fe_to_bytes(h)
  let value = be32_to_bigint(canonical)
  let two_256_minus_one = (BigInt::from_int(1) << 256) - BigInt::from_int(1)
  let expected = two_256_minus_one % p
  @debug.assert_eq(value.to_string() == expected.to_string(), true)
  @debug.assert_eq(value < p, true)
}

///|
test "p256_p_limbs reconstructs to the FIPS 186-4 prime" {
  // Pack the limb table back into a 256-bit BigInt and compare to p.
  let mut acc = BigInt::from_int(0)
  let base = BigInt::from_int(1) << 26
  let mut shift = BigInt::from_int(1)
  for i = 0; i < 10; i = i + 1 {
    acc = acc +
      BigInt::from_int64(p256_p_limbs[i].reinterpret_as_int64()) * shift
    shift = shift * base
  }
  let expected = BigInt::from_string(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    radix=16,
  )
  @debug.assert_eq(acc == expected, true)
}

///|
test "fe add/sub/neg match @bigint oracle" {
  let p = BigInt::from_string(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    radix=16,
  )
  let samples : Array[(String, String)] = [
    ("0", "0"),
    ("1", "2"),
    ("ffffffff", "100000001"),
    ("ffffffff00000001000000000000000000000000fffffffffffffffffffffffe", "1"),
    (
      "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ),
  ]
  for pair in samples {
    let (a_hex, b_hex) = pair
    let a_big = BigInt::from_string(a_hex, radix=16) % p
    let b_big = BigInt::from_string(b_hex, radix=16) % p
    let a = fe_from_bytes(bigint_to_be32(a_big))
    let b = fe_from_bytes(bigint_to_be32(b_big))
    let got_add = be32_to_bigint(fe_to_bytes(fe_add(a, b)))
    let got_sub = be32_to_bigint(fe_to_bytes(fe_sub(a, b)))
    let got_neg = be32_to_bigint(fe_to_bytes(fe_neg(a)))
    let expected_add = (a_big + b_big) % p
    let mut expected_sub = (a_big - b_big) % p
    if expected_sub < BigInt::from_int(0) {
      expected_sub = expected_sub + p
    }
    let expected_neg = if a_big == BigInt::from_int(0) {
      BigInt::from_int(0)
    } else {
      p - a_big
    }
    @debug.assert_eq(got_add.to_string(), expected_add.to_string())
    @debug.assert_eq(got_sub.to_string(), expected_sub.to_string())
    @debug.assert_eq(got_neg.to_string(), expected_neg.to_string())
  }
}

///|
test "fe mul/square match @bigint oracle" {
  let p = BigInt::from_string(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    radix=16,
  )
  let samples : Array[(String, String)] = [
    ("0", "0"),
    ("1", "2"),
    ("ffffffff", "100000001"),
    ("ffffffff00000001000000000000000000000000fffffffffffffffffffffffe", "2"),
    (
      "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ),
  ]
  for pair in samples {
    let (a_hex, b_hex) = pair
    let a_big = BigInt::from_string(a_hex, radix=16) % p
    let b_big = BigInt::from_string(b_hex, radix=16) % p
    let a = fe_from_bytes(bigint_to_be32(a_big))
    let b = fe_from_bytes(bigint_to_be32(b_big))
    let got_mul = be32_to_bigint(fe_to_bytes(fe_mul(a, b)))
    let got_square = be32_to_bigint(fe_to_bytes(fe_square(a)))
    let expected_mul = a_big * b_big % p
    let expected_square = a_big * a_big % p
    @debug.assert_eq(got_mul.to_string(), expected_mul.to_string())
    @debug.assert_eq(got_square.to_string(), expected_square.to_string())
  }
}

///|
test "fe inv matches @bigint oracle for non-zero values" {
  let p = BigInt::from_string(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    radix=16,
  )
  let samples : Array[String] = [
    "1", "2", "ffffffff", "100000001", "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
    "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
  ]
  for s in samples {
    let a_big = BigInt::from_string(s, radix=16) % p
    let a = fe_from_bytes(bigint_to_be32(a_big))
    let inv = fe_inv(a)
    let got = be32_to_bigint(fe_to_bytes(inv))
    let expected = a_big.pow(p - BigInt::from_int(2), modulus=p)
    let prod = be32_to_bigint(fe_to_bytes(fe_mul(a, inv)))
    @debug.assert_eq(got.to_string(), expected.to_string())
    @debug.assert_eq(prod.to_string(), "1")
  }
}

///|
test "fe conditional select chooses operands" {
  let a_big = BigInt::from_string("123456789abcdef", radix=16)
  let b_big = BigInt::from_string("fedcba987654321", radix=16)
  let a = fe_from_bytes(bigint_to_be32(a_big))
  let b = fe_from_bytes(bigint_to_be32(b_big))
  let pick_a = be32_to_bigint(fe_to_bytes(fe_select(a, b, 0UL)))
  let pick_b = be32_to_bigint(fe_to_bytes(fe_select(a, b, 1UL)))
  @debug.assert_eq(pick_a.to_string(), a_big.to_string())
  @debug.assert_eq(pick_b.to_string(), b_big.to_string())
}

///|
test "fe projective point conversion round-trips affine points" {
  let g = generator()
  assert_point_eq(fe_point_to_affine(fe_point_from_affine(g)), g, "G")
  let inf = point_infinity()
  assert_point_eq(fe_point_to_affine(fe_point_from_affine(inf)), inf, "O")
}

///|
test "fe projective point double/add match affine oracle" {
  let g = generator()
  let g2_affine = point_double(g)
  let g3_affine = point_add(g2_affine, g)
  let g_j = fe_point_from_affine(g)
  let g2_j = fe_point_double(g_j)
  assert_point_eq(fe_point_to_affine(g2_j), g2_affine, "2G")
  assert_point_eq(
    fe_point_to_affine(fe_point_add(g2_j, g_j)),
    g3_affine,
    "2G + G",
  )
  let inf = fe_point_from_affine(point_infinity())
  assert_point_eq(fe_point_to_affine(fe_point_add(inf, g_j)), g, "O + G")
  assert_point_eq(fe_point_to_affine(fe_point_add(g_j, inf)), g, "G + O")
}

///|
test "fe projective scalar multiplication matches affine oracle" {
  let g = generator()
  let scalars : Array[Int] = [0, 1, 2, 3, 5, 17, 255]
  for k_int in scalars {
    let k = BigInt::from_int(k_int)
    let got = fe_point_to_affine(
      fe_scalar_mult_variable(k, fe_point_from_affine(g)),
    )
    let expected = scalar_mult(k, g)
    assert_point_eq(got, expected, "k=" + k_int.to_string())
  }
}

///|
test "fe projective point conditional select chooses operands" {
  let g = fe_point_from_affine(generator())
  let inf = fe_point_from_affine(point_infinity())
  assert_point_eq(
    fe_point_to_affine(fe_point_select(inf, g, 0UL)),
    point_infinity(),
    "select O",
  )
  assert_point_eq(
    fe_point_to_affine(fe_point_select(inf, g, 1UL)),
    generator(),
    "select G",
  )
}
