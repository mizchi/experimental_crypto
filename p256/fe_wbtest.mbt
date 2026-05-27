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
test "fe_zero / fe_one round-trip through bytes" {
  let zero_be = fe_to_bytes(fe_zero())
  for i = 0; i < 32; i = i + 1 {
    @debug.assert_eq(zero_be[i], b'\x00')
  }
  let one_be = fe_to_bytes(fe_one())
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
    b'\x6b', b'\x17', b'\xd1', b'\xf2', b'\xe1', b'\x2c', b'\x42', b'\x47',
    b'\xf8', b'\xbc', b'\xe6', b'\xe5', b'\x63', b'\xa4', b'\x40', b'\xf2',
    b'\x77', b'\x03', b'\x7d', b'\x81', b'\x2d', b'\xeb', b'\x33', b'\xa0',
    b'\xf4', b'\xa1', b'\x39', b'\x45', b'\xd8', b'\x98', b'\xc2', b'\x96',
  ]
  let gx_round = fe_to_bytes(fe_from_bytes(gx_be))
  for i = 0; i < 32; i = i + 1 {
    @debug.assert_eq(gx_round[i], gx_be[i])
  }
  let gy_be : FixedArray[Byte] = [
    b'\x4f', b'\xe3', b'\x42', b'\xe2', b'\xfe', b'\x1a', b'\x7f', b'\x9b',
    b'\x8e', b'\xe7', b'\xeb', b'\x4a', b'\x7c', b'\x0f', b'\x9e', b'\x16',
    b'\x2b', b'\xce', b'\x33', b'\x57', b'\x6b', b'\x31', b'\x5e', b'\xce',
    b'\xcb', b'\xb6', b'\x40', b'\x68', b'\x37', b'\xbf', b'\x51', b'\xf5',
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
    "0", "1", "2", "ffff", "100000000",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "fffffffe0000000000000000000000000000000000000000fffffffffffffffe",
    "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    // Values straddling p (mod-reduce in the test so the round-trip
    // matches; fe_to_bytes emits the canonical [0,p) representative).
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
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
    acc = acc + BigInt::from_int64(p256_p_limbs[i].reinterpret_as_int64()) * shift
    shift = shift * base
  }
  let expected = BigInt::from_string(
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
    radix=16,
  )
  @debug.assert_eq(acc == expected, true)
}
