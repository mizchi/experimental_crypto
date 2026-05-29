// Whitebox tests for the P-521 fixed-iteration complete-addition path.
// The affine implementation remains the public-verification oracle.

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
fn assert_bigint_eq(got : BigInt, expected : BigInt, context : String) -> Unit {
  if got.to_string() != expected.to_string() {
    abort(
      context +
      ": got " +
      got.to_string() +
      ", expected " +
      expected.to_string(),
    )
  }
}

///|
test "p521 Montgomery field add/sub/mul match BigInt oracle" {
  let p = p521_p()
  let cases : Array[BigInt] = [
    BigInt::from_int(0),
    BigInt::from_int(1),
    BigInt::from_int(2),
    BigInt::from_int(521),
    p521_gx(),
    p521_gy(),
    p - BigInt::from_int(2),
    p - BigInt::from_int(1),
  ]
  for a in cases {
    for b in cases {
      let fa = fe521_from_bigint(a)
      let fb = fe521_from_bigint(b)
      assert_bigint_eq(
        fe521_to_bigint(fe521_add(fa, fb)),
        mod_pos(a + b, p),
        "p521 fe add",
      )
      assert_bigint_eq(
        fe521_to_bigint(fe521_sub(fa, fb)),
        mod_pos(a - b, p),
        "p521 fe sub",
      )
      assert_bigint_eq(
        fe521_to_bigint(fe521_mul(fa, fb)),
        a * b % p,
        "p521 fe mul",
      )
    }
  }
}

///|
test "p521 complete projective addition matches affine oracle" {
  let g = generator()
  let scalars : Array[Int] = [0, 1, 2, 3, 5, 17]
  for a_int in scalars {
    for b_int in scalars {
      let a = scalar_mult(BigInt::from_int(a_int), g)
      let b = scalar_mult(BigInt::from_int(b_int), g)
      let got = fe521_point_to_affine(
        fe521_point_add_complete(
          fe521_point_from_affine(a),
          fe521_point_from_affine(b),
        ),
      )
      let expected = point_add(a, b)
      assert_point_eq(
        got,
        expected,
        "p521 complete add " +
        a_int.to_string() +
        "G + " +
        b_int.to_string() +
        "G",
      )
    }
  }
  let neg_g : Point = { x: g.x, y: p521_p() - g.y, inf: false }
  assert_point_eq(
    fe521_point_to_affine(
      fe521_point_add_complete(
        fe521_point_from_affine(g),
        fe521_point_from_affine(neg_g),
      ),
    ),
    point_infinity(),
    "p521 complete add G + (-G)",
  )
}

///|
test "p521 complete fixed scalar multiplication matches affine oracle" {
  let g = generator()
  let scalars : Array[String] = [
    "0", "1", "2", "3", "5", "11", "ff", "123456789abcdef",
  ]
  for s in scalars {
    let k = BigInt::from_string(s, radix=16)
    let got = fe521_scalar_mult_base_fixed(k)
    let expected = scalar_mult(k, g)
    assert_point_eq(got, expected, "p521 complete scalar k=0x" + s)
  }
}
