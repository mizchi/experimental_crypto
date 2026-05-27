// Whitebox tests for the P-256 Montgomery-domain complete-addition sign path.
// The existing affine implementation remains the public-verification oracle.

///|
fn assert_mont_bigint_eq(
  got : BigInt,
  expected : BigInt,
  context : String,
) -> Unit {
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
fn assert_mont_point_eq(
  got : Point,
  expected : Point,
  context : String,
) -> Unit {
  if got.inf != expected.inf {
    abort(context + ": infinity flag mismatch")
  }
  if !expected.inf {
    if got.x.to_string() != expected.x.to_string() {
      abort(context + ": x mismatch")
    }
    if got.y.to_string() != expected.y.to_string() {
      abort(context + ": y mismatch")
    }
  } else if !got.inf {
    abort(context + ": expected infinity")
  }
}

///|
test "p256 Montgomery field add/sub/mul match BigInt oracle" {
  let p = p256_p()
  let cases : Array[BigInt] = [
    BigInt::from_int(0),
    BigInt::from_int(1),
    BigInt::from_int(2),
    BigInt::from_int(256),
    p256_gx(),
    p256_gy(),
    p - BigInt::from_int(2),
    p - BigInt::from_int(1),
  ]
  for a in cases {
    for b in cases {
      let fa = fe_mont_from_bigint(a)
      let fb = fe_mont_from_bigint(b)
      assert_mont_bigint_eq(
        fe_mont_to_bigint(fe_mont_add(fa, fb)),
        mod_pos(a + b, p),
        "p256 mont fe add",
      )
      assert_mont_bigint_eq(
        fe_mont_to_bigint(fe_mont_sub(fa, fb)),
        mod_pos(a - b, p),
        "p256 mont fe sub",
      )
      assert_mont_bigint_eq(
        fe_mont_to_bigint(fe_mont_mul(fa, fb)),
        a * b % p,
        "p256 mont fe mul",
      )
    }
  }
}

///|
test "p256 Montgomery complete projective addition matches affine oracle" {
  let g = generator()
  let scalars : Array[Int] = [0, 1, 2, 3, 5, 17, 255]
  for a_int in scalars {
    for b_int in scalars {
      let a = scalar_mult(BigInt::from_int(a_int), g)
      let b = scalar_mult(BigInt::from_int(b_int), g)
      let got = fe_mont_point_to_affine(
        fe_mont_point_add_complete(
          fe_mont_point_from_affine(a),
          fe_mont_point_from_affine(b),
        ),
      )
      let expected = point_add(a, b)
      assert_mont_point_eq(
        got,
        expected,
        "p256 mont complete add " +
        a_int.to_string() +
        "G + " +
        b_int.to_string() +
        "G",
      )
    }
  }
  let neg_g : Point = { x: g.x, y: p256_p() - g.y, inf: false }
  assert_mont_point_eq(
    fe_mont_point_to_affine(
      fe_mont_point_add_complete(
        fe_mont_point_from_affine(g),
        fe_mont_point_from_affine(neg_g),
      ),
    ),
    point_infinity(),
    "p256 mont complete add G + (-G)",
  )
}

///|
test "p256 Montgomery complete fixed scalar multiplication matches affine oracle" {
  let g = generator()
  let scalars : Array[String] = [
    "0", "1", "2", "3", "5", "ff", "0100000000000000000000000000000000000000000000000000000000000000",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
  ]
  for s in scalars {
    let k = BigInt::from_string(s, radix=16)
    let got = fe_mont_scalar_mult_base_fixed(k)
    let expected = scalar_mult(k, g)
    assert_mont_point_eq(got, expected, "p256 mont complete scalar k=0x" + s)
  }
}
