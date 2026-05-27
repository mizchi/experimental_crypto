// Whitebox tests for the secp256k1 fixed-iteration complete-addition path.
// The affine implementation remains the public-verification oracle.

///|
fn assert_point_eq(got : Point, expected : Point, context : String) -> Unit {
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
test "secp256k1 Montgomery field add/sub/mul match BigInt oracle" {
  let p = k1_p()
  let cases : Array[BigInt] = [
    BigInt::from_int(0),
    BigInt::from_int(1),
    BigInt::from_int(2),
    BigInt::from_int(977),
    k1_gx(),
    k1_gy(),
    p - BigInt::from_int(2),
    p - BigInt::from_int(1),
  ]
  for a in cases {
    for b in cases {
      let fa = fe_k1_from_bigint(a)
      let fb = fe_k1_from_bigint(b)
      assert_bigint_eq(
        fe_k1_to_bigint(fe_k1_add(fa, fb)),
        mod_pos(a + b, p),
        "k1 fe add",
      )
      assert_bigint_eq(
        fe_k1_to_bigint(fe_k1_sub(fa, fb)),
        mod_pos(a - b, p),
        "k1 fe sub",
      )
      assert_bigint_eq(
        fe_k1_to_bigint(fe_k1_mul(fa, fb)),
        a * b % p,
        "k1 fe mul",
      )
    }
  }
}

///|
test "secp256k1 complete projective addition matches affine oracle" {
  let g = generator()
  let scalars : Array[Int] = [0, 1, 2, 3, 5, 17, 255]
  for a_int in scalars {
    for b_int in scalars {
      let a = scalar_mult(BigInt::from_int(a_int), g)
      let b = scalar_mult(BigInt::from_int(b_int), g)
      let got = fe_k1_point_to_affine(
        fe_k1_point_add_complete(
          fe_k1_point_from_affine(a),
          fe_k1_point_from_affine(b),
        ),
      )
      let expected = point_add(a, b)
      assert_point_eq(
        got,
        expected,
        "k1 complete add " +
        a_int.to_string() +
        "G + " +
        b_int.to_string() +
        "G",
      )
    }
  }
  let neg_g : Point = { x: g.x, y: k1_p() - g.y, inf: false }
  assert_point_eq(
    fe_k1_point_to_affine(
      fe_k1_point_add_complete(
        fe_k1_point_from_affine(g),
        fe_k1_point_from_affine(neg_g),
      ),
    ),
    point_infinity(),
    "k1 complete add G + (-G)",
  )
}

///|
test "secp256k1 complete fixed scalar multiplication matches affine oracle" {
  let g = generator()
  let scalars : Array[String] = [
    "0", "1", "2", "3", "5", "11", "ff", "123456789abcdef",
  ]
  for s in scalars {
    let k = BigInt::from_string(s, radix=16)
    let got = fe_k1_scalar_mult_base_fixed(k)
    let expected = scalar_mult(k, g)
    assert_point_eq(got, expected, "k1 complete scalar k=0x" + s)
  }
}
