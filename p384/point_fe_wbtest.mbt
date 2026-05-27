// Whitebox tests for the P-384 fixed-iteration complete-addition path.
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
test "p384 complete projective addition matches affine oracle" {
  let g = generator()
  let scalars : Array[Int] = [0, 1, 2, 3, 5, 17]
  for a_int in scalars {
    for b_int in scalars {
      let a = scalar_mult(BigInt::from_int(a_int), g)
      let b = scalar_mult(BigInt::from_int(b_int), g)
      let got = fe384_point_to_affine(
        fe384_point_add_complete(
          fe384_point_from_affine(a),
          fe384_point_from_affine(b),
        ),
      )
      let expected = point_add(a, b)
      assert_point_eq(
        got,
        expected,
        "p384 complete add " +
        a_int.to_string() +
        "G + " +
        b_int.to_string() +
        "G",
      )
    }
  }
  let neg_g : Point = { x: g.x, y: p384_p() - g.y, inf: false }
  assert_point_eq(
    fe384_point_to_affine(
      fe384_point_add_complete(
        fe384_point_from_affine(g),
        fe384_point_from_affine(neg_g),
      ),
    ),
    point_infinity(),
    "p384 complete add G + (-G)",
  )
}
