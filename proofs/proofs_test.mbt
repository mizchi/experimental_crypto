// Runtime tests sit alongside the proofs. The `proof_ensure` clauses are
// formal guarantees over all inputs; these tests are spot checks for
// non-regression and humans reading the file.

///|
test "abs: positive" {
  assert_eq(@proofs.abs(42), 42)
}

///|
test "abs: negative" {
  assert_eq(@proofs.abs(-42), 42)
}

///|
test "abs: zero" {
  assert_eq(@proofs.abs(0), 0)
}

///|
test "mod_pos: positive a" {
  assert_eq(@proofs.mod_pos(17, 5), 2)
}

///|
test "mod_pos: negative a" {
  assert_eq(@proofs.mod_pos(-17, 5), 3)
}

///|
test "mod_pos: a divisible" {
  assert_eq(@proofs.mod_pos(-15, 5), 0)
}

///|
test "hex_value: digit" {
  assert_eq(@proofs.hex_value('0'.to_int()), 0)
  assert_eq(@proofs.hex_value('9'.to_int()), 9)
}

///|
test "hex_value: lowercase" {
  assert_eq(@proofs.hex_value('a'.to_int()), 10)
  assert_eq(@proofs.hex_value('f'.to_int()), 15)
}

///|
test "hex_value: uppercase" {
  assert_eq(@proofs.hex_value('A'.to_int()), 10)
  assert_eq(@proofs.hex_value('F'.to_int()), 15)
}

///|
test "ct_select: mask = 1 picks a" {
  assert_eq(@proofs.ct_select(1, 0xCAFE, 0xBABE), 0xCAFE)
}

///|
test "ct_select: mask = 0 picks b" {
  assert_eq(@proofs.ct_select(0, 0xCAFE, 0xBABE), 0xBABE)
}

///|
test "reduce_once: below m" {
  assert_eq(@proofs.reduce_once(7, 11), 7)
}

///|
test "reduce_once: at m" {
  assert_eq(@proofs.reduce_once(11, 11), 0)
}

///|
test "reduce_once: above m" {
  assert_eq(@proofs.reduce_once(15, 11), 4)
}
