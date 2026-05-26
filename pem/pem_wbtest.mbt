// Whitebox tests run within the package scope.
// Use them to validate internal helpers or invariants.
// Keep them focused; public behavior belongs in `_test.mbt`.

///|
test "pem: label validator rejects ambiguous labels" {
  assert_true(is_valid_pem_label("CERTIFICATE"))
  assert_true(is_valid_pem_label("RSA PRIVATE KEY"))
  assert_true(is_valid_pem_label("X-TEST 123"))
  assert_false(is_valid_pem_label("certificate"))
  assert_false(is_valid_pem_label(" CERTIFICATE"))
  assert_false(is_valid_pem_label("CERTIFICATE "))
  assert_false(is_valid_pem_label("CERT\nIFICATE"))
  assert_false(is_valid_pem_label("CERT\tIFICATE"))
}

///|
test "pem: header validators reject marker injection characters" {
  assert_true(is_valid_pem_header_name("Proc-Type"))
  assert_true(is_valid_pem_header_name("DEK-Info"))
  assert_false(is_valid_pem_header_name("Bad:Name"))
  assert_false(is_valid_pem_header_name("Bad Name"))
  assert_false(is_valid_pem_header_name("Bad\nName"))
  assert_true(contains_newline("line\nbreak"))
  assert_true(contains_newline("line\rbreak"))
  assert_false(contains_newline("single line"))
}
