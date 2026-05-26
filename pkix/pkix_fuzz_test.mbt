// Property-based robustness fuzz for the pkix module. Generating a valid
// X.509 Certificate / Name / SubjectPublicKeyInfo by hand is intricate, so
// these tests only assert the "garbage in → PkixError out, never panic"
// invariant on random Bytes.

///|
test "fuzz pkix: parse_certificate never panics on random bytes" {
  let n = 200
  for input in (@quickcheck.samples(n) : Array[Bytes]) {
    let _ = try? @pkix.parse_certificate(input)
  }
}

///|
test "fuzz pkix: parse_name never panics on random bytes" {
  let n = 200
  for input in (@quickcheck.samples(n) : Array[Bytes]) {
    let _ = try? @pkix.parse_name(input)
  }
}

///|
test "fuzz pkix: parse_subject_public_key_info never panics on random bytes" {
  let n = 200
  for input in (@quickcheck.samples(n) : Array[Bytes]) {
    let _ = try? @pkix.parse_subject_public_key_info(input)
  }
}
