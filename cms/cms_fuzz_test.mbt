// Fuzz CMS SignedData DER parsing. Random input should fail as CmsError or
// parse; it must never abort from ASN.1 shape confusion.

///|
test "fuzz cms: parse_signed_data never panics on random DER bytes" {
  for input in (@quickcheck.samples(200) : Array[Bytes]) {
    let _ = try? @cms.parse_signed_data(input)
  }
}
