// Fuzz CRL DER parsing. Random input should return a typed CrlError or a
// parsed structure; it must not abort. If parsing succeeds, cheap public
// queries should also remain total.

///|
test "fuzz crl: parse never panics on random DER bytes" {
  for input in (@quickcheck.samples(200) : Array[Bytes]) {
    let _ = try? @crl.parse(input)
  }
}

///|
test "fuzz crl: accepted CRLs tolerate random serial lookups" {
  for pair in (@quickcheck.samples(120) : Array[(Bytes, Bytes)]) {
    let (input, serial) = pair
    try @crl.parse(input) catch {
      _ => ()
    } noraise {
      parsed => {
        let _ = @crl.is_revoked(parsed, serial)
      }
    }
  }
}
