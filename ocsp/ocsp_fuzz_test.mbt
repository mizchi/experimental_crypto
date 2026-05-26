// Fuzz OCSPResponse DER parsing. Random input should be rejected as OcspError
// or parsed; it must never abort or expose a partial parser panic.

///|
test "fuzz ocsp: parse_response never panics on random DER bytes" {
  for input in (@quickcheck.samples(200) : Array[Bytes]) {
    let _ = try? @ocsp.parse_response(input)
  }
}
