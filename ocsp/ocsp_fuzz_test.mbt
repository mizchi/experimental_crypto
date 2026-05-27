// Fuzz OCSPResponse DER parsing. Random input should be rejected as OcspError
// or parsed; it must never abort or expose a partial parser panic.

///|
test "fuzz ocsp: parse_response never panics on random DER bytes" {
  for input in (@quickcheck.samples(200) : Array[Bytes]) {
    let _ = try? @ocsp.parse_response(input)
  }
}

///|
fn fuzz_mutate_one_byte(data : Bytes, entropy : Bytes) -> Bytes {
  let idx = if entropy.length() == 0 {
    0
  } else {
    entropy[0].to_int() % data.length()
  }
  let delta = if entropy.length() > 1 && entropy[1] != b'\x00' {
    entropy[1].to_int()
  } else {
    1
  }
  Bytes::makei(data.length(), fn(i) {
    if i == idx {
      (data[i].to_int() ^ delta).to_byte()
    } else {
      data[i]
    }
  })
}

///|
test "fuzz ocsp->pkix_verify: mutated direct response never authenticates" {
  let issuer = @pkix.parse_certificate(@pem.decode(openssl_ref_ca_pem).data)
  let cert = @pkix.parse_certificate(@pem.decode(openssl_ref_leaf_pem).data)
  let fixture = hex_to_bytes(openssl_ref_ocsp_direct_der_hex)
  for entropy in (@quickcheck.samples(80) : Array[Bytes]) {
    let mutated = fuzz_mutate_one_byte(fixture, entropy)
    try @ocsp.verify(mutated, cert, issuer, "270101000000Z") catch {
      _ => ()
    } noraise {
      status =>
        if status == Good {
          abort("mutated OCSP response authenticated")
        }
    }
  }
}
