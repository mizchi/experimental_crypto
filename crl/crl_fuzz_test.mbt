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
test "fuzz crl->pkix_verify: mutated CRL never authenticates" {
  let issuer = @pkix.parse_certificate(@pem.decode(openssl_ref_ca_pem).data)
  let fixture = hex_to_bytes(openssl_ref_crl_der_hex)
  for entropy in (@quickcheck.samples(80) : Array[Bytes]) {
    let mutated = fuzz_mutate_one_byte(fixture, entropy)
    try @crl.verify(mutated, issuer, "270101000000Z") catch {
      _ => ()
    } noraise {
      _ => abort("mutated CRL authenticated")
    }
  }
}
