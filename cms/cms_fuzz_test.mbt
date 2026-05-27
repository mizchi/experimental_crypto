// Fuzz CMS SignedData DER parsing. Random input should fail as CmsError or
// parse; it must never abort from ASN.1 shape confusion.

///|
test "fuzz cms: parse_signed_data never panics on random DER bytes" {
  for input in (@quickcheck.samples(200) : Array[Bytes]) {
    let _ = try? @cms.parse_signed_data(input)
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
test "fuzz cms->pkix->pkix_verify: mutated SignedData never authenticates" {
  let fixture = chained_cms_signature_der()
  let root_cert = @pkix.parse_certificate(chained_root_cert_der())
  let anchor_pk = @pkix_verify.extract_public_key(
    root_cert.tbs.subject_public_key_info,
  )
  for entropy in (@quickcheck.samples(80) : Array[Bytes]) {
    let mutated = fuzz_mutate_one_byte(fixture, entropy)
    try @cms.parse_signed_data(mutated) catch {
      _ => ()
    } noraise {
      sd =>
        try
          @cms.verify_with_chain(
            sd,
            chained_message(),
            anchor_pk,
            "270101000000Z",
          )
        catch {
          _ => ()
        } noraise {
          ok => if ok { abort("mutated CMS SignedData authenticated") }
        }
    }
  }
}
