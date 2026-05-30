// RS256/384/512 credential public keys (the Windows Hello / TPM common case),
// exercised against an openssl-generated, self-consistent assertion vector.
// The hex constants live in rsa_vectors_test.mbt; `wh` is shared from
// webauthn_test.mbt (same blackbox test package).

///|
// Build a COSE_Key (RFC 8230) for the shared RSA modulus/exponent at the given
// COSE alg, expressed as the CBOR negative-int payload v (alg = -(v + 1)):
// RS256 -> 256, RS384 -> 257, RS512 -> 258, PS256 -> 36.
fn rsa_cose(alg_nint : UInt64) -> Bytes {
  @cose_cbor.encode(
    Map([
      (Uint(1UL), Uint(3UL)), // kty = 3 (RSA)
      (Uint(3UL), Nint(alg_nint)), // alg
      (Nint(0UL), Bytes(wh(rsa_n))), // -1 = n
      (Nint(1UL), Bytes(wh(rsa_e))), // -2 = e
    ]),
  )
}

///|
test "parse RS256 COSE key yields the Rs256 variant" {
  match @webauthn.parse_cose_key(rsa_cose(256UL)) {
    Rs256(_) => ()
    _ => abort("expected an Rs256 credential public key")
  }
}

///|
test "verify RS256 / RS384 / RS512 assertions (openssl vector)" {
  @webauthn.verify_assertion(
    rsa_cose(256UL),
    wh(wa_authdata),
    wh(wa_cdh),
    wh(rs256_sig),
    rp_id_hash=wh(wa_rpidhash),
    require_user_verification=true,
  )
  @webauthn.verify_assertion(
    rsa_cose(257UL),
    wh(wa_authdata),
    wh(wa_cdh),
    wh(rs384_sig),
    rp_id_hash=wh(wa_rpidhash),
    require_user_verification=true,
  )
  @webauthn.verify_assertion(
    rsa_cose(258UL),
    wh(wa_authdata),
    wh(wa_cdh),
    wh(rs512_sig),
    rp_id_hash=wh(wa_rpidhash),
    require_user_verification=true,
  )
}

///|
test "an RS384 signature does not verify under RS256 (digest binding)" {
  try
    @webauthn.verify_assertion(
      rsa_cose(256UL),
      wh(wa_authdata),
      wh(wa_cdh),
      wh(rs384_sig),
      rp_id_hash=wh(wa_rpidhash),
    )
    |> ignore
  catch {
    SignatureInvalid => ()
    e => abort("expected SignatureInvalid, got " + repr(e))
  } noraise {
    _ => abort("accepted an RS384 signature under the RS256 alg")
  }
}

///|
test "a tampered RS256 signature is rejected" {
  let sig = wh(rs256_sig)
  let bad = Bytes::makei(sig.length(), fn(i) {
    if i == 0 {
      (sig[i].to_int() ^ 0xff).to_byte()
    } else {
      sig[i]
    }
  })
  try
    @webauthn.verify_assertion(
      rsa_cose(256UL),
      wh(wa_authdata),
      wh(wa_cdh),
      bad,
      rp_id_hash=wh(wa_rpidhash),
    )
    |> ignore
  catch {
    SignatureInvalid => ()
    e => abort("expected SignatureInvalid, got " + repr(e))
  } noraise {
    _ => abort("accepted a tampered RS256 signature")
  }
}

///|
test "RS256 wrong rpId is rejected before signature work" {
  try
    @webauthn.verify_assertion(
      rsa_cose(256UL),
      wh(wa_authdata),
      wh(wa_cdh),
      wh(rs256_sig),
      rp_id_hash=@webauthn.rp_id_hash("attacker.example"),
    )
    |> ignore
  catch {
    RpIdMismatch => ()
    e => abort("expected RpIdMismatch, got " + repr(e))
  } noraise {
    _ => abort("accepted a wrong rpId")
  }
}

///|
test "PS256 (RSASSA-PSS) credential keys remain deferred and fail closed" {
  // alg = -37 (PS256) -> Nint(36). Not yet supported -> must reject.
  try @webauthn.parse_cose_key(rsa_cose(36UL)) |> ignore catch {
    UnsupportedAlgorithm(_) => ()
    e => abort("expected UnsupportedAlgorithm, got " + repr(e))
  } noraise {
    _ => abort("accepted a PS256 RSA credential key (not supported)")
  }
}
