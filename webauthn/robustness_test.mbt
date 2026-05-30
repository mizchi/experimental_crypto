// Fail-closed robustness suite: structural / policy rejection of malformed
// WebAuthn inputs. These need no cryptographic vectors — they assert that the
// parsers and the verifier reject garbage rather than silently accepting it
// (the project's "no false positives in a verifier" rule). `wh` / `att_obj` /
// `rpid_of` are shared from webauthn_test.mbt (same blackbox test package).

///|
// A throwaway COSE EC2 P-256 key with the given (kty, alg, crv) so we can probe
// the kty -> crv -> alg binding without a real point on the curve.
fn cose_ec2(kty : UInt64, alg_nint : UInt64, crv : UInt64) -> Bytes {
  let z = Bytes::makei(32, fn(_i) { b'\x00' })
  @cose_cbor.encode(
    Map([
      (Uint(1UL), Uint(kty)),
      (Uint(3UL), Nint(alg_nint)),
      (Nint(0UL), Uint(crv)),
      (Nint(1UL), Bytes(z)),
      (Nint(2UL), Bytes(z)),
    ]),
  )
}

///|
test "parse_authenticator_data rejects a buffer shorter than 37 bytes" {
  try @webauthn.parse_authenticator_data(wh("00112233")) |> ignore catch {
    ParseError(_) => ()
    e => abort("expected ParseError, got " + repr(e))
  } noraise {
    _ => abort("accepted a truncated authenticatorData")
  }
}

///|
test "parse_authenticator_data rejects AT flag with no attested data" {
  // 37 bytes, flags = 0x40 (AT set) but nothing follows -> truncated.
  let b = Bytes::makei(37, fn(i) { if i == 32 { b'\x40' } else { b'\x00' } })
  try @webauthn.parse_authenticator_data(b) |> ignore catch {
    ParseError(_) => ()
    e => abort("expected ParseError, got " + repr(e))
  } noraise {
    _ => abort("accepted AT flag with no attestedCredentialData")
  }
}

///|
test "parse_authenticator_data rejects a credentialId length past the buffer" {
  // 55 bytes (aaguid+len header fit), AT set, credIdLen = 0x0040 -> overruns.
  let b = Bytes::makei(55, fn(i) {
    if i == 32 {
      b'\x40'
    } else if i == 54 {
      b'\x40'
    } else {
      b'\x00'
    }
  })
  try @webauthn.parse_authenticator_data(b) |> ignore catch {
    ParseError(_) => ()
    e => abort("expected ParseError, got " + repr(e))
  } noraise {
    _ => abort("accepted an out-of-bounds credentialId length")
  }
}

///|
test "parse_cose_key rejects non-CBOR garbage" {
  // map(1) header that promises a pair but supplies none.
  try @webauthn.parse_cose_key(wh("a101")) |> ignore catch {
    Cbor(_) => ()
    ParseError(_) => ()
    e => abort("expected a decode error, got " + repr(e))
  } noraise {
    _ => abort("accepted truncated CBOR as a COSE key")
  }
}

///|
test "parse_cose_key enforces the EC2 P-256 -> ES256 alg binding" {
  // kty=2 (EC2), crv=1 (P-256), but alg=-35 (ES384) -> mismatch.
  try @webauthn.parse_cose_key(cose_ec2(2UL, 34UL, 1UL)) |> ignore catch {
    UnsupportedAlgorithm(_) => ()
    e => abort("expected UnsupportedAlgorithm, got " + repr(e))
  } noraise {
    _ => abort("accepted a P-256 key labelled with the wrong alg")
  }
}

///|
test "parse_cose_key rejects an unknown EC2 curve" {
  // kty=2 (EC2), crv=3 (P-521, unsupported here).
  try @webauthn.parse_cose_key(cose_ec2(2UL, 6UL, 3UL)) |> ignore catch {
    UnsupportedKeyType(_) => ()
    e => abort("expected UnsupportedKeyType, got " + repr(e))
  } noraise {
    _ => abort("accepted an unsupported EC2 curve")
  }
}

///|
test "parse_cose_key rejects an OKP key on the wrong curve" {
  // kty=1 (OKP), crv=4 (X25519, not an Ed25519 signing key).
  let cose = @cose_cbor.encode(
    Map([
      (Uint(1UL), Uint(1UL)),
      (Uint(3UL), Nint(7UL)),
      (Nint(0UL), Uint(4UL)),
      (Nint(1UL), Bytes(Bytes::makei(32, fn(_i) { b'\x00' }))),
    ]),
  )
  try @webauthn.parse_cose_key(cose) |> ignore catch {
    UnsupportedKeyType(_) => ()
    e => abort("expected UnsupportedKeyType, got " + repr(e))
  } noraise {
    _ => abort("accepted an OKP key on a non-Ed25519 curve")
  }
}

///|
test "parse_cose_key still rejects RSA credential keys (deferred)" {
  // kty=3 (RSA), alg=-257 (RS256). Documents the current deferral: RSA
  // credential public keys are not yet accepted, so they fail closed.
  let cose = @cose_cbor.encode(
    Map([
      (Uint(1UL), Uint(3UL)),
      (Uint(3UL), Nint(256UL)),
      (Nint(0UL), Bytes(Bytes::makei(64, fn(_i) { b'\x01' }))),
      (Nint(1UL), Bytes(b"\x01\x00\x01")),
    ]),
  )
  try @webauthn.parse_cose_key(cose) |> ignore catch {
    UnsupportedAlgorithm(_) => ()
    UnsupportedKeyType(_) => ()
    e => abort("expected an unsupported-key error, got " + repr(e))
  } noraise {
    _ => abort("accepted an RSA credential key (not yet supported)")
  }
}

///|
test "verify_attestation rejects an unknown attestation format" {
  let auth = wh(pk_authdata)
  let obj = att_obj("android-safetynet", auth, [(Text("ver"), Text("0"))])
  try
    @webauthn.verify_attestation(obj, wh(pk_hash), rp_id_hash=rpid_of(auth))
    |> ignore
  catch {
    AttestationFailure(_) => ()
    e => abort("expected AttestationFailure, got " + repr(e))
  } noraise {
    _ => abort("accepted an unknown attestation format")
  }
}

///|
test "verify_attestation rejects `none` carrying an x5c chain" {
  let auth = wh(pk_authdata)
  let obj = att_obj("none", auth, [(Text("x5c"), Array([Bytes(wh(pk_x5c))]))])
  try
    @webauthn.verify_attestation(obj, wh(pk_hash), rp_id_hash=rpid_of(auth))
    |> ignore
  catch {
    AttestationFailure(_) => ()
    e => abort("expected AttestationFailure, got " + repr(e))
  } noraise {
    _ => abort("accepted `none` attestation smuggling an x5c chain")
  }
}

///|
test "verify_attestation rejects a missing attStmt" {
  let auth = wh(pk_authdata)
  // Build an attestationObject deliberately missing the attStmt key.
  let obj = @cose_cbor.encode(
    Map([(Text("fmt"), Text("none")), (Text("authData"), Bytes(auth))]),
  )
  try
    @webauthn.verify_attestation(obj, wh(pk_hash), rp_id_hash=rpid_of(auth))
    |> ignore
  catch {
    ParseError(_) => ()
    e => abort("expected ParseError, got " + repr(e))
  } noraise {
    _ => abort("accepted an attestationObject with no attStmt")
  }
}

///|
test "verify_attestation requires attested credential data" {
  // A get-assertion style authData (flags 0x01, no AT) cannot register.
  let rp = wh(
    "0021f5fc0b85cd22e60623bcd7d1ca48948909249b4776eb515154e57b66ae12",
  )
  let auth = Bytes::makei(37, fn(i) {
    if i < 32 {
      rp[i]
    } else if i == 32 {
      b'\x01'
    } else {
      b'\x00'
    }
  })
  let obj = att_obj("none", auth, [(Text("ignored"), Text("x"))])
  try
    @webauthn.verify_attestation(obj, wh(pk_hash), rp_id_hash=rp) |> ignore
  catch {
    AttestationFailure(_) => ()
    e => abort("expected AttestationFailure, got " + repr(e))
  } noraise {
    _ => abort("registered a credential with no attested credential data")
  }
}

///|
test "verify_client_data rejects malformed JSON" {
  try
    @webauthn.verify_client_data(
      "this is not json", "webauthn.get", "q1c5", "https://example.com",
    )
    |> ignore
  catch {
    ClientDataInvalid(_) => ()
    e => abort("expected ClientDataInvalid, got " + repr(e))
  } noraise {
    _ => abort("accepted non-JSON clientDataJSON")
  }
}

///|
test "verify_client_data rejects a ceremony-type mismatch" {
  // type webauthn.create offered where webauthn.get is required.
  let cdj = "{\"type\":\"webauthn.create\",\"challenge\":\"q1c5\",\"origin\":\"https://example.com\"}"
  try
    @webauthn.verify_client_data(
      cdj, "webauthn.get", "q1c5", "https://example.com",
    )
    |> ignore
  catch {
    ClientDataInvalid(_) => ()
    e => abort("expected ClientDataInvalid, got " + repr(e))
  } noraise {
    _ => abort("accepted a webauthn.create assertion as webauthn.get")
  }
}
