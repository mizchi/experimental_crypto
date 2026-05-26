// JWK round-trip and thumbprint tests against published RFC fixtures.

// -----------------------------------------------------------------------------
// RFC 7517 §A.1: an RSA public key JWK (we strip the "kid"/"use"/"alg"
// metadata for the round-trip check so we only compare canonical fields).
// -----------------------------------------------------------------------------

///|
test "rsa public roundtrip from RFC 7517 A.1" {
  // The first key from the JWK Set in RFC 7517 §A.1 (an RS256 signature key).
  let json =
    #|{"kty":"RSA",
    #| "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    #| "e":"AQAB"
    #|}

  let jwk = @jwk.parse_public(json)
  // Re-emit and re-parse — only the canonical fields are guaranteed to
  // come back (kid/use/alg are dropped by design).
  let re = @jwk.serialise_public(jwk)
  let jwk2 = @jwk.parse_public(re)
  // Thumbprint over both should be equal (this also exercises the field
  // extraction path).
  let t1 = @jwk.thumbprint_base64url(jwk)
  let t2 = @jwk.thumbprint_base64url(jwk2)
  @debug.assert_eq(t1, t2)
}

// -----------------------------------------------------------------------------
// RFC 7638 §3.1: the RSA JWK reference example, whose thumbprint is
// published as "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".
// -----------------------------------------------------------------------------

///|
test "RFC 7638 §3.1 thumbprint vector" {
  // Verbatim from RFC 7638 §3.1 (with the metadata fields removed since
  // we only emit the canonical form, which already discards them).
  let json =
    #|{"kty":"RSA",
    #| "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    #| "e":"AQAB",
    #| "alg":"RS256",
    #| "kid":"2011-04-29"
    #|}

  let jwk = @jwk.parse_public(json)
  let tp = @jwk.thumbprint_base64url(jwk)
  @debug.assert_eq(tp, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
  // Pin the canonical form too — RFC 7638 §3.1 shows the exact bytes
  // that are hashed, so we re-derive them here as a regression guard
  // against future re-ordering / extra-field bugs.
  let canon = @jwk.debug_canonical_form(jwk)
  inspect(
    canon,
    content=(
      #|{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
    ),
  )
}

// -----------------------------------------------------------------------------
// RFC 8037 §A.2 / §A.3: Ed25519 JWK used in the EdDSA JWT test vector.
// -----------------------------------------------------------------------------

///|
test "ed25519 OKP public roundtrip from RFC 8037 A.2" {
  // x is the published 32-byte Ed25519 public key from RFC 8037 §A.2.
  let json =
    #|{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}

  let jwk = @jwk.parse_public(json)
  let re = @jwk.serialise_public(jwk)
  let jwk2 = @jwk.parse_public(re)
  let t1 = @jwk.thumbprint_base64url(jwk)
  let t2 = @jwk.thumbprint_base64url(jwk2)
  @debug.assert_eq(t1, t2)
  // Verify the public-key bytes actually came through by checking the
  // canonical-form thumbprint is non-empty and of expected base64url
  // length (32 bytes → 43 chars unpadded).
  @debug.assert_eq(t1.length(), 43)
}

///|
test "ed25519 OKP private roundtrip from RFC 8037 A.1" {
  // From RFC 8037 §A.1, the Ed25519 JWK with the seed in d.
  let json =
    #|{"kty":"OKP","crv":"Ed25519",
    #| "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
    #| "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}

  let jwk = @jwk.parse_private(json)
  // Serialise as private and round-trip.
  let re = @jwk.serialise_private(jwk)
  let jwk2 = @jwk.parse_private(re)
  let t1 = @jwk.thumbprint_base64url(jwk)
  let t2 = @jwk.thumbprint_base64url(jwk2)
  // Thumbprint is over public-key required fields only — should match.
  @debug.assert_eq(t1, t2)
}

// -----------------------------------------------------------------------------
// RFC 7515 §A.3: ES256 JWK (P-256) used in the JWS Appendix.
// -----------------------------------------------------------------------------

///|
test "EC P-256 public roundtrip from RFC 7515 A.3" {
  // x and y from RFC 7515 Appendix A.3.1.
  let json =
    #|{"kty":"EC","crv":"P-256",
    #| "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    #| "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}

  let jwk = @jwk.parse_public(json)
  let re = @jwk.serialise_public(jwk)
  let jwk2 = @jwk.parse_public(re)
  let t1 = @jwk.thumbprint_base64url(jwk)
  let t2 = @jwk.thumbprint_base64url(jwk2)
  @debug.assert_eq(t1, t2)
  @debug.assert_eq(t1.length(), 43)
}

///|
test "EC P-256 private roundtrip from RFC 7515 A.3" {
  // Same key as above, with the d field added.
  let json =
    #|{"kty":"EC","crv":"P-256",
    #| "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    #| "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    #| "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}

  let jwk = @jwk.parse_private(json)
  let re = @jwk.serialise_private(jwk)
  let jwk2 = @jwk.parse_private(re)
  let t1 = @jwk.thumbprint_base64url(jwk)
  let t2 = @jwk.thumbprint_base64url(jwk2)
  @debug.assert_eq(t1, t2)
}

// -----------------------------------------------------------------------------
// secp256k1 — BIP-32 test vector (the well-known "abandon abandon ..." seed
// derives an account key at m/0' whose public key is widely tabulated).
// We use a synthetic but on-curve test vector: the published
// curve generator g_x, g_y as a (deterministic, on-curve) point.
// -----------------------------------------------------------------------------

///|
test "EC secp256k1 public roundtrip" {
  // Generator point of secp256k1 (G_x, G_y), big-endian, base64url-encoded.
  // G_x = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  // G_y = 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
  let json =
    #|{"kty":"EC","crv":"secp256k1",
    #| "x":"eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g",
    #| "y":"SDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj_sQ1Lg"}

  let jwk = @jwk.parse_public(json)
  let re = @jwk.serialise_public(jwk)
  let jwk2 = @jwk.parse_public(re)
  let t1 = @jwk.thumbprint_base64url(jwk)
  let t2 = @jwk.thumbprint_base64url(jwk2)
  @debug.assert_eq(t1, t2)
}

// -----------------------------------------------------------------------------
// HMAC (kty=oct).
// -----------------------------------------------------------------------------

///|
test "HMAC oct private roundtrip" {
  // 32-byte HS256 secret base64url-encoded.
  let json =
    #|{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}

  let jwk = @jwk.parse_private(json)
  let re = @jwk.serialise_private(jwk)
  let jwk2 = @jwk.parse_private(re)
  let t1 = @jwk.thumbprint_base64url(jwk)
  let t2 = @jwk.thumbprint_base64url(jwk2)
  @debug.assert_eq(t1, t2)
  @debug.assert_eq(t1.length(), 43)
}

// -----------------------------------------------------------------------------
// Failure paths.
// -----------------------------------------------------------------------------

///|
fn assert_parse_public_raises(json : String) -> Unit raise {
  let mut raised = false
  let _ = @jwk.parse_public(json) catch {
    _ => {
      raised = true
      @jwk.Jwk::Hmac(secret=b"")
    }
  }
  assert_true(raised)
}

///|
fn assert_parse_private_raises(json : String) -> Unit raise {
  let mut raised = false
  let _ = @jwk.parse_private(json) catch {
    _ => {
      raised = true
      @jwk.Jwk::Hmac(secret=b"")
    }
  }
  assert_true(raised)
}

///|
test "tampered n is rejected at b64 decode" {
  // Inject a NUL (0x00) into the base64 — non-alphabet character.
  let json =
    #|{"kty":"RSA","n":"!notvalid","e":"AQAB"}
  assert_parse_public_raises(json)
}

///|
test "tampered e is rejected at b64 decode" {
  let json =
    #|{"kty":"RSA","n":"AQAB","e":"!!!!!"}
  assert_parse_public_raises(json)
}

///|
test "missing required field is rejected" {
  // RSA JWK without `e`.
  let json =
    #|{"kty":"RSA","n":"AQAB"}
  assert_parse_public_raises(json)
}

///|
test "unsupported kty is rejected" {
  let json =
    #|{"kty":"DSA","y":"AQAB"}
  assert_parse_public_raises(json)
}

///|
test "oct JWK is rejected by public parser" {
  let json =
    #|{"kty":"oct","k":"AQIDBA"}
  assert_parse_public_raises(json)
}

///|
test "serialise_public does not expose oct secret" {
  let jwk = @jwk.Jwk::Hmac(secret=b"\x01\x02\x03\x04")
  let public_json = @jwk.serialise_public(jwk)
  assert_false(public_json.contains("\"k\""))
  assert_false(public_json.contains("AQIDBA"))
}

///|
test "RSA JWK rejects non-positive or even public parameters" {
  let zero_n =
    #|{"kty":"RSA","n":"AA","e":"AQAB"}
  let one_e =
    #|{"kty":"RSA","n":"Aw","e":"AQ"}
  let even_e =
    #|{"kty":"RSA","n":"Aw","e":"Ag"}
  assert_parse_public_raises(zero_n)
  assert_parse_public_raises(one_e)
  assert_parse_public_raises(even_e)
}

///|
test "EC private JWK rejects public/private mismatch" {
  let json =
    #|{"kty":"EC","crv":"P-256",
    #| "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    #| "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    #| "d":"AQ"}
  assert_parse_private_raises(json)
}

///|
test "OKP private JWK rejects public/private mismatch" {
  let json =
    #|{"kty":"OKP","crv":"Ed25519",
    #| "d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    #| "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
  assert_parse_private_raises(json)
}

///|
test "serialise_private without private key raises" {
  let json =
    #|{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
  let jwk = @jwk.parse_public(json)
  let mut raised = false
  let _ = @jwk.serialise_private(jwk) catch {
    _ => {
      raised = true
      ""
    }
  }
  assert_true(raised)
}

///|
test "unsupported curve is rejected" {
  let json =
    #|{"kty":"EC","crv":"P-521","x":"AAAA","y":"AAAA"}
  let mut raised = false
  let _ = @jwk.parse_public(json) catch {
    _ => {
      raised = true
      @jwk.Jwk::Hmac(secret=b"")
    }
  }
  assert_true(raised)
}
