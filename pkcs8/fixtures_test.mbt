// External fixtures: real PEM-wrapped Ed25519 PKCS#8 keys borrowed from the
// RustCrypto/formats project (https://github.com/RustCrypto/formats), which
// uses them to drive its own pkcs8 test suite. They follow RFC 8410 §10.
// These keys are test fixtures and are not used to protect anything.

///|
let ed25519_pkcs8_v1_pem : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MC4CAQAwBQYDK2VwBCIEIBftnHPp22SewYmmEoMcX8VwI4IHwaqd+9LFPj/15eqF
  #|-----END PRIVATE KEY-----

///|
let ed25519_pkcs8_v2_pem : String =
  #|-----BEGIN PRIVATE KEY-----
  #|MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
  #|oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
  #|Z9w7lshQhqowtrbLDFw4rXAxZuE=
  #|-----END PRIVATE KEY-----

///|
fn ed25519_oid_fixture() -> @asn1.ObjectIdentifier raise {
  // id-Ed25519 OID per RFC 8410 §3.
  @asn1.ObjectIdentifier::from_string("1.3.101.112")
}

///|
test "pkcs8 fixture: RustCrypto Ed25519 v1 parses, algorithm OID matches RFC 8410" {
  let key = @pkcs8.parse_pem(ed25519_pkcs8_v1_pem)
  @debug.assert_eq(key.version, 0)
  @debug.assert_eq(key.algorithm.algorithm, ed25519_oid_fixture())
  // RFC 8410 §7: parameters MUST be absent.
  @debug.assert_eq(key.algorithm.parameters, None)
  // privateKey is an OCTET STRING containing the 32-byte seed wrapped in
  // another OCTET STRING (CurvePrivateKey).
  let inner = @asn1.decode_der(key.private_key)
  match inner.value {
    OctetString(seed) => @debug.assert_eq(seed.length(), 32)
    _ => @debug.assert_eq(true, false, msg="expected inner OCTET STRING")
  }
  // v1 carries no publicKey field.
  @debug.assert_eq(key.public_key, None)
}

///|
test "pkcs8 fixture: RustCrypto Ed25519 v2 carries publicKey BIT STRING" {
  let key = @pkcs8.parse_pem(ed25519_pkcs8_v2_pem)
  @debug.assert_eq(key.version, 1)
  @debug.assert_eq(key.algorithm.algorithm, ed25519_oid_fixture())
  @debug.assert_eq(key.algorithm.parameters, None)
  match key.public_key {
    Some(bs) => {
      @debug.assert_eq(bs.bytes.length(), 32) // Ed25519 compressed point
      @debug.assert_eq(bs.unused_bits, 0)
    }
    None => @debug.assert_eq(true, false, msg="expected [1] IMPLICIT publicKey")
  }
}

///|
test "pkcs8 fixture: RustCrypto Ed25519 v2 has the 'Curdle Chairs' attribute" {
  let key = @pkcs8.parse_pem(ed25519_pkcs8_v2_pem)
  // RFC 8410 §10.3 example includes one attribute with OID
  // 1.2.840.113549.1.9.9.20 ("friendlyName" in PKCS#9 context) carrying
  // the string "Curdle Chairs".
  @debug.assert_eq(key.attributes.length(), 1)
}

///|
test "pkcs8 fixture: Ed25519 v1 PEM roundtrip is byte-stable" {
  let parsed = @pkcs8.parse_pem(ed25519_pkcs8_v1_pem)
  let re_encoded = @pkcs8.serialize_pem(parsed)
  let re_parsed = @pkcs8.parse_pem(re_encoded)
  @debug.assert_eq(re_parsed.private_key, parsed.private_key)
  @debug.assert_eq(re_parsed.algorithm.algorithm, parsed.algorithm.algorithm)
}

///|
test "pkcs8 fixture: Ed25519 v2 DER roundtrip is byte-stable" {
  let parsed = @pkcs8.parse_pem(ed25519_pkcs8_v2_pem)
  let der1 = @pkcs8.serialize_der(parsed)
  let re_parsed = @pkcs8.parse_der(der1)
  let der2 = @pkcs8.serialize_der(re_parsed)
  @debug.assert_eq(der1, der2)
}
