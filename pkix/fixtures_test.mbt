// External fixtures: real X.509 certificates fetched from public CAs.
// They exercise the parser against bytes produced by independent (battle-
// hardened) issuers, not by our own serializer.

///|
let lets_encrypt_r10_pem : String =
  #|-----BEGIN CERTIFICATE-----
  #|MIIFBTCCAu2gAwIBAgIQS6hSk/eaL6JzBkuoBI110DANBgkqhkiG9w0BAQsFADBP
  #|MQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFy
  #|Y2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTAeFw0yNDAzMTMwMDAwMDBa
  #|Fw0yNzAzMTIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBF
  #|bmNyeXB0MQwwCgYDVQQDEwNSMTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
  #|AoIBAQDPV+XmxFQS7bRH/sknWHZGUCiMHT6I3wWd1bUYKb3dtVq/+vbOo76vACFL
  #|YlpaPAEvxVgD9on/jhFD68G14BQHlo9vH9fnuoE5CXVlt8KvGFs3Jijno/QHK20a
  #|/6tYvJWuQP/py1fEtVt/eA0YYbwX51TGu0mRzW4Y0YCF7qZlNrx06rxQTOr8IfM4
  #|FpOUurDTazgGzRYSespSdcitdrLCnF2YRVxvYXvGLe48E1KGAdlX5jgc3421H5KR
  #|mudKHMxFqHJV8LDmowfs/acbZp4/SItxhHFYyTr6717yW0QrPHTnj7JHwQdqzZq3
  #|DZb3EoEmUVQK7GH29/Xi8orIlQ2NAgMBAAGjgfgwgfUwDgYDVR0PAQH/BAQDAgGG
  #|MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATASBgNVHRMBAf8ECDAGAQH/
  #|AgEAMB0GA1UdDgQWBBS7vMNHpeS8qcbDpHIMEI2iNeHI6DAfBgNVHSMEGDAWgBR5
  #|tFnme7bl5AFzgAiIyBpY9umbbjAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAKG
  #|Fmh0dHA6Ly94MS5pLmxlbmNyLm9yZy8wEwYDVR0gBAwwCjAIBgZngQwBAgEwJwYD
  #|VR0fBCAwHjAcoBqgGIYWaHR0cDovL3gxLmMubGVuY3Iub3JnLzANBgkqhkiG9w0B
  #|AQsFAAOCAgEAkrHnQTfreZ2B5s3iJeE6IOmQRJWjgVzPw139vaBw1bGWKCIL0vIo
  #|zwzn1OZDjCQiHcFCktEJr59L9MhwTyAWsVrdAfYf+B9haxQnsHKNY67u4s5Lzzfd
  #|u6PUzeetUK29v+PsPmI2cJkxp+iN3epi4hKu9ZzUPSwMqtCceb7qPVxEbpYxY1p9
  #|1n5PJKBLBX9eb9LU6l8zSxPWV7bK3lG4XaMJgnT9x3ies7msFtpKK5bDtotij/l0
  #|GaKeA97pb5uwD9KgWvaFXMIEt8jVTjLEvwRdvCn294GPDF08U8lAkIv7tghluaQh
  #|1QnlE4SEN4LOECj8dsIGJXpGUk3aU3KkJz9icKy+aUgA+2cP21uh6NcDIS3XyfaZ
  #|QjmDQ993ChII8SXWupQZVBiIpcWO4RqZk3lr7Bz5MUCwzDIA359e57SSq5CCkY0N
  #|4B6Vulk7LktfwrdGNVI5BsC9qqxSwSKgRJeZ9wygIaehbHFHFhcBaMDKpiZlBHyz
  #|rsnnlFXCb5s8HKn5LsUgGvB24L7sGNZP2CX7dhHov+YhD+jozLW2p9W4959Bz2Ei
  #|RmqDtmiXLnzqTpXbI+suyCsohKRg6Un0RC47+cpiVwHiXZAW+cn8eiNIjqbVgXLx
  #|KPpdzvvtTnOPlC7SQZSYmdunr3Bf9b77AiC/ZidstK36dRILKz7OA54=
  #|-----END CERTIFICATE-----

///|
fn rsa_encryption_oid() -> @asn1.ObjectIdentifier raise {
  // rsaEncryption per PKCS#1 / RFC 8017.
  @asn1.ObjectIdentifier::from_string("1.2.840.113549.1.1.1")
}

///|
fn sha256_with_rsa_oid() -> @asn1.ObjectIdentifier raise {
  // sha256WithRSAEncryption per PKCS#1.
  @asn1.ObjectIdentifier::from_string("1.2.840.113549.1.1.11")
}

///|
fn common_name_oid() -> @asn1.ObjectIdentifier raise {
  // id-at-commonName per RFC 5280 §4.1.2.4.
  @asn1.ObjectIdentifier::from_string("2.5.4.3")
}

///|
fn lets_encrypt_r10_der() -> Bytes raise {
  @pem.decode(lets_encrypt_r10_pem).data
}

///|
test "pkix fixture: Let's Encrypt R10 v3 cert parses with expected version + algorithm" {
  let cert = @pkix.parse_certificate(lets_encrypt_r10_der())
  @debug.assert_eq(cert.tbs.version, 2) // v3 -- the most common case for real certs
  @debug.assert_eq(cert.signature_algorithm.algorithm, sha256_with_rsa_oid())
  @debug.assert_eq(cert.tbs.signature.algorithm, sha256_with_rsa_oid())
  // Issuer signing alg must match the outer signatureAlgorithm per RFC 5280.
  @debug.assert_eq(cert.tbs.signature, cert.signature_algorithm)
  // SPKI: RSA public key
  @debug.assert_eq(
    cert.tbs.subject_public_key_info.algorithm.algorithm,
    rsa_encryption_oid(),
  )
}

///|
test "pkix fixture: Let's Encrypt R10 subject CN is 'R10'" {
  let cert = @pkix.parse_certificate(lets_encrypt_r10_der())
  // Subject is C=US, O=Let's Encrypt, CN=R10.
  // Look up the CN RDN: it must be the last one in the SEQUENCE OF SET.
  let rdns = cert.tbs.subject.rdns
  assert_true(rdns.length() >= 3)
  let last_rdn = rdns[rdns.length() - 1]
  @debug.assert_eq(last_rdn.length(), 1)
  let av = last_rdn[0]
  @debug.assert_eq(av.oid, common_name_oid())
  // The value is a PrintableString here.
  match av.value.value {
    PrintableString(s) => @debug.assert_eq(s, "R10")
    Utf8String(s) => @debug.assert_eq(s, "R10")
    _ => @debug.assert_eq(true, false, msg="expected R10 CN")
  }
}

///|
test "pkix fixture: Let's Encrypt R10 issuer is ISRG Root X1" {
  let cert = @pkix.parse_certificate(lets_encrypt_r10_der())
  let rdns = cert.tbs.issuer.rdns
  // Issuer is C=US, O=Internet Security Research Group, CN=ISRG Root X1.
  assert_true(rdns.length() >= 3)
  let last_rdn = rdns[rdns.length() - 1]
  let av = last_rdn[0]
  @debug.assert_eq(av.oid, common_name_oid())
  match av.value.value {
    PrintableString(s) => @debug.assert_eq(s, "ISRG Root X1")
    Utf8String(s) => @debug.assert_eq(s, "ISRG Root X1")
    _ => @debug.assert_eq(true, false, msg="expected ISRG Root X1 CN")
  }
}

///|
test "pkix fixture: Let's Encrypt R10 validity is UTCTime-encoded" {
  let cert = @pkix.parse_certificate(lets_encrypt_r10_der())
  // Cert issued 2024-03-13, expires 2027-03-12.
  @debug.assert_eq(cert.tbs.validity.not_before_tag, @asn1.tag_utc_time)
  @debug.assert_eq(cert.tbs.validity.not_after_tag, @asn1.tag_utc_time)
  @debug.assert_eq(cert.tbs.validity.not_before, "240313000000Z")
  @debug.assert_eq(cert.tbs.validity.not_after, "270312235959Z")
}

///|
test "pkix fixture: Let's Encrypt R10 carries v3 extensions including basicConstraints (CA)" {
  let cert = @pkix.parse_certificate(lets_encrypt_r10_der())
  // R10 is an intermediate CA so it must have basicConstraints with cA=TRUE.
  // We just check there are several extensions; the exact contents are out of
  // scope for the parser at this stage.
  assert_true(cert.tbs.extensions.length() >= 4)
  // Find basicConstraints OID 2.5.29.19.
  let basic_constraints_oid = @asn1.ObjectIdentifier::from_string("2.5.29.19")
  let mut found = false
  for ext in cert.tbs.extensions {
    if ext.oid == basic_constraints_oid {
      found = true
      @debug.assert_eq(ext.critical, true)
    }
  }
  @debug.assert_eq(found, true)
}

///|
test "pkix fixture: Let's Encrypt R10 DER roundtrip is byte-stable" {
  let der1 = lets_encrypt_r10_der()
  let cert = @pkix.parse_certificate(der1)
  let der2 = @pkix.serialize_certificate(cert)
  @debug.assert_eq(der1, der2)
}
