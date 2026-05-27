// JS-target PBES2 oracle test against Node.js `crypto` for id-scrypt +
// AES-256-CBC encrypted PKCS#8.

///|
extern "js" fn node_scrypt_aes256_cbc_encrypt(
  password : Bytes,
  salt : Bytes,
  iv : Bytes,
  plaintext : Bytes,
) -> Bytes =
  #| (password, salt, iv, plaintext) => {
  #|   const crypto = globalThis.process.getBuiltinModule("node:crypto")
  #|   const key = crypto.scryptSync(password, salt, 32, {
  #|     N: 16,
  #|     r: 1,
  #|     p: 1,
  #|     maxmem: 64 * 1024 * 1024,
  #|   })
  #|   const cipher = crypto.createCipheriv("aes-256-cbc", key, iv)
  #|   return new Uint8Array(Buffer.concat([
  #|     cipher.update(plaintext),
  #|     cipher.final(),
  #|   ]))
  #| }

///|
fn oracle_oid(s : String) -> @asn1.ObjectIdentifier raise {
  @asn1.ObjectIdentifier::from_string(s)
}

///|
fn oracle_der_null() -> Bytes {
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_null, Null))
}

///|
fn oracle_alg_elem(oid_s : String, params : Bytes?) -> @asn1.Element raise {
  @pkix.algorithm_identifier_to_element({
    algorithm: oracle_oid(oid_s),
    parameters: params,
  })
}

///|
fn oracle_private_key_info() -> @pkcs8.PrivateKeyInfo raise {
  let inner = @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([@asn1.Element::new(@asn1.tag_integer, Integer(b"\x00"))]),
    ),
  )
  {
    version: 0,
    algorithm: {
      algorithm: oracle_oid("1.2.840.113549.1.1.1"),
      parameters: Some(oracle_der_null()),
    },
    private_key: inner,
    attributes: [],
    public_key: None,
  }
}

///|
fn oracle_scrypt_params() -> Bytes {
  @asn1.encode_der(
    @asn1.Element::new(
      @asn1.tag_sequence,
      Sequence([
        @asn1.Element::new(@asn1.tag_octet_string, OctetString(b"salt")),
        @asn1.Element::new(@asn1.tag_integer, Integer(b"\x10")),
        @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
        @asn1.Element::new(@asn1.tag_integer, Integer(b"\x01")),
        @asn1.Element::new(@asn1.tag_integer, Integer(b"\x20")),
      ]),
    ),
  )
}

///|
fn oracle_pbes2_scrypt_aes256_params(iv : Bytes) -> Bytes raise {
  let kdf = oracle_alg_elem(
    "1.3.6.1.4.1.11591.4.11",
    Some(oracle_scrypt_params()),
  )
  let enc = oracle_alg_elem(
    "2.16.840.1.101.3.4.1.42",
    Some(
      @asn1.encode_der(
        @asn1.Element::new(@asn1.tag_octet_string, OctetString(iv)),
      ),
    ),
  )
  @asn1.encode_der(@asn1.Element::new(@asn1.tag_sequence, Sequence([kdf, enc])))
}

///|
test "pbes2 oracle js: decrypts Node crypto id-scrypt + AES-256-CBC fixture" {
  let password : Bytes = b"pw"
  let iv = Bytes::makei(16, fn(i) { (i + 32).to_byte() })
  let expected = oracle_private_key_info()
  let plain = @pkcs8.serialize_der(expected)
  let encrypted_data = node_scrypt_aes256_cbc_encrypt(
    password, b"salt", iv, plain,
  )
  let enc : @pkcs8.EncryptedPrivateKeyInfo = {
    algorithm: {
      algorithm: oracle_oid("1.2.840.113549.1.5.13"),
      parameters: Some(oracle_pbes2_scrypt_aes256_params(iv)),
    },
    encrypted_data,
  }
  let got = @pkcs8.decrypt(enc, password)
  @debug.assert_eq(got.private_key, expected.private_key)
  @debug.assert_eq(got.algorithm.algorithm, expected.algorithm.algorithm)
}
