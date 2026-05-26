// PBES2 (RFC 8018 / PKCS#5 v2.1) decryption for EncryptedPrivateKeyInfo.
//
// Supported parameters:
//   keyDerivationFunc : id-PBKDF2 (1.2.840.113549.1.5.12)
//     prf : hmacWithSHA256 (1.2.840.113549.2.9). hmacWithSHA384/512 and
//           hmacWithSHA1 are recognized but rejected with UnsupportedKdf
//           because @pbkdf2 only implements SHA-256 today.
//   encryptionScheme : aes128-cbc (2.16.840.1.101.3.4.1.2) or
//                      aes256-cbc (2.16.840.1.101.3.4.1.42).
//
// `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256` produces this
// shape. The LibreSSL default PRF (HMAC-SHA1) is *not* supported here.
//
// Padding: PKCS#7 (RFC 8018 §6.1.1) is stripped after decryption. A wrong
// password produces an InvalidPadding error with overwhelming probability
// (~255/256 per ciphertext block); the remaining 1/256 case will reach
// parse_der and surface as Asn1 / UnexpectedStructure. Either way the
// caller cannot recover the plaintext without the correct password, so we
// don't separate the two cases.

///|
let oid_pbes2 : String = "1.2.840.113549.1.5.13"

///|
let oid_pbkdf2 : String = "1.2.840.113549.1.5.12"

///|
let oid_hmac_sha1 : String = "1.2.840.113549.2.7"

///|
let oid_hmac_sha256 : String = "1.2.840.113549.2.9"

///|
let oid_hmac_sha384 : String = "1.2.840.113549.2.10"

///|
let oid_hmac_sha512 : String = "1.2.840.113549.2.11"

///|
let oid_aes128_cbc : String = "2.16.840.1.101.3.4.1.2"

///|
let oid_aes192_cbc : String = "2.16.840.1.101.3.4.1.22"

///|
let oid_aes256_cbc : String = "2.16.840.1.101.3.4.1.42"

///|
fn oid_from_string(s : String) -> @asn1.ObjectIdentifier raise Pkcs8Error {
  @asn1.ObjectIdentifier::from_string(s) catch {
    e => raise Asn1(e)
  }
}

///|
fn parse_pbes2_params(
  params_bytes : Bytes,
) -> (Pbes2Kdf, Pbes2Cipher) raise Pkcs8Error {
  let elem = decode_der(params_bytes)
  let items = expect_sequence(elem)
  if items.length() != 2 {
    raise UnexpectedStructure("PBES2-params arity")
  }
  let kdf_alg = parse_algorithm_identifier_elem(items[0])
  let enc_alg = parse_algorithm_identifier_elem(items[1])
  let kdf = parse_pbkdf2(kdf_alg)
  let cipher = parse_encryption_scheme(enc_alg)
  (kdf, cipher)
}

///|
struct Pbes2Kdf {
  salt : Bytes
  iterations : Int
  key_length : Int? // OPTIONAL keyLength; encryption-scheme implies if absent.
  prf : @pbkdf2.HashAlg
}

///|
struct Pbes2Cipher {
  // We only support AES-{128,256}-CBC; the cipher is implied by key_size +
  // the AES-CBC entry point. Keeping this struct minimal so it does not
  // pretend to express more than we actually decrypt.
  key_size : Int // 16 or 32
  iv : Bytes
}

///|
fn parse_pbkdf2(
  kdf_alg : @pkix.AlgorithmIdentifier,
) -> Pbes2Kdf raise Pkcs8Error {
  if kdf_alg.algorithm != oid_from_string(oid_pbkdf2) {
    raise UnsupportedKdf(kdf_alg.algorithm)
  }
  let params_bytes = match kdf_alg.parameters {
    Some(b) => b
    None => raise UnexpectedStructure("PBKDF2 missing parameters")
  }
  let elem = decode_der(params_bytes)
  let items = expect_sequence(elem)
  if items.length() < 2 {
    raise UnexpectedStructure("PBKDF2-params: too few fields")
  }
  let salt = expect_octet_string(items[0])
  let iterations = expect_integer_small(items[1])
  if iterations < 1 {
    raise UnexpectedStructure("PBKDF2 iterations must be >= 1")
  }
  // Optional keyLength INTEGER and prf AlgorithmIdentifier. Both are
  // optional; if present they appear in this order.
  let mut key_length : Int? = None
  let mut prf : @pbkdf2.HashAlg = @pbkdf2.HashAlg::Sha1 // RFC default
  let mut i = 2
  while i < items.length() {
    let it = items[i]
    if it.tag == @asn1.tag_integer {
      key_length = Some(expect_integer_small(it))
    } else if it.tag == @asn1.tag_sequence {
      let prf_alg = parse_algorithm_identifier_elem(it)
      prf = match prf_alg.algorithm.to_string() {
        s if s == oid_hmac_sha1 => @pbkdf2.HashAlg::Sha1
        s if s == oid_hmac_sha256 => @pbkdf2.HashAlg::Sha256
        s if s == oid_hmac_sha384 => @pbkdf2.HashAlg::Sha384
        s if s == oid_hmac_sha512 => @pbkdf2.HashAlg::Sha512
        _ => raise UnsupportedKdf(prf_alg.algorithm)
      }
    } else {
      raise UnexpectedStructure("PBKDF2: unrecognized field")
    }
    i = i + 1
  }
  { salt, iterations, key_length, prf }
}

///|
fn parse_encryption_scheme(
  enc_alg : @pkix.AlgorithmIdentifier,
) -> Pbes2Cipher raise Pkcs8Error {
  let oid_str = enc_alg.algorithm.to_string()
  let key_size : Int = if oid_str == oid_aes128_cbc {
    16
  } else if oid_str == oid_aes256_cbc {
    32
  } else if oid_str == oid_aes192_cbc {
    // @aead's AES key schedule supports 16 and 32; AES-192 (24) is rejected.
    raise UnsupportedCipher(enc_alg.algorithm)
  } else {
    raise UnsupportedCipher(enc_alg.algorithm)
  }
  // For AES-CBC the parameters MUST be an OCTET STRING (SIZE(16)) carrying
  // the IV. parameters here are the raw DER bytes of that OCTET STRING
  // (per @pkix.AlgorithmIdentifier convention).
  let params_bytes = match enc_alg.parameters {
    Some(b) => b
    None => raise UnexpectedStructure("AES-CBC missing IV parameters")
  }
  let elem = decode_der(params_bytes)
  let iv = expect_octet_string(elem)
  if iv.length() != 16 {
    raise UnexpectedStructure(
      "AES-CBC IV must be 16 bytes, got " + iv.length().to_string(),
    )
  }
  { key_size, iv }
}

///|
fn strip_pkcs7_padding(data : Bytes) -> Bytes raise Pkcs8Error {
  let n = data.length()
  if n == 0 || n % 16 != 0 {
    raise InvalidPadding
  }
  let pad = data[n - 1].to_int()
  if pad < 1 || pad > 16 {
    raise InvalidPadding
  }
  // All trailing `pad` bytes must equal `pad`.
  for i in 0..<pad {
    if data[n - 1 - i].to_int() != pad {
      raise InvalidPadding
    }
  }
  Bytes::makei(n - pad, fn(i) { data[i] })
}

///|
/// Decrypt an `EncryptedPrivateKeyInfo` using the given password. Returns
/// the parsed inner `PrivateKeyInfo`.
///
/// Supports PBES2 (RFC 8018) with PBKDF2-HMAC-SHA256 (today the only PRF
/// `@pbkdf2` implements) and AES-128 / AES-256 CBC. A wrong password
/// surfaces as `InvalidPadding` in almost all cases; in the rare case the
/// (random) padding byte happens to be valid, the subsequent
/// `parse_der` will raise `Asn1` / `UnexpectedStructure` instead.
pub fn decrypt(
  enc : EncryptedPrivateKeyInfo,
  password : Bytes,
) -> PrivateKeyInfo raise Pkcs8Error {
  if enc.algorithm.algorithm != oid_from_string(oid_pbes2) {
    raise UnsupportedKdf(enc.algorithm.algorithm)
  }
  let params_bytes = match enc.algorithm.parameters {
    Some(b) => b
    None => raise UnexpectedStructure("PBES2 missing parameters")
  }
  let (kdf, cipher) = parse_pbes2_params(params_bytes)
  // keyLength from PBKDF2 params is optional; if absent, derive the AES
  // key length from the encryptionScheme.
  let dk_len = match kdf.key_length {
    Some(k) => k
    None => cipher.key_size
  }
  if dk_len != cipher.key_size {
    raise UnexpectedStructure(
      "PBKDF2 keyLength " +
      dk_len.to_string() +
      " disagrees with cipher key size " +
      cipher.key_size.to_string(),
    )
  }
  let key = @pbkdf2.pbkdf2(kdf.prf, password, kdf.salt, kdf.iterations, dk_len) catch {
    e => raise Pbkdf2(e)
  }
  let padded_plain = @aead.aes_cbc_decrypt(key, cipher.iv, enc.encrypted_data) catch {
    e => raise Aead(e)
  }
  let plain = strip_pkcs7_padding(padded_plain)
  parse_der(plain)
}

///|
/// Decrypt a PEM-wrapped EncryptedPrivateKeyInfo. The PEM label must be
/// `ENCRYPTED PRIVATE KEY` (RFC 7468 §11).
pub fn decrypt_pem(
  pem_str : String,
  password : Bytes,
) -> PrivateKeyInfo raise Pkcs8Error {
  let enc = parse_encrypted_pem(pem_str)
  decrypt(enc, password)
}
