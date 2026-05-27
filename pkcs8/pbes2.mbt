// PBES2 (RFC 8018 / PKCS#5 v2.1) decryption for EncryptedPrivateKeyInfo.
//
// Supported parameters:
//   keyDerivationFunc : id-PBKDF2 (1.2.840.113549.1.5.12)
//     prf : hmacWithSHA1/256/384/512
//   keyDerivationFunc : id-scrypt (1.3.6.1.4.1.11591.4.11)
//   encryptionScheme : aes128-cbc (2.16.840.1.101.3.4.1.2) or
//                      aes192-cbc (2.16.840.1.101.3.4.1.22) or
//                      aes256-cbc (2.16.840.1.101.3.4.1.42).
//
// `openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256` produces this
// shape. LibreSSL / OpenSSL HMAC-SHA1 defaults are also accepted.
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
let oid_scrypt : String = "1.3.6.1.4.1.11591.4.11"

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
  let kdf = parse_key_derivation_func(kdf_alg)
  let cipher = parse_encryption_scheme(enc_alg)
  (kdf, cipher)
}

///|
priv enum Pbes2Kdf {
  KdfPbkdf2(Pbkdf2Params)
  KdfScrypt(ScryptParams)
}

///|
priv struct Pbkdf2Params {
  salt : Bytes
  iterations : Int
  key_length : Int? // OPTIONAL keyLength; encryption-scheme implies if absent.
  prf : @pbkdf2.HashAlg
}

///|
priv struct ScryptParams {
  salt : Bytes
  log_n : Int
  r : Int
  p : Int
  key_length : Int?
}

///|
priv struct Pbes2Cipher {
  // We only support AES-{128,192,256}-CBC; the cipher is implied by key_size +
  // the AES-CBC entry point. Keeping this struct minimal so it does not
  // pretend to express more than we actually decrypt.
  key_size : Int // 16, 24, or 32
  iv : Bytes
}

///|
fn parse_key_derivation_func(
  kdf_alg : @pkix.AlgorithmIdentifier,
) -> Pbes2Kdf raise Pkcs8Error {
  let oid_str = kdf_alg.algorithm.to_string()
  if oid_str == oid_pbkdf2 {
    KdfPbkdf2(parse_pbkdf2(kdf_alg))
  } else if oid_str == oid_scrypt {
    KdfScrypt(parse_scrypt(kdf_alg))
  } else {
    raise UnsupportedKdf(kdf_alg.algorithm)
  }
}

///|
fn parse_pbkdf2(
  kdf_alg : @pkix.AlgorithmIdentifier,
) -> Pbkdf2Params raise Pkcs8Error {
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
  let mut saw_key_length = false
  let mut saw_prf = false
  let mut i = 2
  while i < items.length() {
    let it = items[i]
    if it.tag == @asn1.tag_integer {
      if saw_key_length {
        raise UnexpectedStructure("PBKDF2: duplicate keyLength")
      }
      let k = expect_integer_small(it)
      if k < 1 {
        raise UnexpectedStructure("PBKDF2 keyLength must be >= 1")
      }
      key_length = Some(k)
      saw_key_length = true
    } else if it.tag == @asn1.tag_sequence {
      if saw_prf {
        raise UnexpectedStructure("PBKDF2: duplicate prf")
      }
      let prf_alg = parse_algorithm_identifier_elem(it)
      validate_prf_params(prf_alg)
      prf = match prf_alg.algorithm.to_string() {
        s if s == oid_hmac_sha1 => @pbkdf2.HashAlg::Sha1
        s if s == oid_hmac_sha256 => @pbkdf2.HashAlg::Sha256
        s if s == oid_hmac_sha384 => @pbkdf2.HashAlg::Sha384
        s if s == oid_hmac_sha512 => @pbkdf2.HashAlg::Sha512
        _ => raise UnsupportedKdf(prf_alg.algorithm)
      }
      saw_prf = true
    } else {
      raise UnexpectedStructure("PBKDF2: unrecognized field")
    }
    i = i + 1
  }
  { salt, iterations, key_length, prf }
}

///|
fn parse_scrypt(
  kdf_alg : @pkix.AlgorithmIdentifier,
) -> ScryptParams raise Pkcs8Error {
  if kdf_alg.algorithm != oid_from_string(oid_scrypt) {
    raise UnsupportedKdf(kdf_alg.algorithm)
  }
  let params_bytes = match kdf_alg.parameters {
    Some(b) => b
    None => raise UnexpectedStructure("scrypt missing parameters")
  }
  let elem = decode_der(params_bytes)
  let items = expect_sequence(elem)
  if items.length() != 4 && items.length() != 5 {
    raise UnexpectedStructure("scrypt-params arity")
  }
  let salt = expect_octet_string(items[0])
  let cost = expect_integer_small(items[1])
  let r = expect_integer_small(items[2])
  let p = expect_integer_small(items[3])
  let key_length = if items.length() == 5 {
    let k = expect_integer_small(items[4])
    if k < 1 {
      raise UnexpectedStructure("scrypt keyLength must be >= 1")
    }
    Some(k)
  } else {
    None
  }
  if cost < 2 {
    raise UnexpectedStructure("scrypt costParameter must be >= 2")
  }
  if r < 1 {
    raise UnexpectedStructure("scrypt blockSize must be >= 1")
  }
  if p < 1 {
    raise UnexpectedStructure("scrypt parallelizationParameter must be >= 1")
  }
  let log_n = log2_power_of_two(cost)
  validate_scrypt_memory_cost(log_n, r)
  { salt, log_n, r, p, key_length }
}

///|
fn log2_power_of_two(n : Int) -> Int raise Pkcs8Error {
  let mut value = 1
  let mut log = 0
  while value < n {
    value = value << 1
    log = log + 1
  }
  if value != n {
    raise UnexpectedStructure("scrypt costParameter must be a power of two")
  }
  log
}

///|
fn validate_scrypt_memory_cost(log_n : Int, r : Int) -> Unit raise Pkcs8Error {
  // PBES2 inputs are attacker-controlled until the key decrypts. Keep the
  // scrypt V-buffer under 64 MiB so parsing an encrypted key cannot request
  // multi-GB scratch space. OpenSSL's common N=16384,r=8 default is 16 MiB.
  let memory_bytes : UInt64 = (1UL << log_n) * 128UL * r.to_uint64()
  if memory_bytes > 64UL * 1024UL * 1024UL {
    raise UnexpectedStructure("scrypt memory cost exceeds PBES2 limit")
  }
}

///|
fn validate_prf_params(
  alg : @pkix.AlgorithmIdentifier,
) -> Unit raise Pkcs8Error {
  match alg.parameters {
    None => ()
    Some(bytes) =>
      if !is_der_null(bytes) {
        raise UnexpectedStructure(
          "PBKDF2 PRF parameters must be NULL if present",
        )
      }
  }
}

///|
fn is_der_null(bytes : Bytes) -> Bool {
  try @asn1.decode_der(bytes) catch {
    _ => false
  } noraise {
    elem =>
      if elem.tag != @asn1.tag_null {
        false
      } else {
        match elem.value {
          Null => true
          _ => false
        }
      }
  }
}

///|
fn parse_encryption_scheme(
  enc_alg : @pkix.AlgorithmIdentifier,
) -> Pbes2Cipher raise Pkcs8Error {
  let oid_str = enc_alg.algorithm.to_string()
  let key_size : Int = if oid_str == oid_aes128_cbc {
    16
  } else if oid_str == oid_aes192_cbc {
    24
  } else if oid_str == oid_aes256_cbc {
    32
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
/// Supports PBES2 (RFC 8018) with PBKDF2-HMAC-SHA1/256/384/512 and
/// id-scrypt, plus AES-128 / AES-192 / AES-256 CBC. A wrong password
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
  // keyLength from KDF params is optional; if absent, derive the AES
  // key length from the encryptionScheme.
  let dk_len = kdf_key_length(kdf, cipher.key_size)
  if dk_len != cipher.key_size {
    raise UnexpectedStructure(
      "PBES2 keyLength " +
      dk_len.to_string() +
      " disagrees with cipher key size " +
      cipher.key_size.to_string(),
    )
  }
  let key = derive_pbes2_key(kdf, password, dk_len)
  let padded_plain = @aead.aes_cbc_decrypt(key, cipher.iv, enc.encrypted_data) catch {
    e => raise Aead(e)
  }
  let plain = strip_pkcs7_padding(padded_plain)
  parse_der(plain)
}

///|
fn kdf_key_length(kdf : Pbes2Kdf, cipher_key_size : Int) -> Int {
  match kdf {
    KdfPbkdf2(p) =>
      match p.key_length {
        Some(k) => k
        None => cipher_key_size
      }
    KdfScrypt(s) =>
      match s.key_length {
        Some(k) => k
        None => cipher_key_size
      }
  }
}

///|
fn derive_pbes2_key(
  kdf : Pbes2Kdf,
  password : Bytes,
  dk_len : Int,
) -> Bytes raise Pkcs8Error {
  match kdf {
    KdfPbkdf2(k) =>
      @pbkdf2.pbkdf2(k.prf, password, k.salt, k.iterations, dk_len) catch {
        e => raise Pbkdf2(e)
      }
    KdfScrypt(k) => {
      let params : @scrypt.Params = { log_n: k.log_n, r: k.r, p: k.p, dk_len }
      @scrypt.derive_key(params, password, k.salt) catch {
        e => raise Scrypt(e)
      }
    }
  }
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
