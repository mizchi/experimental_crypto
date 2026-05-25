// PKCS#8 (RFC 5208 / RFC 5958) PrivateKeyInfo and EncryptedPrivateKeyInfo.
// Depends on @asn1 for primitives, @pkix for AlgorithmIdentifier, @pem for PEM I/O.

///|
pub struct PrivateKeyInfo {
  version : Int // 0 (v1) or 1 (v2)
  algorithm : @pkix.AlgorithmIdentifier
  private_key : Bytes // contents of OCTET STRING privateKey (algorithm-specific)
  attributes : Array[@asn1.Element] // OPTIONAL [0] IMPLICIT Attributes
  public_key : @asn1.BitString? // v2 only: [1] IMPLICIT PublicKey
} derive(Show)

///|
pub struct EncryptedPrivateKeyInfo {
  algorithm : @pkix.AlgorithmIdentifier
  encrypted_data : Bytes
} derive(Eq, Show)

///|
pub suberror Pkcs8Error {
  Asn1(@asn1.Asn1Error)
  Pkix(@pkix.PkixError)
  Pem(@pem.PemError)
  InvalidVersion(Int)
  UnexpectedStructure(String)
} derive(Show)

///|
pub fn parse_der(der : Bytes) -> PrivateKeyInfo raise Pkcs8Error {
  ignore(der)
  abort("todo: parse PKCS#8 PrivateKeyInfo from DER")
}

///|
pub fn serialize_der(info : PrivateKeyInfo) -> Bytes {
  ignore(info)
  abort("todo: serialize PKCS#8 PrivateKeyInfo to DER")
}

///|
pub fn parse_encrypted_der(
  der : Bytes,
) -> EncryptedPrivateKeyInfo raise Pkcs8Error {
  ignore(der)
  abort("todo: parse EncryptedPrivateKeyInfo from DER")
}

///|
pub fn serialize_encrypted_der(enc : EncryptedPrivateKeyInfo) -> Bytes {
  ignore(enc)
  abort("todo: serialize EncryptedPrivateKeyInfo to DER")
}

///|
pub fn parse_pem(pem_str : String) -> PrivateKeyInfo raise Pkcs8Error {
  ignore(pem_str)
  abort("todo: parse PEM \"-----BEGIN PRIVATE KEY-----\" envelope")
}

///|
pub fn serialize_pem(info : PrivateKeyInfo) -> String {
  ignore(info)
  abort("todo: serialize PEM \"-----BEGIN PRIVATE KEY-----\" envelope")
}

///|
pub fn parse_encrypted_pem(
  pem_str : String,
) -> EncryptedPrivateKeyInfo raise Pkcs8Error {
  ignore(pem_str)
  abort("todo: parse PEM \"-----BEGIN ENCRYPTED PRIVATE KEY-----\" envelope")
}
