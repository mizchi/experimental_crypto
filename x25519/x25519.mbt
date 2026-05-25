///|
pub struct PrivateKey {
  bytes : FixedArray[Byte] // 32 bytes, clamped per RFC 7748 §5
} derive(Eq)

///|
pub impl Show for PrivateKey with fn output(self, logger) {
  ignore(self)
  logger.write_string("PrivateKey(<redacted>)")
}

///|
pub struct PublicKey {
  bytes : FixedArray[Byte] // 32 bytes
} derive(Eq, Show)

///|
pub struct SharedSecret {
  bytes : FixedArray[Byte] // 32 bytes
} derive(Eq)

///|
pub impl Show for SharedSecret with fn output(self, logger) {
  ignore(self)
  logger.write_string("SharedSecret(<redacted>)")
}

///|
pub suberror X25519Error {
  InvalidScalarLength(Int)
  InvalidPointLength(Int)
  AllZeroSharedSecret // small-subgroup attack signal
} derive(Show)

///|
/// Builds a private key from a 32-byte scalar. The bytes are clamped per
/// RFC 7748 §5 before being stored.
pub fn PrivateKey::from_bytes(b : Bytes) -> PrivateKey raise X25519Error {
  ignore(b)
  abort("todo: PrivateKey::from_bytes")
}

///|
pub fn PrivateKey::to_bytes(self : PrivateKey) -> Bytes {
  ignore(self)
  abort("todo: PrivateKey::to_bytes")
}

///|
/// Derives a private key from 32 bytes of fresh random data. The caller is
/// responsible for sourcing entropy.
pub fn PrivateKey::from_random(
  random_32_bytes : Bytes,
) -> PrivateKey raise X25519Error {
  ignore(random_32_bytes)
  abort("todo: PrivateKey::from_random")
}

///|
pub fn PrivateKey::public_key(self : PrivateKey) -> PublicKey {
  ignore(self)
  abort("todo: PrivateKey::public_key")
}

///|
pub fn PublicKey::from_bytes(b : Bytes) -> PublicKey raise X25519Error {
  ignore(b)
  abort("todo: PublicKey::from_bytes")
}

///|
pub fn PublicKey::to_bytes(self : PublicKey) -> Bytes {
  ignore(self)
  abort("todo: PublicKey::to_bytes")
}

///|
/// Performs the X25519 scalar multiplication. Raises `AllZeroSharedSecret`
/// when the result is the all-zero point, which signals a small-subgroup
/// peer key.
pub fn diffie_hellman(
  sk : PrivateKey,
  pk : PublicKey,
) -> SharedSecret raise X25519Error {
  ignore(sk)
  ignore(pk)
  abort("todo: X25519 scalar multiplication")
}
