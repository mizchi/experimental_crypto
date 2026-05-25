///|
pub enum HashAlg {
  Sha256
  Sha384
  Sha512
} derive(Eq, Show)

///|
pub suberror HkdfError {
  OutputTooLong
  InvalidLength
} derive(Show)

///|
pub fn output_size(hash : HashAlg) -> Int {
  match hash {
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
pub fn extract(hash : HashAlg, salt : Bytes, ikm : Bytes) -> Bytes {
  ignore(hash)
  ignore(salt)
  ignore(ikm)
  abort("todo: HKDF-Extract")
}

///|
pub fn expand(
  hash : HashAlg,
  prk : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes raise HkdfError {
  ignore(hash)
  ignore(prk)
  ignore(info)
  ignore(length)
  abort("todo: HKDF-Expand")
}

///|
pub fn hkdf(
  hash : HashAlg,
  salt : Bytes,
  ikm : Bytes,
  info : Bytes,
  length : Int,
) -> Bytes raise HkdfError {
  ignore(hash)
  ignore(salt)
  ignore(ikm)
  ignore(info)
  ignore(length)
  abort("todo: HKDF Extract-then-Expand")
}
