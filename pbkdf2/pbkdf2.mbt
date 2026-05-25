///|
pub enum HashAlg {
  Sha1
  Sha256
  Sha384
  Sha512
} derive(Eq, Show)

///|
pub suberror Pbkdf2Error {
  InvalidIterations
  OutputTooLong
  InvalidLength
} derive(Show)

///|
pub fn pbkdf2(
  hash : HashAlg,
  password : Bytes,
  salt : Bytes,
  iterations : Int,
  dk_len : Int,
) -> Bytes raise Pbkdf2Error {
  ignore(hash)
  ignore(password)
  ignore(salt)
  ignore(iterations)
  ignore(dk_len)
  abort("todo: PBKDF2 with PRF=HMAC-<hash>")
}
