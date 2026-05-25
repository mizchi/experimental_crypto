///|
pub struct Params {
  log_n : Int // log2(N), 14..30 typical. N = 2^log_n
  r : Int // block size factor. usually 8
  p : Int // parallelization factor. usually 1
  dk_len : Int // derived key length in bytes
} derive(Eq, Show)

///|
/// Interactive baseline: log_n=15, r=8, p=1, dk_len=32.
pub fn Params::recommended_interactive() -> Params {
  { log_n: 15, r: 8, p: 1, dk_len: 32 }
}

///|
/// Sensitive baseline: log_n=20, r=8, p=1, dk_len=32.
pub fn Params::recommended_sensitive() -> Params {
  { log_n: 20, r: 8, p: 1, dk_len: 32 }
}

///|
pub suberror ScryptError {
  InvalidParams(String)
  OutputTooLong
} derive(Show)

///|
/// Derives a key of `params.dk_len` bytes from `password` and `salt` using
/// scrypt as specified in RFC 7914.
pub fn derive_key(
  params : Params,
  password : Bytes,
  salt : Bytes,
) -> Bytes raise ScryptError {
  ignore(params)
  ignore(password)
  ignore(salt)
  abort("todo: scrypt derive")
}

///|
/// Computes a PHC-encoded scrypt hash string of the form
/// `$7$<params>$<salt>$<hash>`.
pub fn hash_encoded(
  params : Params,
  password : Bytes,
  salt : Bytes,
) -> String raise ScryptError {
  ignore(params)
  ignore(password)
  ignore(salt)
  abort("todo: scrypt hash_encoded")
}

///|
/// Verifies `password` against a PHC-encoded scrypt string.
pub fn verify_encoded(
  encoded : String,
  password : Bytes,
) -> Unit raise ScryptError {
  ignore(encoded)
  ignore(password)
  abort("todo: scrypt verify_encoded")
}
