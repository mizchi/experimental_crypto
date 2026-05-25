///|
pub enum Variant {
  Argon2d
  Argon2i
  Argon2id
} derive(Eq, Show)

///|
pub struct Params {
  variant : Variant
  m_cost : Int // memory cost in KiB. >= 8 * parallelism
  t_cost : Int // time cost (number of passes). >= 1
  parallelism : Int // 1 .. 2^24 - 1
  output_len : Int // 4 .. 2^32 - 1
} derive(Eq, Show)

///|
/// OWASP 2024 interactive baseline: argon2id, m=19 MiB, t=2, p=1, out=32.
pub fn Params::recommended_interactive() -> Params {
  {
    variant: Argon2id,
    m_cost: 19 * 1024,
    t_cost: 2,
    parallelism: 1,
    output_len: 32,
  }
}

///|
/// Sensitive baseline: argon2id, m=64 MiB, t=3, p=4, out=32.
pub fn Params::recommended_sensitive() -> Params {
  {
    variant: Argon2id,
    m_cost: 64 * 1024,
    t_cost: 3,
    parallelism: 4,
    output_len: 32,
  }
}

///|
/// Default argon2id parameters (alias of `recommended_interactive`).
pub fn Params::default_id() -> Params {
  Params::recommended_interactive()
}

///|
pub suberror Argon2Error {
  InvalidParams(String)
  InvalidOutputLength
  InvalidEncoded(String)
  VerifyFailed
} derive(Show)

///|
/// Computes the raw Argon2 output for `password` and `salt` under `params`.
pub fn hash_raw(
  params : Params,
  password : Bytes,
  salt : Bytes,
) -> Bytes raise Argon2Error {
  ignore(params)
  ignore(password)
  ignore(salt)
  abort("todo: Argon2 hash_raw")
}

///|
/// Computes the raw Argon2 output with optional associated data `ad` and
/// secret key `secret` as defined by RFC 9106.
pub fn hash_raw_with_ad(
  params : Params,
  password : Bytes,
  salt : Bytes,
  ad : Bytes,
  secret : Bytes,
) -> Bytes raise Argon2Error {
  ignore(params)
  ignore(password)
  ignore(salt)
  ignore(ad)
  ignore(secret)
  abort("todo: Argon2 hash_raw_with_ad")
}

///|
/// Computes a PHC-encoded Argon2 hash string of the form
/// `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`.
pub fn hash_encoded(
  params : Params,
  password : Bytes,
  salt : Bytes,
) -> String raise Argon2Error {
  ignore(params)
  ignore(password)
  ignore(salt)
  abort("todo: Argon2 hash_encoded")
}

///|
/// Verifies `password` against a PHC-encoded Argon2 string. Raises
/// `VerifyFailed` on mismatch and `InvalidEncoded` on malformed input.
pub fn verify_encoded(
  encoded : String,
  password : Bytes,
) -> Unit raise Argon2Error {
  ignore(encoded)
  ignore(password)
  abort("todo: Argon2 verify_encoded")
}
