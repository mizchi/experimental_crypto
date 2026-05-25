///|
pub enum Algorithm {
  Aes128Gcm
  Aes256Gcm
  ChaCha20Poly1305
  XChaCha20Poly1305
} derive(Eq, Show)

///|
pub fn Algorithm::key_size(self : Algorithm) -> Int {
  match self {
    Aes128Gcm => 16
    Aes256Gcm => 32
    ChaCha20Poly1305 => 32
    XChaCha20Poly1305 => 32
  }
}

///|
pub fn Algorithm::nonce_size(self : Algorithm) -> Int {
  match self {
    Aes128Gcm => 12
    Aes256Gcm => 12
    ChaCha20Poly1305 => 12
    XChaCha20Poly1305 => 24
  }
}

///|
pub fn Algorithm::tag_size(_self : Algorithm) -> Int {
  16
}

///|
pub suberror AeadError {
  InvalidKeySize(expected~ : Int, got~ : Int)
  InvalidNonceSize(expected~ : Int, got~ : Int)
  CiphertextTooShort
  AuthenticationFailed
  PlaintextTooLong
} derive(Show)

///|
/// Encrypts `plaintext` with `key`, `nonce`, and additional authenticated
/// data `aad`. The 16-byte authentication tag is appended to the returned
/// ciphertext.
pub fn seal(
  alg : Algorithm,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> Bytes raise AeadError {
  ignore(alg)
  ignore(key)
  ignore(nonce)
  ignore(aad)
  ignore(plaintext)
  abort("todo: AEAD seal")
}

///|
/// Decrypts `ciphertext_with_tag` (ciphertext followed by 16-byte tag) under
/// `key`, `nonce`, and `aad`. Raises `AuthenticationFailed` on tag mismatch.
pub fn open(
  alg : Algorithm,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext_with_tag : Bytes,
) -> Bytes raise AeadError {
  ignore(alg)
  ignore(key)
  ignore(nonce)
  ignore(aad)
  ignore(ciphertext_with_tag)
  abort("todo: AEAD open")
}

///|
/// Encrypts `plaintext` and returns the ciphertext and 16-byte tag as a
/// detached pair `(ciphertext, tag)`.
pub fn seal_detached(
  alg : Algorithm,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> (Bytes, Bytes) raise AeadError {
  ignore(alg)
  ignore(key)
  ignore(nonce)
  ignore(aad)
  ignore(plaintext)
  abort("todo: AEAD seal_detached")
}

///|
/// Decrypts `ciphertext` using a detached `tag`. Raises
/// `AuthenticationFailed` on tag mismatch.
pub fn open_detached(
  alg : Algorithm,
  key : Bytes,
  nonce : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
) -> Bytes raise AeadError {
  ignore(alg)
  ignore(key)
  ignore(nonce)
  ignore(aad)
  ignore(ciphertext)
  ignore(tag)
  abort("todo: AEAD open_detached")
}
