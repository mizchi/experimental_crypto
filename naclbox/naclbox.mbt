// libsodium-compatible NaCl `secretbox` and `box` over the
// `crypto_box_curve25519xchacha20poly1305` construction.
//
//   secretbox = XChaCha20-Poly1305 with the 16-byte tag prepended to the
//               ciphertext (libsodium's standard layout).
//   box       = X25519 ECDH → HChaCha20(shared, zeros_16) → secretbox.
//
// This module composes `mizchi/aead` (XChaCha20-Poly1305 + HChaCha20) and
// `mizchi/x25519` (clamped scalar mult on Curve25519); it does not implement
// any cryptographic primitive itself.

///|
pub suberror NaclBoxError {
  InvalidKeyLength(Int)
  InvalidNonceLength(Int)
  InvalidCiphertextLength(Int)
  AuthenticationFailed
  KeyGenerationError(String)
} derive(Show)

///|
pub(all) struct KeyPair {
  public_key : @x25519.PublicKey
  secret_key : @x25519.PrivateKey
}

///|
/// Pre-computed shared key for repeated `box_afternm` / `box_open_afternm`.
/// 32 bytes derived from HChaCha20(X25519_ECDH(sk, pk), zeros_16).
pub(all) struct SharedKey {
  bytes : FixedArray[Byte]
}

///|
/// Derive a Curve25519 keypair from a 32-byte seed. The seed is interpreted
/// as the raw private-scalar input and clamped per RFC 7748 §5.
pub fn KeyPair::from_seed(seed_32 : Bytes) -> KeyPair raise NaclBoxError {
  if seed_32.length() != 32 {
    raise InvalidKeyLength(seed_32.length())
  }
  let sk = try? @x25519.PrivateKey::from_bytes(seed_32)
  match sk {
    Err(e) => raise KeyGenerationError(e.to_string())
    Ok(sk) => { public_key: sk.public_key(), secret_key: sk }
  }
}

///|
/// Symmetric authenticated encryption (libsodium `secretbox_xchacha20poly1305`).
///
/// Layout of returned ciphertext: `tag(16) || encrypted_message`.
/// `key` must be 32 bytes, `nonce` 24 bytes.
pub fn secretbox(
  key : Bytes,
  nonce : Bytes,
  message : Bytes,
) -> Bytes raise NaclBoxError {
  if key.length() != 32 {
    raise InvalidKeyLength(key.length())
  }
  if nonce.length() != 24 {
    raise InvalidNonceLength(nonce.length())
  }
  let aead_result : Result[(Bytes, Bytes), @aead.AeadError] = try? @aead.seal_detached(
    @aead.XChaCha20Poly1305,
    key,
    nonce,
    b"",
    message,
  )
  match aead_result {
    Err(e) => raise KeyGenerationError(e.to_string())
    Ok((ct, tag)) =>
      // libsodium layout: tag || ciphertext.
      Bytes::makei(tag.length() + ct.length(), fn(i) {
        if i < tag.length() {
          tag[i]
        } else {
          ct[i - tag.length()]
        }
      })
  }
}

///|
/// Inverse of `secretbox`. Expects `tag(16) || ciphertext` layout. Raises
/// `AuthenticationFailed` if the tag does not match.
pub fn secretbox_open(
  key : Bytes,
  nonce : Bytes,
  ciphertext : Bytes,
) -> Bytes raise NaclBoxError {
  if key.length() != 32 {
    raise InvalidKeyLength(key.length())
  }
  if nonce.length() != 24 {
    raise InvalidNonceLength(nonce.length())
  }
  if ciphertext.length() < 16 {
    raise InvalidCiphertextLength(ciphertext.length())
  }
  let tag = Bytes::makei(16, fn(i) { ciphertext[i] })
  let ct = Bytes::makei(ciphertext.length() - 16, fn(i) { ciphertext[i + 16] })
  let result : Result[Bytes, @aead.AeadError] = try? @aead.open_detached(
    @aead.XChaCha20Poly1305,
    key,
    nonce,
    b"",
    ct,
    tag,
  )
  match result {
    Ok(pt) => pt
    Err(@aead.AuthenticationFailed) => raise AuthenticationFailed
    Err(e) => raise KeyGenerationError(e.to_string())
  }
}

///|
/// Compute the libsodium `crypto_box_beforenm` shared key:
/// `HChaCha20(X25519(sk, pk), zeros_16)`. The 16-byte zero "nonce" matches
/// the libsodium convention so the resulting `SharedKey` matches what
/// `crypto_box_curve25519xchacha20poly1305_beforenm` produces.
pub fn box_beforenm(
  recipient_pubkey : @x25519.PublicKey,
  sender_privkey : @x25519.PrivateKey,
) -> SharedKey raise NaclBoxError {
  let ecdh_result : Result[@x25519.SharedSecret, @x25519.X25519Error] = try? @x25519.diffie_hellman(
    sender_privkey, recipient_pubkey,
  )
  match ecdh_result {
    Err(e) => raise KeyGenerationError(e.to_string())
    Ok(shared) => {
      // HChaCha20 with a 16-byte all-zero "nonce" — libsodium convention.
      let zeros16 = Bytes::makei(16, fn(_) { b'\x00' })
      let sub_key_bytes = @aead.hchacha20(shared.to_bytes(), zeros16)
      let fa = FixedArray::make(32, b'\x00')
      for i in 0..<32 {
        fa[i] = sub_key_bytes[i]
      }
      { bytes: fa }
    }
  }
}

///|
/// Encrypt `message` with the pre-computed shared key.
/// Output layout matches `secretbox`: `tag(16) || ciphertext`.
pub fn box_afternm(
  shared_key : SharedKey,
  nonce : Bytes,
  message : Bytes,
) -> Bytes raise NaclBoxError {
  let key = Bytes::makei(32, fn(i) { shared_key.bytes[i] })
  secretbox(key, nonce, message)
}

///|
/// Inverse of `box_afternm`.
pub fn box_open_afternm(
  shared_key : SharedKey,
  nonce : Bytes,
  ciphertext : Bytes,
) -> Bytes raise NaclBoxError {
  let key = Bytes::makei(32, fn(i) { shared_key.bytes[i] })
  secretbox_open(key, nonce, ciphertext)
}

///|
/// Public-key authenticated encryption. Convenience wrapper around
/// `box_beforenm` + `box_afternm`. For repeated messages between the same
/// peers, derive a `SharedKey` once and reuse it.
pub fn box_(
  recipient_pubkey : @x25519.PublicKey,
  sender_privkey : @x25519.PrivateKey,
  nonce : Bytes,
  message : Bytes,
) -> Bytes raise NaclBoxError {
  let sk = box_beforenm(recipient_pubkey, sender_privkey)
  box_afternm(sk, nonce, message)
}

///|
/// Inverse of `box_`.
pub fn box_open(
  sender_pubkey : @x25519.PublicKey,
  recipient_privkey : @x25519.PrivateKey,
  nonce : Bytes,
  ciphertext : Bytes,
) -> Bytes raise NaclBoxError {
  let sk = box_beforenm(sender_pubkey, recipient_privkey)
  box_open_afternm(sk, nonce, ciphertext)
}

///|
/// Expose the 32 raw bytes of a `SharedKey`. Exposing the shared key gives
/// an attacker the same power as the underlying ECDH output; treat it like
/// a private key.
pub fn SharedKey::to_bytes(self : SharedKey) -> Bytes {
  Bytes::makei(32, fn(i) { self.bytes[i] })
}
