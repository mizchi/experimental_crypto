// Asymmetric key-pair generation for the curves the library supports — the
// `generateKey` half of a SubtleCrypto / WebAuthn key store.
//
// The core curve modules are deliberately RNG-free (they take key material as
// input); this module is the one place that pulls from the platform CSPRNG
// (`mizchi/experimental_crypto/getrandom`) and turns it into a valid key pair.
//
// Each `*_keypair` returns `(private_bytes, public_bytes)`:
//   - P-256 / P-384: private = big-endian scalar (32 / 48 bytes), public =
//     uncompressed SEC1 point (65 / 97 bytes).
//   - Ed25519: private = 32-byte seed, public = 32-byte key.
//   - X25519: private = 32-byte clamped scalar, public = 32-byte u-coordinate.
//
// RSA key generation (prime search) is not yet implemented; see issue #24.

///|
pub suberror KeygenError {
  Random(@getrandom.GetrandomError)
  /// Rejection sampling failed to find a valid scalar within the retry budget
  /// (astronomically unlikely for the NIST curves — would indicate a broken
  /// RNG returning a constant).
  RejectionExhausted
} derive(Debug)

///|
fn draw(n : Int) -> Bytes raise KeygenError {
  @getrandom.bytes(n) catch {
    e => raise Random(e)
  }
}

///|
/// Generate a P-256 key pair. The scalar is rejection-sampled in `[1, n)` from
/// the CSPRNG (a draw is rejected only if it is 0 or ≥ n, with probability
/// ~2^-32, so this almost always succeeds on the first draw).
pub fn p256_keypair() -> (Bytes, Bytes) raise KeygenError {
  for _attempt in 0..<64 {
    let scalar = draw(32)
    let sk = try? @p256.PrivateKey::from_bytes(scalar)
    match sk {
      Ok(sk) => return (scalar, sk.public_key().to_uncompressed())
      Err(_) => continue
    }
  }
  raise RejectionExhausted
}

///|
/// Generate a P-384 key pair (rejection-sampled scalar in `[1, n)`).
pub fn p384_keypair() -> (Bytes, Bytes) raise KeygenError {
  for _attempt in 0..<64 {
    let scalar = draw(48)
    let sk = try? @p384.PrivateKey::from_bytes(scalar)
    match sk {
      Ok(sk) => return (scalar, sk.public_key().to_uncompressed())
      Err(_) => continue
    }
  }
  raise RejectionExhausted
}

///|
/// Generate an Ed25519 key pair. Any 32 random bytes are a valid seed
/// (RFC 8032 §5.1.5), so no rejection is needed.
pub fn ed25519_keypair() -> (Bytes, Bytes) raise KeygenError {
  let seed = draw(32)
  let sk = @ed25519.PrivateKey::from_seed(seed) catch {
    _ => raise RejectionExhausted
  }
  (seed, sk.public_key().to_bytes())
}

///|
/// Generate an X25519 key pair. The 32 random bytes are clamped per RFC 7748,
/// so every draw is valid.
pub fn x25519_keypair() -> (Bytes, Bytes) raise KeygenError {
  let secret = draw(32)
  let sk = @x25519.PrivateKey::from_random(secret) catch {
    _ => raise RejectionExhausted
  }
  (secret, sk.public_key().to_bytes())
}
