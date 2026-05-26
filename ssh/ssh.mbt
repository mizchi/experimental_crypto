// mizchi/ssh — SSH signing / verification compatible with OpenSSH's
// `ssh-keygen -Y sign / -Y verify` flow. Ed25519-only.
//
// References:
//   - PROTOCOL.sshsig (openssh-portable)
//   - RFC 4251 §5 (SSH binary types)
//   - RFC 8709 (ssh-ed25519 public key + signature wire format)

///|
/// Verify an armored SSHSIG over `message` using whatever public key is
/// embedded in the signature. Returns true iff:
///   - the embedded pubkey is supported (Ed25519, ECDSA-P256/P384, ssh-rsa
///     with rsa-sha2-256/512)
///   - the signature is valid for `message` under that key
///   - the SSHSIG namespace matches `namespace` (default "git")
///
/// The pubkey is returned alongside so the caller can do its own
/// identity binding (e.g. lookup in an allowed_signers map).
pub fn verify_armor_anonymous(
  armor : String,
  message : Bytes,
  namespace? : String = "git",
) -> (SshPublicKey, String) raise SshError {
  let blob = decode_sshsig_armor(armor)
  let sig = decode_sshsig_blob(blob)
  if sig.namespace != namespace {
    raise InvalidSignature
  }
  let signed_data = compute_signed_data(
    sig.namespace,
    sig.hash_algorithm,
    message,
  )
  let ok = verify_signed_data(sig.publickey, signed_data, sig.signature_blob)
  if not(ok) {
    raise InvalidSignature
  }
  (sig.publickey, sig.namespace)
}

///|
/// Verify an armored SSHSIG over `message` against a caller-supplied
/// pubkey. The signature's embedded pubkey MUST match `expected_pubkey`.
/// Returns true on success, false otherwise (does not raise on mismatch).
pub fn verify_armor(
  armor : String,
  message : Bytes,
  expected_pubkey : @ed25519.PublicKey,
  namespace? : String = "git",
) -> Bool raise SshError {
  let blob = decode_sshsig_armor(armor)
  let sig = decode_sshsig_blob(blob)
  if sig.namespace != namespace {
    return false
  }
  match sig.publickey {
    Ed25519(pk) => {
      if pk.to_bytes() != expected_pubkey.to_bytes() {
        return false
      }
      let signed_data = compute_signed_data(
        sig.namespace,
        sig.hash_algorithm,
        message,
      )
      verify_signed_data(sig.publickey, signed_data, sig.signature_blob)
    }
    _ => false
  }
}

///|
/// Same as verify_armor but accepts any SshPublicKey (so callers can hand
/// in an Ed25519, P-256, P-384, or RSA key and let the library pick).
pub fn verify_armor_with(
  armor : String,
  message : Bytes,
  expected_pubkey : SshPublicKey,
  namespace? : String = "git",
) -> Bool raise SshError {
  let blob = decode_sshsig_armor(armor)
  let sig = decode_sshsig_blob(blob)
  if sig.namespace != namespace {
    return false
  }
  if not(pubkeys_equal(sig.publickey, expected_pubkey)) {
    return false
  }
  let signed_data = compute_signed_data(
    sig.namespace,
    sig.hash_algorithm,
    message,
  )
  verify_signed_data(sig.publickey, signed_data, sig.signature_blob)
}

///|
fn pubkeys_equal(a : SshPublicKey, b : SshPublicKey) -> Bool {
  match (a, b) {
    (Ed25519(x), Ed25519(y)) => x.to_bytes() == y.to_bytes()
    (P256(x), P256(y)) => x.to_uncompressed() == y.to_uncompressed()
    (P384(x), P384(y)) => x.to_uncompressed() == y.to_uncompressed()
    (Rsa(x), Rsa(y)) =>
      x.n == y.n && x.e == y.e && x.n_bytes_len == y.n_bytes_len
    _ => false
  }
}

///|
// Dispatch the inner signature verification based on the embedded pubkey
// kind. `signed_data` is the SSHSIG signed-data blob (already includes the
// H(message) prefix).
fn verify_signed_data(
  pubkey : SshPublicKey,
  signed_data : Bytes,
  signature_blob : Bytes,
) -> Bool raise SshError {
  // Peek the inner algorithm name to decide how to interpret the rest.
  let reader = WireReader::new(signature_blob)
  let algo = reader.read_string_ascii()
  let raw = reader.read_string()
  if not(reader.is_empty()) {
    raise InvalidEncoding("trailing bytes after signature blob")
  }
  match (pubkey, algo) {
    (Ed25519(pk), _) => {
      if algo != ed25519_algo {
        raise InvalidEncoding("ed25519 pubkey but sig algo " + algo)
      }
      if raw.length() != 64 {
        raise InvalidEncoding("ed25519 signature must be 64 bytes")
      }
      pk.verify(signed_data, raw)
    }
    (P256(pk), _) => {
      if algo != ecdsa_p256_algo {
        raise InvalidEncoding("p256 pubkey but sig algo " + algo)
      }
      // The 'raw' content is itself a wire-format pair (mpint r, mpint s).
      let raw_sig = ecdsa_inner_to_raw(raw, 32)
      @p256.verify(pk, signed_data, raw_sig, @p256.SignatureFormat::Raw) catch {
        _ => false
      }
    }
    (P384(pk), _) => {
      if algo != ecdsa_p384_algo {
        raise InvalidEncoding("p384 pubkey but sig algo " + algo)
      }
      let raw_sig = ecdsa_inner_to_raw(raw, 48)
      @p384.verify(pk, signed_data, raw_sig, @p384.SignatureFormat::Raw) catch {
        _ => false
      }
    }
    (Rsa(pk), _) => {
      // The inner sig is the modulus-length RSASSA-PKCS1-v1_5 signed value.
      // Algorithm name picks the hash: rsa-sha2-256 / rsa-sha2-512. Plain
      // "ssh-rsa" (SHA-1) is intentionally NOT accepted — deprecated by
      // OpenSSH 9.0.
      let hash_alg = if algo == rsa_sha256_algo {
        @rsa.HashAlg::Sha256
      } else if algo == rsa_sha512_algo {
        @rsa.HashAlg::Sha512
      } else {
        raise UnsupportedAlgorithm(algo)
      }
      pk.verify(signed_data, raw, hash_alg) catch { _ => false }
    }
  }
}

///|
// Convert the SSH ECDSA signature inner blob `(mpint r, mpint s)` to the
// fixed-size big-endian `r || s` representation expected by @p256 /
// @p384's Raw signature format.
fn ecdsa_inner_to_raw(inner : Bytes, half_len : Int) -> Bytes raise SshError {
  let reader = WireReader::new(inner)
  let r_bytes = reader.read_string()
  let s_bytes = reader.read_string()
  if not(reader.is_empty()) {
    raise InvalidEncoding("trailing bytes after ECDSA (r, s)")
  }
  let r_mag = mpint_magnitude(r_bytes)
  let s_mag = mpint_magnitude(s_bytes)
  let r_padded = left_pad(r_mag, half_len)
  let s_padded = left_pad(s_mag, half_len)
  Bytes::makei(half_len * 2, fn(i) {
    if i < half_len {
      r_padded[i]
    } else {
      s_padded[i - half_len]
    }
  })
}

///|
/// Produce an armored SSHSIG over `message` using an Ed25519 private key.
/// `namespace` defaults to "git" (what `ssh-keygen -Y sign -n git` uses).
/// `hash_algorithm` defaults to "sha512", matching ssh-keygen's choice
/// for Ed25519 (PROTOCOL.sshsig: "sha512 is suggested when the signature
/// is over a hash of large content").
pub fn sign_armor(
  privkey : @ed25519.PrivateKey,
  message : Bytes,
  namespace? : String = "git",
  hash_algorithm? : String = "sha512",
) -> String raise SshError {
  let signed_data = compute_signed_data(namespace, hash_algorithm, message)
  let raw_sig = privkey.sign(signed_data)
  let pubkey_blob = serialize_ed25519_pubkey(privkey.public_key())
  // Build inner signature wire blob: "ssh-ed25519" string + raw sig string.
  let inner = WireWriter::new()
  inner.write_string_ascii(ed25519_algo)
  inner.write_string(raw_sig)
  let inner_blob = inner.to_bytes()
  // Build the outer SSHSIG blob.
  let w = WireWriter::new()
  w.write_bytes_raw(sshsig_magic)
  w.write_uint32(sshsig_version)
  w.write_string(pubkey_blob)
  w.write_string_ascii(namespace)
  w.write_string(b"")
  w.write_string_ascii(hash_algorithm)
  w.write_string(inner_blob)
  encode_sshsig_armor(w.to_bytes())
}

///|
// Inside a wire-format Ed25519 signature blob: algorithm string + 64 raw
// signature bytes. Used both inside SSHSIG (where the outer envelope's
// `signature` field is itself a wire-format blob) and on SSH userauth.
fn parse_ed25519_sig_blob(blob : Bytes) -> Bytes raise SshError {
  let reader = WireReader::new(blob)
  let algo = reader.read_string_ascii()
  if algo != ed25519_algo {
    raise UnsupportedAlgorithm(algo)
  }
  let sig = reader.read_string()
  if sig.length() != 64 {
    raise InvalidEncoding(
      "ssh-ed25519 signature must be 64 bytes, got " + sig.length().to_string(),
    )
  }
  if not(reader.is_empty()) {
    raise InvalidEncoding("trailing bytes after ssh-ed25519 signature")
  }
  sig
}
