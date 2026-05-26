// mizchi/ssh — SSHSIG-style signing / verification for Git signing flows.
// This package is not a full OpenSSH verifier.
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
///   - the SSHSIG sig_namespace matches `sig_namespace` (default "git")
///
/// The pubkey is returned alongside so the caller can do its own
/// identity binding (e.g. lookup in an allowed_signers map).
pub fn verify_armor_anonymous(
  armor : String,
  message : Bytes,
  sig_namespace? : String = "git",
) -> (SshPublicKey, String) raise SshError {
  validate_namespace(sig_namespace)
  let blob = decode_sshsig_armor(armor)
  let sig = decode_sshsig_blob(blob)
  if sig.sig_namespace != sig_namespace {
    raise InvalidSignature
  }
  let signed_data = compute_signed_data(
    sig.sig_namespace,
    sig.hash_algorithm,
    message,
  )
  let ok = verify_signed_data(sig.publickey, signed_data, sig.signature_blob)
  if !ok {
    raise InvalidSignature
  }
  (sig.publickey, sig.sig_namespace)
}

///|
/// Verify an armored SSHSIG over `message` against a caller-supplied
/// pubkey. The signature's embedded pubkey MUST match `expected_pubkey`.
/// Returns true on success, false otherwise (does not raise on mismatch).
pub fn verify_armor(
  armor : String,
  message : Bytes,
  expected_pubkey : @ed25519.PublicKey,
  sig_namespace? : String = "git",
) -> Bool raise SshError {
  validate_namespace(sig_namespace)
  let blob = decode_sshsig_armor(armor)
  let sig = decode_sshsig_blob(blob)
  if sig.sig_namespace != sig_namespace {
    return false
  }
  match sig.publickey {
    Ed25519(pk) => {
      if pk.to_bytes() != expected_pubkey.to_bytes() {
        return false
      }
      let signed_data = compute_signed_data(
        sig.sig_namespace,
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
  sig_namespace? : String = "git",
) -> Bool raise SshError {
  validate_namespace(sig_namespace)
  let blob = decode_sshsig_armor(armor)
  let sig = decode_sshsig_blob(blob)
  if sig.sig_namespace != sig_namespace {
    return false
  }
  if !pubkeys_equal(sig.publickey, expected_pubkey) {
    return false
  }
  let signed_data = compute_signed_data(
    sig.sig_namespace,
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
  if !reader.is_empty() {
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
      pk.verify(signed_data, raw, hash_alg) catch {
        _ => false
      }
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
  if !reader.is_empty() {
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
/// `sig_namespace` defaults to "git" (what `ssh-keygen -Y sign -n git` uses).
/// `hash_algorithm` defaults to "sha512".
pub fn sign_armor(
  privkey : @ed25519.PrivateKey,
  message : Bytes,
  sig_namespace? : String = "git",
  hash_algorithm? : String = "sha512",
) -> String raise SshError {
  let signed_data = compute_signed_data(sig_namespace, hash_algorithm, message)
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
  w.write_string_ascii(sig_namespace)
  w.write_string(b"")
  w.write_string_ascii(hash_algorithm)
  w.write_string(inner_blob)
  encode_sshsig_armor(w.to_bytes())
}

// ─── multi-algorithm sign ────────────────────────────────────────────────

///|
pub(all) enum SshPrivateKey {
  Ed25519(@ed25519.PrivateKey)
  P256(@p256.PrivateKey)
  P384(@p384.PrivateKey)
  // RSA SSH signing emits either rsa-sha2-256 or rsa-sha2-512. The
  // hash choice is encoded in the armor by `sign_armor_with`'s
  // `hash_algorithm` parameter (default "sha512", matching modern
  // ssh-keygen).
  Rsa(@rsa.RsaPrivateKey)
}

///|
/// Produce an armored SSHSIG using any supported private-key kind.
/// `sig_namespace` defaults to "git". `hash_algorithm` picks SHA-256 /
/// SHA-384 / SHA-512; this package's default pairing is:
///   Ed25519 → sha512
///   P-256   → sha256
///   P-384   → sha384
///   RSA     → sha256 or sha512 (we default to sha512)
pub fn sign_armor_with(
  privkey : SshPrivateKey,
  message : Bytes,
  sig_namespace? : String = "git",
  hash_algorithm? : String = "",
) -> String raise SshError {
  // Default hash per algorithm if caller didn't supply one.
  let actual_hash = if hash_algorithm == "" {
    match privkey {
      Ed25519(_) => "sha512"
      P256(_) => "sha256"
      P384(_) => "sha384"
      Rsa(_) => "sha512"
    }
  } else {
    hash_algorithm
  }
  let signed_data = compute_signed_data(sig_namespace, actual_hash, message)
  let (pubkey_blob, inner_blob) = match privkey {
    Ed25519(sk) => {
      let raw_sig = sk.sign(signed_data)
      let inner = WireWriter::new()
      inner.write_string_ascii(ed25519_algo)
      inner.write_string(raw_sig)
      (serialize_ed25519_pubkey(sk.public_key()), inner.to_bytes())
    }
    P256(sk) => {
      // @p256.sign returns r||s (64 bytes Raw form). SSH wants
      // wire-format mpint(r), mpint(s).
      let raw_sig = sk.sign(signed_data)
      let r_bytes = Bytes::makei(32, fn(i) { raw_sig[i] })
      let s_bytes = Bytes::makei(32, fn(i) { raw_sig[i + 32] })
      let inner_sig = WireWriter::new()
      inner_sig.write_string(mpint_encode(r_bytes))
      inner_sig.write_string(mpint_encode(s_bytes))
      let inner = WireWriter::new()
      inner.write_string_ascii(ecdsa_p256_algo)
      inner.write_string(inner_sig.to_bytes())
      (serialize_p256_pubkey(sk.public_key()), inner.to_bytes())
    }
    P384(sk) => {
      let raw_sig = sk.sign(signed_data)
      let r_bytes = Bytes::makei(48, fn(i) { raw_sig[i] })
      let s_bytes = Bytes::makei(48, fn(i) { raw_sig[i + 48] })
      let inner_sig = WireWriter::new()
      inner_sig.write_string(mpint_encode(r_bytes))
      inner_sig.write_string(mpint_encode(s_bytes))
      let inner = WireWriter::new()
      inner.write_string_ascii(ecdsa_p384_algo)
      inner.write_string(inner_sig.to_bytes())
      (serialize_p384_pubkey(sk.public_key()), inner.to_bytes())
    }
    Rsa(sk) => {
      let (rsa_hash, rsa_algo_name) = if actual_hash == "sha256" {
        (@rsa.HashAlg::Sha256, rsa_sha256_algo)
      } else if actual_hash == "sha512" {
        (@rsa.HashAlg::Sha512, rsa_sha512_algo)
      } else {
        raise UnsupportedAlgorithm("RSA SSH hash " + actual_hash)
      }
      let raw_sig = sk.sign(signed_data, rsa_hash) catch {
        _ => raise InvalidSignature
      }
      let inner = WireWriter::new()
      inner.write_string_ascii(rsa_algo_name)
      inner.write_string(raw_sig)
      (serialize_rsa_pubkey(sk.public_key()), inner.to_bytes())
    }
  }
  let w = WireWriter::new()
  w.write_bytes_raw(sshsig_magic)
  w.write_uint32(sshsig_version)
  w.write_string(pubkey_blob)
  w.write_string_ascii(sig_namespace)
  w.write_string(b"")
  w.write_string_ascii(actual_hash)
  w.write_string(inner_blob)
  encode_sshsig_armor(w.to_bytes())
}

///|
// Encode a non-negative byte string as an SSH mpint (RFC 4251 §5):
//   - strip leading 0x00 bytes
//   - if the first byte's high bit is set, prepend a 0x00 sign byte
//   - zero magnitude → empty bytes
fn mpint_encode(b : Bytes) -> Bytes {
  let mut start = 0
  while start < b.length() && b[start] == b'\x00' {
    start = start + 1
  }
  if start == b.length() {
    return b""
  }
  let needs_sign = (b[start].to_int() & 0x80) != 0
  let n = b.length() - start
  let total = n + (if needs_sign { 1 } else { 0 })
  Bytes::makei(total, fn(i) {
    if needs_sign && i == 0 {
      b'\x00'
    } else {
      let src = i - (if needs_sign { 1 } else { 0 })
      b[start + src]
    }
  })
}

///|
fn serialize_p256_pubkey(pk : @p256.PublicKey) -> Bytes {
  let w = WireWriter::new()
  w.write_string_ascii(ecdsa_p256_algo)
  w.write_string_ascii("nistp256")
  w.write_string(pk.to_uncompressed())
  w.to_bytes()
}

///|
fn serialize_p384_pubkey(pk : @p384.PublicKey) -> Bytes {
  let w = WireWriter::new()
  w.write_string_ascii(ecdsa_p384_algo)
  w.write_string_ascii("nistp384")
  w.write_string(pk.to_uncompressed())
  w.to_bytes()
}

///|
fn serialize_rsa_pubkey(pk : @rsa.RsaPublicKey) -> Bytes {
  let w = WireWriter::new()
  w.write_string_ascii("ssh-rsa")
  // SSH ssh-rsa: mpint e, mpint n.
  w.write_string(mpint_encode(pk.e.to_octets()))
  w.write_string(mpint_encode(pk.n.to_octets()))
  w.to_bytes()
}
