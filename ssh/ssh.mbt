// mizchi/ssh — SSH signing / verification compatible with OpenSSH's
// `ssh-keygen -Y sign / -Y verify` flow. Ed25519-only.
//
// References:
//   - PROTOCOL.sshsig (openssh-portable)
//   - RFC 4251 §5 (SSH binary types)
//   - RFC 8709 (ssh-ed25519 public key + signature wire format)

///|
/// Verify an armored SSHSIG over `message` against `expected_pubkey`.
/// Returns true iff the signature is valid AND the embedded pubkey matches
/// the supplied one. The caller is responsible for binding the pubkey to
/// an identity (e.g. via an allowed_signers lookup or a known-keys file).
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
      let inner_sig = parse_ed25519_sig_blob(sig.signature_blob)
      pk.verify(signed_data, inner_sig)
    }
  }
}

///|
/// Verify an armored SSHSIG without checking the pubkey identity. Used
/// by callers that resolve the signer separately (e.g. by looking up the
/// pubkey embedded in the signature against an allowed_signers map).
/// Returns the (pubkey, namespace) on success.
pub fn verify_armor_anonymous(
  armor : String,
  message : Bytes,
) -> (@ed25519.PublicKey, String) raise SshError {
  let blob = decode_sshsig_armor(armor)
  let sig = decode_sshsig_blob(blob)
  match sig.publickey {
    Ed25519(pk) => {
      let signed_data = compute_signed_data(
        sig.namespace,
        sig.hash_algorithm,
        message,
      )
      let inner_sig = parse_ed25519_sig_blob(sig.signature_blob)
      if not(pk.verify(signed_data, inner_sig)) {
        raise InvalidSignature
      }
      (pk, sig.namespace)
    }
  }
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
