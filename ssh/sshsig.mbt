// SSHSIG envelope format. Reference: openssh-portable PROTOCOL.sshsig.
//
//   byte[6]  MAGIC_PREAMBLE  = "SSHSIG"
//   uint32   SIG_VERSION     = 1
//   string   publickey         (wire-format pubkey, with algorithm prefix)
//   string   namespace         ("git" for git commits/tags)
//   string   reserved          (empty)
//   string   hash_algorithm    ("sha256" or "sha512")
//   string   signature         (wire-format signature, with algorithm prefix)
//
// The signature value is computed over `signed_data`:
//   byte[6]  MAGIC_PREAMBLE   "SSHSIG"
//   string   namespace
//   string   reserved
//   string   hash_algorithm
//   string   H(message)        (sha256 or sha512 of the original payload)
//
// Wrapped in a PEM-like armor:
//   -----BEGIN SSH SIGNATURE-----
//   <base64 of binary, 70 chars per line>
//   -----END SSH SIGNATURE-----

///|
pub let sshsig_magic : Bytes = b"SSHSIG"

///|
pub let sshsig_version : UInt = 1U

///|
pub(all) struct SshSignature {
  publickey : SshPublicKey
  namespace : String
  hash_algorithm : String // "sha256" or "sha512"
  // Inner signature blob (still in SSH wire format: algorithm + sig bytes).
  signature_blob : Bytes
} derive(Show)

///|
// Decode a binary SSHSIG blob (i.e. base64-decoded armor body) into the
// component fields. Does NOT verify; that's a separate pass.
pub fn decode_sshsig_blob(blob : Bytes) -> SshSignature raise SshError {
  if blob.length() < 6 {
    raise PreambleMismatch
  }
  for i = 0; i < 6; i = i + 1 {
    if blob[i] != sshsig_magic[i] {
      raise PreambleMismatch
    }
  }
  let reader = WireReader::new(blob)
  // Skip the magic preamble.
  let _ = reader.read_bytes(6)
  let version = reader.read_uint32()
  if version != sshsig_version {
    raise UnsupportedSigVersion(version)
  }
  let pubkey_blob = reader.read_string()
  let namespace = read_string_utf8(reader)
  let _reserved = reader.read_string()
  let hash_alg = read_string_utf8(reader)
  let signature_blob = reader.read_string()
  if not(reader.is_empty()) {
    raise InvalidEncoding("trailing bytes after sshsig signature field")
  }
  let publickey = decode_pubkey(pubkey_blob)
  { publickey, namespace, hash_algorithm: hash_alg, signature_blob }
}

///|
// Compute the bytes-to-be-signed: the `signed_data` blob from PROTOCOL.sshsig.
// Hashes `message` with the chosen algorithm before wrapping.
pub fn compute_signed_data(
  namespace : String,
  hash_algorithm : String,
  message : Bytes,
) -> Bytes raise SshError {
  let h = hash_message(hash_algorithm, message)
  let w = WireWriter::new()
  w.write_bytes_raw(sshsig_magic)
  w.write_string_ascii(namespace)
  w.write_string(b"") // reserved
  w.write_string_ascii(hash_algorithm)
  w.write_string(h)
  w.to_bytes()
}

///|
fn hash_message(alg : String, message : Bytes) -> Bytes raise SshError {
  match alg {
    "sha256" => @hash.sha256(message)
    "sha512" => @hash.sha512(message)
    _ => raise HashAlgorithmMismatch(alg)
  }
}

///|
fn decode_pubkey(blob : Bytes) -> SshPublicKey raise SshError {
  // Peek the algorithm to pick the right decoder.
  let reader = WireReader::new(blob)
  let algo = reader.read_string_ascii()
  if algo == ed25519_algo {
    Ed25519(parse_ed25519_pubkey(blob))
  } else {
    raise UnsupportedAlgorithm(algo)
  }
}

///|
fn read_string_utf8(reader : WireReader) -> String raise SshError {
  // For namespace / hash_algorithm we expect ASCII; the SSH spec calls them
  // UTF-8 but in practice these fields are ASCII-only ("git", "sha256",
  // "sha512", "file"). Reuse the ASCII reader.
  let bytes = reader.read_string()
  let buf = StringBuilder::new()
  for i = 0; i < bytes.length(); i = i + 1 {
    let c = bytes[i].to_int()
    if c < 0 || c > 0x7f {
      raise InvalidEncoding("non-ASCII in sshsig field")
    }
    buf.write_char(c.to_char().unwrap())
  }
  buf.to_string()
}

// ─── PEM-like armor ──────────────────────────────────────────────────────

///|
pub let sshsig_pem_label : String = "SSH SIGNATURE"

///|
pub let sshsig_begin : String = "-----BEGIN SSH SIGNATURE-----"

///|
pub let sshsig_end : String = "-----END SSH SIGNATURE-----"

///|
// Decode the armored SSHSIG form. Tolerant of CRLF and surrounding
// whitespace. Returns the binary blob — call `decode_sshsig_blob` on it.
pub fn decode_sshsig_armor(input : String) -> Bytes raise SshError {
  let lines = split_lines(input)
  let mut i = 0
  // Skip any leading blank lines.
  while i < lines.length() && trim_ascii(lines[i]) == "" {
    i = i + 1
  }
  if i >= lines.length() || trim_ascii(lines[i]) != sshsig_begin {
    raise InvalidEncoding("missing -----BEGIN SSH SIGNATURE-----")
  }
  i = i + 1
  let b64 = StringBuilder::new()
  let mut found_end = false
  while i < lines.length() {
    let line = trim_ascii(lines[i])
    i = i + 1
    if line == sshsig_end {
      found_end = true
      break
    }
    b64.write_string(line)
  }
  if not(found_end) {
    raise InvalidEncoding("missing -----END SSH SIGNATURE-----")
  }
  @base64.decode(b64.to_string()) catch {
    _ => raise InvalidEncoding("sshsig base64 body")
  }
}

///|
pub fn encode_sshsig_armor(blob : Bytes) -> String {
  let b64 = @base64.encode(blob[:])
  let sb = StringBuilder::new()
  sb.write_string(sshsig_begin)
  sb.write_char('\n')
  let line_len = 70
  let mut pos = 0
  while pos < b64.length() {
    let take = if pos + line_len <= b64.length() {
      line_len
    } else {
      b64.length() - pos
    }
    for j = 0; j < take; j = j + 1 {
      sb.write_char(b64.get_char(pos + j).unwrap())
    }
    sb.write_char('\n')
    pos = pos + take
  }
  sb.write_string(sshsig_end)
  sb.write_char('\n')
  sb.to_string()
}

///|
fn split_lines(s : String) -> Array[String] {
  let out : Array[String] = []
  let buf = StringBuilder::new()
  for c in s {
    if c == '\n' {
      out.push(buf.to_string())
      buf.reset()
    } else if c == '\r' {
      ()
    } else {
      buf.write_char(c)
    }
  }
  out.push(buf.to_string())
  out
}
