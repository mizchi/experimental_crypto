// SSHSIG envelope format. Based on openssh-portable PROTOCOL.sshsig, with a
// small package-local policy surface rather than a full OpenSSH verifier.
//
//   byte[6]  MAGIC_PREAMBLE  = "SSHSIG"
//   uint32   SIG_VERSION     = 1
//   string   publickey         (wire-format pubkey, with algorithm prefix)
//   string   sig_namespace         ("git" for git commits/tags)
//   string   reserved          (empty)
//   string   hash_algorithm    ("sha256", "sha384", or "sha512" here)
//   string   signature         (wire-format signature, with algorithm prefix)
//
// The signature value is computed over `signed_data`:
//   byte[6]  MAGIC_PREAMBLE   "SSHSIG"
//   string   sig_namespace
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
  sig_namespace : String
  hash_algorithm : String // "sha256" or "sha512"
  // Inner signature blob (still in SSH wire format: algorithm + sig bytes).
  signature_blob : Bytes
}

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
  let sig_namespace = read_string_utf8(reader)
  let reserved = reader.read_string()
  if reserved.length() != 0 {
    raise InvalidEncoding("SSHSIG reserved field must be empty")
  }
  let hash_alg = read_string_utf8(reader)
  let signature_blob = reader.read_string()
  if !reader.is_empty() {
    raise InvalidEncoding("trailing bytes after sshsig signature field")
  }
  validate_namespace(sig_namespace)
  let publickey = decode_pubkey(pubkey_blob)
  { publickey, sig_namespace, hash_algorithm: hash_alg, signature_blob }
}

///|
// Compute the bytes-to-be-signed: the `signed_data` blob from PROTOCOL.sshsig.
// Hashes `message` with the chosen algorithm before wrapping.
pub fn compute_signed_data(
  sig_namespace : String,
  hash_algorithm : String,
  message : Bytes,
) -> Bytes raise SshError {
  validate_namespace(sig_namespace)
  let h = hash_message(hash_algorithm, message)
  let w = WireWriter::new()
  w.write_bytes_raw(sshsig_magic)
  w.write_string_ascii(sig_namespace)
  w.write_string(b"") // reserved
  w.write_string_ascii(hash_algorithm)
  w.write_string(h)
  w.to_bytes()
}

///|
fn hash_message(alg : String, message : Bytes) -> Bytes raise SshError {
  match alg {
    "sha256" => @hash.sha256(message)
    "sha384" => @hash.sha384(message)
    "sha512" => @hash.sha512(message)
    _ => raise HashAlgorithmMismatch(alg)
  }
}

///|
fn validate_namespace(ns : String) -> Unit raise SshError {
  if ns == "" {
    raise InvalidEncoding("SSHSIG sig_namespace must not be empty")
  }
  for c in ns {
    let v = c.to_int()
    if v < 0x21 || v > 0x7e {
      raise InvalidEncoding("SSHSIG sig_namespace must be printable ASCII")
    }
  }
}

///|
fn decode_pubkey(blob : Bytes) -> SshPublicKey raise SshError {
  // Peek the algorithm to pick the right decoder. We do NOT consume the
  // reader here — each per-algorithm parser owns the full blob.
  let reader = WireReader::new(blob)
  let algo = reader.read_string_ascii()
  if algo == ed25519_algo {
    Ed25519(parse_ed25519_pubkey(blob))
  } else if algo == ecdsa_p256_algo || algo == ecdsa_p384_algo {
    parse_ecdsa_pubkey(blob)
  } else if algo == "ssh-rsa" {
    Rsa(parse_rsa_pubkey(blob))
  } else {
    raise UnsupportedAlgorithm(algo)
  }
}

///|
fn read_string_utf8(reader : WireReader) -> String raise SshError {
  // For sig_namespace / hash_algorithm we expect ASCII; the SSH spec calls them
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
  if !found_end {
    raise InvalidEncoding("missing -----END SSH SIGNATURE-----")
  }
  @base64.decode(b64.to_string()) catch {
    _ => raise InvalidEncoding("sshsig base64 body")
  }
}

///|
// Strict variant for verification / trust decisions. It accepts only the
// canonical SSHSIG armor emitted by `encode_sshsig_armor`: exact boundary
// lines, no surrounding whitespace, base64-only body lines, and no data after
// the end marker (apart from the single final newline).
pub fn decode_sshsig_armor_strict(input : String) -> Bytes raise SshError {
  let lines = split_lines_strict(input)
  if lines.length() < 3 || lines[0] != sshsig_begin {
    raise InvalidEncoding("missing -----BEGIN SSH SIGNATURE-----")
  }
  let b64 = StringBuilder::new()
  let mut i = 1
  let mut found_end = false
  while i < lines.length() {
    let line = lines[i]
    if line == sshsig_end {
      found_end = true
      i = i + 1
      break
    }
    if line == "" {
      raise InvalidEncoding("empty line in sshsig base64 body")
    }
    if line.length() > 70 {
      raise InvalidEncoding("sshsig base64 line too long")
    }
    for j = 0; j < line.length(); j = j + 1 {
      if !is_base64_armor_char(line.get_char(j).unwrap()) {
        raise InvalidEncoding("sshsig base64 body")
      }
    }
    b64.write_string(line)
    i = i + 1
  }
  if !found_end {
    raise InvalidEncoding("missing -----END SSH SIGNATURE-----")
  }
  if i < lines.length() {
    if !(i + 1 == lines.length() && lines[i] == "") {
      raise InvalidEncoding("trailing data after -----END SSH SIGNATURE-----")
    }
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

///|
fn split_lines_strict(s : String) -> Array[String] raise SshError {
  let out : Array[String] = []
  let buf = StringBuilder::new()
  let mut i = 0
  while i < s.length() {
    let c = s.get_char(i).unwrap()
    if c == '\n' {
      out.push(buf.to_string())
      buf.reset()
      i = i + 1
    } else if c == '\r' {
      if i + 1 < s.length() && s.get_char(i + 1).unwrap() == '\n' {
        out.push(buf.to_string())
        buf.reset()
        i = i + 2
      } else {
        raise InvalidEncoding("bare CR in sshsig armor")
      }
    } else {
      buf.write_char(c)
      i = i + 1
    }
  }
  out.push(buf.to_string())
  out
}

///|
fn is_base64_armor_char(c : Char) -> Bool {
  let v = c.to_int()
  (v >= 0x41 && v <= 0x5a) ||
  (v >= 0x61 && v <= 0x7a) ||
  (v >= 0x30 && v <= 0x39) ||
  c == '+' ||
  c == '/' ||
  c == '='
}
