// SSH public-key parsing/serialization. Ed25519 only for now.
//
// On the wire (RFC 8709 §4):
//   string  "ssh-ed25519"
//   string  ed25519_public_key (32 bytes)
//
// The text form embeds the wire bytes as standard base64:
//   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... [comment]

///|
pub(all) enum SshPublicKey {
  Ed25519(@ed25519.PublicKey)
  P256(@p256.PublicKey)
  P384(@p384.PublicKey)
  Rsa(@rsa.RsaPublicKey)
  Certificate(SshCertificate)
}

///|
pub(all) struct SshCertificate {
  algorithm : String
  subject_key : SshPublicKey
  serial : UInt64
  cert_type : UInt
  key_id : String
  valid_principals : Array[String]
  valid_after : UInt64
  valid_before : UInt64
  critical_options : Bytes
  extensions : Bytes
  ca_key : SshPublicKey
  signature_blob : Bytes
  signed_data : Bytes
}

///|
pub(all) struct SshPublicKeyText {
  algorithm : String
  blob : Bytes // wire-format pubkey (algorithm-prefixed)
  comment : String?
} derive(Debug)

///|
pub let ed25519_algo : String = "ssh-ed25519"

///|
pub let ecdsa_p256_algo : String = "ecdsa-sha2-nistp256"

///|
pub let ecdsa_p384_algo : String = "ecdsa-sha2-nistp384"

///|
pub let rsa_sha256_algo : String = "rsa-sha2-256"

///|
pub let rsa_sha512_algo : String = "rsa-sha2-512"

///|
pub let ed25519_cert_algo : String = "ssh-ed25519-cert-v01@openssh.com"

///|
pub let ecdsa_p256_cert_algo : String = "ecdsa-sha2-nistp256-cert-v01@openssh.com"

///|
pub let ecdsa_p384_cert_algo : String = "ecdsa-sha2-nistp384-cert-v01@openssh.com"

///|
pub let rsa_cert_algo : String = "ssh-rsa-cert-v01@openssh.com"

///|
pub let ssh_cert_type_user : UInt = 1U

///|
pub let ssh_cert_type_host : UInt = 2U

///|
fn is_supported_pubkey_text_algorithm(algorithm : String) -> Bool {
  algorithm == ed25519_algo ||
  algorithm == ecdsa_p256_algo ||
  algorithm == ecdsa_p384_algo ||
  algorithm == "ssh-rsa"
}

///|
// SSH `mpint` (RFC 4251 §5): two's-complement BE, no redundant leading
// bytes. For non-negative integers with high-bit set, a single 0x00
// sign byte is prepended. Returns the magnitude as a positive byte
// slice (sign byte stripped). Zero ⇒ empty bytes.
fn mpint_magnitude(b : Bytes) -> Bytes raise SshError {
  if b.length() == 0 {
    return b
  }
  if (b[0].to_int() & 0x80) != 0 {
    raise InvalidEncoding("negative mpint")
  }
  if b.length() > 1 && b[0] == b'\x00' {
    if (b[1].to_int() & 0x80) == 0 {
      raise InvalidEncoding("non-minimal mpint")
    }
    // Strip the 0x00 sign byte.
    Bytes::makei(b.length() - 1, fn(i) { b[i + 1] })
  } else if b.length() == 1 && b[0] == b'\x00' {
    raise InvalidEncoding("non-minimal zero mpint")
  } else {
    b
  }
}

///|
// Left-pad `b` with 0x00 to exactly `target_len` bytes. Raises if the
// natural length exceeds target_len (i.e. caller picked too-small a curve).
fn left_pad(b : Bytes, target_len : Int) -> Bytes raise SshError {
  if b.length() > target_len {
    raise InvalidEncoding(
      "integer wider than expected field (" +
      b.length().to_string() +
      " > " +
      target_len.to_string() +
      ")",
    )
  }
  let pad = target_len - b.length()
  Bytes::makei(target_len, fn(i) { if i < pad { b'\x00' } else { b[i - pad] } })
}

///|
fn bigint_is_odd(n : BigInt) -> Bool {
  let oct = n.to_octets()
  oct.length() > 0 && (oct[oct.length() - 1].to_int() & 1) == 1
}

///|
fn bytes_prefix(b : Bytes, n : Int) -> Bytes {
  Bytes::makei(n, fn(i) { b[i] })
}

///|
fn read_ascii_bytes(bytes : Bytes, context : String) -> String raise SshError {
  let buf = StringBuilder::new()
  for i = 0; i < bytes.length(); i = i + 1 {
    let c = bytes[i].to_int()
    if c < 0 || c > 0x7f {
      raise InvalidEncoding("non-ASCII " + context)
    }
    buf.write_char(c.to_char().unwrap())
  }
  buf.to_string()
}

///|
fn string_lex_compare(a : String, b : String) -> Int {
  let n = if a.length() < b.length() { a.length() } else { b.length() }
  for i = 0; i < n; i = i + 1 {
    let av = a.get_char(i).unwrap().to_int()
    let bv = b.get_char(i).unwrap().to_int()
    if av < bv {
      return -1
    }
    if av > bv {
      return 1
    }
  }
  if a.length() < b.length() {
    -1
  } else if a.length() > b.length() {
    1
  } else {
    0
  }
}

///|
fn parse_cert_string_list(blob : Bytes) -> Array[String] raise SshError {
  let out : Array[String] = []
  if blob.length() == 0 {
    return out
  }
  let r = WireReader::new(blob)
  while !r.is_empty() {
    out.push(read_ascii_bytes(r.read_string(), "certificate principal"))
  }
  out
}

///|
fn validate_name_data_sequence(
  blob : Bytes,
  context : String,
) -> Unit raise SshError {
  let r = WireReader::new(blob)
  let mut prev : String? = None
  while !r.is_empty() {
    let name = read_ascii_bytes(r.read_string(), context + " name")
    let _data = r.read_string()
    match prev {
      Some(p) =>
        if string_lex_compare(p, name) >= 0 {
          raise InvalidEncoding(context + " names must be strictly ordered")
        }
      None => ()
    }
    prev = Some(name)
  }
}

///|
fn is_cert_algorithm(algo : String) -> Bool {
  algo == ed25519_cert_algo ||
  algo == ecdsa_p256_cert_algo ||
  algo == ecdsa_p384_cert_algo ||
  algo == rsa_cert_algo
}

///|
pub fn parse_ssh_pubkey_blob(blob : Bytes) -> SshPublicKey raise SshError {
  let reader = WireReader::new(blob)
  let algo = reader.read_string_ascii()
  if is_cert_algorithm(algo) {
    Certificate(parse_ssh_certificate(blob))
  } else {
    parse_raw_ssh_pubkey_blob(blob)
  }
}

///|
fn parse_raw_ssh_pubkey_blob(blob : Bytes) -> SshPublicKey raise SshError {
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
pub fn parse_ssh_certificate(blob : Bytes) -> SshCertificate raise SshError {
  let reader = WireReader::new(blob)
  let algo = reader.read_string_ascii()
  if !is_cert_algorithm(algo) {
    raise UnsupportedAlgorithm(algo)
  }
  let _nonce = reader.read_string()
  let subject_key = if algo == ed25519_cert_algo {
    let pk_bytes = reader.read_string()
    if pk_bytes.length() != 32 {
      raise InvalidEncoding("ssh-ed25519 certificate key must be 32 bytes")
    }
    SshPublicKey::Ed25519(
      @ed25519.PublicKey::from_bytes(pk_bytes) catch {
        _ => raise InvalidEncoding("ed25519 certificate key")
      },
    )
  } else if algo == ecdsa_p256_cert_algo || algo == ecdsa_p384_cert_algo {
    let curve = reader.read_string_ascii()
    let q = reader.read_string()
    if algo == ecdsa_p256_cert_algo {
      if curve != "nistp256" {
        raise InvalidEncoding("expected nistp256 certificate curve")
      }
      SshPublicKey::P256(
        @p256.PublicKey::from_uncompressed(q) catch {
          _ => raise InvalidEncoding("p256 certificate key")
        },
      )
    } else {
      if curve != "nistp384" {
        raise InvalidEncoding("expected nistp384 certificate curve")
      }
      SshPublicKey::P384(
        @p384.PublicKey::from_uncompressed(q) catch {
          _ => raise InvalidEncoding("p384 certificate key")
        },
      )
    }
  } else if algo == rsa_cert_algo {
    let e_bytes = reader.read_string()
    let n_bytes = reader.read_string()
    SshPublicKey::Rsa(parse_rsa_public_numbers(e_bytes, n_bytes))
  } else {
    raise UnsupportedAlgorithm(algo)
  }
  let serial = reader.read_uint64()
  let cert_type = reader.read_uint32()
  let key_id = read_ascii_bytes(reader.read_string(), "certificate key id")
  let valid_principals = parse_cert_string_list(reader.read_string())
  let valid_after = reader.read_uint64()
  let valid_before = reader.read_uint64()
  let critical_options = reader.read_string()
  if critical_options.length() > 0 {
    validate_name_data_sequence(critical_options, "certificate critical option")
  }
  let extensions = reader.read_string()
  validate_name_data_sequence(extensions, "certificate extension")
  let reserved = reader.read_string()
  if reserved.length() != 0 {
    raise InvalidEncoding("OpenSSH certificate reserved field must be empty")
  }
  let ca_key_blob = reader.read_string()
  let ca_key = parse_raw_ssh_pubkey_blob(ca_key_blob)
  let signed_len = reader.position()
  let signature_blob = reader.read_string()
  if !reader.is_empty() {
    raise InvalidEncoding("trailing bytes after SSH certificate")
  }
  {
    algorithm: algo,
    subject_key,
    serial,
    cert_type,
    key_id,
    valid_principals,
    valid_after,
    valid_before,
    critical_options,
    extensions,
    ca_key,
    signature_blob,
    signed_data: bytes_prefix(blob, signed_len),
  }
}

///|
// Parse a single `algorithm base64 [comment]` line. Whitespace at line
// boundaries is tolerated. Returns the algorithm tag, the wire-format
// pubkey bytes (still tagged), and an optional comment.
pub fn parse_ssh_pubkey_text(line : String) -> SshPublicKeyText raise SshError {
  let trimmed = trim_ascii(line)
  let parts = split_whitespace(trimmed)
  if parts.length() < 2 {
    raise InvalidEncoding("expected `algorithm base64 [comment]`")
  }
  let algorithm = parts[0]
  if !is_supported_pubkey_text_algorithm(algorithm) {
    raise UnsupportedAlgorithm(algorithm)
  }
  let base64_blob = parts[1]
  let blob = @base64.decode(base64_blob) catch {
    _ => raise InvalidEncoding("pubkey base64")
  }
  let comment : String? = if parts.length() >= 3 {
    // The rest of the line, joined with single spaces (we already
    // split-by-whitespace, so use the original tail starting at parts[2]).
    let sb = StringBuilder::new()
    for i = 2; i < parts.length(); i = i + 1 {
      if i > 2 {
        sb.write_char(' ')
      }
      sb.write_string(parts[i])
    }
    Some(sb.to_string())
  } else {
    None
  }
  // Sanity: the algorithm encoded in the blob must match the text tag.
  let reader = WireReader::new(blob)
  let inner_algo = reader.read_string_ascii()
  if inner_algo != algorithm {
    raise InvalidEncoding(
      "algorithm mismatch (text=" + algorithm + ", blob=" + inner_algo + ")",
    )
  }
  { algorithm, blob, comment }
}

///|
// Parse an SSH-format Ed25519 pubkey from its wire blob (e.g. what
// parse_ssh_pubkey_text returns in `.blob`, or what's embedded in a
// SSHSIG envelope's publickey field).
pub fn parse_ed25519_pubkey(blob : Bytes) -> @ed25519.PublicKey raise SshError {
  let reader = WireReader::new(blob)
  let algo = reader.read_string_ascii()
  if algo != ed25519_algo {
    raise UnsupportedAlgorithm(algo)
  }
  let key_bytes = reader.read_string()
  if key_bytes.length() != 32 {
    raise InvalidEncoding(
      "ssh-ed25519 pubkey must be 32 bytes, got " +
      key_bytes.length().to_string(),
    )
  }
  if !reader.is_empty() {
    raise InvalidEncoding("trailing bytes after ssh-ed25519 pubkey")
  }
  @ed25519.PublicKey::from_bytes(key_bytes) catch {
    _ => raise InvalidEncoding("ed25519 pubkey decode failed")
  }
}

///|
// Parse an `ecdsa-sha2-nistpN` pubkey blob.
//   string  "ecdsa-sha2-nistpN"
//   string  "nistpN"
//   string  Q  (uncompressed: 04 || X || Y, 1+2N bytes)
pub fn parse_ecdsa_pubkey(blob : Bytes) -> SshPublicKey raise SshError {
  let reader = WireReader::new(blob)
  let algo = reader.read_string_ascii()
  let curve_label = reader.read_string_ascii()
  let q = reader.read_string()
  if !reader.is_empty() {
    raise InvalidEncoding("trailing bytes after ECDSA pubkey")
  }
  if algo == ecdsa_p256_algo {
    if curve_label != "nistp256" {
      raise InvalidEncoding("expected nistp256 curve label, got " + curve_label)
    }
    let pk = @p256.PublicKey::from_uncompressed(q) catch {
      _ => raise InvalidEncoding("p256 pubkey")
    }
    P256(pk)
  } else if algo == ecdsa_p384_algo {
    if curve_label != "nistp384" {
      raise InvalidEncoding("expected nistp384 curve label, got " + curve_label)
    }
    let pk = @p384.PublicKey::from_uncompressed(q) catch {
      _ => raise InvalidEncoding("p384 pubkey")
    }
    P384(pk)
  } else {
    raise UnsupportedAlgorithm(algo)
  }
}

///|
// Parse a `ssh-rsa` pubkey blob.
//   string  "ssh-rsa"
//   mpint   e
//   mpint   n
//
// The same wire format is shared by ssh-rsa / rsa-sha2-256 / rsa-sha2-512;
// the algorithm in the inner signature blob picks the hash.
pub fn parse_rsa_pubkey(blob : Bytes) -> @rsa.RsaPublicKey raise SshError {
  let reader = WireReader::new(blob)
  let algo = reader.read_string_ascii()
  if algo != "ssh-rsa" {
    raise UnsupportedAlgorithm(algo)
  }
  let e_bytes = reader.read_string()
  let n_bytes = reader.read_string()
  if !reader.is_empty() {
    raise InvalidEncoding("trailing bytes after ssh-rsa pubkey")
  }
  parse_rsa_public_numbers(e_bytes, n_bytes)
}

///|
fn parse_rsa_public_numbers(
  e_bytes : Bytes,
  n_bytes : Bytes,
) -> @rsa.RsaPublicKey raise SshError {
  let e_mag = mpint_magnitude(e_bytes)
  let n_mag = mpint_magnitude(n_bytes)
  let e = BigInt::from_octets(e_mag[:])
  let n = BigInt::from_octets(n_mag[:])
  if e.compare_int(3) < 0 || !bigint_is_odd(e) {
    raise InvalidEncoding("RSA exponent must be odd and >= 3")
  }
  if n.compare_int(1) <= 0 || !bigint_is_odd(n) {
    raise InvalidEncoding("RSA modulus must be odd and greater than 1")
  }
  { n, e, n_bytes_len: n_mag.length() }
}

///|
pub fn serialize_ed25519_pubkey(pk : @ed25519.PublicKey) -> Bytes {
  let w = WireWriter::new()
  w.write_string_ascii(ed25519_algo)
  w.write_string(pk.to_bytes())
  w.to_bytes()
}

///|
// Build the textual `ssh-ed25519 BASE64 [comment]` line. No trailing
// newline. `comment` may be empty/None.
pub fn format_ssh_pubkey_text(
  pk : @ed25519.PublicKey,
  comment? : String,
) -> String {
  let blob = serialize_ed25519_pubkey(pk)
  let b64 = @base64.encode(blob[:])
  let sb = StringBuilder::new()
  sb.write_string(ed25519_algo)
  sb.write_char(' ')
  sb.write_string(b64)
  match comment {
    Some(c) =>
      if c.length() > 0 {
        sb.write_char(' ')
        sb.write_string(c)
      }
    None => ()
  }
  sb.to_string()
}

// ─── small string helpers ────────────────────────────────────────────────

///|
fn is_ws(c : Char) -> Bool {
  c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

///|
fn trim_ascii(s : String) -> String {
  let mut start = 0
  let mut end = s.length()
  while start < end && is_ws(s.get_char(start).unwrap()) {
    start = start + 1
  }
  while end > start && is_ws(s.get_char(end - 1).unwrap()) {
    end = end - 1
  }
  if start == 0 && end == s.length() {
    s
  } else {
    let sb = StringBuilder::new()
    for i = start; i < end; i = i + 1 {
      sb.write_char(s.get_char(i).unwrap())
    }
    sb.to_string()
  }
}

///|
fn split_whitespace(s : String) -> Array[String] {
  let out : Array[String] = []
  let buf = StringBuilder::new()
  let mut count = 0
  for c in s {
    if is_ws(c) {
      if count > 0 {
        out.push(buf.to_string())
        buf.reset()
        count = 0
      }
    } else {
      buf.write_char(c)
      count = count + 1
    }
  }
  if count > 0 {
    out.push(buf.to_string())
  }
  out
}
