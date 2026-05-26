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
} derive(Show)

///|
pub(all) struct SshPublicKeyText {
  algorithm : String
  blob : Bytes // wire-format pubkey (algorithm-prefixed)
  comment : String?
} derive(Show)

///|
pub let ed25519_algo : String = "ssh-ed25519"

///|
// Parse a single `algorithm base64 [comment]` line. Whitespace at line
// boundaries is tolerated. Returns the algorithm tag, the wire-format
// pubkey bytes (still tagged), and an optional comment.
pub fn parse_ssh_pubkey_text(
  line : String,
) -> SshPublicKeyText raise SshError {
  let trimmed = trim_ascii(line)
  let parts = split_whitespace(trimmed)
  if parts.length() < 2 {
    raise InvalidEncoding("expected `algorithm base64 [comment]`")
  }
  let algorithm = parts[0]
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
      "algorithm mismatch (text=" +
      algorithm +
      ", blob=" +
      inner_algo +
      ")",
    )
  }
  { algorithm, blob, comment }
}

///|
// Parse an SSH-format Ed25519 pubkey from its wire blob (e.g. what
// parse_ssh_pubkey_text returns in `.blob`, or what's embedded in a
// SSHSIG envelope's publickey field).
pub fn parse_ed25519_pubkey(
  blob : Bytes,
) -> @ed25519.PublicKey raise SshError {
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
  if not(reader.is_empty()) {
    raise InvalidEncoding("trailing bytes after ssh-ed25519 pubkey")
  }
  @ed25519.PublicKey::from_bytes(key_bytes) catch {
    _ => raise InvalidEncoding("ed25519 pubkey decode failed")
  }
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
    Some(c) => {
      if c.length() > 0 {
        sb.write_char(' ')
        sb.write_string(c)
      }
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
