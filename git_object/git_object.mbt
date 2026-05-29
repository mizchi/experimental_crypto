// git commit / tag object signature handling. Just enough to support the
// SSH-signed commit verification flow: parse the headers, extract the
// `gpgsig` header value (the embedded -----BEGIN SSH SIGNATURE----- armor),
// and reconstruct the bytes-that-were-signed by removing the gpgsig header.
//
// References:
//   - git's `t/lib-gpg.sh`, `gpg-interface.c`
//   - https://git-scm.com/docs/signature-format

///|
pub suberror GitObjectError {
  Malformed(String)
  NotSigned
} derive(Debug)

///|
pub(all) struct SignedCommit {
  // Commit content with the gpgsig (and gpgsig-sha256) headers removed —
  // this is what was originally signed.
  signed_content : Bytes
  // The armored signature value: lines de-prefixed (the leading space on
  // continuation lines is stripped), joined by '\n'.
  signature_armor : String
} derive(Debug)

///|
priv enum RawObjectKind {
  NoRawHeader
  RawCommit
  RawTag
}

///|
/// Parse a git commit or tag object and split out the signature. Accepts
/// either the raw object storage form (`commit <len>\0...` / `tag <len>\0...`)
/// or the object content returned by `git cat-file commit|tag`.
pub fn parse_signed_object(
  object_bytes : Bytes,
) -> SignedCommit raise GitObjectError {
  let (content, kind) = strip_raw_object_header(object_bytes)
  match kind {
    RawCommit => require_commit_content(content)
    RawTag => require_tag_content(content)
    NoRawHeader => require_git_object_content(content)
  }
  parse_signed_content(content)
}

///|
/// Parse a git commit object and split out the signature. Returns
/// `NotSigned` if the commit has no `gpgsig` (or `gpgsig-sha256`) header.
///
/// The header recognition is intentionally narrow:
///   - "gpgsig" — OpenPGP / SSH / X.509 (git treats them uniformly here)
///   - "gpgsig-sha256" — same role for SHA-256 commit object IDs
///
/// We preserve byte ordering exactly. The "signed bytes" are produced by
/// dropping all lines belonging to the gpgsig header(s) and nothing else.
pub fn parse_signed_commit(
  commit_bytes : Bytes,
) -> SignedCommit raise GitObjectError {
  let (content, kind) = strip_raw_object_header(commit_bytes)
  match kind {
    RawTag => raise Malformed("not a commit object")
    NoRawHeader | RawCommit => ()
  }
  require_commit_content(content)
  parse_signed_content(content)
}

///|
fn parse_signed_content(
  commit_bytes : Bytes,
) -> SignedCommit raise GitObjectError {
  let text = bytes_to_string(commit_bytes)
  // Find the blank-line boundary between headers and message.
  let header_end = find_header_end(text)
  if header_end == text.length() {
    raise Malformed("missing header/body separator")
  }
  // Walk the header section line by line. A line that starts with "gpgsig"
  // (followed by ' ' or end-of-line) opens a multi-line header value; its
  // continuation lines begin with a single space.
  let lines = split_lines_with_newlines(text)
  let gpgsig_lines : Array[String] = []
  let kept : Array[String] = []
  let mut in_sig_header = false
  let mut seen_gpgsig = false
  let mut byte_index = 0
  for raw in lines {
    let logical_end = byte_index + raw.length()
    let line_is_header = logical_end <= header_end + 1
    let _ = line_is_header
    if in_sig_header {
      // Continuation lines start with a single space.
      if raw.length() > 0 && raw.get_char(0).unwrap() == ' ' {
        validate_gpgsig_continuation(raw)
        // Strip the leading space (and trailing newline if any) before
        // collecting.
        let stripped = drop_first_char(raw)
        gpgsig_lines.push(trim_trailing_newline(stripped))
        byte_index = logical_end
        continue
      } else {
        in_sig_header = false
      }
    }
    // Are we inside the headers? If the line starts a gpgsig header, capture.
    // Use the line's START position (byte_index) rather than its END
    // (logical_end) — a header line whose terminating '\n' sits exactly
    // at header_end is still a header (header_end is the position of
    // the first '\n' of the blank-line separator pair, so the LAST
    // header line ends AT header_end).
    if byte_index <= header_end {
      if header_name_matches(raw, "gpgsig") ||
        header_name_matches(raw, "gpgsig-sha256") {
        // Reject multiple gpgsig headers in a single commit: git itself
        // emits exactly one, so anything more is either a malformed
        // commit object or an attempt to confuse the downstream armor
        // parser (which would otherwise see concatenated armors).
        if seen_gpgsig {
          raise Malformed("multiple gpgsig headers")
        }
        seen_gpgsig = true
        // First gpgsig line: "gpgsig -----BEGIN SSH SIGNATURE-----"
        let after_name = skip_header_name(raw)
        let first_sig_line = trim_trailing_newline(after_name)
        if first_sig_line == "" {
          raise Malformed("empty gpgsig header")
        }
        validate_gpgsig_value_line(first_sig_line)
        gpgsig_lines.push(first_sig_line)
        in_sig_header = true
        byte_index = logical_end
        continue
      }
    }
    kept.push(raw)
    byte_index = logical_end
  }
  if gpgsig_lines.length() == 0 {
    raise NotSigned
  }
  // Reassemble signed content from kept lines.
  let sb = StringBuilder::new()
  for k in kept {
    sb.write_string(k)
  }
  let signed_content_str = sb.to_string()
  let signed_content = string_to_bytes(signed_content_str)
  // Reassemble the armor: gpgsig_lines is already a sequence of armor
  // lines (BEGIN ... base64 lines ... END). Join with '\n', no trailing
  // newline.
  let sb2 = StringBuilder::new()
  for i = 0; i < gpgsig_lines.length(); i = i + 1 {
    if i > 0 {
      sb2.write_char('\n')
    }
    sb2.write_string(gpgsig_lines[i])
  }
  { signed_content, signature_armor: sb2.to_string() }
}

// ─── helpers ─────────────────────────────────────────────────────────────

///|
fn validate_gpgsig_value_line(line : String) -> Unit raise GitObjectError {
  if line.length() == 0 {
    raise Malformed("empty gpgsig header")
  }
  let first = line.get_char(0).unwrap()
  if first == ' ' || first == '\t' {
    raise Malformed("ambiguous gpgsig header whitespace")
  }
}

///|
fn validate_gpgsig_continuation(raw : String) -> Unit raise GitObjectError {
  if raw.length() <= 1 {
    return
  }
  let second = raw.get_char(1).unwrap()
  // A line containing only the required continuation space plus newline is
  // valid: OpenPGP armor can contain a blank line after BEGIN. Extra leading
  // whitespace would be hidden by tolerant armor parsers, so reject it here.
  if second == ' ' || second == '\t' {
    raise Malformed("ambiguous gpgsig continuation whitespace")
  }
}

///|
fn strip_raw_object_header(
  object_bytes : Bytes,
) -> (Bytes, RawObjectKind) raise GitObjectError {
  let mut nul_at = -1
  let mut newline_at = -1
  for i = 0; i < object_bytes.length(); i = i + 1 {
    if object_bytes[i] == b'\x00' {
      nul_at = i
      break
    }
    if object_bytes[i] == b'\n' && newline_at < 0 {
      newline_at = i
    }
  }
  if nul_at < 0 {
    return (object_bytes, NoRawHeader)
  }
  if newline_at >= 0 && newline_at < nul_at {
    return (object_bytes, NoRawHeader)
  }
  let header = bytes_to_string(bytes_slice(object_bytes, 0, nul_at))
  let (kind, size_start) = if header.has_prefix("commit ") {
    (RawCommit, 7)
  } else if header.has_prefix("tag ") {
    (RawTag, 4)
  } else {
    raise Malformed("unsupported raw git object header")
  }
  let size_text = substring(header, size_start, header.length())
  let expected_size = parse_canonical_decimal(size_text) catch {
    _ => raise Malformed("invalid raw git object size")
  }
  let actual_size = object_bytes.length() - nul_at - 1
  if expected_size != actual_size {
    raise Malformed("raw git object size mismatch")
  }
  (bytes_slice(object_bytes, nul_at + 1, object_bytes.length()), kind)
}

///|
fn require_commit_content(content : Bytes) -> Unit raise GitObjectError {
  let text = bytes_to_string(content)
  let header_end = find_header_end(text)
  if header_end == text.length() {
    raise Malformed("missing header/body separator")
  }
  let lines = split_lines_with_newlines(text)
  let mut byte_index = 0
  let mut line_no = 0
  let mut saw_tree = false
  let mut saw_author = false
  let mut saw_committer = false
  for raw in lines {
    if byte_index > header_end {
      break
    }
    if line_no == 0 {
      if !header_name_matches(raw, "tree") {
        raise Malformed("not a commit object")
      }
      saw_tree = true
    } else if header_name_matches(raw, "author") {
      saw_author = true
    } else if header_name_matches(raw, "committer") {
      saw_committer = true
    }
    byte_index = byte_index + raw.length()
    line_no = line_no + 1
  }
  if !saw_tree || !saw_author || !saw_committer {
    raise Malformed("not a commit object")
  }
}

///|
fn require_git_object_content(content : Bytes) -> Unit raise GitObjectError {
  let text = bytes_to_string(content)
  let lines = split_lines_with_newlines(text)
  if lines.length() == 0 {
    raise Malformed("empty git object")
  }
  if header_name_matches(lines[0], "tree") {
    require_commit_content(content)
  } else if header_name_matches(lines[0], "object") {
    require_tag_content(content)
  } else {
    raise Malformed("not a commit or tag object")
  }
}

///|
fn require_tag_content(content : Bytes) -> Unit raise GitObjectError {
  let text = bytes_to_string(content)
  let header_end = find_header_end(text)
  if header_end == text.length() {
    raise Malformed("missing header/body separator")
  }
  let lines = split_lines_with_newlines(text)
  if lines.length() < 5 {
    raise Malformed("not a tag object")
  }
  if !header_name_matches(lines[0], "object") ||
    !is_hex_object_id(header_value(lines[0])) {
    raise Malformed("not a tag object")
  }
  if !header_name_matches(lines[1], "type") ||
    !is_git_object_type(header_value(lines[1])) {
    raise Malformed("not a tag object")
  }
  if !header_name_matches(lines[2], "tag") ||
    header_value(lines[2]).length() == 0 {
    raise Malformed("not a tag object")
  }
  // Be deliberately conservative: signed tag objects produced by git carry a
  // tagger line before gpgsig. Rejecting tagger-less tags is preferable to
  // accepting a malformed signed object under a trusted tag path.
  if !header_name_matches(lines[3], "tagger") ||
    header_value(lines[3]).length() == 0 {
    raise Malformed("not a tag object")
  }
}

///|
fn header_value(line : String) -> String {
  trim_trailing_newline(skip_header_name(line))
}

///|
fn is_hex_object_id(s : String) -> Bool {
  if s.length() != 40 && s.length() != 64 {
    return false
  }
  for c in s {
    if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
      return false
    }
  }
  true
}

///|
fn is_git_object_type(s : String) -> Bool {
  s == "commit" || s == "tree" || s == "blob" || s == "tag"
}

///|
fn parse_canonical_decimal(s : String) -> Int raise GitObjectError {
  if s.length() == 0 {
    raise Malformed("empty decimal")
  }
  if s.length() > 1 && s.get_char(0).unwrap() == '0' {
    raise Malformed("non-canonical decimal")
  }
  let mut out = 0
  for i = 0; i < s.length(); i = i + 1 {
    let c = s.get_char(i).unwrap()
    if c < '0' || c > '9' {
      raise Malformed("non-decimal digit")
    }
    out = out * 10 + (c.to_int() - '0'.to_int())
  }
  out
}

///|
fn bytes_slice(b : Bytes, start : Int, end : Int) -> Bytes {
  Bytes::makei(end - start, fn(i) { b[start + i] })
}

///|
fn substring(s : String, start : Int, end : Int) -> String {
  let sb = StringBuilder::new()
  for i = start; i < end; i = i + 1 {
    sb.write_char(s.get_char(i).unwrap())
  }
  sb.to_string()
}

///|
fn find_header_end(text : String) -> Int {
  // git separates headers from the body with a single blank line ("\n\n"
  // in the byte stream). Return the byte index of the first '\n' of that
  // pair; everything strictly before this is header territory.
  let mut prev_was_nl = false
  for i = 0; i < text.length(); i = i + 1 {
    let c = text.get_char(i).unwrap()
    if c == '\n' {
      if prev_was_nl {
        return i - 1
      }
      prev_was_nl = true
    } else {
      prev_was_nl = false
    }
  }
  text.length()
}

///|
fn split_lines_with_newlines(s : String) -> Array[String] {
  // Each element ends with the trailing '\n' (if any), unlike a typical
  // split that drops it. Preserves exact byte-level reconstruction.
  let out : Array[String] = []
  let buf = StringBuilder::new()
  for c in s {
    buf.write_char(c)
    if c == '\n' {
      out.push(buf.to_string())
      buf.reset()
    }
  }
  let tail = buf.to_string()
  if tail.length() > 0 {
    out.push(tail)
  }
  out
}

///|
fn header_name_matches(line : String, name : String) -> Bool {
  if line.length() < name.length() + 1 {
    return false
  }
  for i = 0; i < name.length(); i = i + 1 {
    if line.get_char(i).unwrap() != name.get_char(i).unwrap() {
      return false
    }
  }
  let after = line.get_char(name.length()).unwrap()
  after == ' ' || after == '\n'
}

///|
fn skip_header_name(line : String) -> String {
  // Drop "<name> " and any trailing newline-only content.
  let mut start = 0
  while start < line.length() && line.get_char(start).unwrap() != ' ' {
    start = start + 1
  }
  if start < line.length() {
    start = start + 1
  }
  let sb = StringBuilder::new()
  for i = start; i < line.length(); i = i + 1 {
    sb.write_char(line.get_char(i).unwrap())
  }
  sb.to_string()
}

///|
fn drop_first_char(s : String) -> String {
  if s.length() == 0 {
    return s
  }
  let sb = StringBuilder::new()
  for i = 1; i < s.length(); i = i + 1 {
    sb.write_char(s.get_char(i).unwrap())
  }
  sb.to_string()
}

///|
fn trim_trailing_newline(s : String) -> String {
  if s.length() == 0 {
    return s
  }
  let last = s.get_char(s.length() - 1).unwrap()
  if last == '\n' {
    let sb = StringBuilder::new()
    for i = 0; i < s.length() - 1; i = i + 1 {
      sb.write_char(s.get_char(i).unwrap())
    }
    sb.to_string()
  } else {
    s
  }
}

///|
fn bytes_to_string(b : Bytes) -> String {
  let sb = StringBuilder::new()
  for i = 0; i < b.length(); i = i + 1 {
    let c = b[i].to_int()
    sb.write_char(c.to_char().unwrap())
  }
  sb.to_string()
}

///|
fn string_to_bytes(s : String) -> Bytes {
  Bytes::makei(s.length(), fn(i) { s.get_char(i).unwrap().to_int().to_byte() })
}
