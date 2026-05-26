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
  InvalidUtf8
} derive(Show)

///|
pub(all) struct SignedCommit {
  // Commit content with the gpgsig (and gpgsig-sha256) headers removed —
  // this is what was originally signed.
  signed_content : Bytes
  // The armored signature value: lines de-prefixed (the leading space on
  // continuation lines is stripped), joined by '\n'.
  signature_armor : String
} derive(Show)

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
  let text = bytes_to_string(commit_bytes)
  // Find the blank-line boundary between headers and message.
  let header_end = find_header_end(text)
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
        if after_name != "" {
          gpgsig_lines.push(trim_trailing_newline(after_name))
        }
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
  Bytes::makei(s.length(), fn(i) {
    s.get_char(i).unwrap().to_int().to_byte()
  })
}
