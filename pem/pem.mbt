// RFC 7468 (Strict / Lax) PEM encoding for cryptographic objects.
// Lenient input parsing: whitespace and CR are tolerated.
// Strict output: 64 base64 chars per line, LF line endings.

///|
pub(all) struct PemBlock {
  label : String
  data : Bytes
  headers : Array[(String, String)] // RFC 1421 style; rare in 7468 but preserved
} derive(Eq, Show)

///|
pub suberror PemError {
  InvalidFormat(String)
  UnexpectedEof
  InvalidBase64
  MissingBeginMarker
  MissingEndMarker
  LabelMismatch(begin~ : String, end~ : String)
} derive(Show)

///|
pub fn decode(input : String) -> PemBlock raise PemError {
  let blocks = decode_all(input)
  if blocks.length() == 0 {
    raise MissingBeginMarker
  }
  if blocks.length() > 1 {
    raise InvalidFormat(
      "expected a single PEM block, found " + blocks.length().to_string(),
    )
  }
  blocks[0]
}

///|
pub fn decode_all(input : String) -> Array[PemBlock] raise PemError {
  let lines = split_lines(input)
  let blocks : Array[PemBlock] = []
  let mut i = 0
  while i < lines.length() {
    let line = trim(lines[i])
    if line == "" {
      i = i + 1
      continue
    }
    let label = match parse_begin_marker(line) {
      Some(l) => l
      None => {
        // skip explanatory text between blocks (RFC 7468 lax mode)
        i = i + 1
        continue
      }
    }
    i = i + 1
    // Headers run until the first blank line; if no blank line and base64
    // starts immediately, treat as no headers (typical for RFC 7468).
    let headers : Array[(String, String)] = []
    let mut saw_colon = false
    let header_start = i
    while i < lines.length() {
      let raw = lines[i]
      let stripped = trim(raw)
      if stripped == "" {
        i = i + 1
        break
      }
      if contains_char(stripped, ':') && not(is_pure_base64_line(stripped)) {
        let (k, v) = split_once(stripped, ':')
        headers.push((trim(k), trim(v)))
        saw_colon = true
        i = i + 1
        continue
      }
      // No header section in this block; rewind to header_start.
      if not(saw_colon) {
        i = header_start
      }
      break
    }
    let _ = header_start
    // Now i points at the first base64 line (or the END marker if empty).
    let b64 = StringBuilder::new()
    let mut end_label : String? = None
    while i < lines.length() {
      let line2 = trim(lines[i])
      i = i + 1
      if line2 == "" {
        continue
      }
      match parse_end_marker(line2) {
        Some(l) => {
          end_label = Some(l)
          break
        }
        None => b64.write_string(line2)
      }
    }
    match end_label {
      None => raise MissingEndMarker
      Some(el) => if el != label { raise LabelMismatch(begin=label, end=el) }
    }
    let data = @base64.decode(b64.to_string(), ignore_whitespace=true) catch {
      _ => raise InvalidBase64
    }
    blocks.push({ label, data, headers })
  }
  blocks
}

///|
pub fn encode(block : PemBlock) -> String {
  let buf = StringBuilder::new()
  buf.write_string("-----BEGIN ")
  buf.write_string(block.label)
  buf.write_string("-----\n")
  if block.headers.length() > 0 {
    for h in block.headers {
      buf.write_string(h.0)
      buf.write_string(": ")
      buf.write_string(h.1)
      buf.write_char('\n')
    }
    buf.write_char('\n')
  }
  let b64 = @base64.encode(block.data[:])
  let mut pos = 0
  while pos < b64.length() {
    let take = if pos + 64 <= b64.length() { 64 } else { b64.length() - pos }
    buf.write_string(slice_string(b64, pos, pos + take))
    buf.write_char('\n')
    pos = pos + take
  }
  buf.write_string("-----END ")
  buf.write_string(block.label)
  buf.write_string("-----\n")
  buf.to_string()
}

///|
pub fn encode_simple(label : String, data : Bytes) -> String {
  encode({ label, data, headers: [] })
}

// ─── helpers ─────────────────────────────────────────────────────────────

///|
fn split_lines(s : String) -> Array[String] {
  let out : Array[String] = []
  let buf = StringBuilder::new()
  for c in s {
    if c == '\n' {
      out.push(buf.to_string())
      buf.reset()
    } else if c == '\r' {
      // skip
    } else {
      buf.write_char(c)
    }
  }
  out.push(buf.to_string())
  out
}

///|
fn trim(s : String) -> String {
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
    slice_string(s, start, end)
  }
}

///|
fn is_ws(c : Char) -> Bool {
  c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

///|
fn slice_string(s : String, start : Int, end : Int) -> String {
  let buf = StringBuilder::new()
  let mut idx = 0
  for c in s {
    if idx >= start && idx < end {
      buf.write_char(c)
    }
    idx = idx + 1
    if idx >= end {
      break
    }
  }
  buf.to_string()
}

///|
fn contains_char(s : String, target : Char) -> Bool {
  for c in s {
    if c == target {
      return true
    }
  }
  false
}

///|
fn split_once(s : String, sep : Char) -> (String, String) {
  let head = StringBuilder::new()
  let tail = StringBuilder::new()
  let mut split = false
  for c in s {
    if not(split) && c == sep {
      split = true
      continue
    }
    if split {
      tail.write_char(c)
    } else {
      head.write_char(c)
    }
  }
  (head.to_string(), tail.to_string())
}

///|
fn parse_begin_marker(line : String) -> String? {
  let prefix = "-----BEGIN "
  let suffix = "-----"
  if not(starts_with(line, prefix)) {
    return None
  }
  if not(ends_with(line, suffix)) {
    return None
  }
  let inner_end = line.length() - suffix.length()
  if inner_end <= prefix.length() {
    return None
  }
  let label = slice_string(line, prefix.length(), inner_end)
  if label == "" {
    return None
  }
  Some(label)
}

///|
fn parse_end_marker(line : String) -> String? {
  let prefix = "-----END "
  let suffix = "-----"
  if not(starts_with(line, prefix)) {
    return None
  }
  if not(ends_with(line, suffix)) {
    return None
  }
  let inner_end = line.length() - suffix.length()
  if inner_end <= prefix.length() {
    return None
  }
  let label = slice_string(line, prefix.length(), inner_end)
  if label == "" {
    return None
  }
  Some(label)
}

///|
fn starts_with(s : String, prefix : String) -> Bool {
  if s.length() < prefix.length() {
    return false
  }
  let mut i = 0
  for c in prefix {
    if s.get_char(i).unwrap() != c {
      return false
    }
    i = i + 1
  }
  true
}

///|
fn ends_with(s : String, suffix : String) -> Bool {
  if s.length() < suffix.length() {
    return false
  }
  let offset = s.length() - suffix.length()
  let mut i = 0
  for c in suffix {
    if s.get_char(offset + i).unwrap() != c {
      return false
    }
    i = i + 1
  }
  true
}

///|
fn is_pure_base64_line(s : String) -> Bool {
  // A "pure" base64 line consists only of the base64 alphabet plus '=' padding.
  // We use this to disambiguate header lines from accidentally colon-bearing
  // base64 (which RFC 7468 forbids anyway, but we are lax on input).
  if s.length() == 0 {
    return false
  }
  for c in s {
    if not(is_base64_char(c)) {
      return false
    }
  }
  true
}

///|
fn is_base64_char(c : Char) -> Bool {
  (c >= 'A' && c <= 'Z') ||
  (c >= 'a' && c <= 'z') ||
  (c >= '0' && c <= '9') ||
  c == '+' ||
  c == '/' ||
  c == '='
}
