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
/// Default decoder. RFC 7468 lax mode: tolerates surrounding whitespace,
/// CRLF, base64 lines of any length, both padded and unpadded base64.
/// For RFC 7468 strict mode use `decode_strict`.
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
/// Default upper bound on input size for decode / decode_all, to prevent
/// trivially-crafted multi-gigabyte PEM strings from causing an OOM via
/// the line splitter. Override per-call by passing `max_input_size?`.
pub let pem_max_input_size : Int = 16 * 1024 * 1024 // 16 MiB

///|
/// Maximum length of any single base64 body line. RFC 7468 §3 caps lines
/// at 64 chars for strict mode; lax mode is more permissive but we still
/// refuse pathological single-line payloads (which would force a single
/// allocation up to pem_max_input_size).
pub let pem_max_line_length : Int = 8 * 1024 // 8 KiB

///|
/// RFC 7468 §3 strict mode. Requires:
///   - base64 padding (lines end with `=` if needed)
///   - base64 lines no longer than 64 characters (RFC 7468 §3 line wrap)
///   - exactly one PemBlock, with no extraneous explanatory text outside
///     the BEGIN/END markers
///
/// For the lax form (whitespace tolerant, padding optional, ignore text
/// outside markers) use `decode`. Both share the same `PemError` family.
pub fn decode_strict(
  input : String,
  max_input_size? : Int,
) -> PemBlock raise PemError {
  let cap = match max_input_size {
    Some(n) => n
    None => pem_max_input_size
  }
  if input.length() > cap {
    raise InvalidFormat(
      "input exceeds max_input_size (" + cap.to_string() + ")",
    )
  }
  // 1. Reject pre-BEGIN garbage (we walk the input ourselves).
  let lines = split_lines(input)
  // Find the first non-empty line.
  let mut idx = 0
  while idx < lines.length() && trim(lines[idx]) == "" {
    idx = idx + 1
  }
  if idx == lines.length() {
    raise MissingBeginMarker
  }
  let first = lines[idx]
  let label = match parse_begin_marker(first) {
    Some(l) => l
    None =>
      if starts_with(first, "-----BEGIN ") {
        raise InvalidFormat("invalid PEM BEGIN label")
      } else {
        raise MissingBeginMarker
      }
  }
  idx = idx + 1
  // 2. Scan base64 lines until the END marker. No headers in strict mode.
  let b64 = StringBuilder::new()
  let mut end_label : String? = None
  let mut saw_any_line = false
  while idx < lines.length() {
    let line = lines[idx]
    idx = idx + 1
    match parse_end_marker(line) {
      Some(l) => {
        end_label = Some(l)
        break
      }
      None => {
        if starts_with(line, "-----END ") {
          raise InvalidFormat("invalid PEM END label")
        }
        // Strict mode: line must be exactly base64 chars + optional '='
        // padding, length <= 64.
        if line.length() > 64 {
          raise InvalidFormat("base64 line longer than 64 chars")
        }
        if not(is_pure_base64_line(line)) {
          raise InvalidFormat("non-base64 character in PEM body")
        }
        b64.write_string(line)
        saw_any_line = true
      }
    }
  }
  let el = match end_label {
    Some(s) => s
    None => raise MissingEndMarker
  }
  if el != label {
    raise LabelMismatch(begin=label, end=el)
  }
  // 3. Strict base64 decode: require padding. core's @base64.decode is
  // strict about padding when ignore_whitespace=false.
  let body_str = b64.to_string()
  if not(has_proper_base64_padding(body_str)) {
    raise InvalidBase64
  }
  let data = @base64.decode(body_str) catch { _ => raise InvalidBase64 }
  // 4. Reject post-END garbage.
  while idx < lines.length() {
    if trim(lines[idx]) != "" {
      raise InvalidFormat("non-empty content after END marker")
    }
    idx = idx + 1
  }
  let _ = saw_any_line
  { label, data, headers: [] }
}

///|
fn has_proper_base64_padding(s : String) -> Bool {
  // RFC 4648 §4: the base64 alphabet is padded to a 4-character boundary
  // with `=`. Length must be a multiple of 4 in strict mode.
  s.length() % 4 == 0
}

///|
pub fn decode_all(input : String) -> Array[PemBlock] raise PemError {
  if input.length() > pem_max_input_size {
    raise InvalidFormat(
      "input exceeds pem_max_input_size (" +
      pem_max_input_size.to_string() +
      ")",
    )
  }
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
        if starts_with(line, "-----BEGIN ") {
          raise InvalidFormat("invalid PEM BEGIN label")
        }
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
        None => {
          if starts_with(line2, "-----END ") {
            raise InvalidFormat("invalid PEM END label")
          }
          if line2.length() > pem_max_line_length {
            raise InvalidFormat(
              "base64 line exceeds pem_max_line_length (" +
              pem_max_line_length.to_string() +
              ")",
            )
          }
          b64.write_string(line2)
        }
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
  validate_pem_label_or_abort(block.label)
  validate_pem_headers_or_abort(block.headers)
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
  if not(is_valid_pem_label(label)) {
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
  if not(is_valid_pem_label(label)) {
    return None
  }
  Some(label)
}

///|
fn is_valid_pem_label(label : String) -> Bool {
  if label.length() == 0 {
    return false
  }
  let mut idx = 0
  for c in label {
    if not(is_pem_label_char(c)) {
      return false
    }
    if (idx == 0 || idx == label.length() - 1) && (c == ' ' || c == '-') {
      return false
    }
    idx = idx + 1
  }
  true
}

///|
fn is_pem_label_char(c : Char) -> Bool {
  (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' || c == '-'
}

///|
fn validate_pem_label_or_abort(label : String) -> Unit {
  if !is_valid_pem_label(label) {
    abort("invalid PEM label")
  }
}

///|
fn validate_pem_headers_or_abort(headers : Array[(String, String)]) -> Unit {
  for h in headers {
    if !is_valid_pem_header_name(h.0) {
      abort("invalid PEM header name")
    }
    if contains_newline(h.1) {
      abort("invalid PEM header value")
    }
  }
}

///|
fn is_valid_pem_header_name(s : String) -> Bool {
  if s.length() == 0 {
    return false
  }
  for c in s {
    if c == ':' || c.to_int() <= 0x20 || c.to_int() > 0x7e {
      return false
    }
  }
  true
}

///|
fn contains_newline(s : String) -> Bool {
  for c in s {
    if c == '\r' || c == '\n' {
      return true
    }
  }
  false
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
