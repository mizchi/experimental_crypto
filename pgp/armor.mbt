// OpenPGP ASCII armor (RFC 9580 §6 / RFC 4880 §6).
//
// Format:
//   -----BEGIN PGP <LABEL>-----
//   Header: value          ← zero or more (e.g. Version, Comment)
//   <blank line>
//   <base64 data, wrapped>
//   =<base64 of 24-bit CRC>     ← CRC line (=BBBB), now OPTIONAL in RFC 9580
//   -----END PGP <LABEL>-----

///|
pub suberror PgpError {
  ArmorMalformed(String)
  ArmorCrcMismatch
  PacketTooShort(String)
  UnsupportedPacketVersion(Int)
  UnsupportedPubkeyAlgo(Int)
  UnsupportedHashAlgo(Int)
  UnsupportedSignatureType(Int)
  InvalidMpi(String)
  Crypto(String)
} derive(Debug)

///|
pub(all) struct Armored {
  label : String
  data : Bytes
}

///|
/// Decode an OpenPGP ASCII armor block. Validates the CRC24 trailer if
/// present (some implementations omit it; RFC 9580 made it optional).
pub fn decode_armor(input : String) -> Armored raise PgpError {
  let lines = split_lines(input)
  let mut i = 0
  while i < lines.length() && trim_ascii(lines[i]) == "" {
    i = i + 1
  }
  if i >= lines.length() {
    raise ArmorMalformed("missing BEGIN line")
  }
  let begin_line = trim_ascii(lines[i])
  i = i + 1
  let label = match parse_label(begin_line, "-----BEGIN PGP ", "-----") {
    Some(l) => l
    None => raise ArmorMalformed("malformed BEGIN line")
  }
  // Skip headers until first blank line.
  let mut in_headers = true
  let buf = StringBuilder::new()
  let mut crc_expected : UInt? = None
  let mut end_label : String? = None
  while i < lines.length() {
    let raw = lines[i]
    i = i + 1
    let line = trim_ascii(raw)
    if in_headers {
      if line == "" {
        in_headers = false
        continue
      }
      // Headers look like "Name: value". Once we see something else we
      // assume the body started (compatible with gpg's compact output
      // which sometimes omits the blank line for short keys).
      if contains_char(line, ':') {
        continue
      } else {
        in_headers = false
      }
    }
    match parse_label(line, "-----END PGP ", "-----") {
      Some(l) => {
        end_label = Some(l)
        break
      }
      None => ()
    }
    if line.length() > 0 &&
      line.get_char(0).unwrap() == '=' &&
      line.length() == 5 {
      // CRC line "=AAAA"
      let crc_b64 = substring(line, 1, line.length())
      let crc_bytes = @base64.decode(crc_b64) catch {
        _ => raise ArmorMalformed("crc base64")
      }
      if crc_bytes.length() != 3 {
        raise ArmorMalformed("crc length")
      }
      let crc = (crc_bytes[0].to_uint() << 16) |
        (crc_bytes[1].to_uint() << 8) |
        crc_bytes[2].to_uint()
      crc_expected = Some(crc)
      continue
    }
    buf.write_string(line)
  }
  match end_label {
    Some(el) =>
      if el != label {
        raise ArmorMalformed("label mismatch: " + label + " vs " + el)
      }
    None => raise ArmorMalformed("missing END line")
  }
  let data = @base64.decode(buf.to_string()) catch {
    _ => raise ArmorMalformed("body base64")
  }
  match crc_expected {
    Some(expected) => if crc24(data) != expected { raise ArmorCrcMismatch }
    None => ()
  }
  { label, data }
}

///|
fn parse_label(line : String, prefix : String, suffix : String) -> String? {
  if !starts_with(line, prefix) {
    return None
  }
  if !ends_with(line, suffix) {
    return None
  }
  Some(substring(line, prefix.length(), line.length() - suffix.length()))
}

///|
fn starts_with(s : String, p : String) -> Bool {
  if s.length() < p.length() {
    return false
  }
  for i = 0; i < p.length(); i = i + 1 {
    if s.get_char(i).unwrap() != p.get_char(i).unwrap() {
      return false
    }
  }
  true
}

///|
fn ends_with(s : String, suf : String) -> Bool {
  if s.length() < suf.length() {
    return false
  }
  let offset = s.length() - suf.length()
  for i = 0; i < suf.length(); i = i + 1 {
    if s.get_char(offset + i).unwrap() != suf.get_char(i).unwrap() {
      return false
    }
  }
  true
}

///|
fn substring(s : String, start : Int, end : Int) -> String {
  let buf = StringBuilder::new()
  for i = start; i < end; i = i + 1 {
    buf.write_char(s.get_char(i).unwrap())
  }
  buf.to_string()
}

///|
fn contains_char(s : String, c : Char) -> Bool {
  for ch in s {
    if ch == c {
      return true
    }
  }
  false
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
    substring(s, start, end)
  }
}

///|
fn is_ws(c : Char) -> Bool {
  c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// ─── CRC24 (RFC 4880 §6.1) ───────────────────────────────────────────────

///|
fn crc24(data : Bytes) -> UInt {
  let mut crc = 0xB704CEU
  for i = 0; i < data.length(); i = i + 1 {
    crc = crc ^ (data[i].to_uint() << 16)
    for _ in 0..<8 {
      crc = crc << 1
      if (crc & 0x1000000U) != 0U {
        crc = crc ^ 0x1864CFBU
      }
    }
  }
  crc & 0xFFFFFFU
}
