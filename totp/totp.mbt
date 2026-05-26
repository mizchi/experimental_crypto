// HOTP (RFC 4226) and TOTP (RFC 6238) one-time passwords.
//
// Algorithm:
//
//   HOTP(K, C) = Truncate(HMAC-H(K, C_be_8))
//
//   Truncate(hmac):
//     offset = hmac[len-1] & 0x0F
//     bin    = ((hmac[offset]   & 0x7F) << 24)
//            | ((hmac[offset+1] & 0xFF) << 16)
//            | ((hmac[offset+2] & 0xFF) <<  8)
//            |  (hmac[offset+3] & 0xFF)
//     return bin mod 10^digits
//
//   TOTP(K, t) = HOTP(K, floor((t - T0) / step))
//
// RFC 6238 §1.2 is ambiguous on the truncation offset for non-SHA-1 HMACs;
// reference implementations (the IETF appendix and Go's `otp` library) use
// `hmac[len-1] & 0x0F` for *every* hash length. We follow that convention so
// the published 8-digit SHA-256 / SHA-512 vectors match.

///|
/// Hash function selector for HOTP / TOTP. SHA-1 is the historical default
/// (Google Authenticator, RFC 4226). SHA-256 / SHA-512 are RFC 6238 §1.2.
pub(all) enum TotpHash {
  Sha1
  Sha256
  Sha512
}

///|
fn totp_hmac(hash : TotpHash, key : Bytes, msg : Bytes) -> Bytes {
  match hash {
    Sha1 => @hash.hmac_sha1(key, msg)
    Sha256 => @hash.hmac_sha256(key, msg)
    Sha512 => @hash.hmac_sha512(key, msg)
  }
}

///|
fn totp_hash_name(hash : TotpHash) -> String {
  match hash {
    Sha1 => "SHA1"
    Sha256 => "SHA256"
    Sha512 => "SHA512"
  }
}

///|
// `counter` packed big-endian into 8 bytes. UInt64 keeps the math
// unsigned; HOTP/TOTP counters are non-negative by definition.
fn counter_be_8(counter : UInt64) -> Bytes {
  let buf = FixedArray::make(8, b'\x00')
  buf.unsafe_set(0, (counter >> 56).to_byte())
  buf.unsafe_set(1, (counter >> 48).to_byte())
  buf.unsafe_set(2, (counter >> 40).to_byte())
  buf.unsafe_set(3, (counter >> 32).to_byte())
  buf.unsafe_set(4, (counter >> 24).to_byte())
  buf.unsafe_set(5, (counter >> 16).to_byte())
  buf.unsafe_set(6, (counter >> 8).to_byte())
  buf.unsafe_set(7, counter.to_byte())
  Bytes::makei(8, fn(j) { buf.unsafe_get(j) })
}

///|
fn pow10(n : Int) -> Int {
  let mut p = 1
  for i = 0; i < n; i = i + 1 {
    let _ = i
    p = p * 10
  }
  p
}

///|
let min_digits : Int = 6

///|
let max_digits : Int = 8

///|
let max_verify_skew : Int = 10

///|
fn valid_digits(digits : Int) -> Bool {
  digits >= min_digits && digits <= max_digits
}

///|
fn is_decimal_string(s : String) -> Bool {
  for i = 0; i < s.length(); i = i + 1 {
    let c = s.code_unit_at(i).to_int()
    if c < 0x30 || c > 0x39 {
      return false
    }
  }
  true
}

///|
// Zero-pad `value` to `width` digits as a decimal string.
fn pad_decimal(value : Int, width : Int) -> String {
  let buf = StringBuilder::new()
  let s = value.to_string()
  for i = s.length(); i < width; i = i + 1 {
    let _ = i
    buf.write_char('0')
  }
  buf.write_string(s)
  buf.to_string()
}

///|
/// HOTP (RFC 4226) — produces an `digits`-digit decimal code from the
/// `digits`-truncation of `HMAC-H(key, counter_be_8)`.
///
/// Default `hash = Sha1`, `digits = 6` (Google Authenticator defaults).
pub fn hotp(
  key : Bytes,
  counter : UInt64,
  digits? : Int = 6,
  hash? : TotpHash = Sha1,
) -> String {
  if !valid_digits(digits) {
    return ""
  }
  let tag = totp_hmac(hash, key, counter_be_8(counter))
  let last = tag.length() - 1
  let offset = tag[last].to_int() & 0x0F
  let bin = ((tag[offset].to_int() & 0x7F) << 24) |
    ((tag[offset + 1].to_int() & 0xFF) << 16) |
    ((tag[offset + 2].to_int() & 0xFF) << 8) |
    (tag[offset + 3].to_int() & 0xFF)
  let modulus = pow10(digits)
  let code = bin % modulus
  pad_decimal(code, digits)
}

///|
// Compute the TOTP counter from `now_seconds`. RFC 6238 §4.2:
//   T = floor((now - T0) / step)
// We do the arithmetic in Int64 so negative `now - T0` is well-defined
// (truncating-toward-zero division, not floor). For all real-world inputs
// `now_seconds >= t0` so the truncating semantics match floor.
fn totp_counter(now_seconds : Int64, step_seconds : Int, t0 : Int64) -> UInt64 {
  let elapsed = now_seconds - t0
  let c = elapsed / step_seconds.to_int64()
  c.reinterpret_as_uint64()
}

///|
fn totp_counter_checked(
  now_seconds : Int64,
  step_seconds : Int,
  t0 : Int64,
) -> UInt64? {
  if step_seconds <= 0 || now_seconds < t0 {
    return None
  }
  Some(totp_counter(now_seconds, step_seconds, t0))
}

///|
/// TOTP (RFC 6238) — HOTP applied to a time-derived counter.
///
/// `now_seconds` is unix-time (seconds since 1970-01-01 UTC). `t0` defaults
/// to 0, `step_seconds` defaults to 30.
pub fn totp(
  key : Bytes,
  now_seconds : Int64,
  step_seconds? : Int = 30,
  t0? : Int64 = 0L,
  digits? : Int = 6,
  hash? : TotpHash = Sha1,
) -> String {
  if !valid_digits(digits) {
    return ""
  }
  match totp_counter_checked(now_seconds, step_seconds, t0) {
    Some(counter) => hotp(key, counter, digits~, hash~)
    None => ""
  }
}

///|
/// Verify `code` against the TOTP of `key` at `now_seconds`, accepting any
/// step in `[-skew, +skew]` to tolerate clock drift. Uses constant-time
/// string comparison once each candidate is materialised, so a leaked code
/// does not reveal which step in the window matched.
pub fn verify_totp(
  key : Bytes,
  code : String,
  now_seconds : Int64,
  step_seconds? : Int = 30,
  t0? : Int64 = 0L,
  digits? : Int = 6,
  hash? : TotpHash = Sha1,
  skew? : Int = 1,
) -> Bool {
  if !valid_digits(digits) ||
    code.length() != digits ||
    !is_decimal_string(code) ||
    skew < 0 ||
    skew > max_verify_skew {
    return false
  }
  let center = match totp_counter_checked(now_seconds, step_seconds, t0) {
    Some(c) => c
    None => return false
  }
  let mut matched = false
  // Walk the whole window even after a match so timing does not leak the
  // offset. `matched |=` rather than early return.
  for d = -skew; d <= skew; d = d + 1 {
    let candidate_counter : UInt64? = if d < 0 {
      let off = (-d).to_uint64()
      if center < off {
        None
      } else {
        Some(center - off)
      }
    } else {
      Some(center + d.to_uint64())
    }
    match candidate_counter {
      Some(c) => {
        let candidate = hotp(key, c, digits~, hash~)
        let eq = ct_eq_string(candidate, code)
        matched = matched || eq
      }
      None => ()
    }
  }
  matched
}

///|
// Constant-time equality for two ASCII / decimal strings. HOTP outputs are
// pure digits so a byte-wise diff over `.code_unit_at(i)` is sufficient and
// avoids leaking the first-difference position.
fn ct_eq_string(a : String, b : String) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i = 0; i < a.length(); i = i + 1 {
    diff = diff | (a.code_unit_at(i).to_int() ^ b.code_unit_at(i).to_int())
  }
  diff == 0
}

///|
/// Build the Google Authenticator `otpauth://totp/...` URI for QR-code
/// provisioning.
///
/// Format (Google "Key URI Format" spec, mirrored by Authy / 1Password):
///
///   otpauth://totp/<label>?secret=<base32>&issuer=<issuer>
///                         &digits=<n>&period=<step>&algorithm=<SHA1|256|512>
///
/// `label` and `issuer` are URI-percent-encoded. `secret` is RFC 4648
/// base32 *without* padding (Google Authenticator rejects `=` padding).
pub fn provisioning_uri(
  label : String,
  secret : Bytes,
  issuer? : String = "",
  digits? : Int = 6,
  step_seconds? : Int = 30,
  hash? : TotpHash = Sha1,
) -> String {
  if !valid_digits(digits) || step_seconds <= 0 || secret.length() == 0 {
    return ""
  }
  let buf = StringBuilder::new()
  buf.write_string("otpauth://totp/")
  buf.write_string(uri_encode(label))
  buf.write_string("?secret=")
  buf.write_string(base32_encode_no_padding(secret))
  if issuer != "" {
    buf.write_string("&issuer=")
    buf.write_string(uri_encode(issuer))
  }
  buf.write_string("&digits=")
  buf.write_string(digits.to_string())
  buf.write_string("&period=")
  buf.write_string(step_seconds.to_string())
  buf.write_string("&algorithm=")
  buf.write_string(totp_hash_name(hash))
  buf.to_string()
}

// ──────────────────────────────────────────────────────────────────────
// Base32 (RFC 4648, no padding)
// ──────────────────────────────────────────────────────────────────────
//
// moonbitlang/core/encoding only ships base64; we inline a small base32
// encoder rather than pull in a new dependency. Encode-only — TOTP secret
// flow is one-way (server emits the URI, scanner reads it).

///|
let base32_alphabet : String = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

///|
fn base32_encode_no_padding(data : Bytes) -> String {
  let n = data.length()
  if n == 0 {
    return ""
  }
  let buf = StringBuilder::new()
  let mut bit_buffer = 0
  let mut bit_count = 0
  for i = 0; i < n; i = i + 1 {
    bit_buffer = (bit_buffer << 8) | (data[i].to_int() & 0xFF)
    bit_count = bit_count + 8
    while bit_count >= 5 {
      bit_count = bit_count - 5
      let idx = (bit_buffer >> bit_count) & 0x1F
      buf.write_char(
        base32_alphabet.code_unit_at(idx).to_int() |> Int::unsafe_to_char,
      )
    }
  }
  if bit_count > 0 {
    let idx = (bit_buffer << (5 - bit_count)) & 0x1F
    buf.write_char(
      base32_alphabet.code_unit_at(idx).to_int() |> Int::unsafe_to_char,
    )
  }
  buf.to_string()
}

// ──────────────────────────────────────────────────────────────────────
// Minimal URI percent-encoder for label / issuer.
// ──────────────────────────────────────────────────────────────────────
//
// Encodes anything outside RFC 3986 `unreserved` set (ALPHA / DIGIT /
// `-._~`). Authenticator apps accept lower-case hex; we emit upper-case
// per RFC 3986 §2.1 to match what most reference implementations produce.

///|
fn uri_encode(s : String) -> String {
  let buf = StringBuilder::new()
  // UTF-16 -> UTF-8 -> %XX. MoonBit String is UTF-16 (BMP code units +
  // surrogate pairs). For TOTP labels we only realistically see ASCII /
  // BMP — but encode the surrogate path too so a label like an emoji
  // issuer string is not silently mangled.
  let mut i = 0
  while i < s.length() {
    let code = s.code_unit_at(i).to_int()
    let cp = if code >= 0xD800 && code <= 0xDBFF && i + 1 < s.length() {
      let lo = s.code_unit_at(i + 1).to_int()
      if lo >= 0xDC00 && lo <= 0xDFFF {
        i = i + 1
        0x10000 + ((code - 0xD800) << 10) + (lo - 0xDC00)
      } else {
        code
      }
    } else {
      code
    }
    i = i + 1
    if is_unreserved(cp) {
      buf.write_char(cp |> Int::unsafe_to_char)
      // UTF-8 encode then percent-encode each byte.
    } else if cp < 0x80 {
      write_pct(buf, cp)
    } else if cp < 0x800 {
      write_pct(buf, 0xC0 | (cp >> 6))
      write_pct(buf, 0x80 | (cp & 0x3F))
    } else if cp < 0x10000 {
      write_pct(buf, 0xE0 | (cp >> 12))
      write_pct(buf, 0x80 | ((cp >> 6) & 0x3F))
      write_pct(buf, 0x80 | (cp & 0x3F))
    } else {
      write_pct(buf, 0xF0 | (cp >> 18))
      write_pct(buf, 0x80 | ((cp >> 12) & 0x3F))
      write_pct(buf, 0x80 | ((cp >> 6) & 0x3F))
      write_pct(buf, 0x80 | (cp & 0x3F))
    }
  }
  buf.to_string()
}

///|
fn is_unreserved(c : Int) -> Bool {
  (c >= 0x41 && c <= 0x5A) || // A-Z
  (c >= 0x61 && c <= 0x7A) || // a-z
  (c >= 0x30 && c <= 0x39) || // 0-9
  c == 0x2D || // -
  c == 0x2E || // .
  c == 0x5F || // _
  c == 0x7E // ~
}

///|
let hex_upper : String = "0123456789ABCDEF"

///|
fn write_pct(buf : StringBuilder, byte : Int) -> Unit {
  buf.write_char('%')
  buf.write_char(
    hex_upper.code_unit_at((byte >> 4) & 0xF).to_int() |> Int::unsafe_to_char,
  )
  buf.write_char(
    hex_upper.code_unit_at(byte & 0xF).to_int() |> Int::unsafe_to_char,
  )
}
