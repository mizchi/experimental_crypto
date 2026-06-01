// Conservative allowed_signers-style file parser. The format mirrors the
// common SSH signing layout:
//
//   principals [options] keytype base64-key [comment]
//
// where:
//   - `principals` is a comma-separated list. May contain `*`/`?` glob
//     patterns. A standalone `*` matches any principal.
//   - `options` may include namespaces="git,file", valid-after="YYYYMMDDZ",
//     and valid-before="YYYYMMDDZ" / "YYYYMMDDHHMMSSZ".
//   - cert-authority is accepted only by the time-aware verification path,
//     because OpenSSH certificates carry their own validity windows.
//   - `keytype` + `base64-key` is exactly what's emitted by ssh-keygen.
//
// Lines starting with `#` and blank lines are ignored.

///|
pub(all) struct AllowedSigner {
  principals : Array[String]
  // Optional sig_namespace filter, derived from a namespaces="..." option.
  // None means the signer is unconstrained.
  namespaces : Array[String]?
  // Optional Unix-time validity window. `valid_before` is exclusive.
  valid_after : Int64?
  valid_before : Int64?
  cert_authority : Bool
  pubkey : SshPublicKey
}

///|
priv struct ParsedAllowedOptions {
  namespaces : Array[String]?
  valid_after : Int64?
  valid_before : Int64?
  cert_authority : Bool
}

///|
/// Parse an allowed_signers file body. Each non-comment line that has
/// the expected shape is returned. Lines with unsupported keytypes are
/// skipped silently — callers that need stricter behaviour should walk
/// the result and check.
pub fn parse_allowed_signers(
  text : String,
) -> Array[AllowedSigner] raise SshError {
  let lines = split_lines_text(text)
  let out : Array[AllowedSigner] = []
  for raw in lines {
    let line = trim_ascii(raw)
    if line == "" {
      continue
    }
    if line.get_char(0).unwrap() == '#' {
      continue
    }
    match try_parse_allowed_signer_line(line) {
      Some(s) => out.push(s)
      None => () // unparseable / unsupported keytype — skip
    }
  }
  out
}

///|
fn try_parse_allowed_signer_line(
  line : String,
) -> AllowedSigner? raise SshError {
  // Tokenise the line into fields. Quoted values ("foo bar") count as one
  // token. The first whitespace-separated piece is principals. After that
  // we walk until we hit a recognised keytype.
  let tokens = tokenise_quoted(line)
  if tokens.length() < 3 {
    return None
  }
  let principals_field = tokens[0]
  let principals : Array[String] = []
  let pbuf = StringBuilder::new()
  let mut pcount = 0
  for c in principals_field {
    if c == ',' {
      if pcount > 0 {
        principals.push(pbuf.to_string())
        pbuf.reset()
        pcount = 0
      }
    } else {
      pbuf.write_char(c)
      pcount = pcount + 1
    }
  }
  if pcount > 0 {
    principals.push(pbuf.to_string())
  }
  if principals.length() == 0 {
    return None
  }
  // Walk remaining tokens. As soon as we hit a recognised keytype, the next
  // token is the base64 key. Security-sensitive options that this module
  // cannot enforce make the line invalid rather than silently widening trust.
  let mut namespaces : Array[String]? = None
  let mut valid_after : Int64? = None
  let mut valid_before : Int64? = None
  let mut cert_authority = false
  let mut idx = 1
  while idx < tokens.length() {
    let t = tokens[idx]
    if is_known_keytype(t) {
      break
    }
    let (ok, parsed) = parse_options_token(t)
    if !ok {
      return None
    }
    match parsed.namespaces {
      Some(ns) =>
        match namespaces {
          Some(_) => return None
          None => namespaces = Some(ns)
        }
      None => ()
    }
    match parsed.valid_after {
      Some(ts) =>
        match valid_after {
          Some(_) => return None
          None => valid_after = Some(ts)
        }
      None => ()
    }
    match parsed.valid_before {
      Some(ts) =>
        match valid_before {
          Some(_) => return None
          None => valid_before = Some(ts)
        }
      None => ()
    }
    if parsed.cert_authority {
      if cert_authority {
        return None
      }
      cert_authority = true
    }
    idx = idx + 1
  }
  if idx + 1 >= tokens.length() {
    return None
  }
  let keytype = tokens[idx]
  let base64_blob = tokens[idx + 1]
  let blob = @base64.decode(base64_blob) catch { _ => return None }
  let pubkey = if keytype == "ssh-ed25519" {
    SshPublicKey::Ed25519(parse_ed25519_pubkey(blob))
  } else if keytype == "ssh-rsa" {
    SshPublicKey::Rsa(parse_rsa_pubkey(blob))
  } else if keytype == "ecdsa-sha2-nistp256" || keytype == "ecdsa-sha2-nistp384" {
    parse_ecdsa_pubkey(blob)
  } else {
    return None
  }
  Some({
    principals,
    namespaces,
    valid_after,
    valid_before,
    cert_authority,
    pubkey,
  })
}

///|
fn parse_options_token(token : String) -> (Bool, ParsedAllowedOptions) {
  let opts = split_options(token)
  let mut namespaces : Array[String]? = None
  let mut valid_after : Int64? = None
  let mut valid_before : Int64? = None
  let mut cert_authority = false
  for opt in opts {
    if opt == "" {
      return (false, { namespaces, valid_after, valid_before, cert_authority })
    }
    if opt == "cert-authority" {
      if cert_authority {
        return (
          false,
          { namespaces, valid_after, valid_before, cert_authority },
        )
      }
      cert_authority = true
      continue
    }
    let eq = index_of(opt, '=')
    if eq < 0 {
      return (false, { namespaces, valid_after, valid_before, cert_authority })
    }
    let k = substr(opt, 0, eq)
    let v = strip_quotes(substr(opt, eq + 1, opt.length()))
    if k == "namespaces" {
      match namespaces {
        Some(_) =>
          return (
            false,
            { namespaces, valid_after, valid_before, cert_authority },
          )
        None => ()
      }
      let ns = split_on(v, ',')
      for n in ns {
        if n == "" {
          return (
            false,
            { namespaces, valid_after, valid_before, cert_authority },
          )
        }
      }
      namespaces = Some(ns)
    } else if k == "valid-after" {
      match valid_after {
        Some(_) =>
          return (
            false,
            { namespaces, valid_after, valid_before, cert_authority },
          )
        None => ()
      }
      match parse_validity_time(v) {
        Some(ts) => valid_after = Some(ts)
        None =>
          return (
            false,
            { namespaces, valid_after, valid_before, cert_authority },
          )
      }
    } else if k == "valid-before" {
      match valid_before {
        Some(_) =>
          return (
            false,
            { namespaces, valid_after, valid_before, cert_authority },
          )
        None => ()
      }
      match parse_validity_time(v) {
        Some(ts) => valid_before = Some(ts)
        None =>
          return (
            false,
            { namespaces, valid_after, valid_before, cert_authority },
          )
      }
    } else {
      return (false, { namespaces, valid_after, valid_before, cert_authority })
    }
  }
  (true, { namespaces, valid_after, valid_before, cert_authority })
}

///|
/// Match `principal` against the entries in `allowed`. Returns all
/// matching signers, ordered by appearance. Glob characters `*` and `?`
/// in the principal are interpreted (`*` = any run, `?` = single char).
/// A literal `*` token alone matches any principal.
pub fn find_signers(
  allowed : Array[AllowedSigner],
  principal : String,
) -> Array[AllowedSigner] {
  let out : Array[AllowedSigner] = []
  for s in allowed {
    for p in s.principals {
      if principal_matches(p, principal) {
        out.push(s)
        break
      }
    }
  }
  out
}

///|
/// End-to-end: parse an `allowed_signers` body, look up `principal`, and
/// verify the armored SSHSIG over `message`. Returns true iff at least
/// one matching signer's key verifies.
pub fn verify_with_allowed_signers(
  allowed_signers_text : String,
  principal : String,
  armor : String,
  message : Bytes,
  sig_namespace? : String = "git",
) -> Bool raise SshError {
  verify_with_allowed_signers_internal(
    allowed_signers_text,
    principal,
    armor,
    message,
    None,
    sig_namespace~,
  )
}

///|
/// Time-aware allowed_signers verification. This is the only high-level API
/// that accepts entries carrying `valid-after` / `valid-before`; the plain
/// `verify_with_allowed_signers` path rejects those entries fail-closed.
pub fn verify_with_allowed_signers_at(
  allowed_signers_text : String,
  principal : String,
  armor : String,
  message : Bytes,
  now_unix : Int64,
  sig_namespace? : String = "git",
) -> Bool raise SshError {
  verify_with_allowed_signers_internal(
    allowed_signers_text,
    principal,
    armor,
    message,
    Some(now_unix),
    sig_namespace~,
  )
}

///|
fn verify_with_allowed_signers_internal(
  allowed_signers_text : String,
  principal : String,
  armor : String,
  message : Bytes,
  now_unix : Int64?,
  sig_namespace~ : String,
) -> Bool raise SshError {
  validate_namespace(sig_namespace)
  let signers = parse_allowed_signers(allowed_signers_text)
  let matched = find_signers(signers, principal)
  if matched.length() == 0 {
    return false
  }
  for s in matched {
    if !signer_namespace_allows(s, sig_namespace) {
      continue
    }
    if !signer_time_allows(s, now_unix) {
      continue
    }
    let ok = if s.cert_authority {
      verify_armor_with_cert_authority(
        armor,
        message,
        s.pubkey,
        principal,
        now_unix,
        sig_namespace~,
      )
    } else {
      verify_armor_with(armor, message, s.pubkey, sig_namespace~)
    }
    if ok {
      return true
    }
  }
  false
}

// ─── helpers ─────────────────────────────────────────────────────────────

///|
fn signer_namespace_allows(s : AllowedSigner, sig_namespace : String) -> Bool {
  match s.namespaces {
    Some(ns_list) => {
      for n in ns_list {
        if n == sig_namespace {
          return true
        }
      }
      false
    }
    None => true
  }
}

///|
fn signer_time_allows(s : AllowedSigner, now_unix : Int64?) -> Bool {
  match (s.valid_after, s.valid_before) {
    (None, None) => true
    _ =>
      match now_unix {
        None => false
        Some(now) => {
          match s.valid_after {
            Some(after) => if now < after { return false }
            None => ()
          }
          match s.valid_before {
            Some(before) => if now >= before { return false }
            None => ()
          }
          true
        }
      }
  }
}

///|
fn verify_armor_with_cert_authority(
  armor : String,
  message : Bytes,
  ca_key : SshPublicKey,
  principal : String,
  now_unix : Int64?,
  sig_namespace~ : String,
) -> Bool raise SshError {
  let now = match now_unix {
    Some(t) => t
    None => return false
  }
  if now < 0L {
    return false
  }
  let blob = decode_sshsig_armor_strict(armor)
  let sig = decode_sshsig_blob(blob)
  if sig.sig_namespace != sig_namespace {
    return false
  }
  let cert = match sig.publickey {
    Certificate(c) => c
    _ => return false
  }
  if !pubkeys_equal(cert.ca_key, ca_key) {
    return false
  }
  if !certificate_trust_policy_allows(cert, principal, now) {
    return false
  }
  let signed_data = compute_signed_data(
    sig.sig_namespace,
    sig.hash_algorithm,
    message,
  )
  verify_signed_data(sig.publickey, signed_data, sig.signature_blob)
}

///|
fn certificate_trust_policy_allows(
  cert : SshCertificate,
  principal : String,
  now : Int64,
) -> Bool {
  if !certificate_basic_policy_allows(cert) {
    return false
  }
  let now_u = now.reinterpret_as_uint64()
  if now_u < cert.valid_after || now_u >= cert.valid_before {
    return false
  }
  certificate_principal_allows(cert, principal)
}

///|
fn certificate_principal_allows(
  cert : SshCertificate,
  principal : String,
) -> Bool {
  // A certificate verified through the cert-authority path is always checked
  // against a concrete `principal`. OpenSSH's `sshkey_cert_check_authority`
  // (driven by `ssh-keygen -Y verify -I <principal>` / sshsig.c) requires the
  // name to appear in the certificate's principal list, and rejects a
  // certificate whose list is empty ("Certificate lacks principal list" /
  // "name is not a listed principal"). An empty list must NOT be treated as a
  // wildcard here: doing so would let a CA-issued certificate that carries no
  // principal binding authenticate as any identity. Fail closed to match
  // OpenSSH and avoid that confused-deputy weakness.
  if cert.valid_principals.length() == 0 {
    return false
  }
  // Exact (non-glob) match, mirroring OpenSSH's `strcmp` over cert principals.
  for p in cert.valid_principals {
    if p == principal {
      return true
    }
  }
  false
}

///|
fn principal_matches(pattern : String, candidate : String) -> Bool {
  // OpenSSH glob: `*` matches any run (including empty), `?` matches one
  // character. We implement the standard recursive globber.
  glob_match(pattern, 0, candidate, 0)
}

///|
fn glob_match(pat : String, pi : Int, s : String, si : Int) -> Bool {
  if pi >= pat.length() {
    return si >= s.length()
  }
  let pc = pat.get_char(pi).unwrap()
  if pc == '*' {
    // Match any number of characters.
    let mut i = si
    while i <= s.length() {
      if glob_match(pat, pi + 1, s, i) {
        return true
      }
      i = i + 1
    }
    return false
  }
  if si >= s.length() {
    return false
  }
  if pc == '?' {
    return glob_match(pat, pi + 1, s, si + 1)
  }
  if pc == s.get_char(si).unwrap() {
    return glob_match(pat, pi + 1, s, si + 1)
  }
  false
}

///|
fn is_known_keytype(s : String) -> Bool {
  s == "ssh-ed25519" ||
  s == "ssh-rsa" ||
  s == "rsa-sha2-256" ||
  s == "rsa-sha2-512" ||
  s == "ecdsa-sha2-nistp256" ||
  s == "ecdsa-sha2-nistp384" ||
  s == "ecdsa-sha2-nistp521"
}

///|
fn parse_validity_time(s : String) -> Int64? {
  let has_date_only = s.length() == 9
  let has_seconds = s.length() == 15
  if !has_date_only && !has_seconds {
    return None
  }
  if s.get_char(s.length() - 1).unwrap() != 'Z' {
    return None
  }
  let year = decimal4(s, 0)
  let month = decimal2(s, 4)
  let day = decimal2(s, 6)
  let hour = if has_seconds { decimal2(s, 8) } else { 0 }
  let minute = if has_seconds { decimal2(s, 10) } else { 0 }
  let second = if has_seconds { decimal2(s, 12) } else { 0 }
  if year < 1970 {
    return None
  }
  if month < 1 || month > 12 {
    return None
  }
  if day < 1 || day > days_in_month(year, month) {
    return None
  }
  if hour < 0 ||
    hour > 23 ||
    minute < 0 ||
    minute > 59 ||
    second < 0 ||
    second > 59 {
    return None
  }
  let days = days_from_civil(year, month, day)
  Some(
    int_to_i64(days) * 86400L +
    int_to_i64(hour) * 3600L +
    int_to_i64(minute) * 60L +
    int_to_i64(second),
  )
}

///|
fn int_to_i64(n : Int) -> Int64 {
  n.to_uint64().reinterpret_as_int64()
}

///|
fn decimal2(s : String, offset : Int) -> Int {
  let hi = digit_at(s, offset)
  let lo = digit_at(s, offset + 1)
  if hi < 0 || lo < 0 {
    -1
  } else {
    hi * 10 + lo
  }
}

///|
fn decimal4(s : String, offset : Int) -> Int {
  let a = digit_at(s, offset)
  let b = digit_at(s, offset + 1)
  let c = digit_at(s, offset + 2)
  let d = digit_at(s, offset + 3)
  if a < 0 || b < 0 || c < 0 || d < 0 {
    -1
  } else {
    ((a * 10 + b) * 10 + c) * 10 + d
  }
}

///|
fn digit_at(s : String, idx : Int) -> Int {
  let c = s.get_char(idx).unwrap()
  if c >= '0' && c <= '9' {
    c.to_int() - '0'.to_int()
  } else {
    -1
  }
}

///|
fn is_leap_year(year : Int) -> Bool {
  (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

///|
fn days_in_month(year : Int, month : Int) -> Int {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31
    4 | 6 | 9 | 11 => 30
    2 => if is_leap_year(year) { 29 } else { 28 }
    _ => 0
  }
}

///|
fn days_from_civil(year : Int, month : Int, day : Int) -> Int {
  let y = if month <= 2 { year - 1 } else { year }
  let era = y / 400
  let yoe = y - era * 400
  let m = if month > 2 { month - 3 } else { month + 9 }
  let doy = (153 * m + 2) / 5 + day - 1
  let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
  era * 146097 + doe - 719468
}

///|
// Split a line on ASCII whitespace, honouring "double-quoted" tokens.
// Backslash escapes inside quotes are NOT supported (allowed_signers
// values don't use them in practice).
fn tokenise_quoted(s : String) -> Array[String] {
  let out : Array[String] = []
  let buf = StringBuilder::new()
  let mut in_quote = false
  let mut count = 0
  for c in s {
    if in_quote {
      if c == '"' {
        in_quote = false
        buf.write_char(c)
        count = count + 1
      } else {
        buf.write_char(c)
        count = count + 1
      }
    } else if c == '"' {
      in_quote = true
      buf.write_char(c)
      count = count + 1
    } else if c == ' ' || c == '\t' {
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

///|
fn split_options(s : String) -> Array[String] {
  let out : Array[String] = []
  let buf = StringBuilder::new()
  let mut in_quote = false
  for c in s {
    if c == '"' {
      in_quote = !in_quote
      buf.write_char(c)
    } else if c == ',' && !in_quote {
      out.push(buf.to_string())
      buf.reset()
    } else {
      buf.write_char(c)
    }
  }
  out.push(buf.to_string())
  out
}

///|
fn split_lines_text(s : String) -> Array[String] {
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
fn index_of(s : String, c : Char) -> Int {
  let mut i = 0
  for ch in s {
    if ch == c {
      return i
    }
    i = i + 1
  }
  -1
}

///|
fn substr(s : String, start : Int, end : Int) -> String {
  let sb = StringBuilder::new()
  for i = start; i < end; i = i + 1 {
    sb.write_char(s.get_char(i).unwrap())
  }
  sb.to_string()
}

///|
fn strip_quotes(s : String) -> String {
  if s.length() >= 2 &&
    s.get_char(0).unwrap() == '"' &&
    s.get_char(s.length() - 1).unwrap() == '"' {
    substr(s, 1, s.length() - 1)
  } else {
    s
  }
}

///|
fn split_on(s : String, sep : Char) -> Array[String] {
  let out : Array[String] = []
  let buf = StringBuilder::new()
  let mut count = 0
  for c in s {
    if c == sep {
      out.push(buf.to_string())
      buf.reset()
      count = 0
    } else {
      buf.write_char(c)
      count = count + 1
    }
  }
  let _ = count
  out.push(buf.to_string())
  out
}
