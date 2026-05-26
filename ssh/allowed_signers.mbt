// OpenSSH allowed_signers(5) file parser. The format (see ssh-keygen man
// page, "ALLOWED SIGNERS"):
//
//   principals [options] keytype base64-key [comment]
//
// where:
//   - `principals` is a comma-separated list. May contain `*`/`?` glob
//     patterns. A standalone `*` matches any principal.
//   - `options` are optional and may include cert-authority,
//     namespaces="git,file", valid-after="...", valid-before="...".
//   - `keytype` + `base64-key` is exactly what's emitted by ssh-keygen.
//
// Lines starting with `#` and blank lines are ignored.

///|
pub(all) struct AllowedSigner {
  principals : Array[String]
  // Optional namespace filter, derived from a namespaces="..." option.
  // None means the signer is unconstrained (the OpenSSH default).
  namespaces : Array[String]?
  pubkey : SshPublicKey
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
fn try_parse_allowed_signer_line(line : String) -> AllowedSigner? raise SshError {
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
  // Walk remaining tokens. Anything looking like `key=...` (or a bareword
  // we know is an option such as cert-authority) goes into options. As
  // soon as we hit a recognised keytype, the next token is the base64 key.
  let mut namespaces : Array[String]? = None
  let mut idx = 1
  while idx < tokens.length() {
    let t = tokens[idx]
    if is_known_keytype(t) {
      break
    }
    // Option: key=value or bareword.
    let eq = index_of(t, '=')
    if eq >= 0 {
      let k = substr(t, 0, eq)
      let v = strip_quotes(substr(t, eq + 1, t.length()))
      if k == "namespaces" {
        namespaces = Some(split_on(v, ','))
      }
      // Other options (valid-after / valid-before / cert-authority) are
      // currently not enforced; record-only here.
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
  Some({ principals, namespaces, pubkey })
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
  namespace? : String = "git",
) -> Bool raise SshError {
  let signers = parse_allowed_signers(allowed_signers_text)
  let matched = find_signers(signers, principal)
  if matched.length() == 0 {
    return false
  }
  for s in matched {
    match s.namespaces {
      Some(ns_list) => {
        let mut ok = false
        for n in ns_list {
          if n == namespace {
            ok = true
            break
          }
        }
        if not(ok) {
          continue
        }
      }
      None => ()
    }
    if verify_armor_with(armor, message, s.pubkey, namespace=namespace) {
      return true
    }
  }
  false
}

// ─── helpers ─────────────────────────────────────────────────────────────

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
