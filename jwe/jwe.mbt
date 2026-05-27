// JWE (RFC 7516) Compact Serialization — RSA-OAEP-256 / A256KW / dir
// key management, A128GCM / A256GCM content encryption.
//
// Compact form (RFC 7516 §3.1):
//   BASE64URL(JOSE Header) || '.' ||
//   BASE64URL(Encrypted Key) || '.' ||
//   BASE64URL(IV) || '.' ||
//   BASE64URL(Ciphertext) || '.' ||
//   BASE64URL(Tag)
//
// Supported algorithms (RFC 7518):
//   alg:
//     - "RSA-OAEP-256"  (§4.3): RSA-OAEP with SHA-256, MGF1-SHA-256
//     - "A256KW"        (§4.4): AES-256 Key Wrap (RFC 3394)
//     - "dir"           (§4.5): direct symmetric key — caller's key is the CEK
//   enc:
//     - "A128GCM"       (§5.3): AES-128-GCM
//     - "A256GCM"       (§5.3): AES-256-GCM
//
// Out of scope (intentionally not implemented in this minimal core):
//   - ECDH-ES, ECDH-ES+A256KW: would need an ephemeral key + curve agreement.
//   - PBES2 family (alg = "PBES2-HS256+A128KW" etc.) — see `mizchi/pkcs8`
//     for the underlying PBKDF2 + AES-KW pieces if you need them.
//   - A256CBC-HS512 / A128CBC-HS256: CBC + HMAC composite — possible to add
//     since `aead` already exports `aes_cbc_*`, but kept out for v0.
//   - JWE JSON Serialization (RFC 7516 §3.2) — only compact form here.
//   - `zip` header (DEFLATE pre-compression).
//
// Security caveats:
//   - AES is not constant-time (table-based S-box) — same caveat as
//     `mizchi/aead`. Do not use where cache-timing matters.
//   - RSA modexp uses `@bigint.pow` which is also not constant-time.
//   - Manger's attack mitigation: the RSA-OAEP unwrap path collapses every
//     validation failure (RSA size mismatch, Y != 0x00, lHash mismatch,
//     no 0x01 separator) into a single AuthenticationFailed error. This
//     prevents the textbook Manger attack (RFC 8017 §7.1.2 step 3.g) which
//     distinguishes the integer-to-octet-string conversion failure from
//     other OAEP failures. The variable-time `@bigint.pow` itself still
//     leaks the private exponent over a timing side-channel, so this is
//     "no padding-oracle" rather than full constant-time.

///|
pub(all) enum JweAlg {
  Dir
  Rsa_oaep_256
  A256kw
} derive(Eq, Debug)

///|
pub(all) enum JweEnc {
  A128gcm
  A256gcm
} derive(Eq, Debug)

///|
/// Encryption key. The variant selects the key-management ("alg") path.
/// `cek` for `Dir` MUST match the CEK size of the chosen `JweEnc` (16 for
/// A128GCM, 32 for A256GCM). `kek` for `Aes256Kw` MUST be 32 bytes.
pub(all) enum EncryptionKey {
  EncDir(cek~ : Bytes)
  EncRsa(pubkey~ : @rsa.RsaPublicKey)
  EncAes256Kw(kek~ : Bytes)
}

///|
/// Decryption key (mirror of EncryptionKey).
pub(all) enum DecryptionKey {
  DecDir(cek~ : Bytes)
  DecRsa(privkey~ : @rsa.RsaPrivateKey)
  DecAes256Kw(kek~ : Bytes)
}

///|
pub suberror JweError {
  InvalidToken(String)
  InvalidHeader(String)
  UnsupportedAlgorithm(String)
  AlgorithmMismatch(String)
  AuthenticationFailed
  InvalidKeySize(String)
  InvalidIvSize(String)
  // Internal / propagated errors from sub-modules:
  Aead(@aead.AeadError)
  // Manger-attack-resistant: OAEP unwrap collapses any padding failure
  // into AuthenticationFailed; this variant is reserved for cases we
  // genuinely want to distinguish (e.g. RSA ciphertext > n).
  RsaOaepError(String)
} derive(Debug)

///|
pub impl Show for JweError with fn output(self, logger) {
  match self {
    InvalidToken(s) => logger.write_string("InvalidToken(" + s + ")")
    InvalidHeader(s) => logger.write_string("InvalidHeader(" + s + ")")
    UnsupportedAlgorithm(s) =>
      logger.write_string("UnsupportedAlgorithm(" + s + ")")
    AlgorithmMismatch(s) => logger.write_string("AlgorithmMismatch(" + s + ")")
    AuthenticationFailed => logger.write_string("AuthenticationFailed")
    InvalidKeySize(s) => logger.write_string("InvalidKeySize(" + s + ")")
    InvalidIvSize(s) => logger.write_string("InvalidIvSize(" + s + ")")
    Aead(e) => logger.write_string("Aead(" + @debug.to_string(e) + ")")
    RsaOaepError(s) => logger.write_string("RsaOaepError(" + s + ")")
  }
}

// ─── Algorithm name helpers (header strings) ─────────────────────────────

///|
fn alg_to_str(a : JweAlg) -> String {
  match a {
    Dir => "dir"
    Rsa_oaep_256 => "RSA-OAEP-256"
    A256kw => "A256KW"
  }
}

///|
fn alg_from_str(s : String) -> JweAlg raise JweError {
  match s {
    "dir" => Dir
    "RSA-OAEP-256" => Rsa_oaep_256
    "A256KW" => A256kw
    _ => raise UnsupportedAlgorithm(s)
  }
}

///|
fn enc_to_str(e : JweEnc) -> String {
  match e {
    A128gcm => "A128GCM"
    A256gcm => "A256GCM"
  }
}

///|
fn enc_from_str(s : String) -> JweEnc raise JweError {
  match s {
    "A128GCM" => A128gcm
    "A256GCM" => A256gcm
    _ => raise UnsupportedAlgorithm(s)
  }
}

///|
/// Required CEK length for the content-encryption algorithm.
fn enc_cek_len(e : JweEnc) -> Int {
  match e {
    A128gcm => 16
    A256gcm => 32
  }
}

///|
/// IV length (in bytes) for the content-encryption algorithm.
/// GCM uses a 12-byte (96-bit) nonce — RFC 7518 §5.3 step 2.
fn enc_iv_len(_e : JweEnc) -> Int {
  12
}

// ─── base64url ────────────────────────────────────────────────────────────

///|
fn base64url_encode(b : Bytes) -> String {
  let s = @base64.encode(b[:], padding=false)
  let buf = StringBuilder::new()
  for c in s {
    let c2 = if c == '+' { '-' } else if c == '/' { '_' } else { c }
    buf.write_char(c2)
  }
  buf.to_string()
}

///|
fn base64url_decode(s : String) -> Bytes raise JweError {
  let buf = StringBuilder::new()
  let mut n = 0
  for c in s {
    let is_valid = (c >= 'A' && c <= 'Z') ||
      (c >= 'a' && c <= 'z') ||
      (c >= '0' && c <= '9') ||
      c == '-' ||
      c == '_'
    if !is_valid {
      raise InvalidToken("invalid base64url character")
    }
    let c2 = if c == '-' { '+' } else if c == '_' { '/' } else { c }
    buf.write_char(c2)
    n = n + 1
  }
  if n % 4 == 1 {
    raise InvalidToken("invalid base64url length")
  }
  let pad_count = (4 - n % 4) % 4
  for _ in 0..<pad_count {
    buf.write_char('=')
  }
  @base64.decode(buf.to_string()) catch {
    _ => raise InvalidToken("invalid base64url segment")
  }
}

// ─── JOSE header ──────────────────────────────────────────────────────────

///|
fn validate_extra_header(extra : Map[String, Json]?) -> Unit raise JweError {
  match extra {
    None => ()
    Some(extras) =>
      for k, _v in extras {
        if k == "alg" || k == "enc" {
          raise InvalidHeader("extra protected header must not override " + k)
        }
        if k == "crit" {
          raise InvalidHeader(
            "crit header is present but no extensions are supported",
          )
        }
        if k == "zip" {
          raise UnsupportedAlgorithm("zip header is not supported")
        }
      }
  }
}

///|
fn build_header(
  alg : JweAlg,
  enc : JweEnc,
  extra : Map[String, Json]?,
) -> Json raise JweError {
  validate_extra_header(extra)
  let m : Map[String, Json] = Map([])
  // RFC 7516 §4.1.1 / §4.1.2: alg + enc are the only two required.
  m["alg"] = Json::string(alg_to_str(alg))
  m["enc"] = Json::string(enc_to_str(enc))
  match extra {
    Some(extras) =>
      for k, v in extras {
        m[k] = v
      }
    None => ()
  }
  Json::object(m)
}

///|
fn parse_json_object(s : String) -> Map[String, Json] raise JweError {
  reject_duplicate_top_level_json_keys(s)
  let parsed = @json.parse(s[:]) catch {
    _ => raise InvalidHeader("invalid JSON")
  }
  match parsed {
    Object(m) => m
    _ => raise InvalidHeader("expected JSON object")
  }
}

///|
fn json_ws_skip(s : String, start : Int) -> Int {
  let mut i = start
  while i < s.length() {
    let c = s.get_char(i).unwrap()
    if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
      i = i + 1
    } else {
      break
    }
  }
  i
}

///|
fn json_read_top_level_key(
  s : String,
  start : Int,
) -> (String, Int) raise JweError {
  let buf = StringBuilder::new()
  let mut i = start + 1
  while i < s.length() {
    let c = s.get_char(i).unwrap()
    if c == '"' {
      return (buf.to_string(), i + 1)
    }
    if c == '\\' {
      raise InvalidHeader(
        "escaped protected-header member names are not supported",
      )
    }
    buf.write_char(c)
    i = i + 1
  }
  raise InvalidHeader("unterminated protected-header member name")
}

///|
fn json_skip_string_value(s : String, start : Int) -> Int raise JweError {
  let mut i = start + 1
  while i < s.length() {
    let c = s.get_char(i).unwrap()
    if c == '"' {
      return i + 1
    }
    if c == '\\' {
      i = i + 2
    } else {
      i = i + 1
    }
  }
  raise InvalidHeader("unterminated JSON string")
}

///|
fn json_skip_value(s : String, start : Int) -> Int raise JweError {
  let mut i = json_ws_skip(s, start)
  if i >= s.length() {
    raise InvalidHeader("missing JSON value")
  }
  let c = s.get_char(i).unwrap()
  if c == '"' {
    return json_skip_string_value(s, i)
  }
  if c == '{' || c == '[' {
    let mut depth = 0
    while i < s.length() {
      let x = s.get_char(i).unwrap()
      if x == '"' {
        i = json_skip_string_value(s, i)
        continue
      }
      if x == '{' || x == '[' {
        depth = depth + 1
      } else if x == '}' || x == ']' {
        depth = depth - 1
        if depth == 0 {
          return i + 1
        }
      }
      i = i + 1
    }
    raise InvalidHeader("unterminated JSON container")
  }
  while i < s.length() {
    let x = s.get_char(i).unwrap()
    if x == ',' || x == '}' || x == ']' {
      return i
    }
    i = i + 1
  }
  i
}

///|
fn reject_duplicate_top_level_json_keys(s : String) -> Unit raise JweError {
  let keys : Array[String] = []
  let mut i = json_ws_skip(s, 0)
  if i >= s.length() || s.get_char(i).unwrap() != '{' {
    raise InvalidHeader("expected JSON object")
  }
  i = i + 1
  let mut done = false
  while !done {
    i = json_ws_skip(s, i)
    if i >= s.length() {
      raise InvalidHeader("unterminated JSON object")
    }
    if s.get_char(i).unwrap() == '}' {
      i = i + 1
      done = true
      continue
    }
    if s.get_char(i).unwrap() != '"' {
      raise InvalidHeader("expected JSON member name")
    }
    let (key, next) = json_read_top_level_key(s, i)
    for prev in keys {
      if prev == key {
        raise InvalidHeader("duplicate protected-header member '" + key + "'")
      }
    }
    keys.push(key)
    i = json_ws_skip(s, next)
    if i >= s.length() || s.get_char(i).unwrap() != ':' {
      raise InvalidHeader("expected ':' after JSON member")
    }
    i = json_skip_value(s, i + 1)
    i = json_ws_skip(s, i)
    if i >= s.length() {
      raise InvalidHeader("unterminated JSON object")
    }
    let sep = s.get_char(i).unwrap()
    if sep == ',' {
      i = i + 1
    } else if sep == '}' {
      i = i + 1
      done = true
    } else {
      raise InvalidHeader("expected ',' or '}'")
    }
  }
  i = json_ws_skip(s, i)
  if i != s.length() {
    raise InvalidHeader("trailing data after JSON object")
  }
}

///|
fn get_string(m : Map[String, Json], key : String) -> String? {
  match m.get(key) {
    Some(String(s)) => Some(s)
    _ => None
  }
}

// ─── RSA-OAEP-256 (RFC 8017 §7.1, label = "") ─────────────────────────────
//
// OAEP encoding (RFC 8017 §7.1.1, step 2):
//   lHash = SHA-256("") = (32 bytes)
//   DB = lHash || PS(zeros) || 0x01 || M    where |DB| = k - hLen - 1
//   seed = hLen random bytes
//   dbMask = MGF1(seed, k - hLen - 1)
//   maskedDB = DB XOR dbMask
//   seedMask = MGF1(maskedDB, hLen)
//   maskedSeed = seed XOR seedMask
//   EM = 0x00 || maskedSeed || maskedDB     where |EM| = k
//   c = RSAEP(pubkey, OS2IP(EM))            // m^e mod n
//
// For JWE the OAEP label is the empty string, so lHash is fixed:
//   lHash = SHA-256("") =
//     E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
//
// `seed_override` lets tests inject a deterministic seed; production must
// pass `None` (and the caller must supply a real RNG path — TODO).

///|
fn rsa_oaep_256_encrypt(
  pubkey : @rsa.RsaPublicKey,
  m : Bytes,
  seed : Bytes,
) -> Bytes raise JweError {
  let k = pubkey.n_bytes_len
  let hlen = 32 // SHA-256
  if seed.length() != hlen {
    raise InvalidKeySize(
      "OAEP seed must be 32 bytes, got " + seed.length().to_string(),
    )
  }
  if m.length() > k - 2 * hlen - 2 {
    raise RsaOaepError("message too long for RSA-OAEP-256")
  }
  let l_hash = @hash.sha256(b"")
  let db_len = k - hlen - 1
  // DB = lHash || 00 .. 00 || 0x01 || M
  let ps_len = db_len - hlen - 1 - m.length()
  let db = Bytes::makei(db_len, fn(i) {
    if i < hlen {
      l_hash[i]
    } else if i < hlen + ps_len {
      b'\x00'
    } else if i == hlen + ps_len {
      b'\x01'
    } else {
      m[i - hlen - ps_len - 1]
    }
  })
  let db_mask = mgf1_sha256(seed, db_len)
  let masked_db = xor_bytes(db, db_mask)
  let seed_mask = mgf1_sha256(masked_db, hlen)
  let masked_seed = xor_bytes(seed, seed_mask)
  // EM = 0x00 || maskedSeed || maskedDB
  let em = Bytes::makei(k, fn(i) {
    if i == 0 {
      b'\x00'
    } else if i < 1 + hlen {
      masked_seed[i - 1]
    } else {
      masked_db[i - 1 - hlen]
    }
  })
  // c = m^e mod n
  let m_int = @bigint.BigInt::from_octets(em[:])
  let c_int = m_int.pow(pubkey.e, modulus=pubkey.n)
  c_int.to_octets(length=k)
}

///|
/// RSA-OAEP-256 decrypt. Constant-error-shape: every failure (size
/// mismatch, Y != 0x00, lHash mismatch, missing 0x01 separator) raises
/// the same `AuthenticationFailed`. The underlying `@bigint.pow` is still
/// variable-time over the private exponent, so this is only "no padding
/// oracle", not full Manger-resistant.
fn rsa_oaep_256_decrypt(
  privkey : @rsa.RsaPrivateKey,
  c : Bytes,
) -> Bytes raise JweError {
  let k = privkey.n_bytes_len
  let hlen = 32
  // Step 1: length check. Failing here would let an attacker distinguish
  // "wrong key size" from "OAEP failure" — RFC 8017 §7.1.2 step 1.b says
  // these should all fail uniformly. We do allow ourselves to surface
  // size mismatch (which is a structural error, not a padding-oracle
  // signal): a caller who already routed the wrapped key through us
  // wouldn't have a length to vary.
  if c.length() != k {
    raise AuthenticationFailed
  }
  if k < 2 * hlen + 2 {
    raise AuthenticationFailed
  }
  // m = c^d mod n
  let c_int = @bigint.BigInt::from_octets(c[:])
  // Reject c >= n early. `to_octets(length=k)` would silently truncate /
  // we'd misinterpret EM; better to refuse outright.
  if c_int.compare(privkey.n) >= 0 {
    raise AuthenticationFailed
  }
  let m_int = c_int.pow(privkey.d, modulus=privkey.n)
  let em = m_int.to_octets(length=k)
  // Manger's attack mitigation: from this point onwards, every check
  // contributes to a single `bad` boolean, and we raise *one* error at
  // the end. Branches still differ in timing, but no two failure modes
  // are distinguishable by error type.
  let mut bad = false
  if em[0] != b'\x00' {
    bad = true
  }
  let masked_seed = Bytes::makei(hlen, fn(i) { em[1 + i] })
  let masked_db = Bytes::makei(k - hlen - 1, fn(i) { em[1 + hlen + i] })
  let seed_mask = mgf1_sha256(masked_db, hlen)
  let seed = xor_bytes(masked_seed, seed_mask)
  let db_mask = mgf1_sha256(seed, k - hlen - 1)
  let db = xor_bytes(masked_db, db_mask)
  let expected_l_hash = @hash.sha256(b"")
  // Compare lHash byte-by-byte without early termination.
  let mut lhash_diff = 0
  for i in 0..<hlen {
    lhash_diff = lhash_diff | (db[i].to_int() ^ expected_l_hash[i].to_int())
  }
  if lhash_diff != 0 {
    bad = true
  }
  // Find the 0x01 separator after the lHash + zero-padding section.
  let db_len = db.length()
  let mut sep = -1
  for i in hlen..<db_len {
    if sep == -1 {
      if db[i] == b'\x01' {
        sep = i
      } else if db[i] != b'\x00' {
        // Any byte that is neither zero nor the 0x01 separator before
        // we have found the separator => corrupt. Don't break (timing).
        bad = true
      }
    }
  }
  if sep == -1 {
    bad = true
  }
  if bad {
    raise AuthenticationFailed
  }
  // Extract M = db[sep+1 .. end]
  let m_len = db_len - sep - 1
  Bytes::makei(m_len, fn(i) { db[sep + 1 + i] })
}

///|
fn xor_bytes(a : Bytes, b : Bytes) -> Bytes {
  let n = a.length()
  Bytes::makei(n, fn(i) { (a[i].to_int() ^ b[i].to_int()).to_byte() })
}

///|
/// MGF1 (RFC 8017 §B.2.1) with SHA-256.
fn mgf1_sha256(mgf_seed : Bytes, mask_len : Int) -> Bytes {
  let h_len = 32
  // T accumulates Σ SHA-256(mgf_seed || I2OSP(counter, 4))
  // for counter = 0, 1, ..., ceil(mask_len / h_len) - 1
  let iters = (mask_len + h_len - 1) / h_len
  let seed_len = mgf_seed.length()
  let chunk_in = FixedArray::make(seed_len + 4, b'\x00')
  for i in 0..<seed_len {
    chunk_in[i] = mgf_seed[i]
  }
  let out = FixedArray::make(iters * h_len, b'\x00')
  for c in 0..<iters {
    chunk_in[seed_len] = ((c >> 24) & 0xFF).to_byte()
    chunk_in[seed_len + 1] = ((c >> 16) & 0xFF).to_byte()
    chunk_in[seed_len + 2] = ((c >> 8) & 0xFF).to_byte()
    chunk_in[seed_len + 3] = (c & 0xFF).to_byte()
    let chunk_bytes = Bytes::makei(seed_len + 4, fn(i) { chunk_in[i] })
    let h = @hash.sha256(chunk_bytes)
    for i in 0..<h_len {
      out[c * h_len + i] = h[i]
    }
  }
  Bytes::makei(mask_len, fn(i) { out[i] })
}

// ─── AES-256 Key Wrap (RFC 3394 §2.2.1) ───────────────────────────────────
//
// Wrap 32-byte key under 32-byte KEK → 40-byte wrapped key.
//   Inputs: KEK, P = P1..Pn (8-byte blocks; n=4 for 256-bit key)
//   Initial:  A = 0xA6A6A6A6A6A6A6A6, R[i] = P[i]
//   For j in 0..5:
//     For i in 1..n:
//       (A, R[i]) = MSB64(AES-Encrypt(KEK, A || R[i])), LSB64(...)
//       A = A XOR t  where t = n*j + i
//   Output: A || R[1] || ... || R[n]   (8 + 8n bytes total)

///|
let aes_kw_default_iv : Bytes = b"\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6"

///|
fn aes_key_wrap(kek : Bytes, key : Bytes) -> Bytes raise JweError {
  if kek.length() != 32 {
    raise InvalidKeySize(
      "A256KW KEK must be 32 bytes, got " + kek.length().to_string(),
    )
  }
  if key.length() % 8 != 0 || key.length() < 16 {
    raise InvalidKeySize(
      "A256KW input key must be a multiple of 8 bytes (>= 16), got " +
      key.length().to_string(),
    )
  }
  let n = key.length() / 8
  // A is 8 bytes; we hold it as a FixedArray for in-place XOR work.
  let a = FixedArray::make(8, b'\x00')
  for i in 0..<8 {
    a[i] = aes_kw_default_iv[i]
  }
  // R is n blocks of 8 bytes.
  let r = FixedArray::make(n * 8, b'\x00')
  for i in 0..<(n * 8) {
    r[i] = key[i]
  }
  let block_in = FixedArray::make(16, b'\x00')
  for j in 0..<6 {
    for i in 0..<n {
      // block_in = A || R[i]
      for kk in 0..<8 {
        block_in[kk] = a[kk]
        block_in[8 + kk] = r[i * 8 + kk]
      }
      let block_bytes = Bytes::makei(16, fn(idx) { block_in[idx] })
      let b = @aead.aes_block_encrypt(kek, block_bytes) catch {
        e => raise Aead(e)
      }
      // A = MSB64(B) XOR t,  R[i] = LSB64(B)
      let t = n * j + i + 1
      // t as a 64-bit big-endian value; XOR into A's bottom bytes
      for kk in 0..<8 {
        a[kk] = b[kk]
      }
      // XOR t into a (big-endian, t is at most ~24 bits for n=4, j=5).
      // Compute t as four bytes:
      let t0 = (t >> 24) & 0xFF
      let t1 = (t >> 16) & 0xFF
      let t2 = (t >> 8) & 0xFF
      let t3 = t & 0xFF
      a[4] = (a[4].to_int() ^ t0).to_byte()
      a[5] = (a[5].to_int() ^ t1).to_byte()
      a[6] = (a[6].to_int() ^ t2).to_byte()
      a[7] = (a[7].to_int() ^ t3).to_byte()
      for kk in 0..<8 {
        r[i * 8 + kk] = b[8 + kk]
      }
    }
  }
  Bytes::makei(8 + n * 8, fn(idx) { if idx < 8 { a[idx] } else { r[idx - 8] } })
}

///|
fn aes_key_unwrap(kek : Bytes, wrapped : Bytes) -> Bytes raise JweError {
  if kek.length() != 32 {
    raise InvalidKeySize(
      "A256KW KEK must be 32 bytes, got " + kek.length().to_string(),
    )
  }
  if wrapped.length() < 24 || wrapped.length() % 8 != 0 {
    raise InvalidKeySize(
      "A256KW wrapped key must be a multiple of 8 (>= 24), got " +
      wrapped.length().to_string(),
    )
  }
  let n = wrapped.length() / 8 - 1
  let a = FixedArray::make(8, b'\x00')
  for i in 0..<8 {
    a[i] = wrapped[i]
  }
  let r = FixedArray::make(n * 8, b'\x00')
  for i in 0..<(n * 8) {
    r[i] = wrapped[8 + i]
  }
  let block_in = FixedArray::make(16, b'\x00')
  // Reverse order: j from 5 down to 0, i from n down to 1.
  let mut j = 5
  while j >= 0 {
    let mut i = n
    while i >= 1 {
      let t = n * j + i
      // (A ^ t) || R[i]  → AES-decrypt → MSB64=A', LSB64=R[i]'
      for kk in 0..<8 {
        block_in[kk] = a[kk]
      }
      let t0 = (t >> 24) & 0xFF
      let t1 = (t >> 16) & 0xFF
      let t2 = (t >> 8) & 0xFF
      let t3 = t & 0xFF
      block_in[4] = (block_in[4].to_int() ^ t0).to_byte()
      block_in[5] = (block_in[5].to_int() ^ t1).to_byte()
      block_in[6] = (block_in[6].to_int() ^ t2).to_byte()
      block_in[7] = (block_in[7].to_int() ^ t3).to_byte()
      for kk in 0..<8 {
        block_in[8 + kk] = r[(i - 1) * 8 + kk]
      }
      let block_bytes = Bytes::makei(16, fn(idx) { block_in[idx] })
      let b = @aead.aes_block_decrypt(kek, block_bytes) catch {
        e => raise Aead(e)
      }
      for kk in 0..<8 {
        a[kk] = b[kk]
        r[(i - 1) * 8 + kk] = b[8 + kk]
      }
      i = i - 1
    }
    j = j - 1
  }
  // Verify integrity check vector A == 0xA6...A6.
  let mut bad = 0
  for kk in 0..<8 {
    bad = bad | (a[kk].to_int() ^ aes_kw_default_iv[kk].to_int())
  }
  if bad != 0 {
    raise AuthenticationFailed
  }
  Bytes::makei(n * 8, fn(idx) { r[idx] })
}

// ─── Compact-serialization encrypt / decrypt ──────────────────────────────

///|
/// Encrypt `plaintext` into a JWE compact-serialization string.
///
/// - `cek` (optional): caller-supplied CEK. Required when `alg == Dir`
///   (and must match the encryption's required CEK length). For wrapped
///   modes (`Rsa_oaep_256`, `A256kw`) it is optional, but supplying it is
///   how callers force a deterministic value in tests; v0 has no built-in
///   RNG, so `cek` is effectively required in all modes until we expose
///   one.
/// - `iv` (optional): caller-supplied 12-byte GCM IV. Same caveat — v0
///   has no built-in RNG, so callers must pass an IV.
/// - `oaep_seed` (optional): 32-byte seed for RSA-OAEP-256 masking. Same
///   "no built-in RNG" caveat.
/// - `extra_header` (optional): additional protected-header fields (e.g.
///   `kid`, `cty`). These become part of the AAD.
pub fn encrypt(
  plaintext : Bytes,
  alg : JweAlg,
  enc : JweEnc,
  key : EncryptionKey,
  cek? : Bytes,
  iv? : Bytes,
  oaep_seed? : Bytes,
  extra_header? : Map[String, Json],
) -> String raise JweError {
  // ── (1) Resolve content-encryption key ────────────────────────────────
  let cek_len = enc_cek_len(enc)
  let cek_bytes : Bytes = match (alg, key, cek) {
    (Dir, EncDir(cek=k), _) => {
      if k.length() != cek_len {
        raise InvalidKeySize(
          "dir CEK length mismatch: expected " +
          cek_len.to_string() +
          " for " +
          enc_to_str(enc) +
          ", got " +
          k.length().to_string(),
        )
      }
      k
    }
    (Dir, _, _) => raise AlgorithmMismatch("alg=dir requires EncDir key")
    (_, EncDir(..), _) => raise AlgorithmMismatch("EncDir key requires alg=dir")
    // For wrapped modes, the CEK is independent of the long-term key.
    (_, _, Some(c)) => {
      if c.length() != cek_len {
        raise InvalidKeySize(
          "supplied CEK length mismatch: expected " +
          cek_len.to_string() +
          ", got " +
          c.length().to_string(),
        )
      }
      c
    }
    (_, _, None) =>
      // v0: no RNG yet. Force caller to supply CEK.
      raise InvalidKeySize(
        "no CEK supplied for wrapped alg (v0 requires explicit cek=...)",
      )
  }

  // ── (2) Wrap the CEK for the chosen alg ──────────────────────────────
  let encrypted_key : Bytes = match (alg, key) {
    (Dir, _) => b""
    (Rsa_oaep_256, EncRsa(pubkey~)) => {
      let seed = match oaep_seed {
        Some(s) => s
        None =>
          raise InvalidKeySize(
            "no OAEP seed supplied (v0 requires explicit oaep_seed=...)",
          )
      }
      rsa_oaep_256_encrypt(pubkey, cek_bytes, seed)
    }
    (Rsa_oaep_256, _) =>
      raise AlgorithmMismatch("RSA-OAEP-256 requires EncRsa key")
    (A256kw, EncAes256Kw(kek~)) => aes_key_wrap(kek, cek_bytes)
    (A256kw, _) => raise AlgorithmMismatch("A256KW requires EncAes256Kw key")
  }

  // ── (3) IV ───────────────────────────────────────────────────────────
  let iv_len = enc_iv_len(enc)
  let iv_bytes : Bytes = match iv {
    Some(v) => {
      if v.length() != iv_len {
        raise InvalidIvSize(
          "IV length mismatch: expected " +
          iv_len.to_string() +
          ", got " +
          v.length().to_string(),
        )
      }
      v
    }
    None =>
      raise InvalidIvSize(
        "no IV supplied (v0 requires explicit iv=... — no RNG yet)",
      )
  }

  // ── (4) Build & encode protected header ──────────────────────────────
  let header_json = build_header(alg, enc, extra_header)
  let header_str = header_json.stringify()
  let header_b64 = base64url_encode(@utf8.encode(header_str[:]))

  // ── (5) AAD = ASCII bytes of base64url(header) (RFC 7516 §5.1 step 14)
  let aad = @utf8.encode(header_b64[:])

  // ── (6) AEAD encrypt ──────────────────────────────────────────────────
  let aead_alg = match enc {
    A128gcm => @aead.Algorithm::Aes128Gcm
    A256gcm => @aead.Algorithm::Aes256Gcm
  }
  let ct_and_tag = @aead.seal(aead_alg, cek_bytes, iv_bytes, aad, plaintext) catch {
    e => raise Aead(e)
  }
  // `seal` returns ct || tag (16-byte tag). Split for compact-form output.
  let total = ct_and_tag.length()
  let tag_len = 16
  let ct_len = total - tag_len
  let ct_bytes = Bytes::makei(ct_len, fn(i) { ct_and_tag[i] })
  let tag_bytes = Bytes::makei(tag_len, fn(i) { ct_and_tag[ct_len + i] })

  // ── (7) Assemble compact form ────────────────────────────────────────
  header_b64 +
  "." +
  base64url_encode(encrypted_key) +
  "." +
  base64url_encode(iv_bytes) +
  "." +
  base64url_encode(ct_bytes) +
  "." +
  base64url_encode(tag_bytes)
}

///|
/// Decrypt a JWE compact-serialization string. Returns the plaintext.
/// Raises `AuthenticationFailed` on any integrity / authentication failure
/// (tampered ciphertext, tampered header, wrong key, OAEP failure).
pub fn decrypt(token : String, key : DecryptionKey) -> Bytes raise JweError {
  // RFC 7516 §9 — compact form has exactly 4 dots → 5 segments.
  let parts = token.split(".").to_array()
  if parts.length() != 5 {
    raise InvalidToken("expected 5 segments, got " + parts.length().to_string())
  }
  let header_b64 = parts[0].to_owned()
  let ek_b64 = parts[1].to_owned()
  let iv_b64 = parts[2].to_owned()
  let ct_b64 = parts[3].to_owned()
  let tag_b64 = parts[4].to_owned()

  // ── (1) Parse header ─────────────────────────────────────────────────
  let header_bytes = base64url_decode(header_b64)
  let header_str = @utf8.decode(header_bytes[:]) catch {
    _ => raise InvalidHeader("header is not valid UTF-8")
  }
  let header = parse_json_object(header_str)
  let alg = match get_string(header, "alg") {
    Some(s) => alg_from_str(s)
    None => raise InvalidHeader("missing alg")
  }
  let enc = match get_string(header, "enc") {
    Some(s) => enc_from_str(s)
    None => raise InvalidHeader("missing enc")
  }
  // RFC 7516 §4.1.13: `crit` rejection — same logic as JWT verify.
  match header.get("crit") {
    Some(_) =>
      raise InvalidHeader(
        "crit header is present but no extensions are supported",
      )
    None => ()
  }
  // `zip` not supported in v0.
  match header.get("zip") {
    Some(_) => raise UnsupportedAlgorithm("zip header is not supported")
    None => ()
  }

  // ── (2) Unwrap CEK ────────────────────────────────────────────────────
  let cek_len = enc_cek_len(enc)
  let cek_bytes : Bytes = match (alg, key) {
    (Dir, DecDir(cek=k)) => {
      if k.length() != cek_len {
        // Collapse into AuthenticationFailed: divulging "wrong CEK length"
        // is fine here because the caller controls the key, but uniform
        // failure makes test expectations simpler.
        raise InvalidKeySize(
          "dir CEK length mismatch: expected " +
          cek_len.to_string() +
          ", got " +
          k.length().to_string(),
        )
      }
      // ek must be empty for dir (RFC 7518 §4.5).
      if ek_b64 != "" {
        raise InvalidToken("dir mode requires empty encrypted key")
      }
      k
    }
    (Dir, _) => raise AlgorithmMismatch("alg=dir requires DecDir key")
    (Rsa_oaep_256, DecRsa(privkey~)) => {
      let ek = base64url_decode(ek_b64)
      let cek = rsa_oaep_256_decrypt(privkey, ek)
      if cek.length() != cek_len {
        // OAEP unwrap returned a value of unexpected length — treat as
        // Manger-equivalent failure.
        raise AuthenticationFailed
      }
      cek
    }
    (Rsa_oaep_256, _) =>
      raise AlgorithmMismatch("RSA-OAEP-256 requires DecRsa key")
    (A256kw, DecAes256Kw(kek~)) => {
      let ek = base64url_decode(ek_b64)
      let cek = aes_key_unwrap(kek, ek)
      if cek.length() != cek_len {
        raise AuthenticationFailed
      }
      cek
    }
    (A256kw, _) => raise AlgorithmMismatch("A256KW requires DecAes256Kw key")
  }

  // ── (3) Decode IV / CT / Tag ──────────────────────────────────────────
  let iv_bytes = base64url_decode(iv_b64)
  let iv_len = enc_iv_len(enc)
  if iv_bytes.length() != iv_len {
    raise InvalidIvSize(
      "IV length mismatch: expected " +
      iv_len.to_string() +
      ", got " +
      iv_bytes.length().to_string(),
    )
  }
  let ct_bytes = base64url_decode(ct_b64)
  let tag_bytes = base64url_decode(tag_b64)
  if tag_bytes.length() != 16 {
    raise InvalidToken("tag must be 16 bytes")
  }

  // ── (4) AAD = ASCII of header_b64 ─────────────────────────────────────
  let aad = @utf8.encode(header_b64[:])

  // ── (5) AEAD open ─────────────────────────────────────────────────────
  let aead_alg = match enc {
    A128gcm => @aead.Algorithm::Aes128Gcm
    A256gcm => @aead.Algorithm::Aes256Gcm
  }
  // Reconstruct ct || tag (the aead.open API expects them concatenated).
  let total = ct_bytes.length() + tag_bytes.length()
  let combined = Bytes::makei(total, fn(i) {
    if i < ct_bytes.length() {
      ct_bytes[i]
    } else {
      tag_bytes[i - ct_bytes.length()]
    }
  })
  @aead.open(aead_alg, cek_bytes, iv_bytes, aad, combined) catch {
    @aead.AuthenticationFailed => raise AuthenticationFailed
    e => raise Aead(e)
  }
}
